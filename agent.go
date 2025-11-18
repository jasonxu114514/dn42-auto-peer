package main

import (
        "encoding/json"
        "fmt"
        "io/ioutil"
        "log"
        "net/http"
        "os"
        "os/exec"
        "path/filepath"
        "regexp"
        "strings"
        "sync"
)

// ================= 配置設定 =================
const (
        ListenAddr     = ":8080" // 監聽端口
        AuthToken      = "aaaatoken" // ⚠️ 請修改此 Token 以確保安全
        PrivateKeyPath = "/etc/wireguard/privatekey"
        BirdFilterPath = "/etc/bird/filter/dn42_filter.conf"
        BirdSessionDir = "/etc/bird/protocol/dn42_session"
        WgConfDir      = "/etc/wireguard"
)

// RequestBody 定義接收的 JSON 格式
type PeerRequest struct {
        ASN      string `json:"asn"`      // 對方 ASN
        IPv6     string `json:"ipv6"`     // 對方 DN42 IPv6
        Endpoint string `json:"endpoint"` // 對方 WireGuard Endpoint (IP:Port)
        PubKey   string `json:"pubkey"`   // 對方 WireGuard Public Key
        Name     string `json:"name"`     // 對方名字
}

// Response 定義回傳的 JSON 格式
type Response struct {
        Success bool   `json:"success"`
        Message string `json:"message"`
        Data    string `json:"data,omitempty"`
}

// 全局鎖，防止並發請求導致配置衝突
var mu sync.Mutex

func main() {
        // 1. 啟動前檢查 Root 權限
        if os.Geteuid() != 0 {
                log.Fatal("❌ 錯誤：請使用 root 權限執行此 Agent")
        }

        // 2. 預先檢查關鍵文件是否存在
        if _, err := os.Stat(PrivateKeyPath); os.IsNotExist(err) {
                log.Fatalf("❌ 錯誤：找不到私鑰文件 %s", PrivateKeyPath)
        }

        // 3. 設定 HTTP 路由
        http.HandleFunc("/add_peer", authMiddleware(handleAddPeer))

        // 4. 啟動伺服器
        fmt.Printf("🚀 DN42 Agent 正在監聽 %s ...\n", ListenAddr)
        fmt.Printf("🔑 驗證 Token: %s\n", AuthToken)
        log.Fatal(http.ListenAndServe(ListenAddr, nil))
}

// authMiddleware 簡單的 Token 驗證中間件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
                token := r.Header.Get("X-API-Key")
                if token != AuthToken {
                        http.Error(w, `{"success":false, "message":"Unauthorized"}`, http.StatusUnauthorized)
                        return
                }
                next(w, r)
        }
}

// handleAddPeer 處理添加 Peer 的請求
func handleAddPeer(w http.ResponseWriter, r *http.Request) {
        // 僅允許 POST
        if r.Method != http.MethodPost {
                http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
                return
        }

        // 解析 JSON
        var req PeerRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                sendJSON(w, false, "無效的 JSON 格式", "")
                return
        }

        // 簡單參數驗證
        if len(req.ASN) < 5 || req.IPv6 == "" || req.Endpoint == "" || req.PubKey == "" || req.Name == "" {
                sendJSON(w, false, "參數不完整或 ASN 格式錯誤", "")
                return
        }

        // 加鎖，開始執行核心邏輯
        mu.Lock()
        defer mu.Unlock()

        log.Printf("收到部署請求: Name=%s, ASN=%s", req.Name, req.ASN)

        // 執行部署邏輯
        if err := deployPeer(req); err != nil {
                log.Printf("❌ 部署失敗: %v", err)
                sendJSON(w, false, fmt.Sprintf("部署失敗: %v", err), "")
                return
        }

        log.Printf("✅ 部署成功: %s", req.Name)
        sendJSON(w, true, "部署成功", fmt.Sprintf("Peer %s (ASN %s) 已上線", req.Name, req.ASN))
}

// deployPeer 核心業務邏輯 (與之前的 CLI 邏輯一致)
func deployPeer(p PeerRequest) error {
        // 1. 準備變數
        asnSuffix4 := p.ASN[len(p.ASN)-4:]
        asnSuffix5 := p.ASN[len(p.ASN)-5:]
        wgInterface := fmt.Sprintf("DN42-%s", asnSuffix4)
        wgConfPath := filepath.Join(WgConfDir, wgInterface+".conf")
        birdConfPath := filepath.Join(BirdSessionDir, fmt.Sprintf("DN42-%s.conf", asnSuffix4))

        // 2. 獲取本機資訊 (每次讀取以防變更)
        localPrivKeyBytes, err := ioutil.ReadFile(PrivateKeyPath)
        if err != nil {
                return fmt.Errorf("讀取私鑰失敗: %v", err)
        }
        localPrivKey := strings.TrimSpace(string(localPrivKeyBytes))

        localIPv6, err := getOwnIPv6(BirdFilterPath)
        if err != nil {
                return fmt.Errorf("解析 OWNIPv6 失敗: %v", err)
        }

        // 3. 生成配置內容
        wgConfig := fmt.Sprintf(`[Interface]
PrivateKey = %s
ListenPort = %s
PostUp = ip addr add %s peer %s dev %%i
Table = off

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 25
`, localPrivKey, asnSuffix5, localIPv6, p.IPv6, p.PubKey, p.Endpoint)

        birdConfig := fmt.Sprintf(`protocol bgp DN42_%s_%s from dnpeers {
        neighbor %s as %s;
}
`, asnSuffix4, p.Name, p.IPv6, p.ASN)

        // 4. 寫入檔案
        if err := ioutil.WriteFile(wgConfPath, []byte(wgConfig), 0600); err != nil {
                return fmt.Errorf("寫入 WireGuard 配置失敗: %v", err)
        }

        if err := os.MkdirAll(BirdSessionDir, 0755); err != nil {
                return err
        }
        if err := ioutil.WriteFile(birdConfPath, []byte(birdConfig), 0644); err != nil {
                return fmt.Errorf("寫入 Bird 配置失敗: %v", err)
        }

        // 5. 系統命令執行
        // 檢查接口是否存在，存在則重啟
        if interfaceExists(wgInterface) {
                exec.Command("wg-quick", "down", wgConfPath).Run()
        }

        // 啟動 WireGuard
        cmdUp := exec.Command("wg-quick", "up", wgConfPath)
        if output, err := cmdUp.CombinedOutput(); err != nil {
                return fmt.Errorf("wg-quick up 失敗: %s, %v", string(output), err)
        }

        // 重載 Bird
        cmdBird := exec.Command("birdc", "configure")
        if output, err := cmdBird.CombinedOutput(); err != nil {
                return fmt.Errorf("birdc configure 失敗: %s, %v", string(output), err)
        }

        return nil
}

// 輔助工具函數
func sendJSON(w http.ResponseWriter, success bool, msg string, data string) {
        w.Header().Set("Content-Type", "application/json")
        if !success {
                w.WriteHeader(http.StatusInternalServerError)
        } else {
                w.WriteHeader(http.StatusOK)
        }
        json.NewEncoder(w).Encode(Response{
                Success: success,
                Message: msg,
                Data:    data,
        })
}

func getOwnIPv6(path string) (string, error) {
        content, err := ioutil.ReadFile(path)
        if err != nil {
                return "", err
        }
        re := regexp.MustCompile(`define\s+OWNIPv6\s*=\s*([^;]+);`)
        matches := re.FindSubmatch(content)
        if len(matches) < 2 {
                return "", fmt.Errorf("找不到 OWNIPv6 定義")
        }
        return strings.TrimSpace(string(matches[1])), nil
}

func interfaceExists(ifaceName string) bool {
        _, err := os.Stat(fmt.Sprintf("/sys/class/net/%s", ifaceName))
        return !os.IsNotExist(err)
}
