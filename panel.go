package main

import (
        "bytes"
        "crypto/ecdsa"
        "crypto/sha512"
        "crypto/x509"
        _ "embed" // 用於嵌入公鑰文件
        "encoding/base64"
        "encoding/json"
        "encoding/pem"
        "errors"
        "fmt"
        "html/template"
        "io"
        "log"
        "math"
        "net/http"
        "time"
)

const ListenAddr = ":8081"

// ⚠️ 請修改此處！這必須與您在 Kioubit 驗證時顯示的 domain 一致
// 如果是在本地測試，通常是 "localhost:8081"
const MyDomain = "localhost:8081"

//go:embed public_key.pem
var pemPubKey []byte

// AgentConfig 儲存單個 DN42 節點的資訊
type AgentConfig struct {
        ID     string `json:"id"`
        Name   string `json:"name"`
        URL    string `json:"url"`
        APIKey string `json:"apiKey"`
}

// DeployRequest 前端傳來的請求結構
type DeployRequest struct {
        NodeID   string `json:"nodeId"`
        PeerASN  string `json:"asn"`
        PeerIPv6 string `json:"ipv6"`
        Endpoint string `json:"endpoint"`
        PubKey   string `json:"pubkey"`
        Name     string `json:"name"`
        AuthData string `json:"authData"` // 對應 URL 中的 'params'
        AuthSig  string `json:"authSig"`  // 對應 URL 中的 'signature'
}

// KioubitData 定義 Kioubit 返回的 JSON 結構
type KioubitData struct {
        ASN    string  `json:"asn"`
        Time   float64 `json:"time"` // JSON 數字通常解析為 float64
        Domain string  `json:"domain"`
}

// 節點列表
var Nodes = []AgentConfig{
        {
                ID:     "taipei-1",
                Name:   "臺北節點 (4242421234)",
                URL:    "http://10.0.0.1:8080/add_peer",
                APIKey: "TAIPEI_NODE_SECRET_KEY_MUST_BE_LONG",
        },
        // ... 其他節點
}

func main() {
        // 檢查公鑰是否正確載入
        if len(pemPubKey) == 0 {
                log.Fatal("❌ 錯誤：public_key.pem 未能嵌入，請確認檔案存在於同級目錄")
        }

        // 載入 index.html 模板
        htmlBytes, err := template.ParseFiles("index.html")
        if err != nil {
                log.Fatalf("無法讀取 index.html: %v", err)
        }
        tmpl := template.Must(htmlBytes, err)

        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                renderIndex(w, r, tmpl)
        })

        http.HandleFunc("/deploy", deployProxyHandler)

        fmt.Printf("🚀 DN42 Control Panel 正在監聽 %s\n", ListenAddr)
        fmt.Printf("🔒 驗證域名設定為: %s\n", MyDomain)
        log.Fatal(http.ListenAndServe(ListenAddr, nil))
}

func renderIndex(w http.ResponseWriter, r *http.Request, tmpl *template.Template) {
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        if err := tmpl.Execute(w, Nodes); err != nil {
                log.Printf("模板渲染錯誤: %v", err)
                http.Error(w, "模板渲染失敗", http.StatusInternalServerError)
        }
}

func deployProxyHandler(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
                http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
                return
        }

        var req DeployRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                http.Error(w, "Invalid JSON input", http.StatusBadRequest)
                return
        }

        // === 1. 執行 Kioubit 驗證 ===
        if req.AuthData == "" || req.AuthSig == "" {
                http.Error(w, "缺少驗證數據 (params/signature)", http.StatusUnauthorized)
                return
        }

        userData, err := verifyAuthToken(req.AuthSig, req.AuthData)
        if err != nil {
                log.Printf("⚠️ 驗證失敗: %v", err)
                http.Error(w, fmt.Sprintf("驗證失敗: %v", err), http.StatusForbidden)
                return
        }

        // === 2. 檢查 ASN 是否匹配 ===
        // 確保用戶提交的 ASN 與 Kioubit 驗證的 ASN 一致
        if userData.ASN != req.PeerASN {
                errMsg := fmt.Sprintf("ASN 不匹配！Token 屬於 %s，但請求配置的是 %s", userData.ASN, req.PeerASN)
                http.Error(w, errMsg, http.StatusForbidden)
                return
        }

        log.Printf("✅ 驗證通過: ASN=%s, Domain=%s", userData.ASN, userData.Domain)

        // === 3. 尋找目標節點並轉發 ===
        var targetNode *AgentConfig
        for i := range Nodes {
                if Nodes[i].ID == req.NodeID {
                  targetNode = &Nodes[i]
                  break
                }
        }

        if targetNode == nil {
                http.Error(w, "Target node not found", http.StatusBadRequest)
                return
        }

        agentPayload := map[string]string{
                "asn":      req.PeerASN,
                "ipv6":     req.PeerIPv6,
                "endpoint": req.Endpoint,
                "pubkey":   req.PubKey,
                "name":     req.Name,
        }
        payloadJSON, _ := json.Marshal(agentPayload)

        client := &http.Client{}
        proxyReq, err := http.NewRequest("POST", targetNode.URL, bytes.NewBuffer(payloadJSON))
        if err != nil {
                http.Error(w, "Cannot create request", http.StatusInternalServerError)
                return
        }

        proxyReq.Header.Set("Content-Type", "application/json")
        proxyReq.Header.Set("X-API-Key", targetNode.APIKey)

        resp, err := client.Do(proxyReq)
        if err != nil {
                http.Error(w, fmt.Sprintf("Error contacting Agent: %v", err), http.StatusServiceUnavailable)
                return
        }
        defer resp.Body.Close()

        for k, v := range resp.Header {
                w.Header()[k] = v
        }
        w.WriteHeader(resp.StatusCode)
        io.Copy(w, resp.Body)
}

// verifyAuthToken 驗證邏輯 (基於官方範例)
// signature: Base64 簽名
// params: Base64 JSON 數據 (注意：這裡是未解碼的 Base64 字串，用來做 Hash)
func verifyAuthToken(signature, params string) (*KioubitData, error) {
        // 1. 解析公鑰
        blockPub, _ := pem.Decode(pemPubKey)
        if blockPub == nil {
                return nil, errors.New("failed to decode PEM block")
        }
        genericPublicKey, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
        if err != nil {
                return nil, errors.New("internal server error: key parse failed")
        }
        publicKey, ok := genericPublicKey.(*ecdsa.PublicKey)
        if !ok {
                return nil, errors.New("internal server error: key type mismatch")
        }

        // 2. Hash parameters (直接 Hash 原始的 Base64 params 字串)
        hash := sha512.Sum512([]byte(params))

        // 3. Decode base64 signature
        // 為了相容性，處理 URL encoding 或 Standard encoding
        var signatureBytes []byte
        if decoded, err := base64.StdEncoding.DecodeString(signature); err == nil {
                signatureBytes = decoded
        } else if decoded, err := base64.URLEncoding.DecodeString(signature); err == nil {
                signatureBytes = decoded
        } else {
                return nil, errors.New("failed to decode signature")
        }

        // 4. Verify signature
        if !ecdsa.VerifyASN1(publicKey, hash[:], signatureBytes) {
                return nil, errors.New("invalid signature")
        }

        // 5. Decode parameters to JSON
        var parameterBytes []byte
        if decoded, err := base64.StdEncoding.DecodeString(params); err == nil {
                parameterBytes = decoded
        } else if decoded, err := base64.URLEncoding.DecodeString(params); err == nil {
                parameterBytes = decoded
        } else {
                return nil, fmt.Errorf("failed decoding verified parameters: %w", err)
        }

        var userData KioubitData
        err = json.Unmarshal(parameterBytes, &userData)
        if err != nil {
                return nil, fmt.Errorf("failed unmarshaling verified parameters: %w", err)
        }

        // 6. 驗證時間 (有效期 120 秒，避免時鐘偏差)
        if math.Abs(userData.Time-float64(time.Now().Unix())) > 120 {
                return nil, errors.New("the request has expired")
        }

        // 7. 驗證域名
        if userData.Domain != MyDomain {
                return nil, fmt.Errorf("domain mismatch: expected %s, got %s", MyDomain, userData.Domain)
        }

        return &userData, nil
}
