package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
)

const ListenAddr = ":8081"
const KioubitPubKeyPath = "public_key.pem" // 請確保此檔案存在

// AgentConfig 儲存單個 DN42 節點的資訊
type AgentConfig struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	APIKey string `json:"apiKey"`
}

// DeployRequest 增加 Kioubit 驗證欄位
type DeployRequest struct {
	NodeID   string `json:"nodeId"`
	PeerASN  string `json:"asn"`
	PeerIPv6 string `json:"ipv6"`
	Endpoint string `json:"endpoint"`
	PubKey   string `json:"pubkey"`
	Name     string `json:"name"`
	AuthData string `json:"authData"` // Kioubit 返回的 JSON data (Base64)
	AuthSig  string `json:"authSig"`  // Kioubit 返回的 Signature (Base64)
}

// KioubitData 定義解碼後的驗證數據結構
type KioubitData struct {
	ASN  string `json:"asn"`
	Time int64  `json:"time"`
}

// 節點列表
var Nodes = []AgentConfig{
	{
		ID:     "taipei-1",
		Name:   "臺北節點 (4242421234)",
		URL:    "http://10.0.0.1:8080/add_peer",
		APIKey: "TAIPEI_NODE_SECRET_KEY_MUST_BE_LONG",
	},
	{
		ID:     "london-2",
		Name:   "倫敦節點 (4242425678)",
		URL:    "http://10.0.0.2:8080/add_peer",
		APIKey: "LONDON_NODE_SECRET_KEY_MUST_BE_LONG",
	},
}

var kioubitPubKey *ecdsa.PublicKey

func main() {
	// 1. 啟動時載入公鑰
	if err := loadPublicKey(); err != nil {
		log.Fatalf("❌ 無法載入 Kioubit 公鑰 (%s): %v\n請從 https://dn42.g-load.eu/auth/assets/public_key.pem 下載並放置於此。", KioubitPubKeyPath, err)
	}
	fmt.Println("✅ Kioubit 公鑰載入成功")

	// 2. 載入 index.html 模板
	htmlBytes, err := os.ReadFile("index.html")
	if err != nil {
		log.Fatalf("無法讀取 index.html: %v", err)
	}
	tmpl := template.Must(template.New("index").Parse(string(htmlBytes)))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		renderIndex(w, r, tmpl)
	})

	http.HandleFunc("/deploy", deployProxyHandler)

	fmt.Printf("🚀 DN42 Control Panel 正在監聽 %s\n", ListenAddr)
	log.Fatal(http.ListenAndServe(ListenAddr, nil))
}

func loadPublicKey() error {
	pemBytes, err := os.ReadFile(KioubitPubKeyPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("failed to parse PEM block")
	}
	genericPub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	var ok bool
	kioubitPubKey, ok = genericPub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("public key is not ECDSA")
	}
	return nil
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

	// === Kioubit 驗證邏輯 ===
	if req.AuthData == "" || req.AuthSig == "" {
		http.Error(w, "必須通過 Kioubit 驗證才能建立 Peer (缺少 AuthData/AuthSig)", http.StatusUnauthorized)
		return
	}

	verifiedASN, err := verifyKioubit(req.AuthData, req.AuthSig)
	if err != nil {
		log.Printf("Kioubit 驗證失敗: %v", err)
		http.Error(w, fmt.Sprintf("驗證失敗: %v", err), http.StatusForbidden)
		return
	}

	// 檢查驗證的 ASN 是否與請求的 ASN 一致
	if verifiedASN != req.PeerASN {
		errMsg := fmt.Sprintf("ASN 不匹配！您驗證的是 %s，但試圖配置 %s", verifiedASN, req.PeerASN)
		http.Error(w, errMsg, http.StatusForbidden)
		return
	}
	log.Printf("✅ 驗證通過: ASN %s", verifiedASN)
	// =======================

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

	// 轉發給 Agent 的 payload
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

// verifyKioubit 驗證簽名並返回 ASN
func verifyKioubit(dataStr, sigStr string) (string, error) {
	// 1. Decode Base64
	dataBytes, err := base64Decode(dataStr)
	if err != nil {
		return "", fmt.Errorf("decode data error: %v", err)
	}
	sigBytes, err := base64Decode(sigStr)
	if err != nil {
		return "", fmt.Errorf("decode sig error: %v", err)
	}

	// 2. Hash Data (SHA-512)
	h := sha512.New()
	h.Write(dataBytes)
	hash := h.Sum(nil)

	// 3. Verify Signature
	// 注意：Kioubit 有時返回 ASN.1 DER 格式，有時是 Raw R|S。
	// Go 的 VerifyASN1 處理標準 DER。如果失敗，可嘗試 Raw 轉換(此處簡化為標準處理)
	valid := ecdsa.VerifyASN1(kioubitPubKey, hash, sigBytes)

	// 如果 ASN.1 驗證失敗，嘗試將 Raw (R|S) 轉換為 BigInt 驗證 (針對某些 PHP/Node 簽署情況)
	if !valid && len(sigBytes) >= 132 { // P-521 R+S 約為 132 bytes
		r := new(big.Int).SetBytes(sigBytes[:len(sigBytes)/2])
		s := new(big.Int).SetBytes(sigBytes[len(sigBytes)/2:])
		valid = ecdsa.Verify(kioubitPubKey, hash, r, s)
	}

	if !valid {
		return "", errors.New("invalid signature")
	}

	// 4. Parse JSON
	var kData KioubitData
	if err := json.Unmarshal(dataBytes, &kData); err != nil {
		return "", fmt.Errorf("json unmarshal error: %v", err)
	}

	return kData.ASN, nil
}

func base64Decode(s string) ([]byte, error) {
	// 嘗試標準解碼
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return b, nil
	}
	// 嘗試 URL Safe 解碼
	return base64.URLEncoding.DecodeString(s)
}
