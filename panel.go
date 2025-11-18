package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
)

const ListenAddr = ":8081"

// AgentConfig 儲存單個 DN42 節點的資訊
type AgentConfig struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	APIKey string `json:"apiKey"`
}

type DeployRequest struct {
	NodeID   string `json:"nodeId"`
	PeerASN  string `json:"asn"`
	PeerIPv6 string `json:"ipv6"`
	Endpoint string `json:"endpoint"`
	PubKey   string `json:"pubkey"`
	Name     string `json:"name"`
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

func main() {

	// 載入 index.html 模板
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
