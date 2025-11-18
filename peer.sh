#!/bin/bash

# ==========================================
# DN42 Peer 全自動部署腳本 (含啟動與重載)
# ==========================================

# 檢查是否為 Root 身份
if [ "$EUID" -ne 0 ]; then
  echo "❌ 請使用 root 權限運行此腳本 (sudo ./add_dn42_peer_auto.sh)"
  exit 1
fi

# ------------------------------------------
# 1. 收集用戶輸入
# ------------------------------------------
echo "--- 請輸入對方 Peer 資訊 ---"
read -p "對方 ASN (例如 4242421234): " PEER_ASN
read -p "對方 DN42 IPv6 (例如 fe80::1 或 fda0:...): " PEER_IPV6
read -p "對方 WireGuard Endpoint (IP:Port): " PEER_ENDPOINT
read -p "對方 WireGuard Public Key: " PEER_PUBKEY
read -p "對方名字 (用於標識，例如 Hostname): " PEER_NAME

# ------------------------------------------
# 2. 處理變數邏輯
# ------------------------------------------

# 擷取 ASN 後 4 位 (用於檔名和 BGP Session 名稱)
ASN_SUFFIX_4=${PEER_ASN: -4}

# 擷取 ASN 後 5 位 (用於 ListenPort)
ASN_SUFFIX_5=${PEER_ASN: -5}

# 定義介面名稱
WG_INTERFACE="DN42-${ASN_SUFFIX_4}"

# 讀取本機 WireGuard Private Key
if [ -f "/etc/wireguard/privatekey" ]; then
    LOCAL_PRIVATE_KEY=$(cat /etc/wireguard/privatekey | tr -d '[:space:]')
else
    echo "❌ 錯誤: 找不到 /etc/wireguard/privatekey"
    exit 1
fi

# 讀取本機 DN42 IPv6
FILTER_FILE="/etc/bird/filter/dn42_filter.conf"
if [ -f "$FILTER_FILE" ]; then
    LOCAL_IPV6=$(grep "define OWNIPv6" "$FILTER_FILE" | awk -F'=' '{print $2}' | tr -d ' ;[:space:]')
    if [ -z "$LOCAL_IPV6" ]; then
        echo "❌ 錯誤: 無法從 $FILTER_FILE 中提取 OWNIPv6"
        exit 1
    fi
else
    echo "❌ 錯誤: 找不到 $FILTER_FILE"
    exit 1
fi

# 定義輸出文件路徑
WG_CONF_PATH="/etc/wireguard/${WG_INTERFACE}.conf"
BIRD_CONF_PATH="/etc/bird/protocol/dn42_session/DN42-${ASN_SUFFIX_4}.conf"

# ------------------------------------------
# 3. 生成 WireGuard 配置
# ------------------------------------------
echo "正在寫入 WireGuard 配置 -> $WG_CONF_PATH ..."

cat > "$WG_CONF_PATH" <<EOF
[Interface]
PrivateKey = $LOCAL_PRIVATE_KEY
ListenPort = $ASN_SUFFIX_5
PostUp = ip addr add $LOCAL_IPV6 peer $PEER_IPV6 dev %i
Table = off

[Peer]
PublicKey = $PEER_PUBKEY
Endpoint = $PEER_ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 25
EOF

chmod 600 "$WG_CONF_PATH"

# ------------------------------------------
# 4. 生成 Bird 配置
# ------------------------------------------
mkdir -p /etc/bird/protocol/dn42_session/

echo "正在寫入 Bird 配置 -> $BIRD_CONF_PATH ..."

cat > "$BIRD_CONF_PATH" <<EOF
protocol bgp DN42_${ASN_SUFFIX_4}_${PEER_NAME} from dnpeers {
        neighbor $PEER_IPV6 as $PEER_ASN;
}
EOF

# ------------------------------------------
# 5. 自動啟動與重載
# ------------------------------------------
echo "--- 正在執行自動化操作 ---"

# 檢查接口是否已經存在，如果存在則先關閉
if ip link show "$WG_INTERFACE" > /dev/null 2>&1; then
    echo "⚠️ 接口 $WG_INTERFACE 已存在，正在重啟..."
    wg-quick down "$WG_CONF_PATH"
fi

# 啟動 WireGuard 接口
echo "🚀 正在啟動 WireGuard 接口 ($WG_INTERFACE)..."
if wg-quick up "$WG_CONF_PATH"; then
    echo "✅ WireGuard 啟動成功"
else
    echo "❌ WireGuard 啟動失敗，請檢查配置"
    exit 1
fi

# 重載 Bird 配置
echo "🐦 正在重載 Bird 配置..."
if birdc configure; then
    echo "✅ Bird 重載成功 (Configured)"
else
    echo "❌ Bird 重載失敗，請檢查 Bird 配置語法"
    exit 1
fi

# (可選) 設定開機自啟
# echo "正在設定開機自啟..."
# systemctl enable wg-quick@$WG_INTERFACE

# ------------------------------------------
# 6. 完成
# ------------------------------------------
echo "---"
echo "🎉 全自動部署完成！"
echo "Peer: $PEER_NAME (ASN: $PEER_ASN)"
echo "狀態: WireGuard 已啟動, Bird 已重載"
