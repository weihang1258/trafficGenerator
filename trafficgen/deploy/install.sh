#!/usr/bin/env bash
# trafficgen 安装脚本（v1，Linux amd64）
#
# 用法一（离线，推荐）：tar 包解开后在包目录内执行
#   sudo ./install.sh
#
# 用法二（在线一条命令）：从 GitHub Releases 拉取 install.sh 执行，零参数
# 自动安装最新发布版本（无需指定版本号）：
#   curl -fsSL https://github.com/weihang1258/trafficGenerator/releases/latest/download/install.sh | sudo bash
#
#   也可显式指定其他发布 base / 版本（或用环境变量 TRAFFICGEN_RELEASE_BASE）：
#   curl -fsSL <base>/install.sh | sudo bash -s -- <base> <版本号如 v1.1.0>
#
# 发布目录需含（make dist 产物）：trafficgen-<版本>-linux-amd64.tar.gz、
# SHA256SUMS、install.sh。
#
# 脚本行为：装 /opt/trafficgen → 建 trafficgen 系统用户与 /var/lib/trafficgen
# 数据目录 → 生成 /etc/trafficgen/config.yaml（自动随机 api_key，已存在则保留）
# → 注册并启动 systemd 服务 → 打印 MCP 端点与密钥。
set -euo pipefail

INSTALL_DIR=/opt/trafficgen
DATA_DIR=/var/lib/trafficgen
CONF_DIR=/etc/trafficgen
CONF_FILE=$CONF_DIR/config.yaml
SERVICE=trafficgen
SERVICE_USER=trafficgen

# 在线模式默认值：base 可被环境变量或第一个参数覆盖；版本号默认自动解析
# GitHub 最新 release（latest_tag），make dist 烧入值仅作解析失败时的回落
# （源码直跑时为占位符，走在线分支会提示显式传参）。
DEFAULT_BASE="${TRAFFICGEN_RELEASE_BASE:-https://github.com/weihang1258/trafficGenerator/releases/download}"
DEFAULT_VERSION="__RELEASE_VERSION__"

log()  { printf '\033[32m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*"; }
die()  { printf '\033[31m错误：%s\033[0m\n' "$*" >&2; exit 1; }

# ---- 0. 前置检查 -----------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo ./install.sh）"
command -v systemctl >/dev/null || die "未找到 systemctl：本脚本依赖 systemd"
[ "$(uname -m)" = "x86_64" ] || die "v1 仅支持 x86_64，当前 $(uname -m)"

# 最新 release 的 tag：releases/latest 302 重定向到 .../tag/<tag>，取尾段。
# 不能带 -L：跟随重定向后 redirect_url 恒为空，必须只读 302 的 Location。
# 非 GitHub 的自定义 base 无 latest 端点（404）→ 回落烧入版本。
latest_tag() {
    local url
    url=$(curl -fsS -o /dev/null -w '%{redirect_url}' --connect-timeout 10 --max-time 30 \
        "${DEFAULT_BASE%/download}/latest") && { url=${url##*/}; [ -n "$url" ] && printf '%s' "$url"; }
}

# 本地包模式判定：$0 必须是真实存在的 install.sh 文件，且同目录有 trafficgen
# 二进制（-f 排除目录——目录也有 x 位，cwd 下恰有 trafficgen 目录时会误判）。
# curl|bash 管道模式 $0 是 "bash"，恒走在线分支。
SRC_DIR=""
if [ -f "$0" ] && [ "$(basename "$0")" = "install.sh" ]; then
    _d="$(cd "$(dirname "$0")" && pwd)"
    [ -f "$_d/trafficgen" ] && [ -x "$_d/trafficgen" ] && SRC_DIR="$_d"
fi
BASE_URL="${1:-$DEFAULT_BASE}"
VERSION="${2:-}"

# ---- 1. 取得发布文件（本地包目录或在线下载）---------------------------------
if [ -n "$SRC_DIR" ]; then
    log "使用本地发布包：$SRC_DIR"
else
    # 版本解析只属在线分支：本地包安装可能是离线机器，不值得白等网络超时。
    [ -n "$VERSION" ] || VERSION=$(latest_tag) || VERSION="$DEFAULT_VERSION"
    [ -n "$BASE_URL" ] && [ -n "$VERSION" ] && [ "$VERSION" != "__RELEASE_VERSION__" ] || die \
        "当前目录没有 trafficgen 二进制，且在线模式缺少发布地址/版本。请在解包后的目录内运行，或显式传入 <发布base> <版本号>（如 v1.1.0），或设 TRAFFICGEN_RELEASE_BASE"
    ARCH=linux-amd64
    TARBALL="trafficgen-${VERSION}-${ARCH}.tar.gz"
    TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
    log "下载 $BASE_URL/$VERSION/$TARBALL"
    # curl 必须带超时：下载地址不可达时无超时会永久挂死（实机安装测出）。
    curl -fsSL --connect-timeout 10 --max-time 300 -o "$TMP/$TARBALL" "$BASE_URL/$VERSION/$TARBALL"
    curl -fsSL --connect-timeout 10 --max-time 60 -o "$TMP/SHA256SUMS" "$BASE_URL/$VERSION/SHA256SUMS" || warn "无 SHA256SUMS，跳过校验"
    [ -f "$TMP/SHA256SUMS" ] && (cd "$TMP" && grep "$TARBALL" SHA256SUMS | sha256sum -c - >/dev/null) \
        || die "SHA256 校验失败，文件可能被篡改"
    tar -xzf "$TMP/$TARBALL" -C "$TMP"
    # 解包目录精确查找：包名固定 trafficgen-<版本>-linux-amd64；
    # 不能用 ls|grep 兜底——排序会拿到 tarball 文件而非目录。
    SRC_DIR=$(find "$TMP" -maxdepth 1 -type d -name 'trafficgen-*' | head -1)
    [ -n "$SRC_DIR" ] && [ -f "$SRC_DIR/trafficgen" ] && [ -x "$SRC_DIR/trafficgen" ] \
        || die "发布包内容异常（缺 trafficgen 二进制）"
fi

# ---- 2. 安装二进制 ----------------------------------------------------------
mkdir -p "$INSTALL_DIR/bin"
install -m 0755 "$SRC_DIR/trafficgen" "$INSTALL_DIR/bin/trafficgen"
install -m 0755 "$SRC_DIR/uninstall.sh" "$INSTALL_DIR/uninstall.sh"
INSTALLED=$("$INSTALL_DIR/bin/trafficgen" -version)

# ---- 3. 系统用户与数据目录 --------------------------------------------------
id -u "$SERVICE_USER" >/dev/null 2>&1 || \
    useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
mkdir -p "$DATA_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"

# ---- 4. 配置（已存在则保留，绝不覆盖用户配置）--------------------------------
mkdir -p "$CONF_DIR"
if [ -f "$CONF_FILE" ]; then
    warn "检测到已有配置 $CONF_FILE —— 保留不动（升级场景）"
    API_KEY=$(awk '/^[[:space:]]*api_key:/ {print $2; exit}' "$CONF_FILE")
else
    API_KEY=$(openssl rand -hex 24 2>/dev/null || head -c 48 /dev/urandom | od -An -tx1 | tr -d ' \n')
    SVC_PW=$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    sed -e "s/__MCP_API_KEY__/$API_KEY/" -e "s/__MCP_SVC_PASSWORD__/$SVC_PW/" \
        "$SRC_DIR/config.yaml.example" > "$CONF_FILE"
    # 0640：owner=root 可写，组 trafficgen（服务运行身份）必须可读——
    # 0600 会让 systemd 服务读配置直接 permission denied（实机测出）。
    chmod 0640 "$CONF_FILE"
    chown root:"$SERVICE_USER" "$CONF_FILE"
fi

# ---- 5. systemd 服务（生成即注册）--------------------------------------------
cat > /etc/systemd/system/${SERVICE}.service <<UNIT
# 由 trafficgen install.sh 生成；手工改动会被 reinstall 覆盖
[Unit]
Description=trafficgen MCP traffic generation service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$DATA_DIR
ExecStart=$INSTALL_DIR/bin/trafficgen -config $CONF_FILE
Restart=on-failure
RestartSec=2
# NIC 实发（pcap 注入）所需能力；仅本地 pcap 文件生成时无用但无害
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"
sleep 1
systemctl --quiet is-active "$SERVICE" || {
    journalctl -u "$SERVICE" -n 30 --no-pager
    die "服务启动失败，见上方日志"
}

# ---- 6. 就绪信息 -------------------------------------------------------------
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
IP=${IP:-127.0.0.1}
log "──────────────────────────────────────────────────────"
log "✅ $INSTALLED 安装完成，服务已启动（开机自启）"
log ""
log "   MCP 端点 :  http://$IP:8086/mcp"
log "   API Key  :  $API_KEY   （客户端请求头 X-MCP-Key）"
log ""
log "   常用命令 :  systemctl status|restart|stop $SERVICE"
log "   日志     :  journalctl -u $SERVICE -f"
log "   卸载     :  sudo $INSTALL_DIR/uninstall.sh"
log "──────────────────────────────────────────────────────"
