#!/usr/bin/env bash
set -Eeuo pipefail
# ============================================
# Cealing-Host 一键部署（默认开启 443，TLS1.2 & HTTP/1.1）
# 拓扑：Client --TLS1.2/HTTP1.1--> NGINX(stream:443, ssl终止)
#      → forger(mitmproxy, 伪造SNI/定向IP, upstream→Squid) → Squid(127.0.0.1:3128) → Internet
# 功能：写入 forgerd.service / NGINX stream / squid.conf / 每日规则更新 timer
# 兼容：Ubuntu 20.04+, Debian 11+, Alpine 3.14+, CentOS 7+, AlmaLinux 8+, Amazon Linux 2
# ============================================

# -------- 可配参数（可用环境变量覆盖） --------
ENABLE_TLS_PROXY="${ENABLE_TLS_PROXY:-true}"   # 始终默认开启 443
ENABLE_HTTP_PROXY="${ENABLE_HTTP_PROXY:-false}" # 如需 80 明文代理设为 true

HTTPS_PORT="${HTTPS_PORT:-443}"
HTTP_PORT="${HTTP_PORT:-80}"         # 仅当 ENABLE_HTTP_PROXY=true 时生成

FORGER_PORT="${FORGER_PORT:-8889}"   # forger 监听（仅 127.0.0.1）
SQUID_PORT="${SQUID_PORT:-3128}"     # Squid 监听（仅 127.0.0.1）

BASE_DIR="${BASE_DIR:-/opt/cealing}" # forger venv 与脚本目录
CERT_DIR="${CERT_DIR:-/opt/ceiling-host/certs}"

RULES_PATH="${RULES_PATH:-/etc/cealing/rules.json}"
RULES_URL="${RULES_URL:-https://raw.githubusercontent.com/SpaceTimee/Cealing-Host/main/Cealing-Host.json}"

# ---------------- 系统检测变量 ----------------
OS_TYPE=""
OS_VERSION=""
PKG_MGR=""
NGINX_PKG=""
SQUID_PKG=""
PYTHON_PKG=""
PYTHON_CMD=""
PIP_CMD=""
SERVICE_MGR=""
NGINX_CONF_PATH=""
NGINX_USER=""

# ---------------- 自动生成代理认证凭据（若未通过环境变量提供） ----------------
# 生成规则：用户名以小写字母/数字，前缀 u，长度 11；密码为大小写字母与数字，长度 20。
# 这些值会被导出到当前环境，并写入 $BASE_DIR/credentials 以便后续查看/持久化（文件权限 600）。
if [[ -z "${PROXY_AUTH_USER:-}" ]]; then
  PROXY_AUTH_USER="u$(tr -dc 'a-z0-9' </dev/urandom | head -c 10 || true)"
fi
if [[ -z "${PROXY_AUTH_PASS:-}" ]]; then
  PROXY_AUTH_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20 || true)"
fi
export PROXY_AUTH_USER PROXY_AUTH_PASS
# 写入持久化凭据文件（覆盖）
mkdir -p "$BASE_DIR"
credfile="$BASE_DIR/credentials"
cat >"$credfile" <<EOF
PROXY_AUTH_USER="$PROXY_AUTH_USER"
PROXY_AUTH_PASS="$PROXY_AUTH_PASS"
EOF
chmod 600 "$credfile" || true
# 也写入 /etc/cealing/credentials 以便系统级查看（如有权限）
if [[ -w "$(dirname "$RULES_PATH")" ]] || [[ -w "/etc" ]]; then
  etcf="/etc/cealing"
  mkdir -p "$etcf" 2>/dev/null || true
  printf 'PROXY_AUTH_USER="%s"\nPROXY_AUTH_PASS="%s"\n' "$PROXY_AUTH_USER" "$PROXY_AUTH_PASS" > "$etcf/credentials" 2>/dev/null || true
  chmod 600 "$etcf/credentials" 2>/dev/null || true
fi
# ---------------------------------------------------------------------------

NGINX_STREAM_DIR="/etc/nginx/streams-enabled"
FORGER_SVC="/etc/systemd/system/forgerd.service"
RULES_UPDATE_SVC="/etc/systemd/system/cealing-rules-update.service"
RULES_UPDATE_TIMER="/etc/systemd/system/cealing-rules-update.timer"

# Alpine Linux 使用 OpenRC
if [[ -d /etc/init.d ]] && [[ ! -d /etc/systemd ]]; then
    FORGER_SVC="/etc/init.d/forgerd"
    SERVICE_MGR="openrc"
fi

info(){ echo -e "\033[1;34m[INFO]\033[0m  $*"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m  $*"; }
err(){  echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }

need_root(){ [[ $(id -u) -eq 0 ]] || err "请用 root 运行"; }

# 增强的系统检测函数
detect_os(){
  [[ -f /etc/os-release ]] || err "缺少 /etc/os-release"
  . /etc/os-release
  
  OS_TYPE="${ID:-}"
  OS_VERSION="${VERSION_ID:-}"
  
  # 检测包管理器和设置系统特定变量
  case "${OS_TYPE}" in
    debian|ubuntu)
      PKG_MGR="apt"
      NGINX_PKG="nginx-full"
      SQUID_PKG="squid"
      PYTHON_PKG="python3 python3-venv"
      PYTHON_CMD="python3"
      PIP_CMD="pip3"
      SERVICE_MGR="systemd"
      NGINX_CONF_PATH="/etc/nginx/nginx.conf"
      NGINX_USER="www-data"
      ;;
    alpine)
      PKG_MGR="apk"
      NGINX_PKG="nginx"
      SQUID_PKG="squid"
      PYTHON_PKG="python3 py3-pip py3-virtualenv"
      PYTHON_CMD="python3"
      PIP_CMD="pip3"
      SERVICE_MGR="openrc"
      NGINX_CONF_PATH="/etc/nginx/nginx.conf"
      NGINX_USER="nginx"
      ;;
    centos|rhel|almalinux|rocky)
      PKG_MGR="yum"
      if [[ "${OS_VERSION%%.*}" -ge 8 ]] 2>/dev/null; then
        PKG_MGR="dnf"
      fi
      NGINX_PKG="nginx"
      SQUID_PKG="squid"
      PYTHON_PKG="python3 python3-pip python3-virtualenv"
      PYTHON_CMD="python3"
      PIP_CMD="pip3"
      SERVICE_MGR="systemd"
      NGINX_CONF_PATH="/etc/nginx/nginx.conf"
      NGINX_USER="nginx"
      ;;
    amzn)
      PKG_MGR="yum"
      NGINX_PKG="nginx"
      SQUID_PKG="squid"
      PYTHON_PKG="python3 python3-pip"
      PYTHON_CMD="python3"
      PIP_CMD="pip3"
      SERVICE_MGR="systemd"
      NGINX_CONF_PATH="/etc/nginx/nginx.conf"
      NGINX_USER="nginx"
      ;;
    *)
      warn "未测试的系统 $OS_TYPE，尝试使用通用配置..."
      # 尝试检测包管理器
      if command -v apt-get >/dev/null 2>&1; then
        PKG_MGR="apt"
      elif command -v yum >/dev/null 2>&1; then
        PKG_MGR="yum"
      elif command -v apk >/dev/null 2>&1; then
        PKG_MGR="apk"
      else
        err "无法检测到支持的包管理器"
      fi
      ;;
  esac
  
  info "检测到系统: $OS_TYPE $OS_VERSION (包管理器: $PKG_MGR, 服务管理器: $SERVICE_MGR)"
}

# 多系统包安装函数
install_packages() {
  local packages="$*"
  
  case "$PKG_MGR" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y --no-install-recommends $packages
      ;;
    yum|dnf)
      $PKG_MGR install -y $packages
      ;;
    apk)
      apk update
      apk add --no-cache $packages
      ;;
    *)
      err "不支持的包管理器: $PKG_MGR"
      ;;
  esac
}

# 增强的依赖包安装函数
ensure_pkgs(){
  info "安装依赖包..."
  
  local base_pkgs="curl openssl ca-certificates"
  local additional_pkgs=""
  
  case "$OS_TYPE" in
    alpine)
      # Alpine 特殊处理
      additional_pkgs="jq nginx-mod-stream"
      install_packages $base_pkgs $additional_pkgs $NGINX_PKG $SQUID_PKG $PYTHON_PKG
      # Alpine 需要启用 stream 模块
      if ! grep -q "load_module.*ngx_stream_module.so" /etc/nginx/nginx.conf 2>/dev/null; then
        sed -i '1i load_module /usr/lib/nginx/modules/ngx_stream_module.so;' /etc/nginx/nginx.conf
      fi
      ;;
    debian|ubuntu)
      additional_pkgs="jq"
      install_packages $base_pkgs $additional_pkgs $NGINX_PKG $SQUID_PKG $PYTHON_PKG
      # 检查 nginx stream 模块
      nginx -V 2>&1 | grep -q -- --with-stream || err "nginx 未启用 stream 模块；请安装 nginx-full"
      ;;
    centos|rhel|almalinux|rocky|amzn)
      # RHEL 系列需要 EPEL
      if [[ "$OS_TYPE" != "amzn" ]]; then
        $PKG_MGR install -y epel-release 2>/dev/null || true
      fi
      additional_pkgs="jq nginx-mod-stream"
      install_packages $base_pkgs $additional_pkgs $NGINX_PKG $SQUID_PKG $PYTHON_PKG
      # RHEL 系列可能需要加载 stream 模块
      if [[ -f /usr/share/nginx/modules/mod-stream.conf ]]; then
        cp /usr/share/nginx/modules/mod-stream.conf /etc/nginx/modules-enabled/ 2>/dev/null || true
      fi
      ;;
    *)
      install_packages $base_pkgs jq $NGINX_PKG $SQUID_PKG $PYTHON_PKG
      ;;
  esac
  
  # 验证 Python
  command -v $PYTHON_CMD >/dev/null || err "Python3 安装失败"
}

make_dirs(){
  mkdir -p "$BASE_DIR/bin" "$BASE_DIR/venv" "$NGINX_STREAM_DIR" "$(dirname "$RULES_PATH")" "$CERT_DIR"
}

fetch_rules_once(){
  info "拉取 Cealing-Host 规则：$RULES_URL"
  if ! curl -fsSL "$RULES_URL" -o "$RULES_PATH"; then
    warn "下载失败，写入示例规则"
    cat >"$RULES_PATH" <<'JSON'
[
  [["example.com","*.example.com"], "front.example-cdn.com", "93.184.216.34"],
  [["$global-only.example"], "front.global.example", "203.0.113.9"],
  [["#browser-only.example"], "ignored.example", "198.51.100.1"],
  [["^ignore.this.com"], "x", "1.1.1.1"]
]
JSON
  fi
}

# 增强的 mitmproxy 安装函数
install_mitmproxy(){
  info "安装 mitmproxy 到 venv（规避 PEP 668）"
  
  # 创建虚拟环境
  case "$OS_TYPE" in
    alpine)
      # Alpine 使用 virtualenv 命令
      if command -v virtualenv >/dev/null 2>&1; then
        virtualenv "$BASE_DIR/venv"
      else
        $PYTHON_CMD -m venv "$BASE_DIR/venv"
      fi
      ;;
    *)
      $PYTHON_CMD -m venv "$BASE_DIR/venv"
      ;;
  esac
  
  # 升级 pip 并安装 mitmproxy
  "$BASE_DIR/venv/bin/python" -m pip install --upgrade pip setuptools wheel >/dev/null
  
  # Alpine 可能需要额外的编译依赖
  if [[ "$OS_TYPE" == "alpine" ]]; then
    apk add --no-cache --virtual .build-deps gcc musl-dev libffi-dev openssl-dev python3-dev 2>/dev/null || true
    "$BASE_DIR/venv/bin/python" -m pip install "mitmproxy>=10,<12" >/dev/null
    apk del .build-deps 2>/dev/null || true
  else
    "$BASE_DIR/venv/bin/python" -m pip install "mitmproxy>=10,<12" >/dev/null
  fi
}

write_forger_plugin(){
  info "写入 forgerules.py（兼容 Cealing-Host：*、$、#、^）"
  cat >"$BASE_DIR/bin/forgerules.py" <<'PY'
import json, ipaddress, socket, traceback, base64
from typing import List, Tuple, Optional
from mitmproxy import ctx, http

def _resolve_target(host_or_ip: str) -> str:
    try:
        ipaddress.ip_address(host_or_ip); return host_or_ip
    except Exception:
        pass
    try:
        infos = socket.getaddrinfo(host_or_ip, None, proto=socket.IPPROTO_TCP)
        for _,_,_,_,sa in infos:
            return sa[0]
    except Exception:
        ctx.log.warn(f"resolve failed: {host_or_ip}")
    return host_or_ip

def _norm_domain(d: str) -> Optional[str]:
    if not d: return None
    if d.startswith("^"): return None   # 显式忽略
    if d.startswith("#"): return None   # 浏览器注入专用 → 中间件忽略
    if d.startswith("$"): d = d[1:]     # 全局可用
    return d.lstrip("*.").lower()

def _check_proxy_auth(flow: http.HTTPFlow) -> bool:
    """    验证 Proxy-Authorization: Basic <base64(user:pass)>
    认证凭据通过 mitmproxy options 传入： proxy_auth_user / proxy_auth_pass
    如果未设置 proxy_auth_user（为空），则跳过认证（无认证）
    """
    try:
        expected_user = (ctx.options.proxy_auth_user or "") or ""
        expected_pass = (ctx.options.proxy_auth_pass or "") or ""
    except Exception:
        return False

    # if expected_user is empty -> auth disabled
    if not expected_user:
        return True

    hdr = None
    try:
        hdr = flow.request.headers.get("Proxy-Authorization") or flow.request.headers.get("proxy-authorization")
    except Exception:
        hdr = None
    if not hdr:
        return False
    parts = hdr.split()
    if len(parts) != 2:
        return False
    scheme, token = parts[0], parts[1]
    if scheme.lower() != "basic":
        return False
    try:
        up = base64.b64decode(token).decode("utf-8", errors="ignore")
        if ":" not in up:
            return False
        user, pw = up.split(":", 1)
        return (user == expected_user) and (pw == expected_pass)
    except Exception:
        return False

class ForgeRules:
    def __init__(self):
        self.rules_path = getattr(ctx.options, "rules_path", "/etc/cealing/rules.json")
        self.rules: List[Tuple[List[str], str, str]] = []
        self._load()

    def load(self, loader):
        loader.add_option("rules_path", str, "/etc/cealing/rules.json", "Path to Cealing rules")
        loader.add_option("proxy_auth_user", str, "", "Proxy auth username (empty to disable auth)")
        loader.add_option("proxy_auth_pass", str, "", "Proxy auth password")

    def _load(self):
        try:
            raw = json.load(open(self.rules_path, "r", encoding="utf-8"))
        except Exception as e:
            ctx.log.warn(f"cannot load rules: {e}")
            raw = []
        rules = []
        for item in raw:
            if not isinstance(item, list) or len(item) < 3: continue
            ds, forged, target = item[0] or [], str(item[1] or ""), str(item[2] or "")
            nds = []
            for d in ds:
                nd = _norm_domain(str(d))
                if nd: nds.append(nd)
            if not nds or not target: continue
            rules.append((nds, forged, target))
        self.rules = rules
        ctx.log.info(f"Loaded {len(self.rules)} rules from {self.rules_path}")

    def configure(self, updates):
        if "rules_path" in updates:
            self.rules_path = ctx.options.rules_path
            self._load()

    def _match(self, host: str) -> Optional[Tuple[str, str]]:
        host = (host or "").lower()
        for domains, forged, target in self.rules:
            for d in domains:
                if host == d or host.endswith("." + d):
                    return forged or "", target
        return None

    def request(self, flow: http.HTTPFlow):
        try:
            if not flow.request:
                return
            # 如果启用了 proxy_auth_user（非空），在处理任何请求前先做认证
            try:
                enabled_user = (ctx.options.proxy_auth_user or "") or ""
            except Exception:
                enabled_user = ""
            if enabled_user:
                if not _check_proxy_auth(flow):
                    # 返回 407 Proxy Authentication Required
                    resp = http.HTTPResponse.make(
                        407,
                        b"Proxy Authentication Required",
                        {"Proxy-Authenticate": 'Basic realm="Cealing"'}
                    )
                    flow.response = resp
                    ctx.log.info("Rejected request due to missing/invalid Proxy-Authorization header")
                    return

            scheme = (flow.request.scheme or "").lower()
            if scheme not in ("http","https"):
                return
            host = flow.request.host
            hit = self._match(host)
            if not hit:
                return

            forged_sni, target = hit
            ip = _resolve_target(target)

            # upstream 模式：改 CONNECT 目标到指定 IP:443；设置上游 TLS 的 SNI
            flow.request.host = ip
            flow.request.port = 443
            if forged_sni:
                try:
                    flow.server_conn.sni = forged_sni
                except Exception as e:
                    ctx.log.warn(f"set SNI failed: {e}")

            # 明文 HTTP 请求保持 Host 头
            if flow.request.method != "CONNECT" and host:
                flow.request.headers["Host"] = host

            ctx.log.info(f"FORGE match host={host} -> CONNECT {ip}:443 with SNI={forged_sni or host}")
        except Exception:
            ctx.log.warn("forgerules exception:\n" + traceback.format_exc())

addons = [ForgeRules()]
PY
}

disable_conflicting_sites(){
  # 避免 http 站点占用 80/443 影响 stream 绑定（只删除默认站点；其他请自行调整）
  [[ -e /etc/nginx/sites-enabled/default ]] && rm -f /etc/nginx/sites-enabled/default || true
}

gen_self_signed_cert(){
  local crt="$CERT_DIR/fullchain.pem" key="$CERT_DIR/privkey.pem"
  if [[ -s "$crt" && -s "$key" ]]; then info "已存在证书：$crt"; return; fi
  info "生成自签证书（仅供代理 TLS 使用，可后续替换为正式证书）"
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
    -subj "/CN=$(hostname -f)" \
    -keyout "$key" -out "$crt" >/dev/null 2>&1
  chmod 600 "$key"
}

# 增强的 nginx 配置函数
write_nginx_stream(){
  info "生成 NGINX stream 配置（强制 TLS1.2 & HTTP/1.1 CONNECT）"
  
  # 根据系统调整配置路径
  local nginx_conf="$NGINX_CONF_PATH"
  
  # 顶层 include（在 http{} 外）
  if ! grep -q 'streams-enabled/\*\.conf' "$nginx_conf"; then
    cat >>"$nginx_conf" <<'CONF'

# ==== NGINX stream (Cealing middleware) ====
stream {
    include /etc/nginx/streams-enabled/*.conf;
}
# ===========================================
CONF
  fi

  disable_conflicting_sites
  mkdir -p "$NGINX_STREAM_DIR"

  # 443：TLS 终止（仅 TLS1.2，服务端不提供 HTTP/2 的 ALPN，客户端将使用 HTTP/1.1 CONNECT）
  cat >"$NGINX_STREAM_DIR/proxy_to_forger_tls.conf" <<CONF
server {
    listen 0.0.0.0:$HTTPS_PORT ssl;

    # --- TLS 强制 1.2，禁 TLS1.3 ---
    ssl_protocols TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;
    # 不启用 http/2（stream 无 http2 指令；不通告 h2，客户端将回退 HTTP/1.1）
    # 证书
    ssl_certificate     $CERT_DIR/fullchain.pem;
    ssl_certificate_key $CERT_DIR/privkey.pem;

    proxy_pass 127.0.0.1:$FORGER_PORT;
    proxy_connect_timeout 30s;
    proxy_timeout 60s;
}
CONF

  # 可选：80 明文代理
  if [[ "${ENABLE_HTTP_PROXY}" == "true" ]]; then
    cat >"$NGINX_STREAM_DIR/proxy_to_forger_http.conf" <<CONF
server {
    listen 0.0.0.0:$HTTP_PORT;
    proxy_pass 127.0.0.1:$FORGER_PORT;
    proxy_connect_timeout 30s;
    proxy_timeout 60s;
}
CONF
  else
    rm -f "$NGINX_STREAM_DIR/proxy_to_forger_http.conf" 2>/dev/null || true
  fi

  nginx -t
  reload_service nginx
}

write_squid_conf(){
  info "写入最小 Squid 配置（仅本机可用，默认直连）"
  local SQ="/etc/squid/squid.conf"
  [[ -f "$SQ" ]] && cp -a "$SQ" "${SQ}.bak.$(date +%s)" || true
  cat >"$SQ" <<SQUID
# Minimal Squid for Cealing stack
http_port 127.0.0.1:$SQUID_PORT
acl localhost src 127.0.0.1/32 ::1
http_access allow localhost
http_access deny all

# 默认直连；如需父代理请添加 cache_peer ... 并启用 never_direct
# 例：
# cache_peer PARENT_IP parent 3128 0 no-query default
# never_direct allow all

dns_v4_first on
pipeline_prefetch on
SQUID
  restart_service squid
}

# 多系统服务管理函数
enable_service() {
  local service="$1"
  case "$SERVICE_MGR" in
    systemd)
      systemctl enable "$service" 2>/dev/null || true
      ;;
    openrc)
      rc-update add "$service" default 2>/dev/null || true
      ;;
  esac
}

start_service() {
  local service="$1"
  case "$SERVICE_MGR" in
    systemd)
      systemctl start "$service"
      ;;
    openrc)
      rc-service "$service" start
      ;;
  esac
}

stop_service() {
  local service="$1"
  case "$SERVICE_MGR" in
    systemd)
      systemctl stop "$service" 2>/dev/null || true
      ;;
    openrc)
      rc-service "$service" stop 2>/dev/null || true
      ;;
  esac
}

restart_service() {
  local service="$1"
  case "$SERVICE_MGR" in
    systemd)
      systemctl restart "$service"
      ;;
    openrc)
      rc-service "$service" restart
      ;;
  esac
}

reload_service() {
  local service="$1"
  case "$SERVICE_MGR" in
    systemd)
      systemctl reload "$service"
      ;;
    openrc)
      rc-service "$service" reload 2>/dev/null || \
      rc-service "$service" restart
      ;;
  esac
}

# Alpine OpenRC 服务脚本创建函数
write_openrc_service() {
  info "创建 OpenRC 服务脚本 (Alpine)"
  
  cat >"$FORGER_SVC" <<'OPENRC'
#!/sbin/openrc-run

name="forgerd"
description="Cealing forger middleware (mitmproxy upstream->squid)"
command="/opt/cealing/venv/bin/mitmdump"
command_args="-vv --listen-host 127.0.0.1 -p 8889 --mode upstream:http://127.0.0.1:3128 -s /opt/cealing/bin/forgerules.py --set rules_path=/etc/cealing/rules.json --set ssl_insecure=true --set connection_strategy=lazy --set block_global=false --set proxy_auth_user=${PROXY_AUTH_USER} --set proxy_auth_pass=${PROXY_AUTH_PASS}"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
command_user="root"
start_stop_daemon_args="--stdout /var/log/forgerd.log --stderr /var/log/forgerd.log"

depend() {
    need net
    after firewall
}
OPENRC
  
  # 替换变量
  sed -i "s/\${PROXY_AUTH_USER}/$PROXY_AUTH_USER/g" "$FORGER_SVC"
  sed -i "s/\${PROXY_AUTH_PASS}/$PROXY_AUTH_PASS/g" "$FORGER_SVC"
  
  chmod +x "$FORGER_SVC"
  enable_service forgerd
}

# 增强的定时任务函数（支持 cron）
write_rules_timer(){
  info "创建规则更新定时任务"
  
  if [[ "$SERVICE_MGR" == "systemd" ]]; then
    # Systemd timer
    cat >"$RULES_UPDATE_SVC" <<UNIT
[Unit]
Description=Update Cealing-Host rules JSON and restart forgerd
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/curl -fsSL $RULES_URL -o $RULES_PATH.tmp
ExecStartPost=/usr/bin/install -m 0644 $RULES_PATH.tmp $RULES_PATH
ExecStartPost=/usr/bin/rm -f $RULES_PATH.tmp
ExecStartPost=/bin/systemctl restart forgerd
UNIT

    cat >"$RULES_UPDATE_TIMER" <<'UNIT'
[Unit]
Description=Daily update of Cealing-Host rules

[Timer]
OnCalendar=daily
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
UNIT

    systemctl daemon-reload
    systemctl enable --now cealing-rules-update.timer
    
  else
    # Cron job (for non-systemd systems)
    local cron_cmd="curl -fsSL $RULES_URL -o $RULES_PATH && rc-service forgerd restart"
    if [[ "$SERVICE_MGR" == "openrc" ]]; then
      # Alpine/OpenRC
      echo "0 3 * * * $cron_cmd" | crontab -
      info "已添加 cron 定时任务（每日凌晨3点）"
    fi
  fi
}

# 增强的防火墙配置函数
open_firewall(){
  info "放行端口（支持多种防火墙）"
  
  # UFW (Ubuntu/Debian)
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -qi "Status: active"; then
    ufw allow "$HTTPS_PORT/tcp" || true
    [[ "$ENABLE_HTTP_PROXY" == "true" ]] && ufw allow "$HTTP_PORT/tcp" || true
    return
  fi
  
  # firewalld (CentOS/RHEL/AlmaLinux)
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-port=$HTTPS_PORT/tcp 2>/dev/null || true
    [[ "$ENABLE_HTTP_PROXY" == "true" ]] && firewall-cmd --permanent --add-port=$HTTP_PORT/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    return
  fi
  
  # iptables (Alpine/通用)
  if command -v iptables >/dev/null 2>&1; then
    iptables -I INPUT -p tcp --dport $HTTPS_PORT -j ACCEPT 2>/dev/null || true
    [[ "$ENABLE_HTTP_PROXY" == "true" ]] && iptables -I INPUT -p tcp --dport $HTTP_PORT -j ACCEPT 2>/dev/null || true
    
    # 尝试保存规则
    if command -v iptables-save >/dev/null 2>&1; then
      if [[ "$OS_TYPE" == "alpine" ]]; then
        rc-service iptables save 2>/dev/null || true
      elif [[ -f /etc/sysconfig/iptables ]]; then
        iptables-save > /etc/sysconfig/iptables
      fi
    fi
    return
  fi
  
  # nftables (新系统)
  if command -v nft >/dev/null 2>&1; then
    nft list chain inet filter input >/dev/null 2>&1 || {
      nft add table inet filter
      nft add chain inet filter input '{ type filter hook input priority 0; }'
    }
    nft add rule inet filter input tcp dport $HTTPS_PORT accept 2>/dev/null || true
    if [[ "$ENABLE_HTTP_PROXY" == "true" ]]; then
      nft add rule inet filter input tcp dport $HTTP_PORT accept 2>/dev/null || true
    fi
  fi
}

show_summary(){
  echo
  info "部署完成 ✅"
  echo "系统类型: $OS_TYPE $OS_VERSION"
  echo "对外入口："
  echo "  - HTTPS 代理（TLS1.2/HTTP1.1）： https://<你的IP>:$HTTPS_PORT"
  [[ "$ENABLE_HTTP_PROXY" == "true" ]] && echo "  - HTTP  代理（明文可选）：     http://<你的IP>:$HTTP_PORT"
  echo
  echo "链路： NGINX(stream) → forgerd(127.0.0.1:$FORGER_PORT) → Squid(127.0.0.1:$SQUID_PORT)"
  echo "规则： $RULES_PATH（Cealing-Host 兼容，已启用每日自动更新）"
  echo
  echo "验证（服务器本机）："
  echo "  curl -v -x http://127.0.0.1:$FORGER_PORT http://httpbin.org/ip"
  echo "  curl -v --proxy-insecure -x https://127.0.0.1:$HTTPS_PORT https://example.com  # 首次可临时 --proxy-insecure"
  echo
  
  if [[ "$SERVICE_MGR" == "systemd" ]]; then
    echo "日志： journalctl -u forgerd -n 120 --no-pager | grep 'FORGE match'"
  else
    echo "日志： tail -f /var/log/forgerd.log | grep 'FORGE match'"
  fi
  
  echo
  echo "⚠️ 客户端（如 v2rayN）走 443 时需开启：TLS + Allow insecure（跳过到代理的证书校验）。"
  # 展示自动生成的代理用户名/密码，便于客户端配置（若为空则未启用认证）
  if [[ -n "${PROXY_AUTH_USER:-}" ]]; then
    echo
    echo "客户端认证（Proxy Basic auth）凭据："
    echo "  用户名: $PROXY_AUTH_USER"
    echo "  密码: $PROXY_AUTH_PASS"
    echo "  （凭据也已写入：$BASE_DIR/credentials）"
  else
    echo "客户端认证未启用（PROXY_AUTH_USER 为空）。"
  fi
}

# 增强的卸载函数
uninstall(){
  info "卸载 forgerd 与定时器（保留 venv/规则/证书，按需手动删除）"
  
  if [[ "$SERVICE_MGR" == "systemd" ]]; then
    systemctl stop forgerd 2>/dev/null || true
    systemctl disable forgerd 2>/dev/null || true
    rm -f "$FORGER_SVC"
    
    systemctl stop cealing-rules-update.timer 2>/dev/null || true
    systemctl disable cealing-rules-update.timer 2>/dev/null || true
    rm -f "$RULES_UPDATE_TIMER" "$RULES_UPDATE_SVC"
    
    systemctl daemon-reload
  else
    stop_service forgerd
    rc-update del forgerd default 2>/dev/null || true
    rm -f "$FORGER_SVC"
    
    # 删除 cron 任务
    crontab -l | grep -v "$RULES_URL" | crontab - 2>/dev/null || true
  fi

  rm -f "$NGINX_STREAM_DIR/proxy_to_forger_tls.conf" "$NGINX_STREAM_DIR/proxy_to_forger_http.conf"
  reload_service nginx || true

  info "已卸载完成。可选清理： rm -rf '$BASE_DIR' '$RULES_PATH' '$CERT_DIR'"
  exit 0
}

# 增强的服务创建函数
write_forger_service(){
  info "写入 forgerd 服务"
  
  if [[ "$SERVICE_MGR" == "systemd" ]]; then
    # Systemd 服务
    cat >"$FORGER_SVC" <<UNIT
[Unit]
Description=Cealing forger middleware (mitmproxy upstream->squid)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$BASE_DIR
ExecStart=$BASE_DIR/venv/bin/mitmdump -vv --listen-host 127.0.0.1 -p $FORGER_PORT --mode upstream:http://127.0.0.1:$SQUID_PORT -s $BASE_DIR/bin/forgerules.py --set rules_path=$RULES_PATH --set ssl_insecure=true --set connection_strategy=lazy --set block_global=false --set proxy_auth_user=$PROXY_AUTH_USER --set proxy_auth_pass=$PROXY_AUTH_PASS
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now forgerd.service || true
    
  elif [[ "$SERVICE_MGR" == "openrc" ]]; then
    # OpenRC 服务
    write_openrc_service
    start_service forgerd
  fi
}

# 系统兼容性检查函数
check_compatibility(){
  info "检查系统兼容性..."
  
  # 检查必要的命令
  local missing_cmds=()
  
  for cmd in curl openssl; do
    if ! command -v $cmd >/dev/null 2>&1; then
      missing_cmds+=($cmd)
    fi
  done
  
  if [[ ${#missing_cmds[@]} -gt 0 ]]; then
    warn "缺少必要命令: ${missing_cmds[*]}，将尝试安装..."
  fi
  
  # 检查 Python 版本
  if command -v $PYTHON_CMD >/dev/null 2>&1; then
    local py_ver=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if [[ $(echo "$py_ver < 3.6" | bc -l 2>/dev/null) == "1" ]]; then
      warn "Python 版本 $py_ver 可能过低，建议升级到 3.6+"
    fi
  fi
  
  # 特殊系统警告
  case "$OS_TYPE" in
    alpine)
      info "Alpine Linux 检测到，将使用 OpenRC 和轻量级配置"
      ;;
    centos)
      if [[ "${OS_VERSION%%.*}" -lt 7 ]] 2>/dev/null; then
        warn "CentOS $OS_VERSION 版本较旧，可能需要手动处理依赖"
      fi
      ;;
  esac
}

# 主函数增强
main(){
  if [[ "${1:-}" == "--uninstall" ]]; then uninstall; fi
  
  need_root
  detect_os
  check_compatibility
  ensure_pkgs
  make_dirs
  fetch_rules_once
  install_mitmproxy
  write_forger_plugin
  write_forger_service
  gen_self_signed_cert
  write_nginx_stream
  write_squid_conf
  write_rules_timer
  open_firewall
  show_summary
}

main "$@"