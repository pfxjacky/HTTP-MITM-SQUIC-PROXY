#!/usr/bin/env bash
set -Eeuo pipefail
# ============================================
# Cealing-Host 一键部署（默认开启 443，TLS1.2 & HTTP/1.1）
# 拓扑：Client --TLS1.2/HTTP1.1--> NGINX(stream:443, ssl终止)
#      → forger(mitmproxy, 伪造SNI/定向IP, upstream→Squid) → Squid(127.0.0.1:3128) → Internet
# 功能：写入 forgerd.service / NGINX stream / squid.conf / 每日规则更新 timer
# 适配：Debian 12+/Ubuntu 20.04+
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
PROXY_AUTH_USER=\"$PROXY_AUTH_USER\"
PROXY_AUTH_PASS=\"$PROXY_AUTH_PASS\"
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

info(){ echo -e "\033[1;34m[INFO]\033[0m  $*"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m  $*"; }
err(){  echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }

need_root(){ [[ $(id -u) -eq 0 ]] || err "请用 root 运行"; }
detect_os(){
  [[ -f /etc/os-release ]] || err "缺少 /etc/os-release"
  . /etc/os-release
  case "${ID:-}" in debian|ubuntu) :;; *) warn "尚未在 $ID 上测试，继续尝试...";; esac
}

ensure_pkgs(){
  info "安装依赖：nginx-full squid python3-venv curl jq openssl ca-certificates"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends nginx-full squid python3 python3-venv curl jq openssl ca-certificates || true
  nginx -V 2>&1 | grep -q -- --with-stream || err "nginx 未启用 stream 模块；请安装 nginx-full"
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

install_mitmproxy(){
  info "安装 mitmproxy 到 venv（规避 PEP 668）"
  python3 -m venv "$BASE_DIR/venv"
  "$BASE_DIR/venv/bin/python" -m pip install --upgrade pip setuptools wheel >/dev/null
  "$BASE_DIR/venv/bin/python" -m pip install "mitmproxy>=10,<12" >/dev/null
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

write_nginx_stream(){
  info "生成 NGINX stream 配置（强制 TLS1.2 & HTTP/1.1 CONNECT）"
  # 顶层 include（在 http{} 外）
  if ! grep -q 'streams-enabled/\*\.conf' /etc/nginx/nginx.conf; then
    cat >>/etc/nginx/nginx.conf <<'CONF'

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
  systemctl reload nginx
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
  systemctl restart squid
}

write_rules_timer(){
  info "创建 systemd timer（每日拉取规则并重启 forgerd）"
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
}

open_firewall(){
  info "放行端口（nftables / UFW；云安全组也需放行）"
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -qi "Status: active"; then
    ufw allow "$HTTPS_PORT/tcp" || true
    [[ "$ENABLE_HTTP_PROXY" == "true" ]] && ufw allow "$HTTP_PORT/tcp" || true
    return
  fi
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
  echo "日志： journalctl -u forgerd -n 120 --no-pager | grep 'FORGE match'"
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

uninstall(){
  info "卸载 forgerd 与定时器（保留 venv/规则/证书，按需手动删除）"
  systemctl stop forgerd 2>/dev/null || true
  systemctl disable forgerd 2>/dev/null || true
  rm -f "$FORGER_SVC"

  systemctl stop cealing-rules-update.timer 2>/dev/null || true
  systemctl disable cealing-rules-update.timer 2>/dev/null || true
  rm -f "$RULES_UPDATE_TIMER" "$RULES_UPDATE_SVC"

  systemctl daemon-reload

  rm -f "$NGINX_STREAM_DIR/proxy_to_forger_tls.conf" "$NGINX_STREAM_DIR/proxy_to_forger_http.conf"
  systemctl reload nginx || true

  info "已卸载完成。可选清理： rm -rf '$BASE_DIR' '$RULES_PATH' '$CERT_DIR'"
  exit 0
}


write_forger_service(){
  info "写入 forgerd.service（mitmproxy upstream → squid）"
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
}


main(){
  if [[ "${1:-}" == "--uninstall" ]]; then uninstall; fi
  need_root
  detect_os
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
