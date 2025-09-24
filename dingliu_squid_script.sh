#!/bin/bash

#############################################
# Integrated AEAD Proxy 部署管理脚本 v4.1
# 架构: Client -> Squid(HTTP/HTTPS+Auth) -> AEAD-Client(8888) -> AEAD-Server(8443) -> Target
#############################################

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# 配置路径
INSTALL_DIR="/opt/aead-proxy"
CONFIG_DIR="$INSTALL_DIR/config"
LOG_DIR="$INSTALL_DIR/logs"
SYSTEMD_DIR="/etc/systemd/system"
BACKUP_DIR="$INSTALL_DIR/backup"

# 全局变量
DOMAIN=""
EMAIL=""
PSK=""
HTTP_USER=""
HTTP_PASS=""
PROXY_PORT="3128"
GITHUB_BINARY_URL="https://raw.githubusercontent.com/pfxjacky/HTTP-MITM-SQUIC-PROXY/refs/heads/main/integrated-aead-proxy"

# 打印函数
log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "此脚本必须以root权限运行"
        exit 1
    fi
}

# 检测系统
detect_system() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        OS="Unknown"
        VER="Unknown"
    fi
    
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    info "系统: $OS $VER - $ARCH"
}

# 主菜单
show_main_menu() {
    clear
    echo -e "${CYAN}=========================================="
    echo -e "   Integrated AEAD Proxy 管理中心 v4.1"
    echo -e "   (Squid Professional Proxy Frontend)"
    echo -e "==========================================${NC}"
    
    if [ -f "$CONFIG_DIR/credentials.txt" ]; then
        echo -e "${GREEN}[已安装]${NC} 系统状态: $(check_system_status)"
        echo ""
        echo "1. 查看系统状态"
        echo "2. 服务管理"
        echo "3. 配置管理"
        echo "4. 日志查看"
        echo "5. 客户端管理"
        echo "6. 故障排查"
        echo "7. 系统更新"
        echo "8. 备份/恢复"
        echo -e "9. ${RED}完全卸载${NC}"
    else
        echo -e "${YELLOW}[未安装]${NC}"
        echo ""
        echo "1. 快速安装"
        echo "2. 自定义安装"
        echo "3. 从备份恢复"
    fi
    
    echo "0. 退出"
    echo "=========================================="
    read -p "请选择 [0-9]: " choice
}

# 检查系统状态
check_system_status() {
    local server_status="❌"
    local client_status="❌"
    local squid_status="❌"
    
    if systemctl is-active --quiet aead-server 2>/dev/null; then
        server_status="✅"
    fi
    
    if systemctl is-active --quiet aead-client 2>/dev/null; then
        client_status="✅"
    fi
    
    if systemctl is-active --quiet squid 2>/dev/null; then
        squid_status="✅"
    fi
    
    echo "Server:$server_status Client:$client_status Squid:$squid_status"
}

# 快速安装
quick_install() {
    log "开始快速安装..."
    
    # 获取基本信息
    read -p "请输入代理端口 (默认3128): " custom_port
    PROXY_PORT=${custom_port:-3128}
    
    # 生成密钥
    PSK=$(openssl rand -base64 32 | tr -d '\n')
    HTTP_USER="user_$(openssl rand -hex 4)"
    HTTP_PASS=$(openssl rand -base64 12 | tr -d '\n')
    
    # 执行安装
    install_dependencies
    create_directories
    install_proxy_binary
    install_squid
    generate_certificate
    generate_configs
    create_services
    optimize_system
    setup_firewall
    start_services
    
    success "安装完成！"
    show_credentials
    
    read -p "按Enter继续..."
}

# 自定义安装
custom_install() {
    log "开始自定义安装..."
    
    # 获取详细配置
    read -p "请输入代理端口 (默认3128): " custom_port
    read -p "请输入自定义PSK (留空自动生成): " custom_psk
    read -p "请输入HTTP用户名 (留空自动生成): " custom_user
    read -p "请输入HTTP密码 (留空自动生成): " custom_pass
    
    PROXY_PORT=${custom_port:-3128}
    
    # 设置密钥
    if [ -n "$custom_psk" ]; then
        PSK="$custom_psk"
    else
        PSK=$(openssl rand -base64 32 | tr -d '\n')
    fi
    
    if [ -n "$custom_user" ]; then
        HTTP_USER="$custom_user"
    else
        HTTP_USER="user_$(openssl rand -hex 4)"
    fi
    
    if [ -n "$custom_pass" ]; then
        HTTP_PASS="$custom_pass"
    else
        HTTP_PASS=$(openssl rand -base64 12 | tr -d '\n')
    fi
    
    # 执行安装
    install_dependencies
    create_directories
    install_proxy_binary
    install_squid
    generate_certificate
    generate_configs
    create_services
    optimize_system
    setup_firewall
    start_services
    
    success "自定义安装完成！"
    show_credentials
    
    read -p "按Enter继续..."
}

# 显示凭据信息
show_credentials() {
    echo ""
    success "===== 安装完成 ====="
    echo ""
    echo "系统配置信息："
    echo "代理端口: $PROXY_PORT"
    echo "PSK: $PSK"
    echo "HTTP用户: $HTTP_USER"
    echo "HTTP密码: $HTTP_PASS"
    echo ""
    echo "客户端连接信息："
    echo "代理服务器: $(hostname -I | awk '{print $1}')"
    echo "端口: $PROXY_PORT"
    echo "用户名: $HTTP_USER"
    echo "密码: $HTTP_PASS"
    echo "代理类型: HTTP/HTTPS"
    echo ""
    echo "配置已保存到: $CONFIG_DIR/credentials.txt"
    echo "=========================================="
}

# 安装依赖
install_dependencies() {
    log "安装依赖..."
    
    export DEBIAN_FRONTEND=noninteractive
    
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        apt-get install -y wget curl openssl ca-certificates netcat-openbsd net-tools squid apache2-utils
    elif command -v yum >/dev/null 2>&1; then
        yum install -y wget curl openssl ca-certificates nc net-tools squid httpd-tools
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y wget curl openssl ca-certificates nc net-tools squid httpd-tools
    fi
    
    success "依赖安装完成"
}

# 创建目录
create_directories() {
    log "创建目录结构..."
    
    mkdir -p "$INSTALL_DIR"/{bin,config,data,logs,backup,client,certs}
    mkdir -p /etc/squid
    
    # 创建用户
    if ! id -u aead-proxy &>/dev/null; then
        useradd -r -s /bin/false -m -d "$INSTALL_DIR" aead-proxy
    fi
    
    chown -R aead-proxy:aead-proxy "$INSTALL_DIR"
    success "目录结构创建完成"
}

# 下载二进制文件从GitHub
download_binary_from_github() {
    log "从GitHub下载integrated-aead-proxy程序..."
    
    local temp_file="/tmp/integrated-aead-proxy-download"
    local target_file="$INSTALL_DIR/bin/integrated-aead-proxy"
    
    # 使用wget下载，支持重试
    for i in {1..3}; do
        log "下载尝试 $i/3..."
        if wget -O "$temp_file" "$GITHUB_BINARY_URL" --timeout=30 --tries=2 2>/dev/null; then
            # 验证下载的文件
            if [ -f "$temp_file" ] && [ -s "$temp_file" ]; then
                # 检查是否是有效的二进制文件
                if file "$temp_file" | grep -q "ELF\|executable"; then
                    mv "$temp_file" "$target_file"
                    chmod +x "$target_file"
                    success "二进制文件下载成功"
                    return 0
                else
                    warn "下载的文件不是有效的二进制文件，尝试直接使用..."
                    mv "$temp_file" "$target_file"
                    chmod +x "$target_file"
                    # 尝试运行验证
                    if "$target_file" --help >/dev/null 2>&1; then
                        success "二进制文件下载并验证成功"
                        return 0
                    fi
                fi
            fi
        fi
        
        # 如果wget失败，尝试使用curl
        if command -v curl >/dev/null 2>&1; then
            log "使用curl重试下载..."
            if curl -L -o "$temp_file" "$GITHUB_BINARY_URL" --max-time 30 2>/dev/null; then
                if [ -f "$temp_file" ] && [ -s "$temp_file" ]; then
                    mv "$temp_file" "$target_file"
                    chmod +x "$target_file"
                    if "$target_file" --help >/dev/null 2>&1; then
                        success "二进制文件下载成功 (使用curl)"
                        return 0
                    fi
                fi
            fi
        fi
        
        [ $i -lt 3 ] && sleep 5
    done
    
    rm -f "$temp_file"
    return 1
}

# 安装代理程序
install_proxy_binary() {
    log "安装代理程序..."
    
    # 首先尝试查找本地二进制文件
    local found=false
    for path in "./integrated-aead-proxy" "../integrated-aead-proxy" "./target/release/integrated-aead-proxy" "/tmp/integrated-aead-proxy"; do
        if [ -f "$path" ]; then
            log "找到本地二进制文件: $path"
            cp "$path" "$INSTALL_DIR/bin/integrated-aead-proxy"
            chmod +x "$INSTALL_DIR/bin/integrated-aead-proxy"
            found=true
            break
        fi
    done
    
    # 如果本地没有找到，从GitHub下载
    if [ "$found" = false ]; then
        warn "未找到本地integrated-aead-proxy程序，尝试从GitHub下载..."
        if ! download_binary_from_github; then
            error "无法下载integrated-aead-proxy程序"
            error "请手动下载并放置到当前目录："
            error "wget $GITHUB_BINARY_URL"
            error "或者编译源代码: cargo build --release"
            exit 1
        fi
    fi
    
    # 验证程序
    if "$INSTALL_DIR/bin/integrated-aead-proxy" --help >/dev/null 2>&1; then
        success "代理程序安装成功"
    else
        # 如果验证失败，但文件存在，仍然继续（可能是兼容性问题）
        if [ -f "$INSTALL_DIR/bin/integrated-aead-proxy" ]; then
            warn "代理程序验证失败，但文件已安装，继续安装过程..."
            warn "如果服务无法启动，请检查二进制文件兼容性"
        else
            error "代理程序安装失败"
            exit 1
        fi
    fi
}

# 安装配置Squid
install_squid() {
    log "配置Squid代理..."
    
    # 停止Squid服务（如果正在运行）
    systemctl stop squid 2>/dev/null || true
    
    success "Squid配置准备完成"
}

# 生成自签名证书
generate_certificate() {
    log "生成SSL证书..."
    
    # 为integrated-aead-proxy server模式生成自签名证书
    local cert_file="$INSTALL_DIR/certs/server.pem"
    local key_file="$INSTALL_DIR/certs/server.key"
    local p12_file="$INSTALL_DIR/certs/server.p12"
    
    # 生成私钥
    openssl genrsa -out "$key_file" 2048
    
    # 生成自签名证书
    openssl req -new -x509 -key "$key_file" -out "$cert_file" -days 365 -subj "/CN=localhost"
    
    # 转换为PKCS#12格式 (integrated-aead-proxy需要)
    openssl pkcs12 -export -out "$p12_file" -inkey "$key_file" -in "$cert_file" -password pass:proxy123
    
    # 设置权限
    chown aead-proxy:aead-proxy "$INSTALL_DIR/certs"/*
    chmod 600 "$INSTALL_DIR/certs"/*
    
    success "证书生成完成"
}

# 生成配置
generate_configs() {
    log "生成配置文件..."
    
    # 保存凭据
    cat > "$CONFIG_DIR/credentials.txt" << EOF
端口: $PROXY_PORT
PSK: $PSK
HTTP用户: $HTTP_USER
HTTP密码: $HTTP_PASS
创建时间: $(date)
EOF

    # Squid配置
    cat > /etc/squid/squid.conf << EOF
# Squid Configuration for AEAD Proxy
http_port $PROXY_PORT

# 设置上游代理为AEAD Client
cache_peer 127.0.0.1 parent 8888 0 no-query default
never_direct allow all

# 基本认证配置
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5 startup=5 idle=1
auth_param basic realm AEAD Proxy Authentication
auth_param basic credentialsttl 2 hours

# ACL定义
acl authenticated proxy_auth REQUIRED
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl Safe_ports port 1025-65535
acl CONNECT method CONNECT

# 访问控制
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow authenticated
http_access deny all

# 缓存设置
cache deny all
cache_dir null /tmp

# 日志设置
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log

# 性能优化
forwarded_for off
request_header_access X-Forwarded-For deny all
request_header_access Via deny all
request_header_access Cache-Control deny all

# 连接设置
connect_timeout 30 seconds
read_timeout 30 seconds
request_timeout 30 seconds
persistent_request_timeout 1 minute

# 错误页面语言
error_directory /usr/share/squid/errors/en
EOF

    # 创建Squid认证文件
    if command -v htpasswd >/dev/null 2>&1; then
        htpasswd -bc /etc/squid/passwd "$HTTP_USER" "$HTTP_PASS"
    else
        # 手动创建认证文件（如果htpasswd不可用）
        local hash=$(openssl passwd -apr1 "$HTTP_PASS")
        echo "$HTTP_USER:$hash" > /etc/squid/passwd
    fi
    
    chmod 640 /etc/squid/passwd
    chown proxy:proxy /etc/squid/passwd 2>/dev/null || chown squid:squid /etc/squid/passwd 2>/dev/null
    
    success "配置文件生成完成"
}

# 创建系统服务
create_services() {
    log "创建系统服务..."

    # AEAD Server服务 (监听8443)
    cat > "$SYSTEMD_DIR/aead-server.service" << EOF
[Unit]
Description=Integrated AEAD Proxy Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aead-proxy
Group=aead-proxy
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/bin/integrated-aead-proxy server \\
    --listen 127.0.0.1:8443 \\
    --pfx $INSTALL_DIR/certs/server.p12 \\
    --pfx-pass proxy123 \\
    --psk-b64 "$PSK" \\
    --verbose
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    # AEAD Client服务 (监听8888，连接8443)
    cat > "$SYSTEMD_DIR/aead-client.service" << EOF
[Unit]
Description=Integrated AEAD Proxy Client
After=network.target aead-server.service
Wants=network-online.target

[Service]
Type=simple
User=aead-proxy
Group=aead-proxy
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/bin/integrated-aead-proxy client \\
    --listen 127.0.0.1:8888 \\
    --server 127.0.0.1:8443 \\
    --sni localhost \\
    --psk-b64 "$PSK" \\
    --insecure \\
    --verbose
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    success "系统服务创建完成"
}

# 优化系统
optimize_system() {
    log "优化系统参数..."
    
    if ! grep -q "# AEAD Proxy Optimization" /etc/sysctl.conf; then
        cat >> /etc/sysctl.conf << 'EOF'

# AEAD Proxy Optimization
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.ip_forward = 1
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 8192
EOF
        sysctl -p >/dev/null 2>&1
        success "系统参数优化完成"
    else
        info "系统参数已优化，跳过"
    fi
}

# 配置防火墙
setup_firewall() {
    log "配置防火墙..."
    
    local ports=($PROXY_PORT)
    
    if command -v ufw >/dev/null 2>&1; then
        for port in "${ports[@]}"; do
            ufw allow $port/tcp >/dev/null 2>&1
        done
        echo "y" | ufw enable >/dev/null 2>&1
        success "UFW防火墙配置完成"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        for port in "${ports[@]}"; do
            firewall-cmd --permanent --add-port=$port/tcp >/dev/null 2>&1
        done
        firewall-cmd --reload >/dev/null 2>&1
        success "FirewallD配置完成"
    else
        warn "未检测到防火墙管理工具"
    fi
}

# 启动服务
start_services() {
    log "启动服务..."
    
    systemctl enable aead-server aead-client squid >/dev/null 2>&1
    
    # 按顺序启动服务
    log "启动AEAD Server..."
    systemctl start aead-server
    sleep 3
    
    if ! systemctl is-active --quiet aead-server; then
        error "AEAD Server启动失败"
        journalctl -u aead-server --no-pager -n 10
        return 1
    fi
    
    log "启动AEAD Client..."
    systemctl start aead-client
    sleep 3
    
    if ! systemctl is-active --quiet aead-client; then
        error "AEAD Client启动失败"
        journalctl -u aead-client --no-pager -n 10
        return 1
    fi
    
    log "启动Squid代理..."
    systemctl restart squid
    sleep 3
    
    if systemctl is-active --quiet aead-server && 
       systemctl is-active --quiet aead-client && 
       systemctl is-active --quiet squid; then
        success "所有服务启动成功"
    else
        warn "部分服务启动失败，请检查日志"
    fi
}

# 加载配置变量
load_config_vars() {
    if [ -f "$CONFIG_DIR/credentials.txt" ]; then
        PROXY_PORT=$(grep "端口:" "$CONFIG_DIR/credentials.txt" | cut -d' ' -f2)
        PSK=$(grep "PSK:" "$CONFIG_DIR/credentials.txt" | cut -d' ' -f2)
        HTTP_USER=$(grep "HTTP用户:" "$CONFIG_DIR/credentials.txt" | cut -d' ' -f2)
        HTTP_PASS=$(grep "HTTP密码:" "$CONFIG_DIR/credentials.txt" | cut -d' ' -f2)
    fi
}

# 服务管理菜单
service_menu() {
    clear
    echo -e "${CYAN}=========================================="
    echo "           服务管理"
    echo "==========================================${NC}"
    echo "1. 查看服务状态"
    echo "2. 启动所有服务"
    echo "3. 停止所有服务"
    echo "4. 重启所有服务"
    echo "5. 启动AEAD Server"
    echo "6. 启动AEAD Client"
    echo "7. 启动Squid服务"
    echo "8. 查看端口监听"
    echo "0. 返回"
    echo "=========================================="
    read -p "请选择 [0-8]: " choice
    
    case $choice in
        1) check_services ;;
        2) start_all_services ;;
        3) stop_all_services ;;
        4) restart_all_services ;;
        5) systemctl start aead-server && success "AEAD Server已启动" ;;
        6) systemctl start aead-client && success "AEAD Client已启动" ;;
        7) systemctl start squid && success "Squid服务已启动" ;;
        8) netstat -tlnp | grep -E "($PROXY_PORT|8443|8888)" || echo "无监听端口" ;;
        0) return ;;
    esac
    
    read -p "按Enter继续..."
    service_menu
}

# 检查服务
check_services() {
    echo ""
    log "服务状态检查："
    echo ""
    
    for service in aead-server aead-client squid; do
        if systemctl is-active --quiet $service; then
            success "$service: 运行中"
        else
            error "$service: 已停止"
        fi
    done
    
    echo ""
    echo "=== 端口监听状态 ==="
    netstat -tlnp | grep -E "(8443|8888|$PROXY_PORT)" || echo "未找到相关端口监听"
}

# 启动所有服务
start_all_services() {
    log "启动所有服务..."
    systemctl start aead-server aead-client squid
    sleep 3
    success "服务启动完成"
}

# 停止所有服务
stop_all_services() {
    log "停止所有服务..."
    systemctl stop squid aead-client aead-server
    success "服务停止完成"
}

# 重启所有服务
restart_all_services() {
    log "重启所有服务..."
    systemctl restart aead-server
    sleep 2
    systemctl restart aead-client
    sleep 2
    systemctl restart squid
    success "服务重启完成"
}

# 配置管理菜单
config_menu() {
    clear
    echo -e "${CYAN}=========================================="
    echo "           配置管理"
    echo "==========================================${NC}"
    echo "1. 查看当前配置"
    echo "2. 修改代理端口"
    echo "3. 重新生成PSK"
    echo "4. 修改HTTP代理凭据"
    echo "5. 编辑Squid配置"
    echo "6. 重新生成证书"
    echo "0. 返回"
    echo "=========================================="
    read -p "请选择 [0-6]: " choice
    
    case $choice in
        1) view_config ;;
        2) change_proxy_port ;;
        3) regenerate_psk ;;
        4) change_http_auth ;;
        5) nano /etc/squid/squid.conf && systemctl restart squid ;;
        6) generate_certificate && systemctl restart aead-server ;;
        0) return ;;
    esac
    
    read -p "按Enter继续..."
    config_menu
}

# 查看配置
view_config() {
    if [ -f "$CONFIG_DIR/credentials.txt" ]; then
        echo ""
        cat "$CONFIG_DIR/credentials.txt"
        echo ""
        echo "=========================================="
        echo "客户端连接说明："
        echo ""
        load_config_vars
        local server_ip=$(hostname -I | awk '{print $1}')
        echo "HTTP代理地址: $server_ip:$PROXY_PORT"
        echo "用户名: $HTTP_USER"
        echo "密码: $HTTP_PASS"
        echo "代理类型: HTTP/HTTPS"
        echo ""
        echo "V2rayN配置："
        echo "  协议: HTTP"
        echo "  地址: $server_ip"
        echo "  端口: $PROXY_PORT"
        echo "  用户名: $HTTP_USER"
        echo "  密码: $HTTP_PASS"
    else
        error "配置文件不存在"
    fi
}

# 修改代理端口
change_proxy_port() {
    if [ ! -f "$CONFIG_DIR/credentials.txt" ]; then
        error "系统未安装"
        return
    fi
    
    local old_port=$PROXY_PORT
    
    echo "当前端口: $old_port"
    read -p "请输入新端口: " new_port
    
    if [ -z "$new_port" ]; then
        error "端口不能为空"
        return
    fi
    
    log "更新端口配置..."
    
    # 更新凭据文件
    sed -i "s/端口: $old_port/端口: $new_port/" "$CONFIG_DIR/credentials.txt"
    
    # 更新Squid配置
    sed -i "s/http_port $old_port/http_port $new_port/" /etc/squid/squid.conf
    
    PROXY_PORT="$new_port"
    
    # 更新防火墙
    setup_firewall
    
    # 重启服务
    systemctl restart squid
    
    success "端口更新完成: $new_port"
}

# 重新生成PSK
regenerate_psk() {
    warn "重新生成PSK将导致现有客户端无法连接，是否继续？"
    read -p "输入 'yes' 确认: " confirm
    
    if [ "$confirm" != "yes" ]; then
        info "操作已取消"
        return
    fi
    
    log "重新生成PSK..."
    
    # 生成新PSK
    local new_psk=$(openssl rand -base64 32 | tr -d '\n')
    
    # 更新凭据文件
    sed -i "s/PSK: .*/PSK: $new_psk/" "$CONFIG_DIR/credentials.txt"
    
    # 更新全局变量
    PSK="$new_psk"
    
    # 重新生成服务配置
    create_services
    systemctl daemon-reload
    
    # 重启服务
    systemctl restart aead-server aead-client
    
    success "PSK重新生成完成: $new_psk"
}

# 修改HTTP代理凭据
change_http_auth() {
    if [ ! -f "$CONFIG_DIR/credentials.txt" ]; then
        error "系统未安装"
        return
    fi
    
    local old_user=$HTTP_USER
    local old_pass=$HTTP_PASS
    
    echo "当前HTTP用户: $old_user"
    read -p "请输入新用户名 (留空保持不变): " new_user
    read -p "请输入新密码 (留空保持不变): " new_pass
    
    if [ -z "$new_user" ]; then
        new_user="$old_user"
    fi
    
    if [ -z "$new_pass" ]; then
        new_pass="$old_pass"
    fi
    
    log "更新HTTP认证凭据..."
    
    # 更新凭据文件
    sed -i "s/HTTP用户: $old_user/HTTP用户: $new_user/" "$CONFIG_DIR/credentials.txt"
    sed -i "s/HTTP密码: $old_pass/HTTP密码: $new_pass/" "$CONFIG_DIR/credentials.txt"
    
    # 更新Squid认证文件
    if command -v htpasswd >/dev/null 2>&1; then
        htpasswd -bc /etc/squid/passwd "$new_user" "$new_pass"
    else
        local hash=$(openssl passwd -apr1 "$new_pass")
        echo "$new_user:$hash" > /etc/squid/passwd
    fi
    
    # 更新全局变量
    HTTP_USER="$new_user"
    HTTP_PASS="$new_pass"
    
    # 重启Squid
    systemctl restart squid
    
    success "HTTP认证凭据更新完成"
}

# 日志查看菜单
log_menu() {
    clear
    echo -e "${CYAN}=========================================="
    echo "           日志查看"
    echo "==========================================${NC}"
    echo "1. AEAD Server日志"
    echo "2. AEAD Client日志"
    echo "3. Squid服务日志"
    echo "4. Squid访问日志"
    echo "5. 实时监控所有日志"
    echo "6. 清理日志文件"
    echo "0. 返回"
    echo "=========================================="
    read -p "请选择 [0-6]: " choice
    
    case $choice in
        1) journalctl -u aead-server -f --no-pager ;;
        2) journalctl -u aead-client -f --no-pager ;;
        3) journalctl -u squid -f --no-pager ;;
        4) tail -f /var/log/squid/access.log ;;
        5) journalctl -u aead-server -u aead-client -u squid -f --no-pager ;;
        6) clear_logs ;;
        0) return ;;
    esac
    
    read -p "按Enter继续..."
    log_menu
}

# 清理日志
clear_logs() {
    warn "这将清理所有服务日志，是否继续？"
    read -p "输入 'yes' 确认: " confirm
    
    if [ "$confirm" != "yes" ]; then
        info "操作已取消"
        return
    fi
    
    log "清理日志文件..."
    
    journalctl --vacuum-time=1d >/dev/null 2>&1
    rm -f /var/log/squid/access.log* /var/log/squid/cache.log* 2>/dev/null
    rm -f "$LOG_DIR"/*.log* 2>/dev/null
    
    success "日志清理完成"
}

# 客户端管理菜单
client_menu() {
    clear
    echo -e "${CYAN}=========================================="
    echo "           客户端管理"
    echo "==========================================${NC}"
    echo "1. 生成客户端配置"
    echo "2. 生成V2rayN配置"
    echo "3. 生成Clash配置"
    echo "4. 连接测试"
    echo "5. 查看连接统计"
    echo "0. 返回"
    echo "=========================================="
    read -p "请选择 [0-5]: " choice
    
    case $choice in
        1) generate_client_config ;;
        2) generate_v2rayn_config ;;
        3) generate_clash_config ;;
        4) connection_test ;;
        5) connection_stats ;;
        0) return ;;
    esac
    
    read -p "按Enter继续..."
    client_menu
}

# 生成客户端配置
generate_client_config() {
    if [ ! -f "$CONFIG_DIR/credentials.txt" ]; then
        error "系统未安装"
        return
    fi
    
    log "生成客户端配置..."
    
    load_config_vars
    
    local config_file="$INSTALL_DIR/client/client_config.txt"
    mkdir -p "$INSTALL_DIR/client"
    
    cat > "$config_file" << EOF
======= AEAD代理客户端配置 =======

HTTP/HTTPS代理设置：
服务器: $(hostname -I | awk '{print $1}')
端口: $PROXY_PORT
协议: HTTP
用户名: $HTTP_USER
密码: $HTTP_PASS

代理类型: HTTP代理（支持CONNECT方法）
加密: 无（本地连接）
认证: Basic Authentication

客户端配置示例：

1. 浏览器代理设置：
   HTTP代理: $(hostname -I | awk '{print $1}'):$PROXY_PORT
   HTTPS代理: $(hostname -I | awk '{print $1}'):$PROXY_PORT
   需要认证: 是
   
2. cURL使用方式：
   curl --proxy http://$HTTP_USER:$HTTP_PASS@$(hostname -I | awk '{print $1}'):$PROXY_PORT https://example.com

3. 系统代理设置：
   代理服务器: $(hostname -I | awk '{print $1}')
   端口: $PROXY_PORT
   用户名: $HTTP_USER
   密码: $HTTP_PASS

生成时间: $(date)
======================================
EOF

    success "客户端配置已生成: $config_file"
    cat "$config_file"
}

# 生成V2rayN配置
generate_v2rayn_config() {
    if [ ! -f "$CONFIG_DIR/credentials.txt" ]; then
        error "系统未安装"
        return
    fi
    
    log "生成V2rayN配置..."
    
    load_config_vars
    mkdir -p "$INSTALL_DIR/client"
    
    echo ""
    echo "V2rayN HTTP代理配置："
    echo "服务器地址: $(hostname -I | awk '{print $1}')"
    echo "端口: $PROXY_PORT"
    echo "用户名: $HTTP_USER"
    echo "密码: $HTTP_PASS"
    echo "传输安全: 无"
    echo ""
    echo "导入说明："
    echo "1. 在V2rayN中选择 '服务器' -> '添加 [HTTP]服务器'"
    echo "2. 填入上述信息"
    echo "3. 不启用TLS选项（本地HTTP代理）"
}

# 生成Clash配置
generate_clash_config() {
    if [ ! -f "$CONFIG_DIR/credentials.txt" ]; then
        error "系统未安装"
        return
    fi
    
    log "生成Clash配置..."
    
    load_config_vars
    mkdir -p "$INSTALL_DIR/client"
    
    local clash_file="$INSTALL_DIR/client/clash_config.yaml"
    local server_ip=$(hostname -I | awk '{print $1}')
    
    cat > "$clash_file" << EOF
port: 7890
socks-port: 7891
allow-lan: false
mode: Rule
log-level: info
external-controller: 127.0.0.1:9090

proxies:
  - name: "AEAD-Proxy"
    type: http
    server: $server_ip
    port: $PROXY_PORT
    username: $HTTP_USER
    password: $HTTP_PASS
    tls: false
    skip-cert-verify: true

proxy-groups:
  - name: "代理选择"
    type: select
    proxies:
      - "AEAD-Proxy"
      - DIRECT

rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - DOMAIN-KEYWORD,baidu,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,代理选择
EOF

    success "Clash配置已生成: $clash_file"
    
    echo ""
    echo "使用说明："
    echo "1. 将配置文件导入到Clash客户端"
    echo "2. 启动Clash并选择'AEAD-Proxy'节点"
    echo "3. 设置系统代理为: 127.0.0.1:7890"
}

# 连接测试
connection_test() {
    log "执行连接测试..."
    
    echo ""
    echo "=== 本地服务测试 ==="
    
    # 测试AEAD Server
    if nc -z 127.0.0.1 8443 2>/dev/null; then
        success "AEAD Server (8443): 正常"
    else
        error "AEAD Server (8443): 无法连接"
    fi
    
    # 测试AEAD Client  
    if nc -z 127.0.0.1 8888 2>/dev/null; then
        success "AEAD Client (8888): 正常"
    else
        error "AEAD Client (8888): 无法连接"
    fi
    
    # 测试Squid
    if nc -z 127.0.0.1 $PROXY_PORT 2>/dev/null; then
        success "Squid HTTP ($PROXY_PORT): 正常"
    else
        error "Squid HTTP ($PROXY_PORT): 无法连接"
    fi
    
    echo ""
    echo "=== 外部连接测试 ==="
    
    if [ -f "$CONFIG_DIR/credentials.txt" ]; then
        load_config_vars
        
        # 测试HTTP代理
        local test_result
        test_result=$(timeout 10 curl -s --proxy http://$HTTP_USER:$HTTP_PASS@127.0.0.1:$PROXY_PORT https://httpbin.org/ip 2>/dev/null || echo "failed")
        
        if [ "$test_result" != "failed" ] && echo "$test_result" | grep -q "origin"; then
            success "HTTP代理测试: 通过"
            echo "   出口IP: $(echo "$test_result" | grep -o '"origin": "[^"]*' | cut -d'"' -f4)"
        else
            error "HTTP代理测试: 失败"
        fi
    fi
}

# 连接统计
connection_stats() {
    echo ""
    log "连接统计信息："
    echo ""
    
    echo "=== 进程状态 ==="
    ps aux | grep -E "(integrated-aead-proxy|squid)" | grep -v grep || echo "无相关进程"
    
    echo ""
    echo "=== 网络连接 ==="
    netstat -an | grep -E "(8443|8888|$PROXY_PORT)" | grep LISTEN || echo "无监听端口"
    
    echo ""
    echo "=== 活动连接数 ==="
    echo "HTTP代理连接: $(netstat -an | grep ":$PROXY_PORT" | grep ESTABLISHED | wc -l)"
    echo "内部Client连接: $(netstat -an | grep ":8888" | grep ESTABLISHED | wc -l)"
    echo "内部Server连接: $(netstat -an | grep ":8443" | grep ESTABLISHED | wc -l)"
}

# 故障排查菜单
troubleshoot_menu() {
    clear
    echo -e "${CYAN}=========================================="
    echo "           故障排查"
    echo "==========================================${NC}"
    echo "1. 系统诊断"
    echo "2. 端口检查"
    echo "3. 证书检查"
    echo "4. 配置检查"
    echo "5. 网络连通性测试"
    echo "0. 返回"
    echo "=========================================="
    read -p "请选择 [0-5]: " choice
    
    case $choice in
        1) system_diagnosis ;;
        2) port_check ;;
        3) cert_check ;;
        4) config_check ;;
        5) network_test ;;
        0) return ;;
    esac
    
    read -p "按Enter继续..."
    troubleshoot_menu
}

# 系统诊断
system_diagnosis() {
    log "执行系统诊断..."
    
    echo ""
    echo "=== 系统信息 ==="
    uname -a
    echo "内存使用: $(free -h | grep "Mem:" | awk '{print $3"/"$2}')"
    echo "磁盘使用: $(df -h / | tail -1 | awk '{print $3"/"$2" ("$5")"}')"
    echo "系统负载: $(uptime | awk -F'load average:' '{print $2}')"
    
    echo ""
    echo "=== 服务状态详情 ==="
    for service in aead-server aead-client squid; do
        echo "--- $service ---"
        systemctl status $service --no-pager -l | head -10
        echo ""
    done
}

# 端口检查
port_check() {
    log "检查端口状态..."
    
    echo ""
    echo "=== 监听端口 ==="
    netstat -tlnp | grep -E "($PROXY_PORT|8443|8888)" || echo "无相关端口监听"
    
    echo ""
    echo "=== 外部连通性 ==="
    local server_ip=$(hostname -I | awk '{print $1}')
    for port in $PROXY_PORT; do
        if timeout 5 nc -z "$server_ip" $port 2>/dev/null; then
            success "$server_ip:$port - 可达"
        else
            error "$server_ip:$port - 不可达"
        fi
    done
}

# 证书检查
cert_check() {
    log "检查证书状态..."
    
    echo ""
    echo "=== 内部证书 ==="
    if [ -f "$INSTALL_DIR/certs/server.p12" ]; then
        success "PKCS12证书存在"
        if openssl pkcs12 -in "$INSTALL_DIR/certs/server.p12" -noout -passin pass:proxy123 2>/dev/null; then
            success "PKCS12证书有效"
        else
            error "PKCS12证书无效"
        fi
    else
        error "PKCS12证书不存在"
    fi
}

# 配置检查
config_check() {
    log "检查配置文件..."
    
    echo ""
    echo "=== 配置文件状态 ==="
    for file in "$CONFIG_DIR/credentials.txt" "/etc/squid/squid.conf"; do
        if [ -f "$file" ]; then
            success "$file - 存在"
            echo "   大小: $(du -h "$file" | cut -f1)"
            echo "   修改时间: $(stat -c %y "$file" 2>/dev/null || stat -f %Sm "$file" 2>/dev/null || echo "未知")"
        else
            error "$file - 不存在"
        fi
    done
    
    echo ""
    echo "=== Squid配置语法检查 ==="
    if squid -k parse 2>/dev/null; then
        success "Squid配置语法正确"
    else
        error "Squid配置语法错误"
    fi
}

# 网络连通性测试
network_test() {
    log "网络连通性测试..."
    
    echo ""
    echo "=== DNS解析测试 ==="
    for domain in google.com cloudflare.com; do
        if nslookup $domain >/dev/null 2>&1; then
            success "$domain - DNS解析正常"
        else
            error "$domain - DNS解析失败"
        fi
    done
    
    echo ""
    echo "=== 网络延迟测试 ==="
    for host in 8.8.8.8 1.1.1.1; do
        ping_result=$(ping -c 3 $host 2>/dev/null | grep "avg" | awk -F'/' '{print $5}' 2>/dev/null || echo "")
        if [ -n "$ping_result" ]; then
            success "$host - 平均延迟: ${ping_result}ms"
        else
            error "$host - 无法连通"
        fi
    done
}

# 系统更新菜单
update_menu() {
    clear
    echo -e "${CYAN}=========================================="
    echo "           系统更新"
    echo "==========================================${NC}"
    echo "1. 更新代理程序"
    echo "2. 更新Squid"
    echo "3. 更新系统依赖"
    echo "0. 返回"
    echo "=========================================="
    read -p "请选择 [0-3]: " choice
    
    case $choice in
        1) update_proxy ;;
        2) update_squid ;;
        3) update_dependencies ;;
        0) return ;;
    esac
    
    read -p "按Enter继续..."
    update_menu
}

# 更新代理程序
update_proxy() {
    log "更新代理程序..."
    
    # 尝试从GitHub下载新版本
    warn "将从GitHub下载最新版本，是否继续？"
    read -p "输入 'yes' 确认: " confirm
    
    if [ "$confirm" != "yes" ]; then
        info "操作已取消"
        return
    fi
    
    # 备份旧版本
    mkdir -p "$BACKUP_DIR"
    cp "$INSTALL_DIR/bin/integrated-aead-proxy" "$BACKUP_DIR/integrated-aead-proxy.old.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
    
    # 停止服务
    systemctl stop aead-server aead-client
    
    # 下载新版本
    if download_binary_from_github; then
        # 重启服务
        systemctl start aead-server aead-client
        success "代理程序更新完成"
    else
        # 恢复旧版本
        cp "$BACKUP_DIR/integrated-aead-proxy.old."* "$INSTALL_DIR/bin/integrated-aead-proxy" 2>/dev/null
        systemctl start aead-server aead-client
        error "更新失败，已恢复旧版本"
    fi
}

# 更新Squid
update_squid() {
    log "更新Squid..."
    
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get upgrade -y squid
    elif command -v yum >/dev/null 2>&1; then
        yum update -y squid
    elif command -v dnf >/dev/null 2>&1; then
        dnf update -y squid
    fi
    
    systemctl restart squid
    success "Squid更新完成"
}

# 更新系统依赖
update_dependencies() {
    log "更新系统依赖..."
    
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get upgrade -y
    elif command -v yum >/dev/null 2>&1; then
        yum update -y
    elif command -v dnf >/dev/null 2>&1; then
        dnf update -y
    fi
    
    success "系统依赖更新完成"
}

# 备份恢复菜单
backup_menu() {
    clear
    echo -e "${CYAN}=========================================="
    echo "           备份/恢复"
    echo "==========================================${NC}"
    echo "1. 创建完整备份"
    echo "2. 查看备份列表"
    echo "3. 从备份恢复"
    echo "4. 删除旧备份"
    echo "0. 返回"
    echo "=========================================="
    read -p "请选择 [0-4]: " choice
    
    case $choice in
        1) create_full_backup ;;
        2) list_backups ;;
        3) restore_from_backup ;;
        4) cleanup_backups ;;
        0) return ;;
    esac
    
    read -p "按Enter继续..."
    backup_menu
}

# 创建完整备份
create_full_backup() {
    log "创建完整系统备份..."
    
    local backup_file="$BACKUP_DIR/full_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    mkdir -p "$BACKUP_DIR"
    
    # 停止服务以确保数据一致性
    systemctl stop squid aead-client aead-server 2>/dev/null || true
    
    tar -czf "$backup_file" \
        -C "$INSTALL_DIR" \
        --exclude=logs \
        --exclude=backup \
        . \
        /etc/squid/squid.conf \
        /etc/squid/passwd \
        2>/dev/null || true
    
    # 重启服务
    systemctl start aead-server aead-client squid 2>/dev/null || true
    
    if [ -f "$backup_file" ]; then
        success "完整备份已创建: $backup_file"
        echo "文件大小: $(du -h "$backup_file" | cut -f1)"
    else
        error "备份创建失败"
    fi
}

# 查看备份列表
list_backups() {
    echo ""
    log "备份文件列表："
    echo ""
    
    if ls "$BACKUP_DIR"/*.tar.gz >/dev/null 2>&1; then
        ls -lah "$BACKUP_DIR"/*.tar.gz | awk '{print $9, $5, $6, $7, $8}'
    else
        warn "未找到备份文件"
    fi
}

# 从备份恢复
restore_from_backup() {
    list_backups
    
    read -p "请输入要恢复的备份文件完整路径: " backup_file
    
    if [ ! -f "$backup_file" ]; then
        error "备份文件不存在"
        return
    fi
    
    warn "恢复备份将覆盖当前所有数据，是否继续？"
    read -p "输入 'yes' 确认: " confirm
    
    if [ "$confirm" != "yes" ]; then
        info "操作已取消"
        return
    fi
    
    log "从备份恢复系统..."
    
    # 停止所有服务
    systemctl stop squid aead-client aead-server 2>/dev/null || true
    
    # 备份当前数据
    cp -r "$INSTALL_DIR" "$INSTALL_DIR.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    
    # 清空目标目录（保留logs和backup）
    find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 ! -name "logs" ! -name "backup" -exec rm -rf {} + 2>/dev/null
    
    # 恢复备份
    tar -xzf "$backup_file" -C / 2>/dev/null
    
    if [ $? -eq 0 ]; then
        # 加载配置
        load_config_vars
        
        # 重新创建服务文件
        create_services
        systemctl daemon-reload
        
        # 启动服务
        start_services
        
        success "系统恢复完成"
    else
        error "系统恢复失败"
    fi
}

# 清理旧备份
cleanup_backups() {
    echo ""
    log "备份清理选项："
    echo "1. 删除7天前的备份"
    echo "2. 删除30天前的备份" 
    echo "3. 只保留最新3个备份"
    echo "0. 返回"
    
    read -p "请选择 [0-3]: " choice
    
    case $choice in
        1) 
            find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete 2>/dev/null
            success "已删除7天前的备份" 
            ;;
        2) 
            find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete 2>/dev/null
            success "已删除30天前的备份" 
            ;;
        3) 
            cd "$BACKUP_DIR" 2>/dev/null || return
            ls -t *.tar.gz 2>/dev/null | tail -n +4 | xargs rm -f 2>/dev/null
            success "已保留最新3个备份"
            cd - >/dev/null
            ;;
        0) return ;;
    esac
}

# 完全卸载
complete_uninstall() {
    warn "这将完全删除AEAD代理系统和所有数据！"
    warn "此操作不可逆转！"
    echo ""
    read -p "输入 'DELETE-ALL' 确认删除: " confirm
    
    if [ "$confirm" != "DELETE-ALL" ]; then
        info "操作已取消"
        return
    fi
    
    log "开始卸载系统..."
    
    # 停止并禁用服务
    systemctl stop squid aead-client aead-server 2>/dev/null || true
    systemctl disable squid aead-client aead-server 2>/dev/null || true
    
    # 删除服务文件
    rm -f "$SYSTEMD_DIR"/aead-*.service
    systemctl daemon-reload
    
    # 删除用户
    userdel -r aead-proxy 2>/dev/null || true
    
    # 删除安装目录
    rm -rf "$INSTALL_DIR"
    
    # 删除Squid配置
    rm -f /etc/squid/squid.conf /etc/squid/passwd
    
    # 删除系统优化配置
    sed -i '/# AEAD Proxy Optimization/,+9d' /etc/sysctl.conf 2>/dev/null || true
    
    success "系统卸载完成"
    
    echo ""
    echo "已删除的内容："
    echo "- 所有服务和配置文件"
    echo "- 用户账户和安装目录"
    echo "- 系统优化配置"
    echo ""
    warn "请手动检查并清理任何剩余的配置"
}

# 状态显示
show_status() {
    clear
    echo -e "${CYAN}=========================================="
    echo "           系统状态详情"
    echo "==========================================${NC}"
    
    if [ -f "$CONFIG_DIR/credentials.txt" ]; then
        load_config_vars
        
        echo "代理端口: $PROXY_PORT"
        echo "服务状态: $(check_system_status)"
        echo "安装时间: $(grep "创建时间:" "$CONFIG_DIR/credentials.txt" | cut -d' ' -f2- 2>/dev/null || echo "未知")"
        echo ""
        
        echo "=== 服务详情 ==="
        for service in aead-server aead-client squid; do
            if systemctl is-active --quiet $service; then
                echo "✅ $service: 运行中"
            else
                echo "❌ $service: 已停止"
            fi
        done
        
        echo ""
        echo "=== 网络监听 ==="
        netstat -tlnp 2>/dev/null | grep -E "($PROXY_PORT|8443|8888)" | while read line; do
            port=$(echo $line | awk '{print $4}' | cut -d':' -f2)
            echo "端口 $port: $(echo $line | awk '{print $1}')"
        done || echo "无监听端口"
        
        echo ""
        echo "=== 资源使用 ==="
        echo "内存: $(free -h | grep Mem | awk '{print $3"/"$2}')"
        echo "磁盘: $(df -h "$INSTALL_DIR" 2>/dev/null | tail -1 | awk '{print $3"/"$2" ("$5")"}' || echo "未知")"
        
        if command -v ss >/dev/null 2>&1; then
            echo "连接数: $(ss -an | grep ESTABLISHED | wc -l)"
        fi
        
    else
        error "系统未安装"
    fi
    
    echo "=========================================="
}

# 主程序入口
main() {
    check_root
    detect_system
    
    while true; do
        show_main_menu
        
        if [ -f "$CONFIG_DIR/credentials.txt" ]; then
            # 已安装系统的菜单
            case $choice in
                1) show_status ;;
                2) service_menu ;;
                3) config_menu ;;
                4) log_menu ;;
                5) client_menu ;;
                6) troubleshoot_menu ;;
                7) update_menu ;;
                8) backup_menu ;;
                9) complete_uninstall ;;
                0) exit 0 ;;
                *) warn "无效选项" ;;
            esac
        else
            # 未安装系统的菜单
            case $choice in
                1) quick_install ;;
                2) custom_install ;;
                3) restore_from_backup ;;
                0) exit 0 ;;
                *) warn "无效选项" ;;
            esac
        fi
        
        echo ""
        read -p "按Enter返回主菜单..."
    done
}

# 脚本入口点
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi