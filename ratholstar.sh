#!/bin/bash

# ===============================================
# RatholStar - Enhanced Tunnel Management Script
# Version: 3.0
# Author: MorteaStar_ir
# GitHub: https://github.com/Moriistar/ratholstar
# Telegram: @MorteaStar_ir
# Description: Advanced tunnel management with enhanced security and monitoring
# ===============================================

# Exit on any error
set -euo pipefail

# Script configuration
readonly SCRIPT_NAME="RatholStar"
readonly SCRIPT_VERSION="3.0"
readonly SCRIPT_AUTHOR="MorteaStar_ir"
readonly SCRIPT_GITHUB="https://github.com/Moriistar/ratholstar"
readonly SCRIPT_TELEGRAM="@MorteaStar_ir"

# Paths and directories
readonly CONFIG_DIR="/opt/ratholstar"
readonly LOG_DIR="/var/log/ratholstar"
readonly BACKUP_DIR="/opt/ratholstar/backups"
readonly SERVICE_DIR="/etc/systemd/system"
readonly CORE_DIR="${CONFIG_DIR}/core"
readonly WEB_DIR="${CONFIG_DIR}/web"
readonly SCRIPTS_DIR="${CONFIG_DIR}/scripts"

# Log files
readonly MAIN_LOG="${LOG_DIR}/ratholstar.log"
readonly ERROR_LOG="${LOG_DIR}/error.log"
readonly TRAFFIC_LOG="${LOG_DIR}/traffic.log"
readonly SECURITY_LOG="${LOG_DIR}/security.log"

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly RESET='\033[0m'

# Unicode symbols
readonly SYMBOL_CHECK="✓"
readonly SYMBOL_CROSS="✗"
readonly SYMBOL_ARROW="→"
readonly SYMBOL_STAR="★"
readonly SYMBOL_GEAR="⚙"
readonly SYMBOL_SHIELD="🛡"
readonly SYMBOL_ROCKET="🚀"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}${SYMBOL_CROSS} This script must be run as root${RESET}"
    exit 1
fi

# Create necessary directories
create_directories() {
    local dirs=("$CONFIG_DIR" "$LOG_DIR" "$BACKUP_DIR" "$CORE_DIR" "$WEB_DIR" "$SCRIPTS_DIR")
    for dir in "${dirs[@]}"; do
        [[ ! -d "$dir" ]] && mkdir -p "$dir"
    done
}

# Logging functions
log_info() {
    local message="$1"
    echo -e "${GREEN}[INFO]${RESET} $message"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $message" >> "$MAIN_LOG"
}

log_warn() {
    local message="$1"
    echo -e "${YELLOW}[WARN]${RESET} $message"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $message" >> "$MAIN_LOG"
}

log_error() {
    local message="$1"
    echo -e "${RED}[ERROR]${RESET} $message" >&2
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $message" >> "$ERROR_LOG"
}

log_security() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SECURITY] $message" >> "$SECURITY_LOG"
}

# Enhanced colorize function
colorize() {
    local color="$1"
    local text="$2"
    local style="${3:-normal}"
    
    case "$color" in
        red) color_code="$RED" ;;
        green) color_code="$GREEN" ;;
        yellow) color_code="$YELLOW" ;;
        blue) color_code="$BLUE" ;;
        magenta) color_code="$MAGENTA" ;;
        cyan) color_code="$CYAN" ;;
        white) color_code="$WHITE" ;;
        *) color_code="$RESET" ;;
    esac
    
    case "$style" in
        bold) style_code="$BOLD" ;;
        *) style_code="" ;;
    esac
    
    echo -e "${style_code}${color_code}${text}${RESET}"
}

# Enhanced system information
get_system_info() {
    SERVER_IP=$(curl -s4 ifconfig.me || curl -s ipinfo.io/ip || echo "Unknown")
    SERVER_COUNTRY=$(curl -s "http://ipwhois.app/json/$SERVER_IP" | jq -r '.country' 2>/dev/null || echo "Unknown")
    SERVER_ISP=$(curl -s "http://ipwhois.app/json/$SERVER_IP" | jq -r '.isp' 2>/dev/null || echo "Unknown")
    SYSTEM_ARCH=$(uname -m)
    SYSTEM_OS=$(lsb_release -ds 2>/dev/null || echo "Unknown")
    SYSTEM_KERNEL=$(uname -r)
    SYSTEM_UPTIME=$(uptime -p 2>/dev/null || echo "Unknown")
}

# Enhanced package installation
install_packages() {
    local packages=("curl" "jq" "unzip" "cron" "iptables" "fail2ban" "htop" "iftop" "nginx")
    
    for package in "${packages[@]}"; do
        if ! command -v "$package" &> /dev/null; then
            log_info "Installing $package..."
            if command -v apt-get &> /dev/null; then
                apt-get update -qq && apt-get install -y "$package"
            elif command -v yum &> /dev/null; then
                yum install -y "$package"
            else
                log_error "Unsupported package manager"
                exit 1
            fi
        fi
    done
}

# Enhanced security configuration
configure_security() {
    log_info "Configuring security settings..."
    
    # Configure firewall
    if command -v ufw &> /dev/null; then
        ufw --force enable
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
    fi
    
    # Configure fail2ban
    if command -v fail2ban-client &> /dev/null; then
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[ratholstar]
enabled = true
port = 1024:65535
filter = ratholstar
logpath = $SECURITY_LOG
maxretry = 10
EOF
        
        cat > /etc/fail2ban/filter.d/ratholstar.conf << EOF
[Definition]
failregex = ^.*\[SECURITY\].*Failed connection from .*$
            ^.*\[SECURITY\].*Suspicious activity from .*$
ignoreregex =
EOF
        
        systemctl restart fail2ban
    fi
    
    log_security "Security configuration completed"
}

# Enhanced rathole core download
download_rathole_core() {
    local force_download="${1:-false}"
    
    if [[ -f "${CORE_DIR}/rathole" ]] && [[ "$force_download" != "true" ]]; then
        log_info "Rathole core already exists"
        return 0
    fi
    
    log_info "Downloading Rathole core..."
    
    local github_entry="185.199.108.133 raw.githubusercontent.com"
    if ! grep -q "$github_entry" /etc/hosts; then
        echo "$github_entry" >> /etc/hosts
    fi
    
    local download_url
    if [[ "$SYSTEM_ARCH" == "x86_64" ]]; then
        download_url='https://github.com/Musixal/rathole-tunnel/raw/main/core/rathole.zip'
    else
        download_url=$(curl -sSL https://api.github.com/repos/rapiz1/rathole/releases/latest | 
                      grep -o "https://.*$SYSTEM_ARCH.*linux.*zip" | head -n 1)
    fi
    
    if [[ -z "$download_url" ]]; then
        log_error "Failed to get download URL"
        exit 1
    fi
    
    local temp_dir=$(mktemp -d)
    curl -sSL -o "$temp_dir/rathole.zip" "$download_url"
    unzip -q "$temp_dir/rathole.zip" -d "$CORE_DIR"
    chmod +x "${CORE_DIR}/rathole"
    rm -rf "$temp_dir"
    
    log_info "Rathole core downloaded successfully"
}

# Enhanced ASCII logo
display_logo() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
    ██████╗  █████╗ ████████╗██╗  ██╗ ██████╗ ██╗     ███████╗████████╗ █████╗ ██████╗ 
    ██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔═══██╗██║     ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
    ██████╔╝███████║   ██║   ███████║██║   ██║██║     ███████╗   ██║   ███████║██████╔╝
    ██╔══██╗██╔══██║   ██║   ██╔══██║██║   ██║██║     ╚════██║   ██║   ██╔══██║██╔══██╗
    ██║  ██║██║  ██║   ██║   ██║  ██║╚██████╔╝███████╗███████║   ██║   ██║  ██║██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
EOF
    echo -e "${RESET}"
    
    echo -e "${BOLD}${WHITE}                        Advanced Tunnel Management System${RESET}"
    echo -e "${CYAN}                              Version: ${YELLOW}$SCRIPT_VERSION${RESET}"
    echo -e "${CYAN}                              Author: ${YELLOW}$SCRIPT_AUTHOR${RESET}"
    echo -e "${CYAN}                              GitHub: ${YELLOW}$SCRIPT_GITHUB${RESET}"
    echo -e "${CYAN}                              Telegram: ${YELLOW}$SCRIPT_TELEGRAM${RESET}"
    echo
}

# Enhanced server information display
display_server_info() {
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${CYAN}${SYMBOL_GEAR} System Information:${RESET}"
    echo -e "${CYAN}  ${SYMBOL_ARROW} Location: ${YELLOW}$SERVER_COUNTRY${RESET}"
    echo -e "${CYAN}  ${SYMBOL_ARROW} ISP: ${YELLOW}$SERVER_ISP${RESET}"
    echo -e "${CYAN}  ${SYMBOL_ARROW} Architecture: ${YELLOW}$SYSTEM_ARCH${RESET}"
    echo -e "${CYAN}  ${SYMBOL_ARROW} OS: ${YELLOW}$SYSTEM_OS${RESET}"
    echo -e "${CYAN}  ${SYMBOL_ARROW} Kernel: ${YELLOW}$SYSTEM_KERNEL${RESET}"
    echo -e "${CYAN}  ${SYMBOL_ARROW} Uptime: ${YELLOW}$SYSTEM_UPTIME${RESET}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${RESET}"
}

# Enhanced core status display
display_core_status() {
    local core_status
    if [[ -f "${CORE_DIR}/rathole" ]]; then
        local core_version=$("${CORE_DIR}/rathole" --version 2>/dev/null | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
        core_status="${GREEN}${SYMBOL_CHECK} Installed (v$core_version)${RESET}"
    else
        core_status="${RED}${SYMBOL_CROSS} Not installed${RESET}"
    fi
    
    echo -e "${CYAN}${SYMBOL_SHIELD} Rathole Core: $core_status${RESET}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${RESET}"
}

# Enhanced port checking
check_port() {
    local port="$1"
    local transport="$2"
    
    case "$transport" in
        tcp) ss -tlnp "sport = :$port" | grep -q ":$port" ;;
        udp) ss -ulnp "sport = :$port" | grep -q ":$port" ;;
        *) return 1 ;;
    esac
}

# Enhanced IPv6 checking
check_ipv6() {
    local ip="$1"
    ip="${ip#[}"
    ip="${ip%]}"
    
    local ipv6_pattern="^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$|^(([0-9a-fA-F]{1,4}:){1,7}|:):((:[0-9a-fA-F]{1,4}){1,7}|:)$"
    [[ "$ip" =~ $ipv6_pattern ]]
}

# Enhanced validation functions
validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && (( port > 22 && port <= 65535 ))
}

validate_token() {
    local token="$1"
    [[ "${#token}" -ge 8 ]] && [[ "$token" =~ ^[a-zA-Z0-9_-]+$ ]]
}

# Enhanced tunnel configuration
configure_tunnel() {
    if [[ ! -f "${CORE_DIR}/rathole" ]]; then
        log_error "Rathole core not found. Please install it first."
        return 1
    fi
    
    clear
    colorize green "${SYMBOL_ROCKET} Advanced Tunnel Configuration" bold
    echo
    colorize yellow "Essential Tips:"
    echo -e "  • Enable TCP_NODELAY for lower latency (higher CPU usage)"
    echo -e "  • Disable Heartbeat for high connection count scenarios"
    echo -e "  • Use IPv6 for better connectivity in some regions"
    echo -e "  • Consider encryption for sensitive data"
    echo
    
    echo -e "${GREEN}1) ${SYMBOL_SHIELD} Configure Iran Server (Server Mode)${RESET}"
    echo -e "${MAGENTA}2) ${SYMBOL_ROCKET} Configure Kharej Server (Client Mode)${RESET}"
    echo -e "${CYAN}3) ${SYMBOL_GEAR} Advanced Configuration${RESET}"
    echo -e "${YELLOW}0) ${SYMBOL_ARROW} Return to Main Menu${RESET}"
    echo
    
    read -p "Enter your choice: " choice
    case "$choice" in
        1) configure_iran_server ;;
        2) configure_kharej_server ;;
        3) configure_advanced_tunnel ;;
        0) return 0 ;;
        *) log_error "Invalid option" && sleep 2 ;;
    esac
}

# Enhanced Iran server configuration
configure_iran_server() {
    clear
    colorize cyan "${SYMBOL_SHIELD} Iran Server Configuration" bold
    echo
    
    # IP version selection
    local local_ip='0.0.0.0'
    read -p "Enable IPv6 support? (y/n): " ipv6_choice
    if [[ "$ipv6_choice" =~ ^[Yy]$ ]]; then
        local_ip='[::]'
        log_info "IPv6 enabled"
    else
        log_info "IPv4 enabled"
    fi
    
    # Tunnel port configuration
    local tunnel_port
    while true; do
        read -p "Tunnel port (1024-65535): " tunnel_port
        if validate_port "$tunnel_port"; then
            if check_port "$tunnel_port" "tcp"; then
                log_error "Port $tunnel_port is already in use"
            else
                break
            fi
        else
            log_error "Invalid port number"
        fi
    done
    
    # Advanced options
    local nodelay heartbeat transport encryption
    
    read -p "Enable TCP_NODELAY (y/n): " nodelay_choice
    nodelay=$([[ "$nodelay_choice" =~ ^[Yy]$ ]] && echo "true" || echo "false")
    
    read -p "Enable Heartbeat (y/n): " heartbeat_choice
    heartbeat=$([[ "$heartbeat_choice" =~ ^[Yy]$ ]] && echo "30" || echo "0")
    
    read -p "Transport type (tcp/udp): " transport
    while [[ "$transport" != "tcp" && "$transport" != "udp" ]]; do
        read -p "Invalid transport. Please enter tcp or udp: " transport
    done
    
    read -p "Enable encryption (y/n): " encryption_choice
    encryption=$([[ "$encryption_choice" =~ ^[Yy]$ ]] && echo "true" || echo "false")
    
    # Token configuration
    local token
    while true; do
        read -p "Security token (min 8 chars, or press Enter for auto-generate): " token
        if [[ -z "$token" ]]; then
            token=$(openssl rand -hex 16)
            log_info "Auto-generated token: $token"
            break
        elif validate_token "$token"; then
            break
        else
            log_error "Invalid token format"
        fi
    done
    
    # Port configuration
    echo
    read -p "Enter ports separated by commas (e.g., 2070,2080,8080): " input_ports
    local -a config_ports
    IFS=',' read -ra ports <<< "${input_ports// /}"
    
    for port in "${ports[@]}"; do
        if validate_port "$port"; then
            config_ports+=("$port")
            log_info "Port $port added"
        else
            log_error "Invalid port: $port"
        fi
    done
    
    if [[ "${#config_ports[@]}" -eq 0 ]]; then
        log_error "No valid ports configured"
        return 1
    fi
    
    # Generate configuration
    local config_file="${CONFIG_DIR}/iran_${tunnel_port}.toml"
    
    cat > "$config_file" << EOF
# RatholStar Iran Server Configuration
# Generated: $(date)
# Version: $SCRIPT_VERSION

[server]
bind_addr = "${local_ip}:${tunnel_port}"
default_token = "$token"
heartbeat_interval = $heartbeat

[server.transport]
type = "tcp"

[server.transport.tcp]
nodelay = $nodelay
EOF

    if [[ "$encryption" == "true" ]]; then
        cat >> "$config_file" << EOF

[server.transport.tcp.tls]
hostname = "ratholstar.local"
trusted_root = "ca.pem"
pkcs12 = "identity.p12"
pkcs12_password = "password"
EOF
    fi

    for port in "${config_ports[@]}"; do
        cat >> "$config_file" << EOF

[server.services.${port}]
type = "$transport"
bind_addr = "${local_ip}:${port}"
EOF
    done
    
    # Create systemd service
    create_systemd_service "iran_${tunnel_port}" "$config_file"
    
    # Create backup
    backup_config "iran_${tunnel_port}"
    
    log_info "Iran server configured successfully"
    log_security "Iran server created on port $tunnel_port"
    
    echo
    colorize green "${SYMBOL_CHECK} Configuration completed!" bold
    echo -e "Config file: $config_file"
    echo -e "Service: ratholstar-iran_${tunnel_port}"
    echo -e "Token: $token"
    echo
    read -p "Press Enter to continue..."
}

# Enhanced Kharej server configuration
configure_kharej_server() {
    clear
    colorize cyan "${SYMBOL_ROCKET} Kharej Server Configuration" bold
    echo
    
    # Iran server details
    local iran_ip tunnel_port
    while true; do
        read -p "Iran server IP address: " iran_ip
        if [[ -n "$iran_ip" ]]; then
            break
        else
            log_error "IP address cannot be empty"
        fi
    done
    
    while true; do
        read -p "Iran server tunnel port: " tunnel_port
        if validate_port "$tunnel_port"; then
            break
        else
            log_error "Invalid port number"
        fi
    done
    
    # Advanced options
    local nodelay heartbeat transport encryption
    
    read -p "Enable TCP_NODELAY (y/n): " nodelay_choice
    nodelay=$([[ "$nodelay_choice" =~ ^[Yy]$ ]] && echo "true" || echo "false")
    
    read -p "Enable Heartbeat (y/n): " heartbeat_choice
    heartbeat=$([[ "$heartbeat_choice" =~ ^[Yy]$ ]] && echo "40" || echo "0")
    
    read -p "Transport type (tcp/udp): " transport
    while [[ "$transport" != "tcp" && "$transport" != "udp" ]]; do
        read -p "Invalid transport. Please enter tcp or udp: " transport
    done
    
    read -p "Enable encryption (y/n): " encryption_choice
    encryption=$([[ "$encryption_choice" =~ ^[Yy]$ ]] && echo "true" || echo "false")
    
    # Token
    read -p "Security token: " token
    while ! validate_token "$token"; do
        read -p "Invalid token. Please enter a valid token: " token
    done
    
    # Local IP determination
    local local_ip='0.0.0.0'
    if check_ipv6 "$iran_ip"; then
        local_ip='[::]'
        iran_ip="${iran_ip#[}"
        iran_ip="${iran_ip%]}"
    fi
    
    # Port configuration
    echo
    read -p "Enter ports separated by commas (e.g., 2070,2080,8080): " input_ports
    local -a config_ports
    IFS=',' read -ra ports <<< "${input_ports// /}"
    
    for port in "${ports[@]}"; do
        if validate_port "$port"; then
            config_ports+=("$port")
            log_info "Port $port added"
        else
            log_error "Invalid port: $port"
        fi
    done
    
    if [[ "${#config_ports[@]}" -eq 0 ]]; then
        log_error "No valid ports configured"
        return 1
    fi
    
    # Generate configuration
    local config_file="${CONFIG_DIR}/kharej_${tunnel_port}.toml"
    
    cat > "$config_file" << EOF
# RatholStar Kharej Server Configuration
# Generated: $(date)
# Version: $SCRIPT_VERSION

[client]
remote_addr = "${iran_ip}:${tunnel_port}"
default_token = "$token"
heartbeat_timeout = $heartbeat
retry_interval = 1

[client.transport]
type = "tcp"

[client.transport.tcp]
nodelay = $nodelay
EOF

    if [[ "$encryption" == "true" ]]; then
        cat >> "$config_file" << EOF

[client.transport.tcp.tls]
hostname = "ratholstar.local"
trusted_root = "ca.pem"
EOF
    fi

    for port in "${config_ports[@]}"; do
        cat >> "$config_file" << EOF

[client.services.${port}]
type = "$transport"
local_addr = "${local_ip}:${port}"
EOF
    done
    
    # Create systemd service
    create_systemd_service "kharej_${tunnel_port}" "$config_file"
    
    # Create backup
    backup_config "kharej_${tunnel_port}"
    
    log_info "Kharej server configured successfully"
    log_security "Kharej client created for $iran_ip:$tunnel_port"
    
    echo
    colorize green "${SYMBOL_CHECK} Configuration completed!" bold
    echo -e "Config file: $config_file"
    echo -e "Service: ratholstar-kharej_${tunnel_port}"
    echo -e "Connecting to: $iran_ip:$tunnel_port"
    echo
    read -p "Press Enter to continue..."
}

# Enhanced systemd service creation
create_systemd_service() {
    local service_name="$1"
    local config_file="$2"
    local service_file="${SERVICE_DIR}/ratholstar-${service_name}.service"
    
    cat > "$service_file" << EOF
[Unit]
Description=RatholStar Tunnel Service ($service_name)
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=${CORE_DIR}/rathole $config_file
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
Restart=always
RestartSec=5
StartLimitIntervalSec=0

# Security settings
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$CONFIG_DIR $LOG_DIR
PrivateTmp=yes

# Resource limits
LimitNOFILE=1048576
LimitNPROC=1048576

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ratholstar-$service_name

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "ratholstar-${service_name}.service"
    systemctl start "ratholstar-${service_name}.service"
    
    log_info "Service ratholstar-$service_name created and started"
}

# Enhanced backup system
backup_config() {
    local config_name="$1"
    local backup_file="${BACKUP_DIR}/${config_name}_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    tar -czf "$backup_file" -C "$CONFIG_DIR" "${config_name}.toml"
    log_info "Configuration backed up to $backup_file"
}

# Enhanced monitoring system
monitor_tunnels() {
    clear
    colorize cyan "${SYMBOL_GEAR} Tunnel Monitoring System" bold
    echo
    
    local -a services
    local index=1
    
    # Collect all services
    for config_file in "$CONFIG_DIR"/*.toml; do
        [[ -f "$config_file" ]] || continue
        
        local config_name
        config_name=$(basename "$config_file" .toml)
        services+=("$config_name")
        
        local service_name="ratholstar-${config_name}.service"
        local status_color status_text
        
        if systemctl is-active "$service_name" &>/dev/null; then
            status_color="$GREEN"
            status_text="${SYMBOL_CHECK} Running"
        else
            status_color="$RED"
            status_text="${SYMBOL_CROSS} Stopped"
        fi
        
        # Get port from config name
        local port="${config_name##*_}"
        local type="${config_name%_*}"
        
        echo -e "${MAGENTA}${index})${RESET} ${CYAN}$type${RESET} tunnel (Port: ${YELLOW}$port${RESET}) - ${status_color}$status_text${RESET}"
        
        # Show additional info if running
        if systemctl is-active "$service_name" &>/dev/null; then
            local memory_usage
            memory_usage=$(systemctl show "$service_name" --property=MemoryCurrent --value 2>/dev/null)
            if [[ -n "$memory_usage" && "$memory_usage" != "[not set]" ]]; then
                memory_usage=$(( memory_usage / 1024 / 1024 ))
                echo -e "   Memory: ${memory_usage}MB"
            fi
        fi
        
        ((index++))
    done
    
    if [[ "${#services[@]}" -eq 0 ]]; then
        log_warn "No tunnel configurations found"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo
    echo -e "${CYAN}Management Options:${RESET}"
    echo -e "${GREEN}r) Refresh status${RESET}"
    echo -e "${YELLOW}l) View logs${RESET}"
    echo -e "${MAGENTA}s) Service management${RESET}"
    echo -e "${CYAN}t) Real-time monitoring${RESET}"
    echo -e "${RED}0) Return to main menu${RESET}"
    echo
    
    read -p "Enter your choice: " choice
    case "$choice" in
        r|R) monitor_tunnels ;;
        l|L) view_logs_menu ;;
        s|S) service_management_menu ;;
        t|T) real_time_monitor ;;
        0) return 0 ;;
        *) log_error "Invalid option" && sleep 2 && monitor_tunnels ;;
    esac
}

# Real-time monitoring
real_time_monitor() {
    clear
    colorize cyan "${SYMBOL_GEAR} Real-time Monitoring (Press Ctrl+C to exit)" bold
    echo
    
    while true; do
        clear
        echo -e "${CYAN}=== RatholStar Real-time Monitor ===${RESET}"
        echo -e "${CYAN}Updated: $(date)${RESET}"
        echo
        
        # System resources
        local cpu_usage
        cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2+$4}' | cut -d'%' -f1)
        local memory_usage
        memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
        
        echo -e "${YELLOW}System Resources:${RESET}"
        echo -e "  CPU: ${cpu_usage}%"
        echo -e "  Memory: ${memory_usage}%"
        echo
        
        # Service status
        echo -e "${YELLOW}Service Status:${RESET}"
        for config_file in "$CONFIG_DIR"/*.toml; do
            [[ -f "$config_file" ]] || continue
            
            local config_name
            config_name=$(basename "$config_file" .toml)
            local service_name="ratholstar-${config_name}.service"
            
            if systemctl is-active "$service_name" &>/dev/null; then
                echo -e "  ${GREEN}${SYMBOL_CHECK}${RESET} $config_name"
            else
                echo -e "  ${RED}${SYMBOL_CROSS}${RESET} $config_name"
            fi
        done
        
        echo
        echo -e "${YELLOW}Network Connections:${RESET}"
        netstat -tuln | grep LISTEN | grep -E ':(80|443|22|[0-9]{4,5})' | head -10
        
        sleep 5
    done
}

# Enhanced main menu
display_main_menu() {
    clear
    display_logo
    get_system_info
    display_server_info
    display_core_status
    
    echo
    echo -e "${BOLD}${WHITE}Main Menu:${RESET}"
    echo -e "${GREEN} 1) ${SYMBOL_ROCKET} Configure New Tunnel${RESET}"
    echo -e "${CYAN} 2) ${SYMBOL_GEAR} Monitor & Manage Tunnels${RESET}"
    echo -e "${YELLOW} 3) ${SYMBOL_SHIELD} Security & Optimization${RESET}"
    echo -e "${MAGENTA} 4) ${SYMBOL_STAR} Advanced Features${RESET}"
    echo -e "${BLUE} 5) ${SYMBOL_GEAR} System Tools${RESET}"
    echo -e "${WHITE} 6) ${SYMBOL_ARROW} Install/Update Core${RESET}"
    echo -e "${RED} 0) ${SYMBOL_CROSS} Exit${RESET}"
    echo
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${RESET}"
}

# Main execution flow
main() {
    # Initialize
    create_directories
    install_packages
    configure_security
    
    # Main loop
    while true; do
        display_main_menu
        read -p "Enter your choice: " choice
        
        case "$choice" in
            1) configure_tunnel ;;
            2) monitor_tunnels ;;
            3) security_menu ;;
            4) advanced_features_menu ;;
            5) system_tools_menu ;;
            6) download_rathole_core "true" ;;
            0) 
                echo -e "${GREEN}Thank you for using RatholStar!${RESET}"
                log_info "RatholStar session ended"
                exit 0 
                ;;
            *) 
                log_error "Invalid option: $choice"
                sleep 2 
                ;;
        esac
    done
}

# Additional menu functions (stubs for now)
security_menu() {
    echo -e "${YELLOW}Security menu - Coming soon!${RESET}"
    sleep 2
}

advanced_features_menu() {
    echo -e "${YELLOW}Advanced features menu - Coming soon!${RESET}"
    sleep 2
}

system_tools_menu() {
    echo -e "${YELLOW}System tools menu - Coming soon!${RESET}"
    sleep 2
}

view_logs_menu() {
    echo -e "${YELLOW}Logs menu - Coming soon!${RESET}"
    sleep 2
}

service_management_menu() {
    echo -e "${YELLOW}Service management menu - Coming soon!${RESET}"
    sleep 2
}

# Trap signals for cleanup
trap 'log_info "RatholStar interrupted"; exit 130' INT
trap 'log_info "RatholStar terminated"; exit 143' TERM

# Start the application
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
