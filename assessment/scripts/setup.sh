#!/bin/bash

# setup.sh - EC2 Instance Setup Script for Wazuh Security Monitoring
# This script installs Docker, Docker Compose, and sets up Wazuh with proper logging

set -euo pipefail  # Exit on any error, undefined variables, or pipe failures

# Configuration
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/var/log/setup.log"
readonly DOCKER_COMPOSE_VERSION="2.21.0"
readonly WAZUH_VERSION="4.7.0"
readonly S3_BUCKET="${s3_bucket}"
readonly AWS_REGION="${region}"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        INFO)  echo -e "$${GREEN}[INFO]$${NC} $message" | tee -a "$LOG_FILE" ;;
        WARN)  echo -e "$${YELLOW}[WARN]$${NC} $message" | tee -a "$LOG_FILE" ;;
        ERROR) echo -e "$${RED}[ERROR]$${NC} $message" | tee -a "$LOG_FILE" >&2 ;;
        *)     echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE" ;;
    esac
}

# Error handling function
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Check if script is run as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

# Create necessary directories
setup_directories() {
    log "INFO" "Creating necessary directories..."
    
    mkdir -p /opt/wazuh
    mkdir -p /opt/wazuh/config
    mkdir -p /opt/wazuh/logs
    mkdir -p /opt/wazuh/data
    mkdir -p /var/log/wazuh-setup
    
    # Set proper permissions
    chmod 755 /opt/wazuh
    chmod 755 /opt/wazuh/config
    chmod 755 /opt/wazuh/logs
    chmod 755 /opt/wazuh/data
}

# Update system and install prerequisites
update_system() {
    log "INFO" "Updating system packages..."
    
    yum update -y || error_exit "Failed to update system packages"
    
    log "INFO" "Installing prerequisite packages..."
    yum install -y \
        curl \
        wget \
        unzip \
        git \
        htop \
        net-tools \
        sysstat \
        awscli \
        amazon-cloudwatch-agent \
        || error_exit "Failed to install prerequisite packages"
}

# Install Docker
install_docker() {
    log "INFO" "Installing Docker..."
    
    # Remove any existing Docker installations
    yum remove -y docker \
                  docker-client \
                  docker-client-latest \
                  docker-common \
                  docker-latest \
                  docker-latest-logrotate \
                  docker-logrotate \
                  docker-engine 2>/dev/null || true
    
    # Install Docker
    yum install -y docker || error_exit "Failed to install Docker"
    
    # Start and enable Docker service
    systemctl start docker || error_exit "Failed to start Docker service"
    systemctl enable docker || error_exit "Failed to enable Docker service"
    
    # Add ec2-user to docker group
    usermod -aG docker ec2-user || log "WARN" "Failed to add ec2-user to docker group"
    
    # Verify Docker installation
    docker --version || error_exit "Docker installation verification failed"
    log "INFO" "Docker installed successfully"
}

# Install Docker Compose
install_docker_compose() {
    log "INFO" "Installing Docker Compose v$DOCKER_COMPOSE_VERSION..."
    
    # Download Docker Compose
    curl -L "https://github.com/docker/compose/releases/download/v$DOCKER_COMPOSE_VERSION/docker-compose-$(uname -s)-$(uname -m)" \
         -o /usr/local/bin/docker-compose || error_exit "Failed to download Docker Compose"
    
    # Make it executable
    chmod +x /usr/local/bin/docker-compose || error_exit "Failed to make Docker Compose executable"
    
    # Create symlink for easier access
    ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
    
    # Verify installation
    docker-compose --version || error_exit "Docker Compose installation verification failed"
    log "INFO" "Docker Compose installed successfully"
}

# Configure system for Wazuh
configure_system_for_wazuh() {
    log "INFO" "Configuring system for Wazuh..."
    
    # Increase virtual memory map count for Elasticsearch
    echo "vm.max_map_count=262144" >> /etc/sysctl.conf
    sysctl -w vm.max_map_count=262144
    
    # Set memory overcommit
    echo "vm.overcommit_memory=1" >> /etc/sysctl.conf
    sysctl -w vm.overcommit_memory=1
    
    # Disable swap
    swapoff -a
    sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
    
    # Configure ulimits
    cat >> /etc/security/limits.conf