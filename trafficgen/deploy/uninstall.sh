#!/usr/bin/env bash
# trafficgen 卸载脚本
#
#   sudo ./uninstall.sh          # 停止并卸载程序；保留配置与数据
#   sudo ./uninstall.sh --purge  # 连同 /etc/trafficgen 与 /var/lib/trafficgen 一起删除
set -euo pipefail

INSTALL_DIR=/opt/trafficgen
DATA_DIR=/var/lib/trafficgen
CONF_DIR=/etc/trafficgen
SERVICE=trafficgen
SERVICE_USER=trafficgen

log()  { printf '\033[32m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*"; }

systemctl stop "$SERVICE" 2>/dev/null || true
systemctl disable "$SERVICE" 2>/dev/null || true
rm -f /etc/systemd/system/${SERVICE}.service
systemctl daemon-reload 2>/dev/null || true

rm -rf "$INSTALL_DIR"
log "已停止服务并删除 $INSTALL_DIR"

if [ "${1:-}" = "--purge" ]; then
    rm -rf "$CONF_DIR" "$DATA_DIR"
    id -u "$SERVICE_USER" >/dev/null 2>&1 && userdel "$SERVICE_USER" || true
    log "已删除配置（$CONF_DIR）、数据（$DATA_DIR）与系统用户 $SERVICE_USER"
else
    warn "配置（$CONF_DIR）与数据（$DATA_DIR，含任务记录/pcap 产物）已保留。"
    warn "确认不要了再执行：sudo $0 --purge"
fi
log "卸载完成"
