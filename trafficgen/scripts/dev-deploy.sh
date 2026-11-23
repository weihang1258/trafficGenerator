#!/usr/bin/env bash
# 开发环境部署：编译 → 换二进制 → 重启 8081。
# 生产（systemd trafficgen，8082/8086）不在此脚本范围内——生产变更必须
# 人工确认后单独执行，脚本刻意不碰 systemctl。
#
# 用法：
#   ./scripts/dev-deploy.sh              # 编译 + 部署 + 重启
#   ./scripts/dev-deploy.sh --build-only # 只编译，不碰运行中的进程
#
# 环境变量（都有默认值，按需覆盖）：
#   DEV_CWD     服务工作目录（数据库/日志的相对根）  默认 /tmp/tg-sv-p5
#   DEV_BIN     部署目标路径                        默认 /home/weihang/bin/tg-server
#   DEV_CONFIG  启动配置                            默认 $DEV_CWD/configs/config.yaml
#   DEV_OWNER   数据文件归属（进程以 root 跑）        默认当前用户
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DEV_CWD="${DEV_CWD:-/tmp/tg-sv-p5}"
DEV_BIN="${DEV_BIN:-/home/weihang/bin/tg-server}"
DEV_CONFIG="${DEV_CONFIG:-$DEV_CWD/configs/config.yaml}"
DEV_OWNER="${DEV_OWNER:-$(id -un)}"
BUILD_ONLY=0
[ "${1:-}" = "--build-only" ] && BUILD_ONLY=1

VERSION="dev-$(git rev-parse --short HEAD)"
COMMIT="$(git rev-parse --short HEAD)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "==> 编译 $VERSION"
CGO_ENABLED=1 go build -buildvcs=false \
  -ldflags "-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE" \
  -o bin/trafficgen ./cmd/server
bin/trafficgen -version

if [ "$BUILD_ONLY" = "1" ]; then
  echo "==> --build-only：产物在 $REPO_ROOT/bin/trafficgen，未部署"
  exit 0
fi

# 配置必须存在：viper 找不到文件时会静默回落默认值（端口/key 全变），
# 开发版历史上漂移正是这么来的。
if [ ! -f "$DEV_CONFIG" ]; then
  echo "ERROR: 配置文件不存在：$DEV_CONFIG" >&2
  echo "      先用 configs/config.dev.yaml 生成一份，或设置 DEV_CONFIG 指向已有配置。" >&2
  exit 1
fi

# 开发环境以 root 起进程：NIC 实发（pcap 注入/抓包）需要 CAP_NET_RAW +
# CAP_NET_ADMIN，非 root 且无 file capability 时 af_packet 打不开网口
# （"You don't have permission to perform this capture on that device"）。
# 用 root 起进程是用户裁定；数据文件仍归还给 $DEV_OWNER，避免 DB/日志变
# root 所有后手工操作踩权限坑。
echo "==> 停止旧进程"
# 进程命令行可能是 "$DEV_BIN" 也可能是 "$DEV_BIN --config ..."，所以不能
# 用 ^...$ 锚定整条命令行；按"首个参数等于部署路径"匹配。顺带排除本脚本
# 自己的 shell（pgrep -f 会匹配到包含该路径的 bash -c）。
OLD_PIDS="$(pgrep -f "^$DEV_BIN( |$)" || true)"
if [ -n "$OLD_PIDS" ]; then
  echo "    PIDs: $OLD_PIDS"
  # shellcheck disable=SC2086
  sudo kill $OLD_PIDS 2>/dev/null || true
  for _ in $(seq 1 30); do
    # shellcheck disable=SC2086
    sudo kill -0 $OLD_PIDS 2>/dev/null || break
    sleep 0.5
  done
  # shellcheck disable=SC2086
  if sudo kill -0 $OLD_PIDS 2>/dev/null; then
    echo "==> 优雅退出超时，强制结束"
    # shellcheck disable=SC2086
    sudo kill -9 $OLD_PIDS 2>/dev/null || true
    sleep 1
  fi
else
  echo "    （没有正在运行的旧进程）"
fi

# 覆盖前确认端口已释放：二进制仍在运行时会 "Text file busy"。
for _ in $(seq 1 20); do
  if ! ss -ltn 2>/dev/null | grep -qE ':(8080|8081) '; then break; fi
  sleep 0.5
done
if ss -ltn 2>/dev/null | grep -qE ':(8080|8081) '; then
  echo "ERROR: 8080/8081 仍被占用，旧进程没有退出干净——不覆盖二进制。" >&2
  ss -ltnp 2>/dev/null | grep -E ':(8080|8081) ' >&2 || true
  exit 1
fi

echo "==> 部署二进制 → $DEV_BIN"
sudo cp bin/trafficgen "$DEV_BIN"
sudo chmod 755 "$DEV_BIN"

echo "==> 启动（root, cwd=$DEV_CWD, config=$DEV_CONFIG）"
# 后台起 root 进程：--config 显式指定；日志由 root 打开追加（server.log 归
# weihang，追加无碍），随后把新写入的文件归还 $DEV_OWNER。
cd "$DEV_CWD"
sudo -- bash -c "nohup '$DEV_BIN' --config '$DEV_CONFIG' >> '$DEV_CWD/server.log' 2>&1 < /dev/null &"

sleep 3
echo "==> 新进程："
if pgrep -af "^$DEV_BIN" >/dev/null; then
  pgrep -af "^$DEV_BIN"
else
  echo "ERROR: 启动失败，看 $DEV_CWD/server.log" >&2
  exit 1
fi

# root 进程会新建/滚动 DB-WAL、pcaps、exports；归还给 DEV_OWNER，后续手工
# 操作（以及测试脚本）不会被 root 文件的权限绊住。
echo "==> 数据文件归属归还 $DEV_OWNER"
sudo chown -R "$DEV_OWNER" "$DEV_CWD/data" 2>/dev/null || true
sudo chown "$DEV_OWNER" "$DEV_CWD/server.log" 2>/dev/null || true

echo "==> 生效权限（应为 CAP_NET_RAW + CAP_NET_ADMIN）："
CAP_PID="$(pgrep -f "^$DEV_BIN" | head -1)"
if [ -n "$CAP_PID" ]; then
  sudo grep -E '^CapEff:' "/proc/$CAP_PID/status" 2>/dev/null || true
  echo "    （0x3000 = cap_net_raw + cap_net_admin）"
fi

echo "==> 监听端口："
ss -ltnp 2>/dev/null | grep -E ':80(80|81)' || true
