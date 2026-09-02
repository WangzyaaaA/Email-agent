#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE_NAME="mail-sentinel"
CONTAINER_NAME="mail-sentinel"
SOURCE_DIR="${MAIL_SENTINEL_SOURCE_DIR:-/mnt/f/repos/email_agent}"
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
BACKUP_ROOT="${PROJECT_DIR}/backups"
DATABASE_NAME="mail_sentinel.db"
service_stopped=false
was_running=false

fail() {
  printf '错误：%s\n' "$*" >&2
  exit 1
}

restore_service_on_error() {
  local status=$?
  if (( status != 0 )) && [[ "$service_stopped" == true && "$was_running" == true ]]; then
    printf '更新失败，正在尝试重新启动原容器……\n' >&2
    docker compose --project-directory "$PROJECT_DIR" start "$SERVICE_NAME" >/dev/null 2>&1 || true
  fi
  exit "$status"
}

trap restore_service_on_error EXIT

for command_name in docker rsync python3 curl; do
  command -v "$command_name" >/dev/null 2>&1 || fail "缺少命令 ${command_name}"
done

[[ $EUID -eq 0 ]] || fail "请使用 root 运行：wsl -d MailSentinel-Test -u root"

SOURCE_DIR="$(realpath -e -- "$SOURCE_DIR")"
PROJECT_DIR="$(realpath -e -- "$PROJECT_DIR")"

[[ "$SOURCE_DIR" != "/" ]] || fail "源码目录不能是根目录"
[[ "$PROJECT_DIR" != "/" ]] || fail "项目目录不能是根目录"
[[ "$SOURCE_DIR" != "$PROJECT_DIR" ]] || fail "源码目录和部署目录不能相同"
[[ -d "$SOURCE_DIR/app" ]] || fail "源码目录缺少 app/：${SOURCE_DIR}"
[[ -f "$PROJECT_DIR/.env" ]] || fail "部署目录缺少 .env：${PROJECT_DIR}"

for required_file in pyproject.toml README.md Dockerfile docker-compose.yml update-wsl.sh; do
  [[ -f "$SOURCE_DIR/$required_file" ]] || fail "源码目录缺少 ${required_file}"
done

docker compose --project-directory "$PROJECT_DIR" config --quiet

container_id="$(docker compose --project-directory "$PROJECT_DIR" ps --all --quiet "$SERVICE_NAME")"
[[ -n "$container_id" ]] || fail "未找到现有 ${SERVICE_NAME} 容器，无法制作升级前备份"

if [[ "$(docker inspect --format '{{.State.Running}}' "$container_id")" == true ]]; then
  was_running=true
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="${BACKUP_ROOT}/pre-update-${stamp}"
if [[ -e "$backup_dir" ]]; then
  backup_dir="${backup_dir}-$$"
fi
raw_backup_dir="${backup_dir}/raw"
consistent_backup="${backup_dir}/mail_sentinel.consistent.db"

install -d -m 0700 "$raw_backup_dir"

printf '停止测试容器……\n'
docker compose --project-directory "$PROJECT_DIR" stop "$SERVICE_NAME"
service_stopped=true

printf '备份数据库卷……\n'
docker cp "${container_id}:/data/." "$raw_backup_dir/"
[[ -f "$raw_backup_dir/$DATABASE_NAME" ]] || fail "数据卷中未找到 ${DATABASE_NAME}"

python3 - "$raw_backup_dir/$DATABASE_NAME" "$consistent_backup" <<'PY'
import sqlite3
import sys

source_path, target_path = sys.argv[1:]
source = sqlite3.connect(source_path)
target = sqlite3.connect(target_path)
try:
    source.backup(target)
    result = target.execute("PRAGMA integrity_check").fetchone()[0]
    if result != "ok":
        raise SystemExit(f"SQLite 备份完整性检查失败：{result}")
finally:
    target.close()
    source.close()
PY
chmod 0600 "$consistent_backup"

printf '同步新版应用文件……\n'
rsync -a --delete -- "$SOURCE_DIR/app/" "$PROJECT_DIR/app/"
for file_name in pyproject.toml README.md Dockerfile docker-compose.yml update-wsl.sh; do
  install -m 0644 "$SOURCE_DIR/$file_name" "$PROJECT_DIR/$file_name"
done
chmod 0755 "$PROJECT_DIR/update-wsl.sh"

printf '重建并启动容器……\n'
docker compose --project-directory "$PROJECT_DIR" up -d --build

healthy=false
for _ in $(seq 1 30); do
  if curl --fail --silent --show-error http://127.0.0.1:8080/health >/dev/null 2>&1; then
    healthy=true
    break
  fi
  sleep 2
done
[[ "$healthy" == true ]] || fail "容器启动后 60 秒内未通过健康检查"

docker exec "$CONTAINER_NAME" python -c "import sqlite3; c=sqlite3.connect('/data/mail_sentinel.db'); result=c.execute('PRAGMA integrity_check').fetchone()[0]; c.close(); raise SystemExit(0 if result == 'ok' else 1)"

service_stopped=false
trap - EXIT

printf '\n更新完成。\n'
printf '备份：%s\n' "$consistent_backup"
docker compose --project-directory "$PROJECT_DIR" ps
curl --fail --silent --show-error http://127.0.0.1:8080/health
printf '\n'
