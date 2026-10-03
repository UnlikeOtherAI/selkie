#!/bin/sh
# Exercise project ownership without touching Docker or production data.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
test_dir=$(mktemp -d "$PWD/.compose-test.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
cat > "$test_dir/docker" <<'STUB'
#!/bin/sh
case "$1" in
    container)
        [ "$SCENARIO" != fresh ]
        ;;
    inspect)
        case "$SCENARIO:$4" in
            unlabeled:*) printf '\n' ;;
            mixed:selkie-coturn) printf 'other\n' ;;
            *) printf 'ops\n' ;;
        esac
        ;;
    compose)
        printf '%s\n' "$*"
        ;;
    *) exit 2 ;;
esac
STUB
chmod +x "$test_dir/docker"
export PATH="$test_dir:$PATH"
for scenario in fresh existing; do
    if [ "$scenario" = fresh ]; then expected=selkie; else expected=ops; fi
    actual=$(SCENARIO=$scenario ./ops/compose-prod.sh up -d --build)
    [ "$actual" = "compose -p $expected --env-file .env -f ops/docker-compose.prod.yml up -d --build" ]
done
for scenario in mixed unlabeled; do
    if SCENARIO=$scenario ./ops/compose-prod.sh up -d --build >"$test_dir/output" 2>&1; then
        echo "Expected $scenario ownership to block deployment" >&2
        exit 1
    fi
    if grep -q '^compose ' "$test_dir/output"; then
        echo "Unexpected mutation with $scenario ownership" >&2
        exit 1
    fi
done
printf 'Compose ownership checks passed (fresh, existing, mixed, unlabeled).\n'
