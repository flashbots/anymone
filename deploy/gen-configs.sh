#!/usr/bin/env bash
# Generate identities + per-node configs for a local anymone deployment.
#
# Every node seeds from the bootnode alone; Kademlia discovers the rest. Output
# layout under $OUT:
#   identities/<name>(.exchange)   long-lived keypairs (secret)
#   configs/<name>.toml            bootstrap config per node
#   run.sh                         launches the whole network
#
# Env: OUT (dir), RELAYS (count, default 3), THRESHOLD (default 2), HOST.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-$ROOT/deploy/local}"
RELAYS="${RELAYS:-3}"
THRESHOLD="${THRESHOLD:-2}"
HOST="${HOST:-127.0.0.1}"
COMMITTEE=3

BIN="$ROOT/target/release/anymone-node"

if [[ -e "$OUT" && "${FORCE:-0}" != "1" ]]; then
    echo "error: $OUT exists; set FORCE=1 to regenerate" >&2
    exit 1
fi
ID="$OUT/identities"
CFG="$OUT/configs"
# Only the generated trees; $OUT also holds hand-written launchers (run-local.sh,
# run-local-txbus.sh) that must survive regeneration.
rm -rf "$ID" "$CFG"
mkdir -p "$ID" "$CFG"

echo "building anymone-node…" >&2
cargo build --jobs 8 --release -p anymone-node >&2

# gen <name> -> echoes "pubkey exchange_pubkey peer_id", writes the identity.
gen() {
    local out
    out="$("$BIN" keygen --out "$ID/$1")"
    echo "$(awk '$1=="pubkey"{print $2}' <<<"$out")" \
         "$(awk '$1=="exchange_pubkey"{print $2}' <<<"$out")" \
         "$(awk '$1=="peer_id"{print $2}' <<<"$out")"
}

read -r _BOOT_PK _BOOT_XP BOOT_PID < <(gen bootnode)
BOOT_ADDR="/ip4/$HOST/tcp/7100/p2p/$BOOT_PID"

# Committee block (shared by every config) + identities.
COMMITTEE_BLOCK=""
for i in $(seq 0 $((COMMITTEE - 1))); do
    read -r PK XP _PID < <(gen "committee-$i")
    COMMITTEE_BLOCK+=$'\n[[governance.committee]]\n'"pubkey = \"$PK\""$'\n'"exchange_pubkey = \"$XP\""$'\n'
done

# write_cfg <name> <listen-port> <bootstrap-peers-toml-array> [extra-committee-toml] [identity-name]
write_cfg() {
    cat >"$CFG/$1.toml" <<EOF
identity_path = "$ID/${5:-$1}"

[network]
listen = "/ip4/0.0.0.0/tcp/$2"
bootstrap_peers = [$3]

[governance]
threshold = $THRESHOLD
$COMMITTEE_BLOCK
[committee]
committee_round_ms = 10000
public_round_ms = 4000
${4:-}
EOF
}

SEED="\"$BOOT_ADDR\""
write_cfg bootnode 7100 ""          # the seed dials no one
for i in $(seq 0 $((COMMITTEE - 1))); do write_cfg "committee-$i" $((7110 + i)) "$SEED"; done
for i in $(seq 0 $((RELAYS - 1)));    do write_cfg "relay-$i"     $((7120 + i)) "$SEED"; done
write_cfg chat     7130 "$SEED"
write_cfg client   7131 "$SEED"
write_cfg observer 7150 "$SEED"

# Tx-bus demo (run-local-txbus.sh): the RPC gateway plus two forwarding bridges,
# and a committee pinned to scheduled Panetiere with 16 KiB messages so
# transactions that size ride the bus. Separate committee configs reusing the
# same identities, so run-local.sh keeps its ADCNet→Panetiere escalation ladder.
TXBUS_COMMITTEE='protocol = "scheduled-panetiere"
message_size = 16384
vector_bytes = 65536
min_capacity = 40'
for i in $(seq 0 $((COMMITTEE - 1))); do
    write_cfg "committee-txbus-$i" $((7110 + i)) "$SEED" "$TXBUS_COMMITTEE" "committee-$i"
done
for name in gateway bridge-a bridge-b; do gen "$name" >/dev/null; done
write_cfg gateway  7140 "$SEED"
write_cfg bridge-a 7141 "$SEED"
write_cfg bridge-b 7142 "$SEED"

# run.sh: launch everything. Relays/committee expose /state/peers for the
# observer to scrape; chat + dashboard serve on 8080 / 7000.
{
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo "ROOT=\"$ROOT\"; CFG=\"$CFG\""
    echo 'NODE="$ROOT/target/release/anymone-node"'
    echo 'CHAT="$ROOT/target/release/anymone-chat"'
    echo 'OBS="$ROOT/target/release/anymone-observer"'
    echo "cargo build --jobs 8 --release -p anymone-node -p anymone-chat -p anymone-observer"
    echo 'pids=(); trap '"'"'kill "${pids[@]}" 2>/dev/null'"'"' EXIT'
    echo '"$NODE" bootnode --config "$CFG/bootnode.toml" & pids+=($!)'
    echo 'sleep 1'
    for i in $(seq 0 $((COMMITTEE - 1))); do
        echo "\"\$NODE\" run --role committee --config \"\$CFG/committee-$i.toml\" --peers-port $((7210 + i)) & pids+=(\$!)"
    done
    SCRAPE=""
    for i in $(seq 0 $((COMMITTEE - 1))); do SCRAPE+=" --scrape http://$HOST:$((7210 + i))"; done
    for i in $(seq 0 $((RELAYS - 1))); do
        echo "\"\$NODE\" run --role relay --config \"\$CFG/relay-$i.toml\" --peers-port $((7220 + i)) & pids+=(\$!)"
        SCRAPE+=" --scrape http://$HOST:$((7220 + i))"
    done
    echo '"$CHAT" --config "$CFG/chat.toml" --port 8080 & pids+=($!)'
    echo '"$CHAT" --config "$CFG/client.toml" --bot lark & pids+=($!)'
    echo "\"\$OBS\" run --config \"\$CFG/observer.toml\" --dashboard-port 7000 --chat-endpoint http://$HOST:8080$SCRAPE & pids+=(\$!)"
    echo 'echo "dashboard: http://localhost:7000   chat: http://localhost:8080"'
    echo 'wait'
} >"$OUT/run.sh"
chmod +x "$OUT/run.sh"

echo "wrote $((2 * COMMITTEE + RELAYS + 7)) configs to $CFG" >&2
echo "bootnode: $BOOT_ADDR" >&2
echo "launch:   $OUT/run.sh" >&2
