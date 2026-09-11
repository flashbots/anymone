#!/usr/bin/env bash
# Generate identities + per-node configs for a local anymone deployment.
#
# Nodes sit on one of two planes. Backbone members (bootnode, committee, relays,
# and the services: chat, observer, gateway) dial the bootnode, are mutually
# authenticated, and only accept peers a tracked set names — so every backbone
# key is listed in `genesis_peers`, which is what the fleet has before the first
# signed config exists. Client-plane processes (the chat bot, the forwarding
# bridges) join no peer set: they hold encrypted streams to the nodes that serve
# clients. A backbone service that mints virtual clients gets that stream list
# too, since its clients live on the client plane.
#
# Output layout under $OUT:
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
# Preserve files outside the generated identity and config directories.
rm -rf "$ID" "$CFG"
mkdir -p "$ID" "$CFG"

echo "building anymone-node…" >&2
cargo build --jobs 8 --release -p anymone-node >&2

declare -A PK ECDH KEM

# gen <name> — mint the identity and record its public material.
gen() {
    local out
    out="$("$BIN" keygen --out "$ID/$1")"
    PK[$1]="$(awk '$1=="pubkey"{print $2}' <<<"$out")"
    ECDH[$1]="$(awk '$1=="exchange_ecdh"{print $2}' <<<"$out")"
    KEM[$1]="$(awk '$1=="exchange_kem"{print $2}' <<<"$out")"
}

BACKBONE=(bootnode chat observer gateway)
for i in $(seq 0 $((COMMITTEE - 1))); do BACKBONE+=("committee-$i"); done
for i in $(seq 0 $((RELAYS - 1))); do BACKBONE+=("relay-$i"); done
for name in "${BACKBONE[@]}" client bridge-a bridge-b; do gen "$name"; done

BOOT_P2P=7100
BOOT_STREAM=7600
relay_p2p() { echo $((7120 + $1)); }
relay_stream() { echo $((7620 + $1)); }

# The committee's keys are tracked implicitly, so `genesis_peers` carries the
# rest of the backbone.
GENESIS=""
for name in "${BACKBONE[@]}"; do
    [[ $name == committee-* ]] && continue
    GENESIS+="${GENESIS:+, }\"${PK[$name]}\""
done

# Nodes a client dials, relays first: the bootnode serves clients too, but only
# as the fallback when no relay answers.
STREAMS=""
for i in $(seq 0 $((RELAYS - 1))); do
    STREAMS+="${STREAMS:+, }\"${PK[relay-$i]}@$HOST:$(relay_stream "$i")\""
done
STREAMS+=", \"${PK[bootnode]}@$HOST:$BOOT_STREAM\""

COMMITTEE_BLOCK=""
for i in $(seq 0 $((COMMITTEE - 1))); do
    COMMITTEE_BLOCK+=$'\n[[governance.committee]]\n'"pubkey = \"${PK[committee-$i]}\""$'\n'
    COMMITTEE_BLOCK+="exchange_pubkey = { ecdh = \"${ECDH[committee-$i]}\", kem = \"${KEM[committee-$i]}\" }"$'\n'
done

# tail <extra-committee-toml>
tail_block() {
    cat <<EOF

[governance]
threshold = $THRESHOLD
$COMMITTEE_BLOCK
[committee]
committee_round_ms = 10000
public_round_ms = 4000
${1:-}
EOF
}

# backbone_cfg <name> <p2p-port> <stream-port|""> <serves-clients:0|1> [extra-committee] [identity]
backbone_cfg() {
    local name=$1 p2p=$2 stream=$3 clients=$4 extra=${5:-} identity=${6:-$1}
    {
        echo "identity_path = \"$ID/$identity\""
        echo
        echo '[network]'
        echo "listen_addr = \"0.0.0.0:$p2p\""
        echo "dialable_addr = \"$HOST:$p2p\""
        echo 'local = true'
        [[ $name != bootnode ]] && echo "bootstrappers = [\"${PK[bootnode]}@$HOST:$BOOT_P2P\"]"
        echo "genesis_peers = [$GENESIS]"
        [[ -n $stream ]] && echo "stream_listen = \"0.0.0.0:$stream\""
        [[ $clients == 1 ]] && echo "stream_bootstrappers = [$STREAMS]"
        tail_block "$extra"
    } >"$CFG/$name.toml"
}

# client_cfg <name> — no listen address, no peer set: streams and nothing else.
client_cfg() {
    {
        echo "identity_path = \"$ID/$1\""
        echo
        echo '[network]'
        echo "stream_bootstrappers = [$STREAMS]"
        tail_block ""
    } >"$CFG/$1.toml"
}

backbone_cfg bootnode $BOOT_P2P $BOOT_STREAM 0
for i in $(seq 0 $((COMMITTEE - 1))); do backbone_cfg "committee-$i" $((7110 + i)) "" 0; done
for i in $(seq 0 $((RELAYS - 1))); do
    backbone_cfg "relay-$i" "$(relay_p2p "$i")" "$(relay_stream "$i")" 0
done
# chat serves a room and the observer runs the dashboard's load bots, so both
# mint virtual clients of their own.
backbone_cfg chat 7130 "" 1
backbone_cfg observer 7150 "" 1
client_cfg client

# Tx-bus configs: the RPC gateway plus two forwarding bridges,
# and a committee pinned to scheduled Panetiere with 16 KiB messages so
# transactions that size ride the bus. Separate committee configs reusing the
# same identities, with independent protocol settings.
TXBUS_COMMITTEE='protocol = "scheduled-panetiere"
message_size = 16384
vector_bytes = 65536
min_capacity = 40'
for i in $(seq 0 $((COMMITTEE - 1))); do
    backbone_cfg "committee-txbus-$i" $((7110 + i)) "" 0 "$TXBUS_COMMITTEE" "committee-$i"
done
# gateway announces the bus tag and submits through virtual clients; the two
# bridges only forward what the bus carried, so they are pure clients.
backbone_cfg gateway 7140 "" 1
client_cfg bridge-a
client_cfg bridge-b

# run.sh: launch everything. Relays/committee expose /state/peers for the
# observer to scrape; chat + dashboard serve on 8080 / 7000.
{
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo "ROOT=\"$ROOT\"; CFG=\"$CFG\""
    echo 'NODE="$ROOT/target/release/anymone-node"'
    echo 'CHAT="$ROOT/target/release/anymone-chat"'
    echo 'OBS="$ROOT/target/release/anymone-observer"'
    echo 'export RUST_LOG="${RUST_LOG:-info,anymone=debug,commonware_p2p=warn,commonware_runtime=warn}"'
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
echo "bootnode: ${PK[bootnode]}@$HOST:$BOOT_P2P (clients: $HOST:$BOOT_STREAM)" >&2
echo "launch:   $OUT/run.sh" >&2
