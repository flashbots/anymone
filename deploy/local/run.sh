#!/usr/bin/env bash
set -euo pipefail
ROOT="/home/mateusz/work/anymone"; CFG="/home/mateusz/work/anymone/deploy/local/configs"
NODE="$ROOT/target/release/anymone-node"
CHAT="$ROOT/target/release/anymone-chat"
OBS="$ROOT/target/release/anymone-observer"
cargo build --jobs 8 --release -p anymone-node -p anymone-chat -p anymone-observer
pids=(); trap 'kill "${pids[@]}" 2>/dev/null' EXIT
"$NODE" bootnode --config "$CFG/bootnode.toml" & pids+=($!)
sleep 1
"$NODE" run --role committee --config "$CFG/committee-0.toml" --peers-port 7210 & pids+=($!)
"$NODE" run --role committee --config "$CFG/committee-1.toml" --peers-port 7211 & pids+=($!)
"$NODE" run --role committee --config "$CFG/committee-2.toml" --peers-port 7212 & pids+=($!)
"$NODE" run --role relay --config "$CFG/relay-0.toml" --peers-port 7220 & pids+=($!)
"$NODE" run --role relay --config "$CFG/relay-1.toml" --peers-port 7221 & pids+=($!)
"$NODE" run --role relay --config "$CFG/relay-2.toml" --peers-port 7222 & pids+=($!)
"$CHAT" --config "$CFG/chat.toml" --port 8080 & pids+=($!)
"$CHAT" --config "$CFG/client.toml" --bot lark & pids+=($!)
"$OBS" run --config "$CFG/observer.toml" --dashboard-port 7000 --chat-endpoint http://127.0.0.1:8080 --scrape http://127.0.0.1:7210 --scrape http://127.0.0.1:7211 --scrape http://127.0.0.1:7212 --scrape http://127.0.0.1:7220 --scrape http://127.0.0.1:7221 --scrape http://127.0.0.1:7222 & pids+=($!)
echo "dashboard: http://localhost:7000   chat: http://localhost:8080"
wait
