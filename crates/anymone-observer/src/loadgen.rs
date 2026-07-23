//! Live load generation for a real deployment.
//!
//! Backs the dashboard's `clients` knob with artificial chat clients, one OS
//! process each (`anymone-chat --bot`), reconciled to the knob every tick. Each
//! client gets a unique auto-generated identity and a distinct listen port (so
//! relays can dial it into the subnet mesh — an ephemeral `tcp/0` port is not
//! reachable and never joins). Everything else (bootstrap peers, governance) is
//! inherited from the observer's own config. This is the real-network analogue
//! of the in-memory demo's client supervisor — open the dashboard, raise the
//! knob, watch the anonymity set climb.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::Arc;
use std::time::Duration;

use crate::DemoControls;

/// First listen port for load clients; client `n` listens on `BASE + n`. Chosen
/// above the deployment's own ports (p2p 71xx, peers 72xx, chat 8080).
const LISTEN_BASE: u16 = 7400;

/// Hard ceiling on live bot processes, independent of the (uncapped) knob value.
const MAX_LOAD_CLIENTS: usize = 512;

/// Derive a per-client bootstrap config from the observer's own config text:
/// same `[network] bootstrap_peers` + `[governance]`, but a unique identity and
/// a distinct, dialable listen port.
fn child_config(orig: &str, identity_path: &Path, listen_port: u16) -> String {
    let mut out = format!("identity_path = \"{}\"\n", identity_path.display());
    for line in orig.lines() {
        let t = line.trim_start();
        if t.starts_with("identity_path") {
            continue; // replaced above
        }
        if t.starts_with("listen") && t.contains('=') {
            out.push_str(&format!("listen = \"/ip4/0.0.0.0/tcp/{listen_port}\"\n"));
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Spawn the supervisor task. It reconciles the live child-process population to
/// the `clients` knob forever, using stable slot indices (so each client keeps a
/// fixed identity + port): surplus highest slots are killed, exited ones are
/// pruned and refilled into the same slot.
pub fn spawn_supervisor(
    controls: Arc<DemoControls>,
    config_text: String,
    chat_bin: PathBuf,
    state_dir: PathBuf,
) {
    tokio::spawn(async move {
        if let Err(e) = std::fs::create_dir_all(&state_dir) {
            tracing::error!("loadgen: cannot create {}: {e}", state_dir.display());
            return;
        }
        // (slot, child) — slots stay contiguous 0..len, so port = LISTEN_BASE + slot.
        let mut children: Vec<(usize, Child)> = Vec::new();
        loop {
            // Drop handles for clients that exited on their own; refilled below.
            children.retain_mut(|(_, c)| matches!(c.try_wait(), Ok(None)));

            let want = controls
                .knob("clients")
                .map(|k| k.get())
                .unwrap_or(0)
                .min(MAX_LOAD_CLIENTS);

            while children.len() < want {
                let used: HashSet<usize> = children.iter().map(|(s, _)| *s).collect();
                let slot = (0..).find(|s| !used.contains(s)).unwrap();
                let id_path = state_dir.join(format!("bot-{slot}"));
                let cfg_path = state_dir.join(format!("bot-{slot}.toml"));
                let port = LISTEN_BASE + slot as u16;
                let _ = std::fs::create_dir_all(&state_dir); // robust if the dir was removed
                if let Err(e) =
                    std::fs::write(&cfg_path, child_config(&config_text, &id_path, port))
                {
                    tracing::warn!("loadgen: write {}: {e}", cfg_path.display());
                    break;
                }
                match std::process::Command::new(&chat_bin)
                    .arg("--config")
                    .arg(&cfg_path)
                    .arg("--bot")
                    .arg(format!("bot-{slot}"))
                    .spawn()
                {
                    Ok(child) => children.push((slot, child)),
                    Err(e) => {
                        tracing::warn!("loadgen: spawn {}: {e}", chat_bin.display());
                        break;
                    }
                }
            }
            // Remove surplus, highest slot first, so the live slots stay 0..want.
            while children.len() > want {
                if let Some(pos) = children
                    .iter()
                    .enumerate()
                    .max_by_key(|(_, (s, _))| *s)
                    .map(|(i, _)| i)
                {
                    let (_, mut c) = children.remove(pos);
                    let _ = c.kill();
                    let _ = c.wait();
                }
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
}
