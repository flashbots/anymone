//! Live load generation for a real deployment.
//!
//! Backs the dashboard's `clients` knob with artificial chat clients, one OS
//! process each (`anymone-chat --bot`), reconciled to the knob every tick. Each
//! client gets a unique auto-generated identity; everything else (streams to
//! dial, governance) is inherited from the observer's own config. This is the
//! real-network analogue of the in-memory demo's client supervisor — open the
//! dashboard, raise the knob, watch the anonymity set climb.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::Arc;
use std::time::Duration;

use crate::DemoControls;

/// Hard ceiling on live bot processes, independent of the (uncapped) knob value.
const MAX_LOAD_CLIENTS: usize = 512;

/// Derive a per-client bootstrap config from the observer's own config text: the
/// same streams + `[governance]`, but a unique identity. A bot is a client-plane
/// process — it joins no peer set — so the observer's backbone keys are dropped.
fn child_config(orig: &str, identity_path: &Path) -> String {
    let mut out = format!("identity_path = \"{}\"\n", identity_path.display());
    for line in orig.lines() {
        let key = line.split('=').next().unwrap_or("").trim();
        if matches!(
            key,
            "identity_path"
                | "listen_addr"
                | "dialable_addr"
                | "bootstrappers"
                | "genesis_peers"
                | "stream_listen"
                | "local"
        ) {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_config_keeps_only_the_client_plane() {
        let observer = "identity_path = \"/x/observer\"\n[network]\nlisten_addr = \"0.0.0.0:7140\"\ndialable_addr = \"10.0.0.1:7140\"\nlocal = true\ngenesis_peers = [\"ed25519:aa\"]\nbootstrappers = [\"ed25519:bb@10.0.0.1:7100\"]\nstream_bootstrappers = [\"ed25519:cc@10.0.0.1:7620\"]\n[governance]\nthreshold = 2\n";
        let out = child_config(observer, Path::new("/x/bot-0"));
        assert!(out.starts_with("identity_path = \"/x/bot-0\"\n"));
        // A bot joins no peer set, so it keeps only what it dials.
        let keys: Vec<&str> = out
            .lines()
            .map(|l| l.split('=').next().unwrap_or("").trim())
            .collect();
        for dropped in [
            "listen_addr",
            "dialable_addr",
            "genesis_peers",
            "bootstrappers",
            "local",
        ] {
            assert!(!keys.contains(&dropped), "{dropped} survived: {out}");
        }
        assert!(out.contains("stream_bootstrappers = [\"ed25519:cc@10.0.0.1:7620\"]"));
        assert!(out.contains("threshold = 2"));
    }
}

/// Spawn the supervisor task. It reconciles the live child-process population to
/// the `clients` knob forever, using stable slot indices (so each client keeps a
/// fixed identity): surplus highest slots are killed, exited ones are pruned and
/// refilled into the same slot.
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
                let _ = std::fs::create_dir_all(&state_dir); // robust if the dir was removed
                if let Err(e) = std::fs::write(&cfg_path, child_config(&config_text, &id_path)) {
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
