use std::{collections::HashMap, net::TcpListener, path::Path, sync::Arc};

use anyhow::{Context, Result};
use anymone_core::{
    cw::{CommonwareConfig, CommonwareNetwork, StreamClientConfig, StreamClientNetwork},
    transport::Transport,
    Identity, Pubkey,
};

pub struct DemoNetwork {
    nodes: HashMap<Pubkey, Arc<dyn Transport>>,
    clients: StreamClientConfig,
    pub relay_addresses: HashMap<Pubkey, String>,
}

impl DemoNetwork {
    pub fn start(committee: &[Identity], relays: &[Identity], output: &Path) -> Result<Self> {
        if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir(output).context("choose a fresh --output directory for this demo")?;
        let ids: Vec<_> = committee.iter().chain(relays).collect();
        let sockets: Vec<_> = (0..ids.len() * 2)
            .map(|_| TcpListener::bind("127.0.0.1:0"))
            .collect::<std::io::Result<_>>()?;
        let addresses: Vec<_> = sockets
            .iter()
            .map(|s| s.local_addr())
            .collect::<std::io::Result<_>>()?;
        let peers: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| (id.pubkey(), addresses[i * 2]))
            .collect();
        let servers: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| (id.pubkey(), addresses[i * 2 + 1]))
            .collect();
        let members: Vec<_> = committee.iter().map(Identity::pubkey).collect();
        drop(sockets);
        let mut nodes = HashMap::new();
        for (i, id) in ids.iter().enumerate() {
            let cfg = CommonwareConfig {
                listen: addresses[i * 2],
                dialable: addresses[i * 2],
                bootstrappers: peers.clone(),
                genesis_peers: peers.iter().map(|(pk, _)| *pk).collect(),
                committee: members.clone(),
                local: true,
                stream_listen: Some(addresses[i * 2 + 1]),
                good_clients: anymone_core::GoodClients::all(),
            };
            nodes.insert(
                id.pubkey(),
                CommonwareNetwork::start(id, cfg) as Arc<dyn Transport>,
            );
        }
        let mut bootstrap = format!(
            "identity_path = {}\n\n[network]\nstream_bootstrappers = [\n",
            serde_json::to_string(&output.join("client.identity"))?
        );
        for (pk, addr) in &servers {
            bootstrap.push_str(&format!("  \"{pk}@{addr}\",\n"));
        }
        bootstrap.push_str("]\n\n[governance]\nthreshold = 2\n");
        for id in committee {
            let keys = id.exchange_keys();
            bootstrap.push_str(&format!(
                "\n[[governance.committee]]\npubkey = \"{}\"\nexchange_pubkey = {{ ecdh = \"{}\", kem = \"{}\" }}\n",
                id.pubkey(), hex::encode(keys.ecdh), hex::encode(keys.kem),
            ));
        }
        anymone_core::BootstrapConfig::from_toml_str(&bootstrap)?;
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join("client.toml"))?
            .write_all(bootstrap.as_bytes())?;
        Ok(Self {
            nodes,
            clients: StreamClientConfig {
                servers: servers.clone(),
                ..Default::default()
            },
            relay_addresses: servers
                .into_iter()
                .map(|(pk, addr)| (pk, addr.to_string()))
                .collect(),
        })
    }

    pub fn handle(&self, id: &Identity) -> Arc<dyn Transport> {
        self.nodes
            .get(&id.pubkey())
            .cloned()
            .unwrap_or_else(|| StreamClientNetwork::start(id, self.clients.clone()))
    }
}
