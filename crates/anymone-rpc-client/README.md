# Anymone RPC client

The application owns the existing remote mobile session. Its RPC broker receives an `Upload` interface; response reading and decryption work independently of the phone.

## Run the demo

From the workspace root:

```sh
RAYON_NUM_THREADS=8 cargo build --locked -j 8 \
  -p anymone-observer -p anymone-eth-service \
  -p anymone-rpc-client -p anymone-remote-session
RAYON_NUM_THREADS=8 target/debug/anymone-observer demo \
  --output target/rpc-demo --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```

Wait for **RPC demo ready**, then in another terminal:

```sh
kohaku anymone setup --connection target/rpc-demo/rpc-client/connection.json \
  --output target/rpc-demo/kohaku.json
kohaku --anymone-profile target/rpc-demo/kohaku.json anymone connect
kohaku --anymone-profile target/rpc-demo/kohaku.json anymone status
```

The demo starts all components and a software developer session. Use a fresh
output directory. Add `--bundler-url URL` to forward to an existing bundler. Ctrl-C stops every demo
process. See the [demo guide](../anymone-eth-service/demo.md) for wallet use and
connecting to an existing remote Anymone deployment.

## Connect to a network

Start with a bootnode or node RPC URL:

```sh
RAYON_NUM_THREADS=8 anymone-rpc-client serve --bootnode 'https://seed.example#<genesis-hash>' --remote
```

Use `--node-rpc` for a node URL. Both expose `GET /network`. On first use, supply the trusted genesis hash in the URL or import `--genesis genesis.json`. Subsequent starts need only the URL: the client remembers genesis and rejects configuration rollback. Obtain the hash independently from the network operator; nodes print it when starting their discovery API.

Committee-signed configurations supply relay streams and service descriptor URLs. The client verifies each descriptor against the authorized service identity and obtains its public response-feed URLs. Descriptors and endpoints refresh every 30 seconds. Changing the chain or response-feed format requires restarting the client; mirror and key changes preserve pending response capabilities.

Start Remote on your phone, keep it in the foreground, and allow local-network access. `--remote` discovers phones over mDNS, prompts you to select one and enter its eight-digit code, then connects the upload session. Use `--remote IP:PORT` for a direct address when multicast discovery is unavailable. Prompts appear in the RPC client's terminal. No pairing file is needed.

Local state defaults to `$XDG_STATE_HOME/anymone-rpc-client`, or `~/.local/state/anymone-rpc-client`. Override it with `--state-dir`. Identity and authentication token are created automatically. Without `--remote`, discovery and response reading start immediately; a later Kohaku `anymone connect` prompts for the phone in the RPC client's terminal. After disconnecting, restart Remote on the phone to obtain a fresh code before connecting again.

For automation only, pass `--remote-pairing FILE` (`--pairing FILE` remains an alias). Pairing files are never loaded implicitly.

The client writes `connection.json` for Kohaku:

```sh
kohaku anymone setup
kohaku --anymone-profile anymone.json anymone connect
```

For a custom state directory, use `anymone setup --connection /path/to/state/connection.json`. Select `--execution service/route` or `--bundler service/route` if several providers are available.

An explicit configuration is also supported with `serve --config client.json`:

```json
{
  "broker": {
    "services": {
      "provider_a": { "service_identity": [], "signed": {} },
      "provider_b": { "service_identity": [], "signed": {} }
    },
    "feed_mirrors": ["https://feed.example"],
    "listen": "127.0.0.1:8546",
    "token": "client-token.txt",
    "database": "operations.sqlite",
    "session_seconds": 3600
  },
  "remote_session": {
    "bootstrap": "bootstrap.toml",
    "remote": "discover"
  }
}
```

Replace each service entry with its pinned 32-byte identity and signed descriptor from the service's `GET /descriptor`. Service names are local aliases; descriptors have distinct Anymone tags and share a network, chain and response feed. Each service can handle both reads and submissions. The remote-session backend handles pairing and attestation policy; the RPC application adds no attestation-mode selector.

```sh
RAYON_NUM_THREADS=8 cargo run -j 8 -p anymone-rpc-client -- serve --config client.json
```

The application installs the remote backend before opening upload pipes. Wallet keys, transaction construction, signing, hash checks and receipt polling remain in Kohaku.

Authenticated loopback endpoints:

- `POST /rpc/:service/:route`: forward a complete JSON-RPC request or batch to a selected provider and upstream route.
- `GET /status`: chain, provider routes, response-reader deadline and upload-session status.
- `POST /session/connect`: connect the upload session and start the response reader if needed.
- `POST /session/disconnect`: disconnect upload; response reading continues until its deadline.
- `GET /operations/:id`: saved response status.
- `GET /operations/:id/capability` and `/response`: portable decryption capability and ciphertext export.

Supply a bearer-token file with at least 32 characters and restrict access to it. Requests require the configured loopback Host and reject browser Origin headers.

To obtain independent answers, send the same read to `/rpc/provider_a/execution` and `/rpc/provider_b/execution`. Each has its own operation and authenticated response. The client does not vote, merge answers or automatically fan out submissions.

Kohaku selects the client through `--anymone-profile`:

```json
{
  "endpoint": "http://127.0.0.1:8546",
  "tokenFile": "client-token.txt",
  "routes": {
    "execution": "provider_a/execution",
    "bundler": "provider_a/pimlico"
  }
}
```

A route is `service/upstream-route`. Existing Viem and Pimlico clients use these endpoints. For custom EntryPoints, the optional `entryPoints` map associates lowercase addresses with Viem EntryPoint versions.

The response reader starts independently of mobile pairing. Failed or malformed epoch downloads consume scheduled slots and retry without advancing the cursor. Clients fetch whole variable-size epochs, including when they have no pending operations. Each response is one encrypted packet carrying a service signature; the feed has no consensus or completeness guarantee.

Exported ciphertext can be decrypted without a phone:

```sh
anymone-rpc-client decrypt --capability capability.json --response response.bin
```

Capabilities bind the service, request, chain and delivery context. The decoder enforces expiry. Independent network retrieval also requires full-epoch downloads on a fixed schedule to hide which response is being read. Response PIR remains a future retrieval feature.

The protocol is unreleased and uses version 0.
