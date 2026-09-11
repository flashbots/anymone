# Ethereum RPC demo

Build from the workspace root:

```sh
RAYON_NUM_THREADS=8 cargo build --locked -j 8 \
  -p anymone-observer -p anymone-eth-service \
  -p anymone-rpc-client -p anymone-remote-session
```

Start the demo with a remote Ethereum execution RPC:

```sh
RAYON_NUM_THREADS=8 target/debug/anymone-observer demo \
  --output target/rpc-demo --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```

Wait for **RPC demo ready**. The command starts the network, Ethereum service,
response board, desktop RPC client and a software developer session. It creates
their configuration and reads the chain ID from the upstream. The output
directory must be fresh. The dashboard is at http://127.0.0.1:7000; child logs
are in the output directory.

In another terminal, connect a compatible Kohaku CLI:

```sh
kohaku anymone setup --connection target/rpc-demo/rpc-client/connection.json \
  --output target/rpc-demo/kohaku.json
kohaku --anymone-profile target/rpc-demo/kohaku.json anymone connect
kohaku --anymone-profile target/rpc-demo/kohaku.json anymone status
```

Use that profile with ordinary Kohaku commands, for example
`kohaku --anymone-profile target/rpc-demo/kohaku.json balances`.
Select a wallet on the service's chain; submissions require a funded account.
Wallet signing remains in Kohaku. Reads and signed submissions pass through
Anymone to the selected execution RPC.

Options on the demo command:

- `--rpc-url URL`: another remote execution RPC, or a separately running Anvil.
- `--pairing /path/to/pairing.json`: use a phone's remote-session export instead
  of the software host. Keep the phone app running and reachable from the desktop.
- `--bundler-url URL`: forward ERC-4337 calls to an existing bundler on the same
  chain. Kohaku discovers this route during setup.

The software session uses ordinary signing keys and provides no hardware
attestation. Phone attestation belongs to the remote-session implementation.
The Ethereum service and response board have no phone connection.

Ctrl-C stops the demo and its child processes. State and logs remain available.
Start another demo with a fresh output directory.

## Use an existing remote Anymone deployment

Start only the desktop client, using the operator's trusted discovery URL and
genesis hash:

```sh
RAYON_NUM_THREADS=8 anymone-rpc-client serve \
  --bootnode 'https://network.example/bootstrap#<genesis-hash>' \
  --pairing /path/to/pairing.json --state-dir rpc-client-state
kohaku anymone setup --connection rpc-client-state/connection.json --output anymone.json
kohaku --anymone-profile anymone.json anymone connect
```

Keep the client running; run the Kohaku commands in another terminal.
Discovery supplies relay streams, service descriptors and feed mirrors.
Alternatively pass `--genesis genesis.json` with an unpinned URL, or use
`--node-rpc` for an authorized node's discovery endpoint.

## Response reading

The desktop client fetches complete epochs on a fixed schedule and decrypts
responses independently of the phone. Feed size reveals aggregate traffic;
individual answers are signed, without a completeness or correctness proof.
Disconnecting the phone leaves the reader running until its session deadline.

An unknown submission outcome needs reconciliation, not automatic resubmission.
Use `kohaku --anymone-profile anymone.json anymone operation ID` to inspect it.
The client's operation API can export a decryption capability and response;
any holder can use `anymone-rpc-client decrypt --capability capability.json
--response response.bin` before expiry.
