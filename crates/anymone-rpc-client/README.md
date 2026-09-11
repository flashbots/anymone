# Anymone RPC client

A local JSON-RPC broker for anonymous uploads and encrypted responses.
Wallet construction and signing stay in Kohaku. See the [demo guide](../anymone-eth-service/demo.md)
for a complete local setup.

## Connect

```sh
RAYON_NUM_THREADS=8 anymone-rpc-client serve --bootnode 'https://seed.example#<genesis-hash>' --remote
```

Obtain the genesis hash independently from the network operator. Alternatively,
use `--genesis genesis.json`; later starts can reuse the stored genesis.
`--node-rpc` accepts a node discovery URL instead of a bootnode.

Start **Remote** on the phone and keep it foregrounded. Select it and enter its
eight-digit code in the client's terminal. Use `--remote IP:PORT` when discovery
is unavailable. After a desktop restart or disconnect, restart the phone host
and pair again. See [remote sessions](../anymone-remote-session/README.md).

State defaults to `$XDG_STATE_HOME/anymone-rpc-client` or
`~/.local/state/anymone-rpc-client`; override with `--state-dir`.
The client creates its identity, authentication token and `connection.json`.

```sh
kohaku anymone setup
kohaku --anymone-profile anymone.json anymone connect
```

For a custom state directory, pass `--connection /path/to/state/connection.json`
to setup. Select `--execution service/route` or `--bundler service/route` when
multiple routes are available. Explicit configuration uses `serve --config client.json`;
see [the configuration types](src/main.rs).

## Local API

Endpoints require bearer authentication and the configured loopback Host;
browser Origin headers are rejected.

- `POST /rpc/:service/:route`: submit a JSON-RPC request or batch.
- `GET /status`: routes and session status.
- `POST /session/connect`, `POST /session/disconnect`: control upload.
- `GET /operations/:id`: response status.
- `GET /operations/:id/capability`, `GET /operations/:id/response`: export decryption capability and ciphertext.

Response reading continues after upload disconnects, until its deadline.
Readers fetch whole feed epochs on a fixed schedule. Answers are authenticated
per service; there is no consensus or completeness guarantee.

```sh
anymone-rpc-client decrypt --capability capability.json --response response.bin
```

Use `--remote-pairing FILE` for automated pairing. See `--help` for other options.
