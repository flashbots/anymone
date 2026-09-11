# Ethereum RPC service

Forwards anonymous JSON-RPC requests to execution nodes and ERC-4337 bundlers.
Clients construct and sign transactions. Routes explicitly allow methods;
administrative and signing methods are rejected.

For a working setup, use the [demo guide](demo.md).

## Run

```sh
RAYON_NUM_THREADS=8 cargo run --locked -j 8 -p anymone-eth-service -- service --config service.json
RAYON_NUM_THREADS=8 cargo run --locked -j 8 -p anymone-eth-service -- board --config board.json
```

See [ServiceConfig and BoardConfig](src/main.rs) for the configuration schemas.
The service needs bootstrap configuration, upstream routes, signing and request
keys, a SQLite database, and a response board. Key files contain 32 raw bytes or
64 hexadecimal characters. Board writer-token files contain at least 32 characters.

Set `descriptor_url` and `feed_mirrors` to public reader URLs.
`board_endpoint` and `board_token` configure the service's writer connection.
Keep upstream credentials on the service.

Enable discovery on a relay:

```sh
anymone-node run --config relay.toml --role relay --rpc-listen 0.0.0.0:8080 --rpc-url https://node.example
```

Relay stream addresses must also be reachable by clients.

## Delivery

Submission intent is persisted before forwarding. Saved replies are reused;
unresolved submissions return `-32098` and are never automatically resent.
The journal holds 100,000 distinct submissions and needs a retention policy.

Services publish signed, encrypted replies to a shared response feed. Clients
download whole epochs on a fixed schedule and decrypt locally. All providers
must share the feed descriptor. The feed provides no consensus or completeness
guarantee.

Protocol version 0 is unreleased; upgrade committee, nodes, services and clients
together.
