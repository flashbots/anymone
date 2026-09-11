# Anonymous Ethereum RPC forwarding

See the [local demo and remote client guide](demo.md) for running this service
with the observer demo and connecting through discovery and Kohaku.

The service forwards reads and transaction submissions to configured execution nodes and existing ERC-4337 bundlers. Kohaku prepares and signs transactions with its existing Viem and bundler integration.

Each named upstream route has an endpoint and an explicit method list. A route can handle reads and submissions:

```json
{
  "routes": {
    "execution": {
      "endpoint": "http://127.0.0.1:8545",
      "methods": ["eth_chainId", "eth_getBalance", "eth_call", "eth_sendRawTransaction"]
    },
    "pimlico": {
      "endpoint": "https://public.pimlico.io/v2/1/rpc",
      "methods": ["eth_sendUserOperation", "eth_estimateUserOperationGas", "eth_getUserOperationReceipt", "pimlico_getUserOperationGasPrice"]
    }
  }
}
```

Administrative and signing methods are rejected. Add the estimation, paymaster and receipt methods your existing client uses to the route allowlist.

Run with:

```sh
RAYON_NUM_THREADS=8 cargo run -j 8 -p anymone-eth-service -- service --config service.json
```

The service configuration contains:

| Field | Purpose |
|---|---|
| `bootstrap` | Anymone bootstrap file, including the service identity path |
| `chain`, `tag` | Ethereum chain ID and unique service tag |
| `network` | Optional genesis hash assertion; derived from bootstrap governance when omitted |
| `limits` | `ServiceLimits`: request/response bytes, batch size, log range and lifetime |
| `feed` | Shared response-feed descriptor |
| `expires_at` | Signed descriptor expiry, in Unix seconds |
| `signing_key`, `request_key` | Response signing and HPKE private-key files |
| `database` | One SQLite database for operations, submission intents and pending publications |
| `routes` | Upstream routes as shown above |
| `listen` | Address serving `GET /descriptor` |
| `descriptor_url` | Public URL of `GET /descriptor`, advertised through service registration |
| `feed_mirrors` | Public response-feed base URLs, included in the signed descriptor |
| `board_endpoint`, `board_token` | Response-board URL and writer bearer-token file |

The service derives its public keys, identity and route list and signs the descriptor at startup. The committee includes its registered descriptor URL in the signed network configuration. Clients discover the descriptor and verify it against the service's committee-authorized identity. See `ServiceConfig` in `src/main.rs` for the exact schema. Key files contain 32 raw bytes or 64 hexadecimal characters. Keep upstream credentials on the service.

Enable the public discovery API on relays:

```sh
anymone-node run --config relay.toml --role relay --rpc-listen 0.0.0.0:8080 --rpc-url https://node.example
```

The relay's existing signed registration carries its RPC URL. `network.stream_listen` must name a client-reachable address. A bootnode can expose the same `GET /network` API with `anymone-node bootnode --config bootnode.toml --rpc-listen 0.0.0.0:8080`. The endpoint returns genesis and the existing committee-signed configuration. A reverse proxy can provide HTTPS; local demos can use loopback HTTP URLs.

For example, set `descriptor_url` to `https://rpc-service.example/descriptor` and `feed_mirrors` to `["https://feed.example"]`. These are public reader endpoints; `board_endpoint` and `board_token` remain the service's writer connection.

The library exposes shared wire types and cryptography. Server execution, forwarding, storage and HTTP modules belong to the service binary. The desktop RPC client imports the shared library; the server has no remote-session dependency.

Batches remain intact during anonymous upload. The service forwards each call, preserves upstream results and errors, and restores JSON-RPC IDs. Submission deduplication uses the chain, route, method and parameters, excluding the JSON-RPC ID. Intent is persisted before network I/O. Saved replies are reused; unresolved intents return `-32098` and are never automatically resent. Journal capacity is 100,000 distinct submissions and requires an operational retention policy.

## Response feed

`board --config board.json` runs the common encrypted feed. Its configuration has `feed`, `database`, `listen`, and `writers`, a map of writer names to `{ "token": "writer-token.txt", "quota_bytes": 1048064 }`. Writer tokens contain at least 32 characters.

The feed descriptor contains only `feed` (32-byte identifier), `genesis_time`, `epoch_seconds`, `max_epoch_bytes`, and `retained_epochs`. Every provider in a client profile uses the same feed.

Services persist one signed, encrypted packet per response before posting it to `POST /responses/:epoch`. Retries reuse identical bytes. Once an epoch closes, `GET /epochs/:epoch` serves its whole response packets, ordered by locator. Empty epochs contain an empty list. The byte limit bounds resource use; responses have no padding or chunking.

Readers fetch complete epochs on a fixed schedule and match/decrypt responses locally. Mirrors can cache complete epochs; individual-response retrieval is not exposed.

Each Anymone service signs its own answer, bound to the request and route. Different providers may return different answers. The feed provides no consensus or guarantee of correctness or completeness. Clients authenticate each answer independently.

Response PIR is future work for privately retrieving individual encrypted responses.

The protocol is unreleased and uses version 0. The endpoint fields change registration, configuration and descriptor encoding; upgrade committee, nodes, services and clients together. Mobile attestation is handled by the separate remote-session implementation.
