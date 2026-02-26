# tor-bootstrap-helper

A Deno server that fetches the current Tor network consensus and all associated microdescriptors from directory authorities, packages them into a store-only ZIP, and serves it over HTTP.

Intended to help Tor clients bootstrap faster by providing a pre-fetched snapshot of the network state.

## Usage

```sh
deno run --allow-net --unstable-kv main.ts
```

The server starts on port 8080 (falls back to 8081, 8082, ... if in use).

`GET /` returns `tor-bootstrap.zip` containing:

- `cached-microdesc-consensus` — the full microdescriptor consensus
- `cached-microdescs.new` — all microdescriptors referenced by the consensus

The ZIP uses store-only compression (level 0) so contents can be read without decompression.

## How it works

1. On startup, fetches the latest `consensus-microdesc` from Tor directory authorities (bastet, longclaw, maatuska, tor26)
2. Extracts all microdescriptor digests from the consensus
3. Fetches microdescriptors in batches of 92, with 5 concurrent workers
4. Caches individual microdescriptors in Deno KV (keyed by SHA-256 digest, expires after 7 days)
5. Packages everything into a store-only ZIP and serves it at `/`
6. Automatically rebuilds when the consensus `valid-until` time passes

## Authority fetch resilience

- Authorities are tried in random order
- 2s timeout for initial HTTP response, 60s for body download
- Automatic decompression of `deflate`/`gzip` responses (Tor authorities send zlib-wrapped deflate)
- Response validation (consensus must start with `network-status-version`, microdescs must contain `-----BEGIN` and no `<html`)
- Each authority is tried up to 3 full rounds before giving up

## Requirements

- [Deno](https://deno.land) v2+