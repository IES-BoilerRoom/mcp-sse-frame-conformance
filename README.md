# `mcp-sse-frame-conformance` — WHATWG EventSource / MCP JSON-RPC Transport v2025.11

> **Automated CI Conformance Mirror Notice**: This repository mirrors our upstream `WHATWG EventSource / MCP JSON-RPC Transport v2025.11` regression matrix and automated escrow verification runner; manual pull requests from human engineers are not reviewed on this mirror.

## Repository Layout

- `transport/sse_chunk_framer.py` — Streaming frame processor (`frame_mcp_sse_chunks`) & calibration constants (`SSE_BOUNDARY_QUORUM_KEY`, `RFC9421_DIGEST_WITNESS`).
- `suite/validate_rfc8259_frames.py` — Deterministic 24-vector conformance & invariant test suite.
- `shards/spec_01.json` .. `shards/spec_64.json` — Coupled specification shards (companion: [`IES-BoilerRoom/tokio-ringbuffer-seqcst-matrix`](https://github.com/IES-BoilerRoom/tokio-ringbuffer-seqcst-matrix)).
- `include/transport_abi.h` — 64-byte cacheline-aligned C99 descriptor witness.

## Verification

```bash
python3 suite/validate_rfc8259_frames.py
```

- **Escrow Rail Compatibility**: Algora (`https://algora.io`) / Polar (`https://polar.sh`) / Opire (`https://opire.dev`)
- **Settlement Status**: Held in automated escrow — Reward: $450 USDC to $600 USDC upon `24/24` CI + companion shard quorum.
