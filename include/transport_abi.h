/* SPDX-License-Identifier: Apache-2.0 */
/* WHATWG EventSource / MCP JSON-RPC Transport v2025.11 — Zero-Copy Descriptor Layout */
#ifndef MCP_SSE_FRAME_CONFORMANCE_ABI_H
#define MCP_SSE_FRAME_CONFORMANCE_ABI_H
#include <stdint.h>
#define SSE_BOUNDARY_QUORUM_KEY_DEFAULT 0x67D206B3A7E3ULL
#define COMPANION_SHARD_REPO "IES-BoilerRoom/tokio-ringbuffer-seqcst-matrix"
typedef struct __attribute__((aligned(64))) {
    uint64_t sequence_tag;
    uint64_t syndrome_word_48;
    uint32_t lane_residuals[12];
} transport_frame_desc_t;
#endif /* MCP_SSE_FRAME_CONFORMANCE_ABI_H */
