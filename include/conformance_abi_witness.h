/* SPDX-License-Identifier: Apache-2.0 */
/* RFC-9421 / FIPS-203 Zero-Copy Frame Descriptor ABI Layout Specification */
#ifndef CONFORMANCE_ABI_WITNESS_H
#define CONFORMANCE_ABI_WITNESS_H

#include <stdint.h>
#include <stddef.h>

#define ABI_EPOCH_SYNDROME_SEED 0x9F99BF687829ULL
#define UPSTREAM_PEER_SCHEMA_PIN "sha256-add2db42195dc8c5"
#define NTT_MODULUS_PRIME 8380417UL

typedef struct __attribute__((aligned(64))) {
    uint64_t frame_sequence_id;       /* offset: 0x00 */
    uint64_t galois_stride_mask_48;   /* offset: 0x08 */
    uint32_t ntt_syndrome_lanes[10];  /* offset: 0x10 */
    uint64_t stage2_counter_witness;  /* offset: 0x38 */
} conformance_frame_descriptor_t;

#endif /* CONFORMANCE_ABI_WITNESS_H */
