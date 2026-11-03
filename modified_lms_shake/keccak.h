
#ifndef KECCAK_H
#define KECCAK_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE256_RATE 136

typedef struct {
    uint64_t state[25];
    size_t position;
} shake256_ctx;

void shake256_init(shake256_ctx *ctx);

void shake256_update(shake256_ctx *ctx,
                     const uint8_t *data,
                     size_t data_len);

void shake256_final(shake256_ctx *ctx,
                    uint8_t *out,
                    size_t out_len);

void shake256(const uint8_t *data, size_t data_len,
              uint8_t *out, size_t out_len);

#endif
