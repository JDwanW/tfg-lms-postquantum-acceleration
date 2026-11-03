
    #include "keccak.h"
    #include <string.h>

    static const uint64_t round_constants[24] = {
        UINT64_C(0x0000000000000001),
        UINT64_C(0x0000000000008082),
        UINT64_C(0x800000000000808A),
        UINT64_C(0x8000000080008000),
        UINT64_C(0x000000000000808B),
        UINT64_C(0x0000000080000001),
        UINT64_C(0x8000000080008081),
        UINT64_C(0x8000000000008009),
        UINT64_C(0x000000000000008A),
        UINT64_C(0x0000000000000088),
        UINT64_C(0x0000000080008009),
        UINT64_C(0x000000008000000A),
        UINT64_C(0x000000008000808B),
        UINT64_C(0x800000000000008B),
        UINT64_C(0x8000000000008089),
        UINT64_C(0x8000000000008003),
        UINT64_C(0x8000000000008002),
        UINT64_C(0x8000000000000080),
        UINT64_C(0x000000000000800A),
        UINT64_C(0x800000008000000A),
        UINT64_C(0x8000000080008081),
        UINT64_C(0x8000000000008080),
        UINT64_C(0x0000000080000001),
        UINT64_C(0x8000000080008008)
    };

    static const unsigned int rotation_constants[24] = {
        1, 3, 6, 10, 15, 21, 28, 36,
        45, 55, 2, 14, 27, 41, 56, 8,
        25, 43, 62, 18, 39, 61, 20, 44
    };

    static const unsigned int permutation_indices[24] = {
        10, 7, 11, 17, 18, 3, 5, 16,
        8, 21, 24, 4, 15, 23, 19, 13,
        12, 2, 20, 14, 22, 9, 6, 1
    };

    static uint64_t rotate_left64(uint64_t value, unsigned int shift)
    {
        return (value << shift) | (value >> (64 - shift));
    }

    static void keccak_f1600(uint64_t state[25])
    {
        uint64_t column[5];
        uint64_t t;

        for (unsigned int round = 0; round < 24; round++) {

            /* Theta */
            for (unsigned int x = 0; x < 5; x++) {
                column[x] = state[x]
                          ^ state[x + 5]
                          ^ state[x + 10]
                          ^ state[x + 15]
                          ^ state[x + 20];
            }

            for (unsigned int x = 0; x < 5; x++) {
                uint64_t d = column[(x + 4) % 5]
                           ^ rotate_left64(
                                 column[(x + 1) % 5], 1);

                for (unsigned int y = 0; y < 25; y += 5) {
                    state[x + y] ^= d;
                }
            }

            /* Rho y Pi */
            t = state[1];

            for (unsigned int i = 0; i < 24; i++) {
                unsigned int j = permutation_indices[i];
                uint64_t tmp = state[j];

                state[j] = rotate_left64(
                    t, rotation_constants[i]);

                t = tmp;
            }

            /* Chi */
            for (unsigned int y = 0; y < 25; y += 5) {
                for (unsigned int x = 0; x < 5; x++) {
                    column[x] = state[y + x];
                }

                for (unsigned int x = 0; x < 5; x++) {
                    state[y + x] =
                        column[x] ^
                        ((~column[(x + 1) % 5]) &
                           column[(x + 2) % 5]);
                }
            }

            /* Iota */
            state[0] ^= round_constants[round];
        }
    }

    static void xor_byte(uint64_t state[25],
                         size_t position, uint8_t value)
    {
        state[position / 8] ^=
            (uint64_t)value << (8 * (position % 8));
    }

    static uint8_t read_byte(const uint64_t state[25],
                             size_t position)
    {
        return (uint8_t)(
            state[position / 8] >> (8 * (position % 8))
        );
    }

    void shake256_init(shake256_ctx *ctx)
    {
        memset(ctx->state, 0, sizeof(ctx->state));
        ctx->position = 0;
    }


    void shake256_update(shake256_ctx *ctx,
                     const uint8_t *data,
                     size_t data_len)
    {
    if (ctx == NULL || (data == NULL && data_len != 0)) {
        return;
    }

    while (data_len > 0) {
        size_t take = SHAKE256_RATE - ctx->position;

        if (take > data_len) {
            take = data_len;
        }

        for (size_t i = 0; i < take; i++) {
            xor_byte(ctx->state, ctx->position + i, data[i]);
        }

        ctx->position += take;
        data += take;
        data_len -= take;

        if (ctx->position == SHAKE256_RATE) {
            keccak_f1600(ctx->state);
            ctx->position = 0;
        }
    }
}

    void shake256_final(shake256_ctx *ctx,
                        uint8_t *out,
                        size_t out_len)
    {
        if (ctx == NULL || (out == NULL && out_len != 0)) {
            return;
        }

        /* Padding de SHAKE256 */
        xor_byte(ctx->state, ctx->position, 0x1F);
        xor_byte(ctx->state, SHAKE256_RATE - 1, 0x80);

        keccak_f1600(ctx->state);
        ctx->position = 0;

        /* Extracción de la salida XOF */
        for (size_t i = 0; i < out_len; i++) {
            if (ctx->position == SHAKE256_RATE) {
                keccak_f1600(ctx->state);
                ctx->position = 0;
            }

            out[i] = read_byte(ctx->state, ctx->position);
            ctx->position++;
        }
    }

    /* Interfaz de una sola llamada, por compatibilidad. */
    void shake256(const uint8_t *data, size_t data_len,
                  uint8_t *out, size_t out_len)
    {
        shake256_ctx ctx;

        if (out == NULL && out_len != 0) {
            return;
        }

        if (data == NULL && data_len != 0) {
            return;
        }

        shake256_init(&ctx);
        shake256_update(&ctx, data, data_len);
        shake256_final(&ctx, out, out_len);
    }
