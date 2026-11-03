
#include "config.h"
#include "keccak.h"
#include <stdint.h>
#include <stddef.h>

void hash_shake256(const uint8_t *prefix,
                   size_t prefix_len,
                   const uint8_t *data,
                   size_t data_len,
                   uint8_t *out)
{
    shake256_ctx ctx;

    if (out == NULL ||
        (prefix == NULL && prefix_len != 0) ||
        (data == NULL && data_len != 0)) {
        return;
    }

    shake256_init(&ctx);

    /* Absorber el prefijo. */
    shake256_update(&ctx, prefix, prefix_len);

    /* Continuar absorbiendo los datos, sin reiniciar SHAKE. */
    shake256_update(&ctx, data, data_len);

    /* Aplicar padding y generar HASH_LEN bytes. */
    shake256_final(&ctx, out, HASH_LEN);
}
