#ifndef TIDECOIN_RANDOMBYTES_H
#define TIDECOIN_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int randombytes(uint8_t *buf, size_t n);

#ifdef __cplusplus
}
#endif

#endif
