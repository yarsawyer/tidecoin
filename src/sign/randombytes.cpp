#include "randombytes.h"

#include "random.h"

#include <span>

int randombytes(uint8_t *buf, size_t n)
{
    if (n == 0) {
        return 0;
    }
    GetStrongRandBytes(std::span<unsigned char>(buf, n));
    return 0;
}
