// Copyright (c) 2024-present The Tidecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TIDECOIN_CRYPTO_YESPOWER_TIDECOIN_POW_H
#define TIDECOIN_CRYPTO_YESPOWER_TIDECOIN_POW_H

#include <span.h>
#include <uint256.h>

#include <cstddef>

bool TidecoinYespowerHash(std::span<const unsigned char> input, uint256& out);

#endif // TIDECOIN_CRYPTO_YESPOWER_TIDECOIN_POW_H
