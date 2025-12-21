// Copyright (c) 2024-present The Tidecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/yespower/tidecoin_pow.h>

#include <crypto/yespower/yespower.h>

bool TidecoinYespowerHash(std::span<const unsigned char> input, uint256& out)
{
    static const yespower_params_t yespower_tidecoin = {
        YESPOWER_1_0,
        2048,
        8,
        nullptr,
        0,
    };

    static_assert(sizeof(yespower_binary_t) == uint256::size());
    static_assert(alignof(yespower_binary_t) == 1);

    auto* out_ptr = reinterpret_cast<yespower_binary_t*>(out.begin());
    if (yespower_tls(input.data(), input.size(), &yespower_tidecoin, out_ptr) != 0) {
        return false;
    }
    return true;
}
