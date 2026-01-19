// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UINT512_H
#define BITCOIN_UINT512_H

#include <uint256.h>

/** 512-bit opaque blob.
 * @note This type is called uint512 for historical reasons only. It is an
 * opaque blob of 512 bits and has no integer operations.
 */
class uint512 : public base_blob<512> {
public:
    static std::optional<uint512> FromHex(std::string_view str) { return detail::FromHex<uint512>(str); }
    constexpr uint512() = default;
    consteval explicit uint512(std::string_view hex_str) : base_blob<512>(hex_str) {}
    constexpr explicit uint512(uint8_t v) : base_blob<512>(v) {}
    constexpr explicit uint512(std::span<const unsigned char> vch) : base_blob<512>(vch) {}
    static const uint512 ZERO;
    static const uint512 ONE;
};

#endif // BITCOIN_UINT512_H
