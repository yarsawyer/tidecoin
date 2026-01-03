// Copyright (c) 2024-present The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_KEYPATH_H
#define BITCOIN_UTIL_KEYPATH_H

#include <cstdint>
#include <string>
#include <vector>

/** Format a hardened-only keypath without the leading "m". */
std::string FormatKeypath(const std::vector<uint32_t>& path, bool hardened_suffix = true);

/** Write a hardened-only keypath string with a leading "m". */
std::string WriteKeypath(const std::vector<uint32_t>& path, bool hardened_suffix = true);

#endif // BITCOIN_UTIL_KEYPATH_H
