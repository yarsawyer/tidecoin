// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ECC_CONTEXT_H
#define BITCOIN_ECC_CONTEXT_H

class ECC_Context
{
public:
    ECC_Context() = default;
    ~ECC_Context() = default;
};

inline bool ECC_InitSanityCheck()
{
    return true;
}

#endif // BITCOIN_ECC_CONTEXT_H
