// Copyright (c) 2026
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_TEST_CONTROLS_H
#define BITCOIN_TEST_UTIL_TEST_CONTROLS_H

#include <boost/test/unit_test.hpp>

#include <cstdlib>

namespace testutil {

inline bool EnvVarEnabled(const char* name)
{
    const char* env = std::getenv(name);
    return env && env[0] && env[0] != '0';
}

inline bool WalletTestsEnabled()
{
    return EnvVarEnabled("TIDECOIN_RUN_WALLET_TESTS");
}

} // namespace testutil

// Skip wallet-heavy test cases unless explicitly enabled.
//
// Note: Use this at the top of individual test cases (not in fixtures), so
// selecting a test with --run_test still works when enabled, and doesn't burn
// time when disabled.
#define REQUIRE_WALLET_TESTS_ENABLED()                                        \
    do {                                                                     \
        if (!testutil::WalletTestsEnabled()) {                               \
            BOOST_TEST_MESSAGE(                                              \
                "Wallet tests are disabled by default; set "                 \
                "TIDECOIN_RUN_WALLET_TESTS=1 to enable.");                   \
            BOOST_CHECK(true);                                               \
            return;                                                          \
        }                                                                    \
    } while (0)

#endif // BITCOIN_TEST_UTIL_TEST_CONTROLS_H

