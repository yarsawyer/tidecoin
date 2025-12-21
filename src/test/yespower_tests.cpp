// Copyright (c) 2024-present The Tidecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/yespower/tidecoin_pow.h>
#include <test/util/setup_common.h>

#include <array>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(yespower_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(yespower_tls_link_smoke_test)
{
    std::array<unsigned char, 80> input_zero{};
    std::array<unsigned char, 80> input_one{};
    input_one.back() = 1;

    uint256 out_zero;
    uint256 out_one;

    bool ret_zero = TidecoinYespowerHash(input_zero, out_zero);
    bool ret_one = TidecoinYespowerHash(input_one, out_one);

    BOOST_CHECK(ret_zero);
    BOOST_CHECK(ret_one);
    BOOST_CHECK(out_zero != out_one);
}

BOOST_AUTO_TEST_SUITE_END()
