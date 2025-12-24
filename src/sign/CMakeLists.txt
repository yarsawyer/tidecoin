# Copyright (c) 2024-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(bitcoin_falcon STATIC EXCLUDE_FROM_ALL
  fips202.c
  randombytes.cpp
  falcon-512/codec.c
  falcon-512/common.c
  falcon-512/fft.c
  falcon-512/fpr.c
  falcon-512/keygen.c
  falcon-512/pqclean.c
  falcon-512/rng.c
  falcon-512/sign.c
  falcon-512/vrfy.c
)

target_link_libraries(bitcoin_falcon
  PRIVATE
    core_interface
    bitcoin_util
)

target_include_directories(bitcoin_falcon
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
