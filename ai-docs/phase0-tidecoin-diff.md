# Phase 0: Tidecoin vs Current Repo Differences

## Repos and Roles
- Current repo (target): `/home/yaroslav/dev/tidecoin/tidecoin`
- Old Tidecoin (Falcon-512 reference): `/home/yaroslav/dev/tidecoin/oldtidecoin/tidecoin`
- Unfinished Tidecoin-to-Bitcoin upgrade: `/home/yaroslav/dev/tidecoin/newtidecoin`

Notes:
- `newtidecoin` matches `oldtidecoin` for chainparams and PoW hashing, but has a
  different `chainparamsbase` layout and ports.

## Chainparams: Main/Test/Regtest
Source: `oldtidecoin` and `newtidecoin` chainparams are in
`/home/yaroslav/dev/tidecoin/oldtidecoin/tidecoin/src/chainparams.cpp` and
`/home/yaroslav/dev/tidecoin/newtidecoin/src/kernel/chainparams.cpp`.
Current repo chainparams are in `/home/yaroslav/dev/tidecoin/tidecoin/src/kernel/chainparams.cpp`.

### Mainnet (old/new Tidecoin vs current)
- Genesis:
  - Tidecoin: nTime 1609074580, nNonce 11033477, nBits 0x2001ffff, hash 0x480ecc76...
  - Current: Bitcoin genesis (nTime 1231006505, nNonce 2083236893, nBits 0x1d00ffff).
- Subsidy/activations:
  - Tidecoin: nSubsidyHalvingInterval 262800; BIP34/65/66 height 1; SegWit always active.
  - Current: Bitcoin heights for BIP34/65/66/CSV/SegWit.
- PoW params:
  - Tidecoin: powLimit 0x01ffff..., spacing 60s, timespan 5 days, window 8064, threshold 6048.
  - Current: powLimit 0x00000000ffff..., spacing 10min, timespan 2 weeks, window 2016, threshold 1815 (90%).
- Networking:
  - Tidecoin: pchMessageStart ec fa ce a5, default P2P port 8755, seeds `seed.tidecoin.co`, `tidecoin.ddnsgeek.com`, `tidecoin.theworkpc.com`.
  - Current: Bitcoin message start f9 be b4 d9, P2P port 8333, Bitcoin DNS seeds.
- Addressing:
  - Tidecoin: base58 PUBKEY 33, SCRIPT 70, SCRIPT_ADDRESS2 65, SECRET 125; bech32 hrp `tbc`.
  - Current: base58 PUBKEY 0, SCRIPT 5, SECRET 128; bech32 hrp `bc`.

### Testnet
- Genesis:
  - Tidecoin: nTime 1609074580, nNonce 13027434, nBits 0x2001ffff, hash 0xc94f901c...
  - Current: Bitcoin testnet genesis (nTime 1296688602, nNonce 414098458, nBits 0x1d00ffff).
- PoW params:
  - Tidecoin: spacing 60s, timespan 5 days, allow min-difficulty true.
  - Current: spacing 10min, timespan 2 weeks, allow min-difficulty true (testnet).
- Networking:
  - Tidecoin: pchMessageStart fc a5 b7 e6, P2P port 18755, seed `tidetest.ddnsgeek.com`.
  - Current: Bitcoin testnet message start 0b 11 09 07, P2P port 18333.
- Addressing:
  - Tidecoin: base58 PUBKEY 92, SCRIPT 132, SCRIPT_ADDRESS2 127, SECRET 180; bech32 hrp `ttbc`.
  - Current: base58 PUBKEY 111, SCRIPT 196, SECRET 239; bech32 hrp `tb`.

### Regtest
- Genesis:
  - Tidecoin: nTime 1609074580, nNonce 12350701, nBits 0x207fffff, hash 0xd71ebc33...
  - Current: Bitcoin regtest genesis (nTime 1296688602, nNonce 2, nBits 0x207fffff).
- PoW params:
  - Tidecoin: spacing 60s, timespan 24h, allow min-difficulty true, no retargeting true, window 144.
  - Current: spacing 10min, timespan 24h, allow min-difficulty true, no retargeting true, window 144.
- Networking:
  - Tidecoin: pchMessageStart ba ce 3f da, P2P port 18778.
  - Current: Bitcoin regtest message start fa bf b5 da, P2P port 18444.
- Addressing:
  - Tidecoin: base58 PUBKEY 117, SCRIPT 186, SCRIPT_ADDRESS2 122, SECRET 15; bech32 hrp `rtbc`.
  - Current: base58 PUBKEY 111, SCRIPT 196, SECRET 239; bech32 hrp `bcrt`.

## RPC Ports and Base Chain Params
- Old Tidecoin base RPC ports are defined in `/home/yaroslav/dev/tidecoin/oldtidecoin/tidecoin/src/chainparamsbase.cpp`:
  - main 7585, test 17585, regtest 17595.
- New Tidecoin base RPC ports are defined in `/home/yaroslav/dev/tidecoin/newtidecoin/src/chainparamsbase.cpp`:
  - main 8755, test 18755, regtest 18443.
- Current repo base RPC ports are in `/home/yaroslav/dev/tidecoin/tidecoin/src/chainparamsbase.cpp`:
  - main 8332, testnet 18332, regtest 18443.

## PoW Hashing and Difficulty
Source: `oldtidecoin` PoW hash is in `/home/yaroslav/dev/tidecoin/oldtidecoin/tidecoin/src/primitives/block.cpp`
and `newtidecoin` in `/home/yaroslav/dev/tidecoin/newtidecoin/src/primitives/block.cpp`. Current repo has no
`GetPoWHash` and uses header hash in `/home/yaroslav/dev/tidecoin/tidecoin/src/primitives/block.cpp`.

- Tidecoin uses yespower:
  - `GetPoWHash()` computes yespower (YESPOWER_1_0, N=2048, r=8).
  - Consensus PoW checks call `GetPoWHash()` in old/new validation paths.
- Current repo uses the standard header hash (double-SHA256 via `GetHash()`).

Difficulty retarget differences:
- Tidecoin `GetNextWorkRequired()` adjusts the lookback to avoid a 51% attack edge
  case: it uses a full-period lookback except for the very first retarget
  after genesis, where it uses `interval - 1` (Art Forz rule).
- Tidecoin `CalculateNextWorkRequired()` applies a one-bit overflow guard:
  shift right before scaling if the target would overflow, then shift back.
  - File: `/home/yaroslav/dev/tidecoin/oldtidecoin/tidecoin/src/pow.cpp`
- Current repo uses ancestor-based retargeting and includes `PermittedDifficultyTransition()`
  and BIP94 rules.
  - File: `/home/yaroslav/dev/tidecoin/tidecoin/src/pow.cpp`

## Policy Defaults
Source: `oldtidecoin` policy is in `/home/yaroslav/dev/tidecoin/oldtidecoin/tidecoin/src/policy/policy.h`,
`newtidecoin` policy in `/home/yaroslav/dev/tidecoin/newtidecoin/src/policy/policy.h`, and current repo
policy in `/home/yaroslav/dev/tidecoin/tidecoin/src/policy/policy.h`.

Key differences (old/new Tidecoin vs current):
- `DEFAULT_BLOCK_MAX_WEIGHT`: `MAX_BLOCK_WEIGHT - 4000` (Tidecoin) vs `MAX_BLOCK_WEIGHT` (current).
- `DEFAULT_BLOCK_MIN_TX_FEE`: 1000 (Tidecoin) vs 1 (current).
- `MAX_STANDARD_TX_WEIGHT`: 800000 (Tidecoin) vs 400000 (current).
- `MIN_STANDARD_TX_NONWITNESS_SIZE`: 82 (Tidecoin) vs 65 (current).
- `DUST_RELAY_TX_FEE`: 30000 (Tidecoin) vs 3000 (current).
- `DEFAULT_MIN_RELAY_TX_FEE`: 1000 (Tidecoin) vs 100 (current).
- Witness stack limits: Tidecoin uses 1000-byte stack item and 100000-byte script
  for P2WSH; current uses 80-byte items and 3600-byte scripts.
- Tidecoin policy retains older standardness flags (and in `newtidecoin` still
  includes tapscript-related constants), while current policy reflects Bitcoin 0.30.

## Other Notable Deltas
- Base58 `SCRIPT_ADDRESS2` exists in old/new Tidecoin (`key_io.cpp` and chainparams)
  and is absent in the current repo.
  - Files: `/home/yaroslav/dev/tidecoin/oldtidecoin/tidecoin/src/key_io.cpp`,
    `/home/yaroslav/dev/tidecoin/oldtidecoin/tidecoin/src/chainparams.h`,
    `/home/yaroslav/dev/tidecoin/newtidecoin/src/key_io.cpp`,
    `/home/yaroslav/dev/tidecoin/newtidecoin/src/kernel/chainparams.h`.
