# Multisig Tutorial (Tidecoin)

This tutorial shows a real Tidecoin multisig workflow using descriptor wallets and
PSBTs.

## Requirements

- Built binaries (`tidecoind`, `tidecoin-cli`)
- `jq`

## 1. Start a local regtest node

```bash
./build/bin/tidecoind -regtest -daemon
```

Set a CLI helper:

```bash
CLI="./build/bin/tidecoin-cli -regtest"
```

## 2. Create signer and multisig wallets

Create three signer wallets (private keys enabled):

```bash
for n in 1 2 3; do
  $CLI createwallet "participant_${n}"
done
```

Create a watch-only multisig wallet (blank + no private keys):

```bash
$CLI -named createwallet wallet_name="multisig_wallet_01" disable_private_keys=true blank=true
```

## 3. Collect pubkeys from each signer

For each participant, collect:

- one external pubkey (from `getnewaddress`)
- one internal/change pubkey (from `getrawchangeaddress`)

```bash
declare -a external_pubkeys
declare -a internal_pubkeys

for n in 1 2 3; do
  w="participant_${n}"

  ext_addr=$($CLI -rpcwallet="$w" getnewaddress)
  int_addr=$($CLI -rpcwallet="$w" getrawchangeaddress)

  ext_pub=$($CLI -rpcwallet="$w" getaddressinfo "$ext_addr" | jq -r '.pubkey')
  int_pub=$($CLI -rpcwallet="$w" getaddressinfo "$int_addr" | jq -r '.pubkey')

  external_pubkeys+=("$ext_pub")
  internal_pubkeys+=("$int_pub")
done
```

## 4. Build multisig descriptors (2-of-3)

Join pubkeys and create external/internal descriptors:

```bash
external_keys_csv=$(IFS=,; echo "${external_pubkeys[*]}")
internal_keys_csv=$(IFS=,; echo "${internal_pubkeys[*]}")

external_desc_raw="wsh(sortedmulti(2,${external_keys_csv}))"
internal_desc_raw="wsh(sortedmulti(2,${internal_keys_csv}))"

external_desc=$($CLI getdescriptorinfo "$external_desc_raw" | jq -r '.descriptor')
internal_desc=$($CLI getdescriptorinfo "$internal_desc_raw" | jq -r '.descriptor')
```

Import both descriptors into the watch-only wallet:

```bash
import_json=$(jq -nc \
  --arg ext "$external_desc" \
  --arg int "$internal_desc" \
  '[
     {"desc": $ext, "timestamp": "now", "internal": false, "active": false},
     {"desc": $int, "timestamp": "now", "internal": true,  "active": false}
   ]')

$CLI -rpcwallet="multisig_wallet_01" importdescriptors "$import_json"
```

Note: these are fixed-key (non-ranged) descriptors, so `active` is set to
`false`. We derive addresses directly from descriptor strings.

## 5. Derive receive/change addresses

```bash
receive_addr=$($CLI -rpcwallet="multisig_wallet_01" deriveaddresses "$external_desc" | jq -r '.[0]')
change_addr=$($CLI -rpcwallet="multisig_wallet_01" deriveaddresses "$internal_desc" | jq -r '.[0]')

echo "receive_addr=$receive_addr"
echo "change_addr=$change_addr"
```

## 6. Fund the multisig wallet

Mine spendable funds to `participant_1`, then send to the multisig receive address:

```bash
funding_addr=$($CLI -rpcwallet="participant_1" getnewaddress)
$CLI generatetoaddress 101 "$funding_addr" >/dev/null

$CLI -rpcwallet="participant_1" sendtoaddress "$receive_addr" 6.15
$CLI generatetoaddress 1 "$funding_addr" >/dev/null

$CLI -rpcwallet="multisig_wallet_01" getbalance
```

## 7. Create a PSBT from the multisig wallet

```bash
destination_addr=$($CLI -rpcwallet="participant_3" getnewaddress)

outputs=$(jq -nc --arg addr "$destination_addr" --argjson amount 1.0 '{($addr): $amount}')
options=$(jq -nc --arg change "$change_addr" '{changeAddress: $change, feeRate: 0.00010}')

funded_psbt=$($CLI -rpcwallet="multisig_wallet_01" -named \
  walletcreatefundedpsbt inputs='[]' outputs="$outputs" options="$options" | jq -r '.psbt')

$CLI -rpcwallet="multisig_wallet_01" analyzepsbt "$funded_psbt"
```

## 8. Sign with two participants (parallel signing)

Each signer signs the same PSBT independently:

```bash
psbt_1=$($CLI -rpcwallet="participant_1" walletprocesspsbt "$funded_psbt" | jq -r '.psbt')
psbt_2=$($CLI -rpcwallet="participant_2" walletprocesspsbt "$funded_psbt" | jq -r '.psbt')
```

Combine, finalize, and broadcast:

```bash
psbt_list=$(jq -nc --arg p1 "$psbt_1" --arg p2 "$psbt_2" '[ $p1, $p2 ]')

combined_psbt=$($CLI combinepsbt "$psbt_list")
final_hex=$($CLI finalizepsbt "$combined_psbt" | jq -r '.hex')

txid=$($CLI sendrawtransaction "$final_hex")
echo "broadcast txid=$txid"

$CLI generatetoaddress 1 "$funding_addr" >/dev/null
```

## 9. Alternative: sequential signing

Instead of signing in parallel and combining, sign in series:

```bash
step1=$($CLI -rpcwallet="participant_1" walletprocesspsbt "$funded_psbt")
psbt_a=$(echo "$step1" | jq -r '.psbt')

step2=$($CLI -rpcwallet="participant_2" walletprocesspsbt "$psbt_a")

# When complete=true, walletprocesspsbt includes final hex.
complete=$(echo "$step2" | jq -r '.complete')
echo "complete=$complete"
```

If `complete=true`, broadcast `step2.hex` directly:

```bash
seq_hex=$(echo "$step2" | jq -r '.hex // empty')
if [ -n "$seq_hex" ]; then
  $CLI sendrawtransaction "$seq_hex"
  $CLI generatetoaddress 1 "$funding_addr" >/dev/null
fi
```

## 10. Important Tidecoin notes

- This tutorial uses explicit PQ pubkeys in descriptors.
- `sortedmulti(...)` is recommended so key order does not affect script
  derivation.
- With fixed-key descriptors, receive/change addresses are derived from known
  descriptor strings.
- For production, each participant should protect signer-wallet backups and
  verify PSBT outputs before signing.
