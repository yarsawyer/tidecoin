# Notes

## PQ strict activation and PSBT analysis flags

- `SCRIPT_VERIFY_PQ_STRICT` is a consensus script flag activated at
  `nAuxpowStartHeight` (set in `GetBlockScriptFlags`).
- Mempool policy is forward-looking: when checking policy, we compare
  `next_height = tip + 1` against `nAuxpowStartHeight`. This avoids accepting
  legacy signatures right before activation that would be invalid in the next
  block.
- Wallet/PSBT analysis uses dynamic flags derived from tip+1 so UI/RPC analysis
  reflects the same rules as the next block:
  - `analyzepsbt` RPC computes flags from `tip + 1` and passes them into
    `AnalyzePSBT(psbtx, script_verify_flags)`.
  - Qt PSBT dialog does the same via `ClientModel::getNumBlocks()` + 1.
  - Wallet PSBT completeness checks and fee-bump input sizing also use the
    same tip+1 flag computation.
- `AnalyzePSBT(psbtx)` remains as a wrapper using
  `STANDARD_SCRIPT_VERIFY_FLAGS` to keep tests and fuzz targets stable.

Implementation rule of thumb:
`flags = STANDARD_SCRIPT_VERIFY_FLAGS; if (tip + 1 >= nAuxpowStartHeight) flags |= SCRIPT_VERIFY_PQ_STRICT;`
