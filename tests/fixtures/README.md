# Test fixtures

`AstatineMiner.json` contains test-only creation bytecode produced from a private upstream EVM source repository pinned at commit `80e8f7cbeb21b18bc5f7475d8b751c9d9e8fb9d1`, using Solidity 0.8.28, the Shanghai EVM, optimizer enabled with 200 runs, and `bytecode_hash = "none"`. `AstatineGenesisCoordinator.json` contains test-only creation bytecode produced from a private upstream Genesis Coordinator source repository pinned at commit `c710b4d7add5f10de326487d0ff851eb926499c6`, built with that repository's pinned Foundry settings. `MockAST.json` contains a test-only mock produced from the separately pinned private upstream EVM source commit `eb9ea498ed4da10536cd6b4d5d8b55cf38e8aa30`. These fixtures do not change public contracts and are not included in release archives.

The pinned upstream `AstatineMiner` and `AstatineGenesisCoordinator` source files declare Apache-2.0. The pinned `MockAST` source file declares MIT and is never deployed to a public network. Both pinned EVM source trees reference OpenZeppelin Contracts commit `dbb6104ce834628e473d2173bbc9d47f81a9eec3`, which is MIT licensed; its license and copyright notice are reproduced in `OPENZEPPELIN_LICENSE.txt`. These SPDX declarations do not replace verification of upstream redistribution rights or any applicable NOTICE obligations.

`synthetic-injective-virtual-receipt.json` is a synthetic RPC receipt fixture. It reproduces the Injective EVM receipt shape with three EVM event logs and five virtual Cosmos logs so `src/rpc.rs` can prove that virtual logs do not invalidate signed transaction inclusion. Transaction-specific hashes, addresses and log payloads are synthetic; the virtual-log address and ERC-20 Transfer topic are protocol/interface constants also present in the former capture. It contains no contract bytecode and is compiled only into `cfg(test)` through `include_str!`.

`PROVENANCE.json` records the exact fixture bytes, hashes, recorded or declared compiler settings, runtime purpose, consumers, license status and regeneration limits. `support/verify-fixture-provenance.py` rechecks that inventory offline.

## Rights and notice checklist

Publication of this repository or a release archive stays BLOCKED until every item is resolved and recorded in `rights_review.notice_checklist` of `PROVENANCE.json`. No automated check can establish ownership, authority or NOTICE applicability; these actions need a human decision.

- [ ] **RIGHTS-01** — Record written first-party ownership of `AstatineMiner` and `AstatineGenesisCoordinator` and confirm the owner can license them for redistribution. Owner attestation alone is not independent verification.
- [ ] **RIGHTS-02** — Decide whether Apache-2.0 NOTICE propagation applies to each distributed artifact. The contract fixtures are not release-archive members, so any obligation follows source redistribution of the fixtures rather than the miner binary.
- [ ] **RIGHTS-03** — If the two first-party contract fixtures remain in the public source tree, add the Apache-2.0 license text and a copyright statement for them, or remove those fixtures from the public tree.
- [ ] **RIGHTS-04** — Confirm authorship and redistribution authority for `MockAST` and keep the OpenZeppelin MIT notice with any redistribution of it.
- [ ] **RIGHTS-05** — Record the final decision here and in `PROVENANCE.json` before publishing the repository or a release archive.

The OpenZeppelin license identity is verified and reproduced; that resolves the license text only, not first-party rights or notice applicability.

To regenerate the bytecode fixtures from isolated checkouts of the exact source commits (keep adjacent contract worktrees untouched):

```sh
# ASTATINE_EVM_ROOT is an isolated checkout at 80e8f7cbeb21b18bc5f7475d8b751c9d9e8fb9d1
forge build --root "$ASTATINE_EVM_ROOT"
python3 support/update-evm-test-fixtures.py "$ASTATINE_EVM_ROOT"
# ASTATINE_COORDINATOR_ROOT is an isolated checkout at c710b4d7add5f10de326487d0ff851eb926499c6
forge build --root "$ASTATINE_COORDINATOR_ROOT" --out "$COORDINATOR_OUT" --cache-path "$COORDINATOR_CACHE" --no-lint src/AstatineGenesisCoordinator.sol
python3 support/update-genesis-coordinator-fixture.py "$ASTATINE_COORDINATOR_ROOT" --source-commit c710b4d7add5f10de326487d0ff851eb926499c6 --artifact "$COORDINATOR_OUT/AstatineGenesisCoordinator.sol/AstatineGenesisCoordinator.json"
```

The Rust integration tests deploy the bytecode fixtures to Anvil and exercise real local transactions, receipts, events, reward transfers, confirmations, and reorgs. Production binaries use only the pinned Testnet manifest and never load these files.

Regeneration requires access to the private pinned source repositories; a clone of this source tree cannot regenerate the bytecodes by itself. The inventory records the pre-existing fixture hashes; the fixtures were not regenerated for this inventory. First-party authorship of the Astatine contracts is owner-attested, not independently verified. NOTICE applicability remains unresolved; see `PROVENANCE.json` for the exact status.
