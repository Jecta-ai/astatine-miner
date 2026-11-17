# Test fixtures

`AstatineMiner.json` contains test-only creation bytecode produced from a private upstream EVM source repository pinned at commit `80e8f7cbeb21b18bc5f7475d8b751c9d9e8fb9d1`, using Solidity 0.8.28, the Shanghai EVM, optimizer enabled with 200 runs, and `bytecode_hash = "none"`. `AstatineGenesisCoordinator.json` contains test-only creation bytecode produced from a private upstream Genesis Coordinator source repository pinned at commit `c710b4d7add5f10de326487d0ff851eb926499c6`, built with that repository's pinned Foundry settings. `MockAST.json` contains a test-only mock produced from the separately pinned private upstream EVM source commit `eb9ea498ed4da10536cd6b4d5d8b55cf38e8aa30`. These fixtures do not change public contracts and are not included in release archives.

The pinned upstream `AstatineMiner` and `AstatineGenesisCoordinator` source files declare Apache-2.0. The pinned `MockAST` source file declares MIT and is never deployed to a public network. Both pinned EVM source trees reference OpenZeppelin Contracts commit `dbb6104ce834628e473d2173bbc9d47f81a9eec3`, which is MIT licensed; its license and copyright notice are reproduced in `OPENZEPPELIN_LICENSE.txt`. The `MockAST` pinned source imports one OpenZeppelin component; the `AstatineGenesisCoordinator` pinned source declares zero direct OpenZeppelin imports. No OpenZeppelin code in `AstatineMiner` is asserted here.

Owner-authorized release intent for candidate `v0.1.0-testnet.1` is recorded by the project owner as documented in `rights_review.release_intent_authorization` of `PROVENANCE.json`. This is an owner decision on source and binary distribution intent; final release controls remain outstanding. The offline fixture inventory (fixture bytes and hashes) is unchanged; this update records the owner authorization and the technical NOTICE review evidence. Repository technical review determined NOTICE applicability; no legal conclusion or separate approval is asserted:

- `LICENSE-APACHE-2.0.txt` is the canonical Apache License 2.0 text. It covers the first-party `AstatineMiner` and `AstatineGenesisCoordinator` fixture bytecode, copyright `Copyright (c) 2026 emyrinj`.
- `LICENSE-MIT.txt` is the standard MIT text for `Copyright (c) 2026 emyrinj`. It covers the first-party `MockAST` fixture bytecode. MIT redistribution of `MockAST` reflects owner-authorized release intent by the project owner.
- `NOTICE` records the first-party Apache-2.0 and MIT attributions, retains the OpenZeppelin MIT notice for any fixture redistribution to which it applies, and records the technical NOTICE review finding that no separate upstream NOTICE file was found in the pinned contract fixture subtrees.
- The OpenZeppelin MIT notice in `OPENZEPPELIN_LICENSE.txt` (Copyright (c) 2016-2023 zOS Global Limited and contributors) is retained for any fixture redistribution to which it applies. This notice does not assert OpenZeppelin code in every fixture.

The contract fixtures remain excluded from binary archives (`release_archive_member` is false for every fixture). Release execution still requires external controls: the exact release tag, `main` CI, a protected environment, attestations, an immutable release, and no bypass of controls. No other tag or version, no mainnet or paid-operation risk acceptance, and no independent legal verification are authorized. Final release controls remain outstanding.

`synthetic-injective-virtual-receipt.json` is a synthetic RPC receipt fixture. It reproduces the Injective EVM receipt shape with three EVM event logs and five virtual Cosmos logs so `src/rpc.rs` can prove that virtual logs do not invalidate signed transaction inclusion. Transaction-specific hashes, addresses and log payloads are synthetic; the virtual-log address and ERC-20 Transfer topic are protocol/interface constants also present in the former capture. It contains no contract bytecode and is compiled only into `cfg(test)` through `include_str!`.

`PROVENANCE.json` records the exact fixture bytes, hashes, recorded or declared compiler settings, runtime purpose, consumers, license status and regeneration limits. `support/verify-fixture-provenance.py` rechecks that inventory offline.

## Rights and notice checklist

Technical review is recorded for owner-authorized release intent for `v0.1.0-testnet.1` source and binary distribution intent (macOS ARM64 and Linux x86_64); final release controls remain outstanding as recorded in `rights_review.release_intent_authorization` of `PROVENANCE.json`. The authorization is by the project owner on 2026-11-17; it is an owner decision on distribution intent, not a legal conclusion or separate approval. Project owner only; no separate release approver was appointed, consulted, or asserted. The repository itself was already public; that visibility is not the owner-authorized distribution intent. No automated check can establish ownership, authority or NOTICE applicability; repository technical review recorded the evidence-based finding.

- [x] **RIGHTS-01** — The project owner confirmed ownership of the first-party `AstatineMiner` and `AstatineGenesisCoordinator` contracts for Phase D. This is an owner attestation, not independent verification or a waiver of third-party obligations.
- [x] **RIGHTS-02** — Decide whether Apache-2.0 NOTICE propagation applies to each distributed artifact. The contract fixtures are not release-archive members, so any obligation follows source redistribution of the fixtures rather than the miner binary.
- [x] **RIGHTS-03** — If the two first-party contract fixtures remain in the public source tree, add the Apache-2.0 license text and a copyright statement for them, or remove those fixtures from the public tree.
- [x] **RIGHTS-04** — Confirm authorship and redistribution authority for `MockAST` and keep the OpenZeppelin MIT notice with any redistribution of it.
- [x] **RIGHTS-05** — Record the final rights and notice decision here and in `PROVENANCE.json` before publishing the repository or a release archive.

RIGHTS-02 is covered by repository technical review recorded on 2026-11-17: no separate upstream NOTICE file was found in the pinned contract fixture subtrees; the Apache-2.0 license text and fixture NOTICE are included. RIGHTS-03 is resolved by `LICENSE-APACHE-2.0.txt` with copyright `Copyright (c) 2026 emyrinj` and the fixture `NOTICE`, with owner authorization. RIGHTS-04 is resolved by the project owner's MIT redistribution authorization for first-party `MockAST` (copyright `Copyright (c) 2026 emyrinj`) with the OpenZeppelin MIT notice retained in `OPENZEPPELIN_LICENSE.txt` for any applicable redistribution. RIGHTS-05 is recorded by the project owner in this decision and the `PROVENANCE.json` inventory with technical review citations. All ownership and authority statements remain owner-attested and have not been independently verified. This is a technical review, not a legal conclusion or separate approval, and final release controls remain outstanding.

The OpenZeppelin license identity is verified and reproduced; that resolves the license text only, not first-party rights or notice applicability. Citations: `tests/fixtures/PROVENANCE.json`, `tests/fixtures/README.md`, `tests/fixtures/LICENSE-APACHE-2.0.txt`, `tests/fixtures/LICENSE-MIT.txt`, `tests/fixtures/OPENZEPPELIN_LICENSE.txt`, `tests/fixtures/NOTICE`.

## Release intent authorization (2026-11-17)

The project owner recorded owner-authorized release intent for source and binary distribution intent for Astatine `v0.1.0-testnet.1` for macOS ARM64 and Linux x86_64. This supersedes the narrow 2026-11-16 review/CI branch-push exception, which authorized no archive or release distribution. The exact scope, evidence, technical review, limits, and non-authorized items are recorded in `rights_review.release_intent_authorization` of `PROVENANCE.json`, including the `technical_notice_review` object. No separate release approver was appointed, consulted, or asserted. No legal conclusion is made. Release execution still requires the exact tag, `main` CI, a protected environment, attestations, an immutable release, and no bypass of controls; final release controls remain outstanding.

## Review/CI branch push authorization (2026-11-16, superseded)

The project owner authorized pushing the `fix/phase-e-e02-e07` remediation branch to the already-public repository solely for review and CI. That visibility did not authorize a source archive, binary archive or release, tag or release publication, or workflow attestation dispatch. It granted no broader license or legal clearance. This exception is now superseded by the 2026-11-17 owner-authorized release intent recorded in `rights_review.release_intent_authorization` and is retained here as historical context.

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

Regeneration requires access to the private pinned source repositories; a clone of this source tree cannot regenerate the bytecodes by itself. The inventory records the pre-existing fixture hashes; the fixtures were not regenerated for this inventory. First-party authorship of the Astatine contracts and MockAST is owner-attested, not independently verified. See `PROVENANCE.json` for the exact release-intent and technical review status.
