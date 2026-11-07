# Local EVM lifecycle bytecode fixtures

`AstatineMiner.json` contains test-only creation bytecode from `emyrinj/astatineEVM` commit `80e8f7cbeb21b18bc5f7475d8b751c9d9e8fb9d1`, using Solidity 0.8.28, the Shanghai EVM, optimizer enabled with 200 runs, and `bytecode_hash = "none"`. `AstatineGenesisCoordinator.json` contains test-only creation bytecode from `emyrinj/astatine-coordinator` commit `c710b4d7add5f10de326487d0ff851eb926499c6`, built with that repository's pinned Foundry settings. `MockAST.json` remains a test-only mock from the separately pinned EVM source commit `eb9ea498ed4da10536cd6b4d5d8b55cf38e8aa30`. These fixtures do not change public contracts and are not included in release archives.

The upstream `AstatineMiner` source and imported OpenZeppelin contracts are Apache-2.0 licensed. The local `MockAST` contract is MIT licensed and is never deployed to a public network.

To regenerate them from isolated checkouts of the exact source commits (keep adjacent contract worktrees untouched):

```sh
# ASTATINE_EVM_ROOT is an isolated checkout at 80e8f7cbeb21b18bc5f7475d8b751c9d9e8fb9d1
forge build --root "$ASTATINE_EVM_ROOT"
python3 support/update-evm-test-fixtures.py "$ASTATINE_EVM_ROOT"
# ASTATINE_COORDINATOR_ROOT is an isolated checkout at c710b4d7add5f10de326487d0ff851eb926499c6
forge build --root "$ASTATINE_COORDINATOR_ROOT" --out "$COORDINATOR_OUT" --cache-path "$COORDINATOR_CACHE" --no-lint src/AstatineGenesisCoordinator.sol
python3 support/update-genesis-coordinator-fixture.py "$ASTATINE_COORDINATOR_ROOT" --source-commit c710b4d7add5f10de326487d0ff851eb926499c6 --artifact "$COORDINATOR_OUT/AstatineGenesisCoordinator.sol/AstatineGenesisCoordinator.json"
```

The Rust integration tests deploy these fixtures to Anvil and exercise real local transactions, receipts, events, reward transfers, confirmations, and reorgs. Production binaries use only the pinned Testnet manifest and never load these files.
