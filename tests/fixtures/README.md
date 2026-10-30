# Local EVM lifecycle bytecode fixtures

`AstatineMiner.json` and `MockAST.json` contain only compiled contract creation bytecode for local Anvil integration tests. They were generated with Foundry from `emyrinj/astatineEVM` commit `eb9ea498ed4da10536cd6b4d5d8b55cf38e8aa30` using Solidity 0.8.28, the Shanghai EVM, optimizer enabled with 200 runs and `bytecode_hash = "none"`; no Solidity source or deployed contract was changed for Testnet.8. `AstatineGenesisCoordinator.json` contains test-only creation bytecode from `emyrinj/astatine-coordinator` commit `54588aa7b020cd7e49fa2275a560cde8138dd707`, built with that repository's pinned Foundry settings. The fixtures are test-only and are not included in release archives.

The upstream `AstatineMiner` source and imported OpenZeppelin contracts are Apache-2.0 licensed. The local `MockAST` contract is MIT licensed and is never deployed to a public network.

To regenerate them when intentionally updating the pinned local integration version:

```sh
forge build --root "$ASTATINE_EVM_ROOT"
python3 support/update-evm-test-fixtures.py "$ASTATINE_EVM_ROOT"
forge build --root "$ASTATINE_COORDINATOR_ROOT" --out "$COORDINATOR_OUT" --cache-path "$COORDINATOR_CACHE" --no-lint src/AstatineGenesisCoordinator.sol
python3 support/update-genesis-coordinator-fixture.py "$ASTATINE_COORDINATOR_ROOT" --artifact "$COORDINATOR_OUT/AstatineGenesisCoordinator.sol/AstatineGenesisCoordinator.json"
```

The Rust integration tests deploy these fixtures to Anvil and exercise real local transactions, receipts, events, reward transfers, confirmations, and reorgs. Production binaries use only the pinned Testnet manifest and never load these files.
