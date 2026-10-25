# Astatine Miner

Astatine is an open-source Proof-of-Work mining project on Injective EVM. Miners search for valid hashes locally on their CPUs; Injective contracts verify submissions and settle each work window on-chain. This gives CPU miners a way to compete using verifiable work.

The protocol has nine independent mining nodes, each with its own work and window state. A miner can work across all nodes or select specific nodes.

## Install

On macOS, stop the running miner and run this single command to download the matching Apple Silicon or Intel build, verify its SHA-256 checksum, and replace only `~/.local/bin/astatine`. Configuration, wallets, and transaction journals are untouched:

```sh
bash -c 'set -euo pipefail; case "$(uname -s)" in Darwin) ;; *) printf "%s\n" "macOS is required" >&2; exit 1;; esac; case "$(uname -m)" in arm64|aarch64) asset=astatine-macos-aarch64.tar.gz;; x86_64|amd64) asset=astatine-macos-x86_64.tar.gz;; *) printf "%s\n" "Unsupported macOS architecture" >&2; exit 1;; esac; version=v0.1.0-testnet.5; base="https://github.com/emyrinj/astatine-miner/releases/download/$version"; tmp="$(mktemp -d)"; trap "rm -rf \"$tmp\"" EXIT; curl -fsSL "$base/$asset" -o "$tmp/$asset"; curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"; (cd "$tmp"; grep -F "  $asset" SHA256SUMS | shasum -a 256 -c -); tar -xzf "$tmp/$asset" -C "$tmp"; mkdir -p "$HOME/.local/bin"; install -m 0755 "$tmp/astatine" "$HOME/.local/bin/astatine"; "$HOME/.local/bin/astatine" --version'
```

If `~/.local/bin` is not on your `PATH`, add it before running `astatine` from a new terminal.

## Use

```sh
astatine init
astatine mine
astatine mine --compute-only
```

`astatine init` configures the wallet, network, CPU budget, reserve, transaction cap, and confirmation depth. Interactive terminals show live node, balance, hashrate, transaction, and session-exposure status; redirected output uses plain-text progress. The dashboard distinguishes proof checking, signed-but-not-yet-broadcast, broadcast/confirmation, chain waiting, required/retrying finalization, and policy-blocked finalization. Autonomous mining retains the best queued proof per node in a bounded inbox, revalidates it against current verified work, and reports bounded per-node proof-pipeline counters on exit (including rejection reasons, paid-attempt suppression, broadcast, and verified candidate events). `--compute-only` hashes locally without unlocking a wallet or sending transactions. Use `--nodes 1,3,5` to restrict mining to selected nodes.

**Transaction costs:** Each proof submission pays a `0.01 INJ` fee. Finalizing a window consumes INJ gas, including when the window is empty or another miner wins. These costs count toward the configured per-session cap. The default cap is zero, which disables transaction signing; a positive cap explicitly authorizes spending. Mainnet transaction signing is disabled.

## License

The miner is licensed under [MIT](LICENSE-MIT). Third-party dependency notices are in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
