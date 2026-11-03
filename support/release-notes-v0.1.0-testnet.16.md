## Astatine Miner v0.1.0-testnet.16

Testnet.16 adds a latched terminal state for paid mining when the remaining durable per-session authorization falls below the canonical 0.01 INJ proof fee.

### Highlights

- Paid mining compares the remaining authorized session exposure against the canonical proof fee using integer wei and a strict less-than comparison. Exactly 0.01 INJ remaining is not considered exhausted; zero-limit compute-only operation is unchanged.
- When the threshold is crossed, CPU and GPU workers stop, queued proofs are discarded, and the run refuses additional proof submissions and finalizations. The already-authorized transaction continues through the existing signing, broadcast, receipt, and recovery lifecycle.
- The terminal dashboard clearly displays `SESSION LIMIT REACHED`, zero hashrate, amber node state, and Ctrl+C instructions. It stays open while read-only observation and existing transaction recovery continue; observer stalls, fatal updates, or a closed update channel do not exit the terminal state. When monitoring is unavailable, the last verified block is identified as stale and mining remains stopped.
- Starting a paid invocation with less than one proof fee remaining skips compute-worker startup and signer unlocking. In approved per-run policy mode, a later explicit invocation uses the existing fresh-session policy rather than refilling the current run.
- Durable maximum transaction exposure remains charged after a lower actual receipt cost or a refreshed chain snapshot. Observer data cannot increase or refund the current session allowance.
- CPU and physical Apple M4 GPU Anvil regressions exercise proof submission, terminal latching, expiry without automatic finalization, clean Ctrl+C shutdown, and the next explicit session. Tests use local Anvil and pinned Testnet.15 contract bytecode fixtures only.

The proof algorithm, deployed contracts and addresses, contract behavior, rewards, and 0.01 INJ submission fee are unchanged. Automatic AST reward forwarding remains disabled because the selected RPC can fabricate reward evidence. Mainnet transaction signing remains disabled.

GitHub Actions builds and attests unsigned assets only. The owner verifies production tag provenance online, signs offline with the existing V3 key, and manually publishes the signed inventory. A tag does not sign or publish by itself.

Commit-pinned source: https://github.com/__RELEASE_REPOSITORY__/tree/__RELEASE_COMMIT__
