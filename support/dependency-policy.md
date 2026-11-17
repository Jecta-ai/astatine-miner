# Dependency advisory policy

## RUSTSEC-2026-0387 guarded exception (not a clean fix)

Recorded advisory facts: `RUSTSEC-2026-0387` is a secret-dependent-timing
advisory affecting `crypto-bigint` releases before the patched `>=0.7.6`
release line. `Cargo.lock` retains the optional `crypto-bigint 0.5.5` entry
as an optional transitive dependency of `alloy-primitives 1.7.3` through
`k256 0.13.4` and `elliptic-curve 0.13.8`. There is no patched 0.5.x release
to select within the locked `k256 0.13` dependency line, and
`alloy-primitives 1.7.3` is the current pinned dependency line, so safe
removal of the lockfile entry is not available. A targeted attempt to update
the optional lock entry to `0.5.6` found no such package version. Manually
removing an optional transitive package from `Cargo.lock` is not compatible
with the repository's `--locked` build policy, and forcing such an edit is
explicitly out of scope. The optional dependency is therefore retained until
its upstream dependency line can be safely removed or upgraded.

The miner enables only `alloy-primitives`' `std` feature, so the optional
`k256` 0.13.x feature of `alloy-primitives 1.7.3` — the path that would
pull `crypto-bigint 0.5.5` through `k256 0.13.4` and `elliptic-curve 0.13.8`
— is inactive and outside the resolved build graph. The `k256` that is
actually built is `k256 0.14.0`, reached through `bip32 0.6.0` and
`elliptic-curve 0.14.3`; the active target graph therefore uses
`crypto-bigint 0.7.9`, which is on the patched `>=0.7.6` release line.

This is a guarded exception, not a clean fix. It does not state that the
advisory can never apply; it only records that the affected `0.5.5` package
is outside the active build graph, which is enforced by the checks below.
This exception must be revisited on upstream upgrade. The exact transition
is: while `crypto-bigint 0.5.5` (or any other affected `<0.7.6` entry) may
be present in `Cargo.lock`, the checker requires the
`cargo audit --ignore RUSTSEC-2026-0387` exception to stay; once `0.5.5` is
absent and every remaining locked `crypto-bigint` is on the patched
`>=0.7.6` line (or none remain) and the runtime positive active-graph check
proves no active build below that line, the audit exception must be removed
from `ci.yml`, and the checker fails if it is still present. Removing the
ignore flag is therefore a future `ci.yml` edit that must only happen when
the checker state flips, never pre-emptively while `0.5.5` is present.

CI keeps the existing `cargo audit --ignore RUSTSEC-2026-0387` exception
while the `0.5.5` entry is present, and enforces the guard via
`python3 support/check_dependency_policy.py --require-inactive`: with
`0.5.5` present it runs
`cargo tree --locked --all-features --target all -i crypto-bigint@0.5.5`
and fails if `crypto-bigint v0.5.5` appears; with `0.5.5` absent it runs the
positive check
`cargo tree --locked --all-features --target all --prefix none` and fails
if any active `crypto-bigint` is below the patched `>=0.7.6` line (no
active lines means the dependency is removed and passes). If a graph guard
ever finds an affected package in the active graph, the exception stays
and the build fails closed. `derivative 2.2.0` is also reported as
unmaintained by `cargo audit`, but is not a vulnerability advisory.
