# Historical v0.1.0-testnet.4 release-intent record

This file preserves the `.4` release intent and packaging state as recorded
before the `v0.1.0-testnet.5` Windows shell correction. It is historical
evidence, not current release authorization. Nothing below is rewritten by the
`.5` change.

## Immutable facts

- Release tag: `v0.1.0-testnet.4` exists at `192a0ba8cff66f18c3da0237703a5b250a40e004` (same as `origin/main`), unchanged; no existing tag was moved or deleted.
- Release notes: `support/release/RELEASE_NOTES-v0.1.0-testnet.4.md`
  (SHA-256 `15af63988bed3d5fc76396f3f3b79d494ddae1afa48e764bfa4723066b08d5bc`)
  preserved byte-for-byte.
- Release audit: `support/release/RELEASE_AUDIT-v0.1.0-testnet.4.md` preserved byte-for-byte; it retains the `.1`/`.2`/`.3` history and the `.2` failed live packaging run (`44283340169`).
- The `.4` workflow Windows steps lacked explicit shells: `build-windows` assert exact tag identity, install pinned toolchain, observe toolchain versions, and build locked release binary, plus `windows-archive-smoke` archive attestation verification, had no `shell:` declaration and would execute under the Windows runner default. The `.5` revision adds `shell: bash` to those bash steps while preserving `shell: pwsh` for PowerShell steps and all gates.
- The `.4` candidate is superseded and must not be approved or published as `.5` evidence.

## Preserved release-intent text

The following values are copied verbatim from the `.4` release-intent record.
They remain the authoritative `.4` history and must not be edited to describe
`.5`.

- Rights decision:
  > OWNER-AUTHORIZED RELEASE INTENT — project owner authorized first-party
  > source and binary distribution intent for v0.1.0-testnet.4 under the
  > explicitly documented owner self-approval policy; technical NOTICE review
  > recorded; final release controls outstanding; not a legal conclusion, not
  > independent review, and not a separate approval.
- Scope:
  > Owner-authorized first-party source and binary distribution intent for
  > v0.1.0-testnet.4 on macOS ARM64, Linux x86_64, and Windows x86_64 under an explicit owner
  > self-approval policy; no independent reviewer or separate approver; final
  > release controls remain outstanding.
- Approval roles:
  > Project owner only; the owner explicitly authorized owner self-approval
  > for the protected release environment. No independent reviewer and no
  > separate release approver was appointed, consulted, or asserted;
  > separation of duties is explicitly reduced and recorded as a security
  > tradeoff.

## Current .5 relationship

`v0.1.0-testnet.5` is a narrow Windows shell correction plus version-pin update on a new commit. It preserves this `.4` record and the `.1` historical record in `historical_release_intent` and in the preserved `.4` notes and audit. The `.4` tag remains unchanged, not moved or deleted, and no `.4` tag, release, or asset is rewritten by the `.5` change.
