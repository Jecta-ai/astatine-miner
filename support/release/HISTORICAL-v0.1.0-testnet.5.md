# Historical v0.1.0-testnet.5 release-intent record

This file preserves the `.5` release intent and packaging state as recorded
before the `v0.1.0-testnet.6` Windows archive path correction. It is historical
evidence, not current release authorization. Nothing below is rewritten by the
`.6` change.

## Immutable facts

- Release tag: `v0.1.0-testnet.5` exists at `c31b39b099362114e366df27b2e0b8c307748517`, unchanged; no existing tag was moved or deleted.
- Release notes: `support/release/RELEASE_NOTES-v0.1.0-testnet.5.md`
  (SHA-256 `c3644634d2603b8ed48cdc235445727d51691a47be5cd73e37967904d5f5315c`)
  preserved byte-for-byte.
- The `.4` record (`support/release/HISTORICAL-v0.1.0-testnet.4.md`) and the `.1` historical record in `historical_release_intent` remain preserved byte-for-byte.
- The `.5` workflow Windows archive validation defined the archive root with a trailing slash (`$root = "astatine-$env:RELEASE_TAG-windows-x86_64/"`) while members appended another slash (`"$root/astatine.exe"`), producing double-slash expectations that could not match the packaged members. The `.6` revision defines the root without a trailing slash, rejects double-slash expectations, and adds native synthetic-ZIP validation coverage with positive and negative cases.
- The `.5` candidate is superseded and must not be approved or published as `.6` evidence.

## Preserved release-intent text

The following values are copied verbatim from the `.5` release-intent record.
They remain the authoritative `.5` history and must not be edited to describe
`.6`.

- Rights decision:
  > OWNER-AUTHORIZED RELEASE INTENT — project owner authorized first-party
  > source and binary distribution intent for v0.1.0-testnet.5 under the
  > explicitly documented owner self-approval policy; technical NOTICE review
  > recorded; final release controls outstanding; not a legal conclusion, not
  > independent review, and not a separate approval.
- Scope:
  > Owner-authorized first-party source and binary distribution intent for
  > v0.1.0-testnet.5 on macOS ARM64, Linux x86_64, and Windows x86_64 under an explicit owner
  > self-approval policy; no independent reviewer or separate approver; final
  > release controls remain outstanding.
- Approval roles:
  > Project owner only; the owner explicitly authorized owner self-approval
  > for the protected release environment. No independent reviewer and no
  > separate release approver was appointed, consulted, or asserted;
  > separation of duties is explicitly reduced and recorded as a security
  > tradeoff.

## Current .6 relationship

`v0.1.0-testnet.6` is a narrow Windows archive path correction plus version-pin update on a new commit. It preserves this `.5` record, the `.4` record, and the `.1` historical record in `historical_release_intent` and in the preserved notes and audit. The `.4` and `.5` tags remain unchanged, not moved or deleted, and no prior tag, release, or asset is rewritten by the `.6` change.
