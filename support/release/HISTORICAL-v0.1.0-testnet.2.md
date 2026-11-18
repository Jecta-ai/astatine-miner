# Historical v0.1.0-testnet.2 release-intent record

This file preserves the `.2` release intent and packaging state as recorded
before the `v0.1.0-testnet.3` schema correction. It is historical evidence,
not current release authorization. Nothing below is rewritten by the `.3`
change.

## Immutable facts

- Release tag: `v0.1.0-testnet.2` exists at `206d97b1e157e7f386f37f4f1b3b3a158eb0e3c4` (same as `origin/main`), unchanged; no existing tag was moved
  or deleted.
- Release notes: `support/release/RELEASE_NOTES-v0.1.0-testnet.2.md`
  (SHA-256 `f2102858c7346ccbbcf24e87ce0b19597947d1bf2cd2538a850bb4878cdb1e6b`)
  preserved byte-for-byte.
- The `.2` live packaging run (`44283340169`) failed closed in the
  `release-package` provenance validator because
  `support/release/build-release.py` nested `rights_decision` under `gate`
  while the workflow required top-level `rights_decision`. The `release-draft`
  validator was not reached; no archive attestations or draft were created.
  No draft or release exists for `.2`; no assets were attached, replaced,
  or clobbered.
- The `.2` environment model used the explicit owner self-approval policy. It
  did not claim independent review or separation of duties.
- The `.2` candidate is superseded and must not be approved or published as
  `.3` evidence.

## Preserved release-intent text

The following values are copied verbatim from the `.2` release-intent record.
They remain the authoritative `.2` history and must not be edited to describe
`.3`.

- Rights decision:
  > OWNER-AUTHORIZED RELEASE INTENT — project owner authorized first-party
  > source and binary distribution intent for v0.1.0-testnet.2 under the
  > explicitly documented owner self-approval policy; technical NOTICE review
  > recorded; final release controls outstanding; not a legal conclusion, not
  > independent review, and not a separate approval.
- Scope:
  > Owner-authorized first-party source and binary distribution intent for
  > v0.1.0-testnet.2 on macOS ARM64 and Linux x86_64 under an explicit owner
  > self-approval policy; no independent reviewer or separate approver; final
  > release controls remain outstanding.
- Approval roles:
  > Project owner only; the owner explicitly authorized owner self-approval
  > for the protected release environment. No independent reviewer and no
  > separate release approver was appointed, consulted, or asserted;
  > separation of duties is explicitly reduced and recorded as a security
  > tradeoff.

## Current .3 relationship

`v0.1.0-testnet.3` is a schema-correction candidate that adds top-level
`rights_decision` to release provenance while preserving the nested `gate`
record for backward compatibility. It preserves this `.2` record and the
`.1` historical record in `historical_release_intent` and in
[`HISTORICAL-v0.1.0-testnet.1.md`](HISTORICAL-v0.1.0-testnet.1.md). The `.2`
tag remains unchanged, not moved or deleted, and no `.2` release or draft
was published; the `.3` change creates, moves, or deletes no tags.
