# Historical v0.1.0-testnet.1 release-intent record

This file preserves the `.1` release intent and publication state as recorded
before the `v0.1.0-testnet.2` owner self-approval revision. It is historical
evidence, not current release authorization. Nothing below is rewritten by the
`.2` change.

## Immutable facts

- Release tag: `v0.1.0-testnet.1`
- Tag target commit: `99a8630a7ae7f5c5950031dfba8c3b0c3f132cbc`
- Release notes: `support/release/RELEASE_NOTES-v0.1.0-testnet.1.md`
  (SHA-256 `12d7605b5e48c80f1c838a95d245c08da8cd5c831d008da3bb3dea420bdc31b9`)
- The `.1` tag was not moved, deleted, or retargeted.
- The `.1` release workflow run was not cancelled, deleted, or replaced; it
  remained pending environment approval when this record was written.
- No `.1` release was published. Release URL, asset URLs, and checksums were
  not available because no draft was created.
- The `.1` environment model required a non-self reviewer. It did not use the
  `.2` owner self-approval exception.
- The `.1` run is superseded and must not be approved or published as `.2`
  evidence. Its current live reviewer configuration is unchanged until a
  coordinator-approved environment update.

## Preserved release-intent text

The following values are copied verbatim from the `.1` release-intent record.
They remain the authoritative `.1` history and must not be edited to describe
`.2`.

- Rights decision:
  > OWNER-AUTHORIZED RELEASE INTENT — project owner authorized first-party
  > source and binary distribution intent for v0.1.0-testnet.1; technical
  > NOTICE review recorded; final release controls outstanding; not a legal
  > conclusion or separate approval.
- Scope:
  > Owner-authorized first-party source and binary distribution intent
  > for v0.1.0-testnet.1 on macOS ARM64 and Linux x86_64; final release
  > controls remain outstanding.
- Approval roles:
  > Project owner only; no separate release approver was appointed,
  > consulted, or asserted.

## Current .2 relationship

`v0.1.0-testnet.2` is a new candidate on a new commit. It uses an explicitly
documented owner self-approval policy and does not claim independent review or
separation of duties. The `.2` inventories preserve this `.1` record in
`historical_release_intent`. The `.1` tag and pending workflow remain untouched
and must not be used as evidence of `.2` approval.
