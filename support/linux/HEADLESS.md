# Operator-attended Linux host: state and recovery

This is an operating checklist, not evidence that a particular host, container
restart, GPU, or paid Testnet transaction has been qualified. The intended
architecture is one ASTATINE CLI on one host. The host operator can inspect
terminal input and process memory: do not give an untrusted host a wallet whose
loss you cannot accept.

## Persistent state and identity

- Keep the same Linux user and UID, HOME, and absolute `XDG_CONFIG_HOME` across
  application and container lifetimes. By default ASTATINE uses
  `$HOME/.config/astatine`; with an absolute `XDG_CONFIG_HOME` it uses
  `$XDG_CONFIG_HOME/astatine`. The checkpoint lookup is bound to the
  **canonical** data-root path, not merely the files' names. Mount the persistent
  volume at that same path in every container, and do not introduce a different
  symlink resolution.
- Persist the entire ASTATINE data root: `config.toml`, `wallets/`, and
  `transactions/` including its journal, lock and archives. Persist the matching
  Secret Service collection data under the same user. Keep its unlock
  credentials separately and supply them through a trusted interactive mechanism;
  do not include them in backups, images, persistent volumes or startup
  configuration. For a conventional GNOME Keyring setup its keyring files
  are typically under `$XDG_DATA_HOME/keyrings` (default
  `$HOME/.local/share/keyrings`); verify the actual provider's configuration.
  Do not treat a D-Bus socket or an unlocked daemon process as persistent data.
- Directories containing private state must be owned by the intended user and
  restricted to mode `0700`; private configuration, keystore, journal and lock
  files must be mode `0600`. Verify ownership and modes on mounted volumes before
  use. Protect backups of the encrypted keystore, journal and matching provider
  state together; a journal alone is not a recoverable checkpoint.
- Loss of the container alone need not lose state if both designated persistent
  stores survive at the same canonical path. Loss of either store, the keyring
  unlock material, or the keystore password can prevent authentication or wallet
  use. Do not delete or reset an unresolved journal to make startup succeed.

## Attended session

1. Use an Ubuntu host with a compatible NVIDIA driver when CUDA is needed. Check
   hardware without a wallet or RPC using `astatine devices` or
   `astatine benchmark`. The physical GPU and driver for the actual candidate
   still require their own acceptance test.
2. Start a private session D-Bus and a Secret Service provider for the **same**
   user and persistent keyring. Arrange a trusted, interactive way to unlock that
   existing collection before starting ASTATINE. A provider that is absent,
   locked, belongs to another user, or uses different persisted keyring data is
   not equivalent to the unlocked original. ASTATINE does not start or unlock
   it for you. Headless provider initialization and manual unlock after container
   recreation are **not yet qualified** by the existing workflow.
3. Connect through SSH with a PTY, for example `ssh -tt` to a host you trust.
   Use the existing CLI to create or import a dedicated encrypted wallet and
   approve the intended per-session policy interactively. The wallet keystore
   password is a separate prompt from the Secret Service unlock. Do not put
   passwords, mnemonics, keys or checkpoint material in shell history, command
   arguments, environment variables, images, logs or CI artifacts.
4. After shutdown or disconnect, reconnect to the same user/session and ensure
   the provider is available and unlocked. Run `astatine recover` before
   authorizing another paid run; follow its output and do not blindly rebroadcast
   uncertain transactions. An SSH disconnect can end the foreground application;
   do not assume mining continues. Session managers and remote SSH policies have
   their own trust and lifecycle properties and are not established by the CI
   loopback fixture.
5. Approve only a budget you can afford. The cap is **per mining session**, not
   a lifetime limit. The saved policy approval applies to later explicit paid
   `astatine mine` invocations: each can start a fresh session at the full cap
   without another full-cap approval prompt. The miner signs automatically while
   an authorized run is active; repeated runs can spend more in aggregate.
   Unresolved exposure and existing transaction safeguards remain relevant. Do
   not configure automatic unlocking, unattended launch or unattended restart.

## Restart versus recreation

Restarting a process, restarting a stopped container, recreating a new container
from an image with persistent volumes, and rebooting the host are distinct
operations. A successful process restart does not establish the other three.
Before relying on any of them, test the intended provider and volume setup on a
disposable host without paid mining, verify unavailable/locked credentials fail
closed, and verify recovery after a human unlock. Never manufacture or copy a
checkpoint to make the test pass.
