use crate::cli::Network;
use alloy_primitives::{Address, U256, hex};
use anyhow::{Context, Result, anyhow, bail};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(any(unix, windows))]
use std::fs::File;
use std::{
    env, fs,
    fs::OpenOptions,
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tempfile::{NamedTempFile, PersistError};
use zeroize::Zeroizing;

const CONFIG_FILE: &str = "config.toml";
const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_KEYSTORE_BYTES: u64 = 64 * 1024;
const MAX_TRANSACTION_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TRANSACTION_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024;
const WEI_PER_INJ: u128 = 1_000_000_000_000_000_000;
const DEFAULT_TRANSACTION_CONFIRMATIONS: u8 = 2;
const MAX_TRANSACTION_CONFIRMATIONS: u8 = 12;
const LEGACY_CONFIG_SCHEMA_VERSION: u32 = 1;
const PER_RUN_CONFIG_SCHEMA_VERSION: u32 = 2;
const JOURNAL_LOCK_RETRY_ATTEMPTS: u32 = 20;
const JOURNAL_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[cfg(test)]
std::thread_local! {
    static JOURNAL_LOCK_RETRY_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
static TEST_JOURNAL_ANCHORS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, Zeroizing<Vec<u8>>>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static TEST_JOURNAL_ANCHOR_WRITE_FAILURES: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, TestJournalAnchorWriteFailure>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
#[derive(Clone, Copy)]
struct TestJournalAnchorWriteFailure {
    successful_writes: usize,
    after_persist: bool,
}

#[cfg(test)]
static TEST_ATOMIC_WRITE_FAILURES: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<PathBuf, AtomicWriteFailPoint>>,
> = std::sync::OnceLock::new();

#[cfg(all(test, unix))]
static TEST_ATOMIC_WRITE_PAUSE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<PathBuf, PathBuf>>,
> = std::sync::OnceLock::new();

#[cfg(all(test, unix))]
pub(crate) fn pause_atomic_write_before_rename_for_test(path: PathBuf, ready: PathBuf) {
    TEST_ATOMIC_WRITE_PAUSE
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .insert(path, ready);
}

#[cfg(test)]
static TEST_ARCHIVE_TAMPER_POINTS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<PathBuf, ArchiveTamperPoint>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtomicWriteFailPoint {
    BeforeWrite,
    BeforeFileSync,
    BeforeRename,
    AfterRename,
    BeforeDirectorySync,
    AfterDirectorySync,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArchiveTamperPoint {
    AtomicWrite,
    WriteReadback,
    ArchiveRead,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub schema_version: u32,
    pub network: Network,
    pub wallet_address: Option<String>,
    pub cpu_threads: usize,
    pub minimum_reserve_inj: String,
    pub per_session_spending_limit_inj: String,
    #[serde(default)]
    pub testnet_rpc: Option<String>,
    #[serde(default)]
    pub mainnet_rpc: Option<String>,
    #[serde(default = "default_transaction_confirmations")]
    pub transaction_confirmations: u8,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: PER_RUN_CONFIG_SCHEMA_VERSION,
            network: Network::Testnet,
            wallet_address: None,
            cpu_threads: conservative_thread_budget(),
            minimum_reserve_inj: "0.1".to_owned(),
            per_session_spending_limit_inj: "1".to_owned(),
            testnet_rpc: None,
            mainnet_rpc: None,
            transaction_confirmations: DEFAULT_TRANSACTION_CONFIRMATIONS,
        }
    }
}

impl AppConfig {
    pub fn validate(&self) -> Result<()> {
        if !matches!(
            self.schema_version,
            LEGACY_CONFIG_SCHEMA_VERSION | PER_RUN_CONFIG_SCHEMA_VERSION
        ) {
            bail!(
                "unsupported configuration schema version {}",
                self.schema_version
            );
        }
        if !(1..=256).contains(&self.cpu_threads) {
            bail!("CPU thread budget must be in the range 1..=256");
        }
        parse_inj_wei(&self.minimum_reserve_inj)
            .context("minimum reserve must be a decimal INJ amount with at most 18 decimals")?;
        parse_inj_wei(&self.per_session_spending_limit_inj)
            .context("spending limit must be a decimal INJ amount with at most 18 decimals")?;
        if !(1..=MAX_TRANSACTION_CONFIRMATIONS).contains(&self.transaction_confirmations) {
            bail!(
                "transaction confirmation threshold must be within 1..={MAX_TRANSACTION_CONFIRMATIONS} blocks"
            );
        }
        if let Some(address) = &self.wallet_address {
            Address::from_str(address).context("configured wallet address is invalid")?;
        }
        if let Some(rpc) = &self.testnet_rpc {
            validate_rpc_url(rpc).context("Testnet RPC override is invalid")?;
        }
        if let Some(rpc) = &self.mainnet_rpc {
            validate_rpc_url(rpc).context("Mainnet RPC override is invalid")?;
        }
        Ok(())
    }

    pub fn rpc_override(&self, network: Network) -> Option<&str> {
        match network {
            Network::Testnet => self.testnet_rpc.as_deref(),
            Network::Mainnet => self.mainnet_rpc.as_deref(),
        }
    }

    pub fn set_rpc_override(&mut self, network: Network, rpc: Option<String>) {
        match network {
            Network::Testnet => self.testnet_rpc = rpc,
            Network::Mainnet => self.mainnet_rpc = rpc,
        }
    }

    pub fn per_run_sessions_enabled(&self) -> bool {
        self.schema_version >= PER_RUN_CONFIG_SCHEMA_VERSION
    }
}

pub fn validate_rpc_url(endpoint: &str) -> Result<Url> {
    if endpoint.is_empty() || endpoint.len() > 4096 {
        bail!("RPC URL is empty or exceeds the supported length");
    }
    let url = Url::parse(endpoint).context("parse RPC URL")?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("RPC URL must not embed username or password credentials");
    }
    if url.fragment().is_some() {
        bail!("RPC URL must not contain a fragment");
    }
    let host = url.host_str().context("RPC URL must include a host")?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(host) => {}
        "http" => bail!("remote RPC endpoints must use HTTPS"),
        _ => bail!("RPC URL scheme must be HTTP or HTTPS"),
    }
    Ok(url)
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn default_transaction_confirmations() -> u8 {
    DEFAULT_TRANSACTION_CONFIRMATIONS
}

#[derive(Clone, Debug)]
pub struct ConfigStore {
    root: PathBuf,
    anchor_scope: Arc<OnceLock<std::result::Result<String, String>>>,
}

impl ConfigStore {
    pub fn system_default() -> Result<Self> {
        Ok(Self {
            root: system_config_dir()?,
            anchor_scope: Arc::new(OnceLock::new()),
        })
    }

    #[cfg(test)]
    pub(crate) fn at_root(root: PathBuf) -> Self {
        Self {
            root,
            anchor_scope: Arc::new(OnceLock::new()),
        }
    }

    pub fn wallet_dir(&self) -> PathBuf {
        self.root.join("wallets")
    }

    pub fn prepare_wallet_dir(&self) -> Result<PathBuf> {
        ensure_private_directory(&self.root)?;
        let directory = self.wallet_dir();
        ensure_private_directory(&directory)?;
        Ok(directory)
    }

    pub fn load(&self) -> Result<AppConfig> {
        let path = self.root.join(CONFIG_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(AppConfig::default());
            }
            Err(error) => return Err(error).context("inspect configuration file"),
        }
        ensure_private_directory(&self.root)?;
        let text = String::from_utf8(read_regular_limited(&path, MAX_CONFIG_BYTES, true)?)
            .context("configuration file is not valid UTF-8")?;
        let config: AppConfig = toml::from_str(&text).context("parse configuration file")?;
        config.validate()?;
        Ok(config)
    }

    pub fn save(&self, config: &AppConfig) -> Result<()> {
        config.validate()?;
        ensure_private_directory(&self.root)?;
        let mut text = toml::to_string_pretty(config).context("serialize configuration")?;
        text.push('\n');
        atomic_write(&self.root.join(CONFIG_FILE), text.as_bytes(), true)
            .context("atomically write configuration")
    }

    pub fn keystore_path(&self, address: Address) -> PathBuf {
        self.wallet_dir()
            .join(format!("{:#x}.json", address).to_ascii_lowercase())
    }

    pub fn read_keystore(&self, address: Address) -> Result<Vec<u8>> {
        let path = self.keystore_path(address);
        ensure_private_directory(&self.root)?;
        ensure_private_directory(&self.wallet_dir())?;
        let contents = read_regular_limited(&path, MAX_KEYSTORE_BYTES, true)
            .context("read encrypted wallet file")?;
        if contents.is_empty() {
            bail!("wallet file is empty");
        }
        Ok(contents)
    }

    pub fn store_keystore(&self, address: Address, data: &[u8]) -> Result<PathBuf> {
        if data.is_empty() || data.len() as u64 > MAX_KEYSTORE_BYTES {
            bail!("encrypted wallet file is empty or exceeds the supported size limit");
        }
        self.prepare_wallet_dir()?;
        let path = self.keystore_path(address);
        atomic_write(&path, data, false).context("atomically store encrypted wallet")?;
        Ok(path)
    }

    pub(crate) fn read_transaction_journal(&self) -> Result<Option<Vec<u8>>> {
        let path = self.transaction_journal_path()?;
        match fs::symlink_metadata(&path) {
            Ok(_) => read_regular_limited(&path, MAX_TRANSACTION_JOURNAL_BYTES, true)
                .map(Some)
                .context("read private transaction journal"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("inspect private transaction journal"),
        }
    }

    #[cfg(test)]
    pub(crate) fn transaction_journal_path_for_test(&self) -> Result<PathBuf> {
        self.transaction_journal_path()
    }

    pub(crate) fn write_transaction_journal(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() || data.len() as u64 > MAX_TRANSACTION_JOURNAL_BYTES {
            bail!("transaction journal is empty or exceeds its 8 MiB size limit");
        }
        let path = self.transaction_journal_path()?;
        atomic_write(&path, data, true).context("atomically write private transaction journal")
    }

    pub(crate) fn read_journal_anchor(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        #[cfg(test)]
        {
            let account = self.journal_anchor_account()?;
            return Ok(TEST_JOURNAL_ANCHORS
                .get_or_init(Default::default)
                .lock()
                .map_err(|_| anyhow!("test journal-anchor mutex was poisoned"))?
                .get(&account)
                .map(|secret| Zeroizing::new(secret.to_vec())));
        }

        #[cfg(all(
            not(test),
            any(target_os = "linux", target_os = "macos", target_os = "windows")
        ))]
        {
            self.read_journal_anchor_from_platform()
        }

        #[cfg(all(
            not(test),
            not(any(target_os = "linux", target_os = "macos", target_os = "windows"))
        ))]
        {
            bail!("transaction signing requires a supported OS credential store")
        }
    }

    #[cfg(all(
        test,
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    pub(crate) fn read_journal_anchor_from_os_for_test(
        &self,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.read_journal_anchor_from_platform()
    }

    #[cfg(all(
        test,
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    pub(crate) fn write_journal_anchor_to_os_for_test(&self, data: &[u8]) -> Result<()> {
        self.journal_anchor_entry()?
            .set_secret(data)
            .map_err(anyhow::Error::new)
            .context("write the transaction authorization checkpoint to the OS credential store")
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn read_journal_anchor_from_platform(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let entry = self.journal_anchor_entry()?;
        match entry.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(anyhow!(error)).context(
                "read the transaction authorization checkpoint from the OS credential store",
            ),
        }
    }

    pub(crate) fn write_journal_anchor(&self, data: &[u8]) -> Result<()> {
        #[cfg(test)]
        {
            let account = self.journal_anchor_account()?;
            let failure = {
                let mut failures = TEST_JOURNAL_ANCHOR_WRITE_FAILURES
                    .get_or_init(Default::default)
                    .lock()
                    .map_err(|_| anyhow!("test journal-anchor failure mutex was poisoned"))?;
                match failures.get_mut(&account) {
                    Some(failure) if failure.successful_writes == 0 => {
                        let failure = *failure;
                        failures.remove(&account);
                        Some(failure.after_persist)
                    }
                    Some(failure) => {
                        failure.successful_writes -= 1;
                        None
                    }
                    None => None,
                }
            };
            if failure == Some(false) {
                bail!("injected OS credential-store checkpoint write failure");
            }
            TEST_JOURNAL_ANCHORS
                .get_or_init(Default::default)
                .lock()
                .map_err(|_| anyhow!("test journal-anchor mutex was poisoned"))?
                .insert(account, Zeroizing::new(data.to_vec()));
            if failure == Some(true) {
                bail!("injected failure after OS credential-store checkpoint persistence");
            }
            Ok(())
        }

        #[cfg(all(
            not(test),
            any(target_os = "linux", target_os = "macos", target_os = "windows")
        ))]
        {
            self.journal_anchor_entry()?
                .set_secret(data)
                .map_err(anyhow::Error::new)
                .context(
                    "write the transaction authorization checkpoint to the OS credential store",
                )
        }

        #[cfg(all(
            not(test),
            not(any(target_os = "linux", target_os = "macos", target_os = "windows"))
        ))]
        {
            bail!("transaction signing requires a supported OS credential store")
        }
    }

    #[cfg(test)]
    pub(crate) fn clear_journal_anchor_for_test(&self) -> Result<()> {
        let account = self.journal_anchor_account()?;
        TEST_JOURNAL_ANCHORS
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| anyhow!("test journal-anchor mutex was poisoned"))?
            .remove(&account);
        TEST_JOURNAL_ANCHOR_WRITE_FAILURES
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| anyhow!("test journal-anchor failure mutex was poisoned"))?
            .remove(&account);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_journal_anchor_write_before_for_test(
        &self,
        successful_writes: usize,
    ) -> Result<()> {
        let account = self.journal_anchor_account()?;
        TEST_JOURNAL_ANCHOR_WRITE_FAILURES
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| anyhow!("test journal-anchor failure mutex was poisoned"))?
            .insert(
                account,
                TestJournalAnchorWriteFailure {
                    successful_writes,
                    after_persist: false,
                },
            );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_journal_anchor_write_after_persist_for_test(
        &self,
        successful_writes: usize,
    ) -> Result<()> {
        let account = self.journal_anchor_account()?;
        TEST_JOURNAL_ANCHOR_WRITE_FAILURES
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| anyhow!("test journal-anchor failure mutex was poisoned"))?
            .insert(
                account,
                TestJournalAnchorWriteFailure {
                    successful_writes,
                    after_persist: true,
                },
            );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_atomic_write_for_test(
        &self,
        path: PathBuf,
        point: AtomicWriteFailPoint,
    ) -> Result<()> {
        TEST_ATOMIC_WRITE_FAILURES
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| anyhow!("test atomic-write failure mutex was poisoned"))?
            .insert(path, point);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn tamper_archive_at_for_test(&self, point: ArchiveTamperPoint) -> Result<()> {
        TEST_ARCHIVE_TAMPER_POINTS
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| anyhow!("test archive-tamper mutex was poisoned"))?
            .insert(self.root.clone(), point);
        Ok(())
    }

    fn journal_anchor_account(&self) -> Result<String> {
        self.anchor_scope
            .get_or_init(|| {
                canonical_root_identity(&self.root)
                    .map(|identity| hex::encode(Sha256::digest(identity)))
                    .map_err(|error| format!("{error:#}"))
            })
            .clone()
            .map_err(anyhow::Error::msg)
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn journal_anchor_entry(&self) -> Result<keyring::Entry> {
        keyring::Entry::new(
            "ai.jecta.astatine.transaction-journal",
            &self.journal_anchor_account()?,
        )
        .map_err(anyhow::Error::new)
        .context("open the OS credential-store entry for the transaction journal")
    }

    pub(crate) fn write_transaction_archive(&self, name: &str, data: &[u8]) -> Result<()> {
        if data.is_empty() || data.len() as u64 > MAX_TRANSACTION_ARCHIVE_BYTES {
            bail!("transaction archive is empty or exceeds its 8 MiB size limit");
        }
        let path = self.transaction_archive_path(name)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let existing = read_regular_limited(&path, MAX_TRANSACTION_ARCHIVE_BYTES, true)?;
                if existing != data {
                    bail!("transaction archive identifier already exists with different contents");
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                atomic_write(&path, data, false)
                    .context("atomically create private transaction archive")?;
                #[cfg(test)]
                if take_archive_tamper_point(&self.root, ArchiveTamperPoint::AtomicWrite)? {
                    tamper_archive_for_test(&path)?;
                }
                let stored = read_regular_limited(&path, MAX_TRANSACTION_ARCHIVE_BYTES, true)
                    .context("read back newly written private transaction archive")?;
                if stored != data {
                    bail!("transaction archive bytes differ from the authenticated write payload");
                }
                #[cfg(test)]
                if take_archive_tamper_point(&self.root, ArchiveTamperPoint::WriteReadback)? {
                    tamper_archive_for_test(&path)?;
                }
                Ok(())
            }
            Err(error) => Err(error).context("inspect private transaction archive"),
        }
    }

    pub(crate) fn read_transaction_archive(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.transaction_archive_path(name)?;
        let contents = read_regular_limited(&path, MAX_TRANSACTION_ARCHIVE_BYTES, true)
            .context("read private transaction archive")?;
        #[cfg(test)]
        if take_archive_tamper_point(&self.root, ArchiveTamperPoint::ArchiveRead)? {
            tamper_archive_for_test(&path)?;
        }
        Ok(contents)
    }

    pub(crate) fn lock_transaction_journal(&self) -> Result<File> {
        let path = self
            .transaction_journal_path()?
            .with_file_name("miner.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            );
        }
        let file = options
            .open(&path)
            .context("open transaction journal lock")?;
        let metadata = file
            .metadata()
            .context("inspect transaction journal lock")?;
        if !metadata.is_file() {
            bail!("transaction journal lock is not a regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .context("restrict transaction journal lock permissions")?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                != 0
            {
                bail!("transaction journal lock is a reparse point");
            }
        }
        // A just-released journal lock can transiently report WouldBlock in
        // parallel stress even when lsof shows no remaining holder fd. The
        // exact cause is not established; a short-lived inherited fd or a
        // lock-release visibility race remains possible. Retry briefly so a
        // just-released lock is not misreported as contention. A genuinely
        // held lock still fails closed after the bound.
        let mut attempts = 0_u32;
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock)
                    if attempts < JOURNAL_LOCK_RETRY_ATTEMPTS =>
                {
                    attempts += 1;
                    #[cfg(test)]
                    JOURNAL_LOCK_RETRY_TEST_HOOK.with(|hook| {
                        if let Some(hook) = hook.borrow_mut().as_mut() {
                            hook();
                        }
                    });
                    std::thread::sleep(JOURNAL_LOCK_RETRY_INTERVAL);
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(anyhow!(
                        "another astatine mining process already holds the transaction journal at {}: lock acquisition failed because the operation would block",
                        path.display()
                    ));
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(anyhow::Error::new(error)).with_context(|| {
                        format!("acquire the transaction journal lock at {}", path.display())
                    });
                }
            }
        }
        Ok(file)
    }

    fn transaction_journal_path(&self) -> Result<PathBuf> {
        ensure_private_directory(&self.root)?;
        let directory = self.root.join("transactions");
        ensure_private_directory(&directory)?;
        Ok(directory.join("journal.json"))
    }

    fn transaction_archive_path(&self, name: &str) -> Result<PathBuf> {
        if !name.starts_with("archive-")
            || !name.ends_with(".json")
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        {
            bail!("transaction archive name is invalid");
        }
        ensure_private_directory(&self.root)?;
        let transaction_dir = self.root.join("transactions");
        ensure_private_directory(&transaction_dir)?;
        let directory = transaction_dir.join("archives");
        ensure_private_directory(&directory)?;
        Ok(directory.join(name))
    }
}

#[cfg(unix)]
fn canonical_root_identity(root: &Path) -> Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;

    let canonical = fs::canonicalize(root).context("canonicalize transaction data root")?;
    Ok(canonical.as_os_str().as_bytes().to_vec())
}

#[cfg(windows)]
fn canonical_root_identity(root: &Path) -> Result<Vec<u8>> {
    use std::os::windows::ffi::OsStrExt;

    let canonical = fs::canonicalize(root).context("canonicalize transaction data root")?;
    Ok(canonical
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect())
}

#[cfg(not(any(unix, windows)))]
fn canonical_root_identity(_root: &Path) -> Result<Vec<u8>> {
    bail!("transaction signing requires a supported canonical data-root identity")
}

fn system_config_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        windows_config_dir(env::var_os("APPDATA").as_deref())
    }

    #[cfg(target_os = "macos")]
    {
        let home = env::var_os("HOME").filter(|value| !value.is_empty());
        let home =
            home.context("HOME is not set; cannot locate the user configuration directory")?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Astatine"))
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        xdg_config_dir(
            env::var_os("XDG_CONFIG_HOME").as_deref(),
            env::var_os("HOME").as_deref(),
        )
    }

    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let home = env::var_os("HOME")
            .or_else(|| env::var_os("USERPROFILE"))
            .filter(|value| !value.is_empty());
        let home = home.context("home directory is not set; cannot locate configuration")?;
        Ok(PathBuf::from(home).join(".astatine"))
    }
}

#[cfg(target_os = "windows")]
fn windows_config_dir(app_data: Option<&std::ffi::OsStr>) -> Result<PathBuf> {
    let app_data = app_data
        .filter(|value| !value.is_empty())
        .context("APPDATA is not set; cannot locate the user configuration directory")?;
    let app_data = PathBuf::from(app_data);
    if !app_data.is_absolute() {
        bail!("APPDATA must be an absolute user configuration directory");
    }
    Ok(app_data.join("Astatine"))
}

#[cfg(all(unix, any(not(target_os = "macos"), test)))]
fn xdg_config_dir(
    config_home: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Result<PathBuf> {
    if let Some(config_home) = config_home.filter(|value| !value.is_empty()) {
        let config_home = PathBuf::from(config_home);
        if config_home.is_absolute() {
            return Ok(config_home.join("astatine"));
        }
    }
    let home = home
        .filter(|value| !value.is_empty())
        .context("HOME is not set; cannot locate the user configuration directory")?;
    Ok(PathBuf::from(home).join(".config").join("astatine"))
}

pub fn conservative_thread_budget() -> usize {
    std::thread::available_parallelism()
        .map(|available| (available.get() / 2).clamp(1, 256))
        .unwrap_or(1)
}

/// Parse a finite, non-negative decimal INJ amount without floating-point rounding.
pub fn parse_inj_wei(amount: &str) -> Result<U256> {
    if amount.is_empty() || amount.starts_with(['+', '-']) || amount.trim() != amount {
        bail!("invalid decimal amount");
    }
    let mut parts = amount.split('.');
    let whole = parts.next().unwrap_or_default();
    let fractional = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
        || fractional.len() > 18
    {
        bail!("invalid decimal amount");
    }
    let whole = U256::from_str(whole).context("whole INJ amount is out of range")?;
    let mut fractional_padded = fractional.to_owned();
    fractional_padded.extend(std::iter::repeat_n('0', 18 - fractional.len()));
    let fractional = if fractional_padded.is_empty() {
        U256::ZERO
    } else {
        U256::from_str(&fractional_padded).context("fractional INJ amount is invalid")?
    };
    whole
        .checked_mul(U256::from(WEI_PER_INJ))
        .and_then(|base| base.checked_add(fractional))
        .context("INJ amount is out of range")
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(path).context("create private storage directory")?;
        }
        Err(error) => return Err(error).context("inspect private storage directory"),
    }
    let metadata = fs::symlink_metadata(path).context("recheck sensitive storage directory")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("sensitive storage path is not a real directory; refusing to follow it");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            bail!("sensitive storage path is a Windows reparse point; refusing to follow it");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .context("open sensitive storage directory without following symlinks")?;
        if !directory
            .metadata()
            .context("inspect opened storage directory")?
            .is_dir()
        {
            bail!("sensitive storage path changed and is no longer a directory");
        }
        directory
            .set_permissions(fs::Permissions::from_mode(0o700))
            .context("restrict private storage directory permissions")?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)
}

#[cfg(windows)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::{os::windows::ffi::OsStrExt, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::CreateDirectoryW,
    };

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !windows_reparse_point(&metadata) => return Ok(()),
        Ok(_) => return Err(std::io::ErrorKind::AlreadyExists.into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        match fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.is_dir() && !windows_reparse_point(&metadata) => {}
            Ok(_) => return Err(std::io::ErrorKind::NotADirectory.into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_directory(parent)?;
            }
            Err(error) => return Err(error),
        }
    }

    struct LocalDescriptor(*mut core::ffi::c_void);
    impl Drop for LocalDescriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    // Set the protected DACL atomically at creation; standard users cannot
    // reliably rewrite an inherited DACL after creating a directory.
    let security_sddl = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            security_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let descriptor = LocalDescriptor(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(windows)]
fn windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
}

/// Read a regular file through a no-follow handle and enforce a hard size limit.
pub(crate) fn read_regular_limited(
    path: &Path,
    maximum: u64,
    restrict_windows_permissions: bool,
) -> Result<Vec<u8>> {
    let file = open_regular_file(path, restrict_windows_permissions)?;
    let metadata = file.metadata().context("inspect opened file")?;
    if metadata.len() > maximum {
        bail!("file exceeds the supported size limit");
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut contents)
        .context("read opened file")?;
    if contents.len() as u64 > maximum {
        bail!("file exceeds the supported size limit");
    }
    Ok(contents)
}

fn open_regular_file(path: &Path, _restrict_windows_permissions: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        };
        options
            .access_mode(FILE_GENERIC_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .context("open regular file without following links")?;
    let metadata = file.metadata().context("inspect opened file")?;
    if !metadata.is_file() {
        bail!("path is not a regular file; refusing to follow it");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            bail!("path is a Windows reparse point; refusing to follow it");
        }
    }
    Ok(file)
}

fn atomic_write(path: &Path, data: &[u8], replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .context("destination has no parent directory")?;
    ensure_private_directory(parent)?;
    let mut temporary = NamedTempFile::new_in(parent).context("create private temporary file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .context("restrict temporary file permissions")?;
    }
    #[cfg(test)]
    fail_atomic_write_if_requested(path, AtomicWriteFailPoint::BeforeWrite)?;
    temporary.write_all(data).context("write staged file")?;
    #[cfg(test)]
    fail_atomic_write_if_requested(path, AtomicWriteFailPoint::BeforeFileSync)?;
    temporary
        .as_file()
        .sync_all()
        .context("flush staged file")?;
    #[cfg(test)]
    fail_atomic_write_if_requested(path, AtomicWriteFailPoint::BeforeRename)?;
    #[cfg(all(test, unix))]
    if let Some(ready) = TEST_ATOMIC_WRITE_PAUSE
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| anyhow!("test atomic-write pause mutex was poisoned"))?
        .remove(path)
    {
        fs::write(ready, b"staged file synced; rename not started")?;
        loop {
            std::thread::park();
        }
    }
    if replace {
        persist_replace(temporary, path)?;
    } else {
        persist_create(temporary, path)?;
    }
    #[cfg(test)]
    fail_atomic_write_if_requested(path, AtomicWriteFailPoint::AfterRename)?;
    #[cfg(test)]
    fail_atomic_write_if_requested(path, AtomicWriteFailPoint::BeforeDirectorySync)?;
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("flush containing directory")?;
    #[cfg(test)]
    fail_atomic_write_if_requested(path, AtomicWriteFailPoint::AfterDirectorySync)?;
    Ok(())
}

#[cfg(test)]
fn fail_atomic_write_if_requested(path: &Path, point: AtomicWriteFailPoint) -> Result<()> {
    let mut failures = TEST_ATOMIC_WRITE_FAILURES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| anyhow!("test atomic-write failure mutex was poisoned"))?;
    if failures.get(path) == Some(&point) {
        failures.remove(path);
        bail!("injected atomic-write failure at {point:?}");
    }
    Ok(())
}

#[cfg(test)]
fn take_archive_tamper_point(root: &Path, expected: ArchiveTamperPoint) -> Result<bool> {
    let mut points = TEST_ARCHIVE_TAMPER_POINTS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| anyhow!("test archive-tamper mutex was poisoned"))?;
    if points.get(root) == Some(&expected) {
        points.remove(root);
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
fn tamper_archive_for_test(path: &Path) -> Result<()> {
    let mut contents = fs::read(path).context("read archive for injected test tampering")?;
    let first = contents
        .first_mut()
        .context("archive test fixture unexpectedly has no bytes")?;
    *first ^= 1;
    fs::write(path, contents).context("write injected archive test tampering")
}

fn persist_replace(file: NamedTempFile, path: &Path) -> Result<()> {
    file.persist(path)
        .map(|_| ())
        .map_err(|error| persist_error(error, "replace destination"))
}

fn persist_create(file: NamedTempFile, path: &Path) -> Result<()> {
    file.persist_noclobber(path)
        .map(|_| ())
        .map_err(|error| persist_error(error, "create destination"))
}

fn persist_error(error: PersistError, operation: &str) -> anyhow::Error {
    anyhow::Error::new(error.error).context(format!("cannot {operation} atomically"))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::read_regular_limited;
    #[cfg(windows)]
    use super::windows_config_dir;
    #[cfg(unix)]
    use super::xdg_config_dir;
    use super::{AppConfig, ConfigStore, parse_inj_wei, validate_rpc_url};
    use crate::cli::Network;
    use alloy_primitives::U256;
    use std::{ffi::OsStr, path::PathBuf};

    #[cfg(unix)]
    struct JournalLockRetryHookGuard;

    #[cfg(unix)]
    impl Drop for JournalLockRetryHookGuard {
        fn drop(&mut self) {
            super::JOURNAL_LOCK_RETRY_TEST_HOOK.with(|hook| {
                hook.borrow_mut().take();
            });
        }
    }

    #[cfg(unix)]
    fn install_journal_lock_retry_hook(hook: impl FnMut() + 'static) -> JournalLockRetryHookGuard {
        super::JOURNAL_LOCK_RETRY_TEST_HOOK.with(|slot| {
            assert!(
                slot.borrow_mut().replace(Box::new(hook)).is_none(),
                "journal lock retry hooks cannot be nested"
            );
        });
        JournalLockRetryHookGuard
    }

    fn child_test_evidence(child: &std::process::Output) -> Result<(), String> {
        let stdout = String::from_utf8_lossy(&child.stdout);
        let stderr = String::from_utf8_lossy(&child.stderr);
        if !child.status.success() {
            return Err(format!(
                "child process failed with {}\nstdout: {stdout}\nstderr: {stderr}",
                child.status
            ));
        }
        if !stdout.contains("running 1 test") {
            return Err(format!(
                "child did not execute exactly one test\nstdout: {stdout}\nstderr: {stderr}"
            ));
        }
        if !stdout.contains("1 passed") {
            return Err(format!(
                "child did not report one passed test\nstdout: {stdout}\nstderr: {stderr}"
            ));
        }
        Ok(())
    }

    fn assert_child_executed_one_test(child: &std::process::Output, context: &str) {
        if let Err(details) = child_test_evidence(child) {
            panic!("{context}: {details}");
        }
    }

    #[cfg(unix)]
    fn run_child_with_timeout(
        mut command: std::process::Command,
        timeout: std::time::Duration,
        context: &str,
    ) -> std::process::Output {
        command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().unwrap();
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "{context} did not finish within {timeout:?}; stdout={:?} stderr={:?}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        child.wait_with_output().unwrap()
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn guard_child_output(
        test_name: &str,
        root_env: &str,
        root: &std::path::Path,
        marker: Option<&str>,
        mode: Option<&str>,
    ) -> std::process::Output {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--ignored", "--exact", test_name, "--nocapture"])
            .env(root_env, root)
            .env("HOME", root)
            .env("XDG_CONFIG_HOME", root)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/definitely-unavailable-astatine-test-bus",
            );
        match marker {
            Some(value) => {
                command.env(DISPOSABLE_CREDENTIAL_STORE_ENV, value);
            }
            None => {
                command.env_remove(DISPOSABLE_CREDENTIAL_STORE_ENV);
            }
        }
        match mode {
            Some(value) => {
                command.env("ASTATINE_QUALIFICATION_MODE", value);
            }
            None => {
                command.env_remove("ASTATINE_QUALIFICATION_MODE");
            }
        }
        command.output().unwrap()
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn assert_guard_failure(child: &std::process::Output, expected: &str, context: &str) {
        assert!(
            !child.status.success(),
            "{context}: child unexpectedly succeeded; stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        let stderr = String::from_utf8_lossy(&child.stderr);
        assert!(
            stderr.contains(expected),
            "{context}: missing guard message {expected:?}; stderr={stderr:?}"
        );
    }

    #[cfg(target_os = "linux")]
    fn gdbus_output(arguments: &[&str]) -> String {
        let output = std::process::Command::new("gdbus")
            .args(arguments)
            .output()
            .expect("Linux qualification requires gdbus");
        assert!(
            output.status.success(),
            "gdbus failed: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    #[cfg(target_os = "linux")]
    fn assert_ambient_secret_service_qualification_state() {
        let mode = ambient_secret_service_qualification_mode();
        let owned = || {
            gdbus_output(&[
                "call",
                "--session",
                "--dest",
                "org.freedesktop.DBus",
                "--object-path",
                "/org/freedesktop/DBus",
                "--method",
                "org.freedesktop.DBus.NameHasOwner",
                "org.freedesktop.secrets",
            ])
            .contains("true")
        };
        match mode.as_str() {
            "locked" => {
                assert!(owned(), "locked mode requires an owned Secret Service");
                let alias = gdbus_output(&[
                    "call",
                    "--session",
                    "--dest",
                    "org.freedesktop.secrets",
                    "--object-path",
                    "/org/freedesktop/secrets",
                    "--method",
                    "org.freedesktop.Secret.Service.ReadAlias",
                    "default",
                ]);
                let path = alias
                    .split("objectpath '")
                    .nth(1)
                    .and_then(|value| value.split('\'').next())
                    .filter(|value| !value.is_empty())
                    .expect("locked mode requires a default Secret Service collection");
                let locked = gdbus_output(&[
                    "call",
                    "--session",
                    "--dest",
                    "org.freedesktop.secrets",
                    "--object-path",
                    path,
                    "--method",
                    "org.freedesktop.DBus.Properties.Get",
                    "org.freedesktop.Secret.Collection",
                    "Locked",
                ]);
                assert!(
                    locked.contains("true"),
                    "locked mode requires the default collection to report Locked=true: {locked:?}"
                );
            }
            "missing" => {
                assert!(
                    !owned(),
                    "missing mode must not have an owned Secret Service"
                );
            }
            other => panic!("unsupported ambient Secret Service mode: {other}"),
        }
    }

    fn require_native_credential_store(value: Option<&OsStr>) -> bool {
        value.is_some_and(|value| !value.is_empty())
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn native_persistence_parent_requires_provider_mode_before_store_access() {
        let root = tempfile::tempdir().unwrap();
        let child = guard_child_output(
            "config::tests::native_journal_anchor_persists_across_processes_and_is_root_scoped",
            NATIVE_ANCHOR_CHILD_ROOT_ENV,
            root.path(),
            Some("1"),
            Some("missing"),
        );
        assert_guard_failure(
            &child,
            "require ASTATINE_QUALIFICATION_MODE=provider",
            "native persistence parent in missing mode",
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn native_anchor_child_requires_exact_marker_and_provider_mode_before_store_access() {
        let root = tempfile::tempdir().unwrap();
        let marker_zero = guard_child_output(
            "config::tests::native_anchor_child_reads_secret",
            NATIVE_ANCHOR_CHILD_ROOT_ENV,
            root.path(),
            Some("0"),
            Some("provider"),
        );
        assert_guard_failure(
            &marker_zero,
            "without ASTATINE_DISPOSABLE_CREDENTIAL_STORE=1",
            "native child with marker 0",
        );
        let wrong_mode = guard_child_output(
            "config::tests::native_anchor_child_reads_secret",
            NATIVE_ANCHOR_CHILD_ROOT_ENV,
            root.path(),
            Some("1"),
            Some("missing"),
        );
        assert_guard_failure(
            &wrong_mode,
            "require ASTATINE_QUALIFICATION_MODE=provider",
            "native child in missing mode",
        );
    }

    #[test]
    fn native_store_requirement_is_presence_of_a_nonempty_value() {
        assert!(!require_native_credential_store(None));
        assert!(!require_native_credential_store(Some(OsStr::new(""))));
        assert!(require_native_credential_store(Some(OsStr::new("1"))));
        assert!(require_native_credential_store(Some(OsStr::new("0"))));
        assert!(require_native_credential_store(Some(OsStr::new("true"))));
    }

    #[test]
    fn child_test_evidence_rejects_a_zero_test_exit() {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "config::tests::definitely_not_a_real_test_name"])
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "the test harness must exit zero when it runs zero tests"
        );
        let error = child_test_evidence(&child)
            .expect_err("a zero-test child must not satisfy the evidence guard");
        assert!(
            error.contains("did not execute exactly one test"),
            "unexpected evidence error: {error}"
        );
    }

    #[test]
    fn child_test_evidence_accepts_a_single_test_run() {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "config::tests::decimal_inj_conversion_is_exact"])
            .output()
            .unwrap();
        assert_child_executed_one_test(&child, "single-test evidence");
    }

    #[test]
    #[ignore = "child-harness smoke test; does not access a credential store"]
    fn ignored_child_harness_smoke() {
        if std::env::var_os("ASTATINE_IGNORED_CHILD_HARNESS_SMOKE").is_some() {
            eprintln!("ignored-child-harness-smoke-ran");
        }
    }

    #[test]
    fn ignored_child_harness_smoke_runs_with_ignored_flag_without_keyring_access() {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "config::tests::ignored_child_harness_smoke",
                "--nocapture",
            ])
            .env("ASTATINE_IGNORED_CHILD_HARNESS_SMOKE", "1")
            .output()
            .unwrap();
        assert_child_executed_one_test(&child, "ignored child-harness smoke");
        assert!(
            String::from_utf8_lossy(&child.stderr).contains("ignored-child-harness-smoke-ran"),
            "the ignored child harness must execute the test body, not zero tests: {}",
            String::from_utf8_lossy(&child.stderr)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn native_anchor_child_probe_fails_closed_without_parent_environment() {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "config::tests::native_anchor_child_reads_secret",
            ])
            .env_remove(NATIVE_ANCHOR_CHILD_ROOT_ENV)
            .output()
            .unwrap();
        assert!(
            !child.status.success(),
            "the native anchor child probe must not silently pass without its parent environment"
        );
        let stdout = String::from_utf8_lossy(&child.stdout);
        let stderr = String::from_utf8_lossy(&child.stderr);
        assert!(
            stdout.contains("requires ASTATINE_NATIVE_ANCHOR_CHILD_ROOT"),
            "unexpected child probe output: stdout={stdout:?} stderr={stderr:?}"
        );
    }

    #[test]
    fn decimal_inj_conversion_is_exact() {
        assert_eq!(
            parse_inj_wei("0.1").unwrap(),
            U256::from(100_000_000_000_000_000u128)
        );
        assert_eq!(
            parse_inj_wei("2").unwrap(),
            U256::from(2_000_000_000_000_000_000u128)
        );
        assert_eq!(
            parse_inj_wei("0.000000000000000001").unwrap(),
            U256::from(1)
        );
        assert!(parse_inj_wei("0.0000000000000000001").is_err());
        assert!(parse_inj_wei("1e-3").is_err());
    }

    #[test]
    fn confirmation_threshold_defaults_and_is_bounded() {
        let config = AppConfig::default();
        assert_eq!(config.transaction_confirmations, 2);
        assert_eq!(config.schema_version, 2);
        assert_eq!(config.per_session_spending_limit_inj, "1");
        assert!(config.per_run_sessions_enabled());
        assert!(config.validate().is_ok());
        let invalid = AppConfig {
            transaction_confirmations: 13,
            ..config
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn legacy_config_and_network_scoped_rpc_overrides_are_backward_compatible() {
        let legacy: AppConfig = toml::from_str(
            r#"
schema_version = 1
network = "testnet"
wallet_address = "0x0000000000000000000000000000000000000001"
cpu_threads = 2
minimum_reserve_inj = "0.1"
per_session_spending_limit_inj = "0"
transaction_confirmations = 2
"#,
        )
        .unwrap();
        assert!(!legacy.per_run_sessions_enabled());
        assert_eq!(legacy.rpc_override(Network::Testnet), None);
        assert_eq!(legacy.rpc_override(Network::Mainnet), None);

        let temporary = tempfile::tempdir().unwrap();
        let store = ConfigStore::at_root(temporary.path().join("config"));
        let mut config = AppConfig::default();
        config.set_rpc_override(
            Network::Testnet,
            Some("https://rpc.test.example/v1/private-token?key=secret".to_owned()),
        );
        store.save(&config).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(
            loaded.rpc_override(Network::Testnet),
            Some("https://rpc.test.example/v1/private-token?key=secret")
        );
        assert_eq!(loaded.rpc_override(Network::Mainnet), None);
    }

    #[test]
    fn rpc_url_transport_and_credential_rules_allow_only_local_http() {
        for url in [
            "https://rpc.example.org/evm",
            "http://localhost:8545",
            "http://127.0.0.1:8545",
            "http://[::1]:8545",
        ] {
            assert!(validate_rpc_url(url).is_ok(), "{url}");
        }
        for url in [
            "http://rpc.example.org/evm",
            "ftp://rpc.example.org/evm",
            "https://user:pass@rpc.example.org/evm",
            "https://rpc.example.org/evm#fragment",
            "not a URL",
        ] {
            let error = validate_rpc_url(url).unwrap_err();
            assert!(
                !format!("{error:#}").contains(url),
                "RPC validation errors must not echo URL tokens"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn linux_config_directory_obeys_xdg_and_falls_back_for_relative_values() {
        assert_eq!(
            xdg_config_dir(
                Some(OsStr::new("/tmp/xdg-config")),
                Some(OsStr::new("/home/miner")),
            )
            .unwrap(),
            PathBuf::from("/tmp/xdg-config/astatine")
        );
        assert_eq!(
            xdg_config_dir(
                Some(OsStr::new("relative-config")),
                Some(OsStr::new("/home/miner")),
            )
            .unwrap(),
            PathBuf::from("/home/miner/.config/astatine")
        );
        assert!(xdg_config_dir(None, None).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_config_directory_requires_appdata() {
        assert!(windows_config_dir(None).is_err());
        assert!(windows_config_dir(Some(OsStr::new(""))).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_config_directory_uses_appdata_and_private_storage_handles_unicode_paths() {
        let app_data = OsStr::new(r"C:\Users\miner\AppData\Roaming");
        assert_eq!(
            windows_config_dir(Some(app_data)).unwrap(),
            PathBuf::from(r"C:\Users\miner\AppData\Roaming\Astatine")
        );

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("Astatine ü data");
        let store = ConfigStore::at_root(root);
        let config = AppConfig {
            network: Network::Testnet,
            ..AppConfig::default()
        };
        store.save(&config).unwrap();
        assert_eq!(store.load().unwrap(), config);

        let address = alloy_primitives::Address::with_last_byte(0x42);
        store
            .store_keystore(address, b"private-keystore-bytes")
            .unwrap();
        assert_eq!(
            store.read_keystore(address).unwrap(),
            b"private-keystore-bytes"
        );

        let first_lock = store.lock_transaction_journal().unwrap();
        assert!(store.lock_transaction_journal().is_err());
        drop(first_lock);
        assert!(store.lock_transaction_journal().is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_point_storage_roots_are_rejected() {
        use std::process::Command;

        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target");
        let junction = temporary.path().join("private-root-junction");
        std::fs::create_dir(&target).unwrap();
        let result = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "could not create test junction: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            ConfigStore::at_root(junction)
                .save(&AppConfig::default())
                .is_err()
        );
    }

    const NATIVE_ANCHOR_TEST_SECRET: &[u8] = b"disposable-native-journal-anchor-test";
    const NATIVE_ANCHOR_CHILD_ROOT_ENV: &str = "ASTATINE_NATIVE_ANCHOR_CHILD_ROOT";
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    const DISPOSABLE_CREDENTIAL_STORE_ENV: &str = "ASTATINE_DISPOSABLE_CREDENTIAL_STORE";

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn require_disposable_credential_store() {
        assert_eq!(
            std::env::var(DISPOSABLE_CREDENTIAL_STORE_ENV).as_deref(),
            Ok("1"),
            "refusing to access a native credential store without {DISPOSABLE_CREDENTIAL_STORE_ENV}=1; run through support/linux/run-private-session.sh or set the marker only for a disposable store"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn require_disposable_provider_mode() {
        require_disposable_credential_store();
        assert_eq!(
            std::env::var("ASTATINE_QUALIFICATION_MODE").as_deref(),
            Ok("provider"),
            "native credential-store tests require ASTATINE_QUALIFICATION_MODE=provider"
        );
    }

    #[cfg(target_os = "linux")]
    fn require_disposable_missing_mode() {
        require_disposable_credential_store();
        assert_eq!(
            std::env::var("ASTATINE_QUALIFICATION_MODE").as_deref(),
            Ok("missing"),
            "unavailable Secret Service tests require ASTATINE_QUALIFICATION_MODE=missing"
        );
    }

    #[cfg(target_os = "linux")]
    fn ambient_secret_service_qualification_mode() -> String {
        require_disposable_credential_store();
        let mode = std::env::var("ASTATINE_QUALIFICATION_MODE").expect(
            "ambient Secret Service qualification requires ASTATINE_QUALIFICATION_MODE=locked or missing",
        );
        assert!(
            mode == "locked" || mode == "missing",
            "ambient Secret Service qualification only permits locked or missing mode, got {mode:?}"
        );
        mode
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    #[ignore = "child probe; invoked by native_journal_anchor_persists_across_processes_and_is_root_scoped"]
    fn native_anchor_child_reads_secret() {
        let root = std::env::var_os(NATIVE_ANCHOR_CHILD_ROOT_ENV).expect(
            "native anchor child probe requires ASTATINE_NATIVE_ANCHOR_CHILD_ROOT from its parent test",
        );
        require_disposable_provider_mode();
        let store = ConfigStore::at_root(PathBuf::from(root));
        let secret = store
            .read_journal_anchor_from_os_for_test()
            .expect("child process could not read the disposable OS credential")
            .expect("disposable OS credential was absent in the child process");
        assert_eq!(&secret[..], NATIVE_ANCHOR_TEST_SECRET);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child probe; invoked by native_journal_anchor_persists_across_processes_and_is_root_scoped"]
    fn native_anchor_child_rejects_unavailable_store() {
        let root = std::env::var_os(NATIVE_ANCHOR_CHILD_ROOT_ENV).expect(
            "native anchor unavailable child probe requires ASTATINE_NATIVE_ANCHOR_CHILD_ROOT from its parent test",
        );
        require_disposable_missing_mode();
        let store = ConfigStore::at_root(PathBuf::from(root));
        let error = store
            .read_journal_anchor_from_os_for_test()
            .expect_err("an unavailable Secret Service must fail closed, not look empty");
        assert!(
            !format!("{error:#}").is_empty(),
            "an unavailable credential store must return a useful error"
        );
        assert!(
            store
                .write_journal_anchor_to_os_for_test(NATIVE_ANCHOR_TEST_SECRET)
                .is_err(),
            "an unavailable Secret Service must reject checkpoint writes"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    #[ignore = "requires a native OS credential store; run explicitly on a provider-equipped host"]
    fn native_journal_anchor_persists_across_processes_and_is_root_scoped() {
        require_disposable_provider_mode();
        struct DeleteCredentialOnDrop(keyring::Entry);
        impl Drop for DeleteCredentialOnDrop {
            fn drop(&mut self) {
                let _ = self.0.delete_credential();
            }
        }

        let root_a = tempfile::tempdir().unwrap();
        let root_b = tempfile::tempdir().unwrap();
        let store_a = ConfigStore::at_root(root_a.path().to_path_buf());
        let store_b = ConfigStore::at_root(root_b.path().to_path_buf());
        assert_ne!(
            store_a.journal_anchor_account().unwrap(),
            store_b.journal_anchor_account().unwrap(),
            "separate canonical data roots must use separate credential entries"
        );

        // Any non-empty value is an explicit requirement. Unset or empty lets
        // the test report an unavailable native store without failing, while a
        // required store must fail on entry construction, read, or write.
        let require_native = require_native_credential_store(
            std::env::var_os("ASTATINE_REQUIRE_NATIVE_CREDENTIAL_STORE").as_deref(),
        );

        #[cfg(target_os = "linux")]
        {
            let unavailable_root = tempfile::tempdir().unwrap();
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "config::tests::native_anchor_child_rejects_unavailable_store",
                ])
                .env(NATIVE_ANCHOR_CHILD_ROOT_ENV, unavailable_root.path())
                .env(DISPOSABLE_CREDENTIAL_STORE_ENV, "1")
                .env("ASTATINE_QUALIFICATION_MODE", "missing")
                .env(
                    "DBUS_SESSION_BUS_ADDRESS",
                    "unix:path=/definitely-unavailable-astatine-test-bus",
                )
                .output()
                .unwrap();
            assert_child_executed_one_test(&child, "headless Secret Service fail-closed child");
        }

        let credential = match store_a.journal_anchor_entry() {
            Ok(credential) => credential,
            Err(error) => {
                let app_error = store_a.read_journal_anchor_from_os_for_test().expect_err(
                    "entry construction failed but the platform read did not fail closed",
                );
                assert!(
                    !format!("{app_error:#}").is_empty(),
                    "OS credential-store access failures must propagate instead of falling back"
                );
                if require_native {
                    panic!("required native credential store is unavailable: {error:#}");
                }
                eprintln!(
                    "native credential store unavailable; production-equivalent reads failed closed: {error:#}"
                );
                return;
            }
        };
        let _cleanup = DeleteCredentialOnDrop(credential);

        match _cleanup.0.get_secret() {
            Err(keyring::Error::NoEntry) => {}
            Err(error) => {
                let app_error = store_a.read_journal_anchor_from_os_for_test().expect_err(
                    "credential-store access failed but the platform read did not fail closed",
                );
                assert!(
                    !format!("{app_error:#}").is_empty(),
                    "OS credential-store access failures must propagate instead of falling back"
                );
                if require_native {
                    panic!("required native credential store is unavailable: {error}");
                }
                eprintln!(
                    "native credential store unavailable; production-equivalent reads failed closed: {error}"
                );
                return;
            }
            Ok(_) => {
                panic!("unique temporary data-root credential unexpectedly already exists")
            }
        }

        eprintln!(
            "native credential store is available; checking persistent writes and data-root isolation"
        );
        let secret = super::Zeroizing::new(NATIVE_ANCHOR_TEST_SECRET.to_vec());
        if let Err(error) = store_a.write_journal_anchor_to_os_for_test(&secret) {
            let app_error = store_a.read_journal_anchor_from_os_for_test().expect_err(
                "credential-store write failed but the platform read did not fail closed",
            );
            assert!(
                !format!("{app_error:#}").is_empty(),
                "failed OS credential writes must propagate instead of falling back"
            );
            if require_native {
                panic!(
                    "required native credential store could not write a disposable entry: {error}"
                );
            }
            eprintln!(
                "native credential store could not write; production-equivalent operations failed closed: {error}"
            );
            return;
        }

        assert_eq!(
            &store_a
                .read_journal_anchor_from_os_for_test()
                .unwrap()
                .unwrap()[..],
            NATIVE_ANCHOR_TEST_SECRET
        );
        assert!(
            store_b
                .read_journal_anchor_from_os_for_test()
                .unwrap()
                .is_none()
        );
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "config::tests::native_anchor_child_reads_secret",
            ])
            .env(NATIVE_ANCHOR_CHILD_ROOT_ENV, root_a.path())
            .env(DISPOSABLE_CREDENTIAL_STORE_ENV, "1")
            .env("ASTATINE_QUALIFICATION_MODE", "provider")
            .output()
            .unwrap();
        assert_child_executed_one_test(&child, "native credential-store restart child");
    }

    #[cfg(target_os = "linux")]
    const LINUX_SECRET_SERVICE_CHILD_ROOT_ENV: &str = "ASTATINE_LINUX_SECRET_SERVICE_CHILD_ROOT";

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child probe; invoked by linux_secret_service_unavailable_fails_closed_without_native_keyring"]
    fn linux_secret_service_unavailable_child_probe() {
        let root = std::env::var_os(LINUX_SECRET_SERVICE_CHILD_ROOT_ENV).expect(
            "Linux Secret Service child probe requires ASTATINE_LINUX_SECRET_SERVICE_CHILD_ROOT from its parent test",
        );
        require_disposable_missing_mode();
        let store = ConfigStore::at_root(PathBuf::from(root));
        let read_error = store
            .read_journal_anchor_from_os_for_test()
            .expect_err("an unavailable Secret Service must fail closed, not look empty");
        assert!(
            !format!("{read_error:#}").is_empty(),
            "an unavailable credential store must return a useful error"
        );
        assert!(
            store
                .write_journal_anchor_to_os_for_test(b"must-not-persist")
                .is_err(),
            "an unavailable Secret Service must reject checkpoint writes"
        );
        assert!(
            store.read_transaction_journal().unwrap().is_none(),
            "a failed inspection must not create or fall back to a plaintext journal"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_secret_service_child_probe_fails_closed_without_parent_environment() {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "config::tests::linux_secret_service_unavailable_child_probe",
            ])
            .env_remove(LINUX_SECRET_SERVICE_CHILD_ROOT_ENV)
            .output()
            .unwrap();
        assert!(
            !child.status.success(),
            "the Linux Secret Service child probe must not silently pass without its parent environment"
        );
        let stdout = String::from_utf8_lossy(&child.stdout);
        let stderr = String::from_utf8_lossy(&child.stderr);
        assert!(
            stdout.contains("requires ASTATINE_LINUX_SECRET_SERVICE_CHILD_ROOT"),
            "unexpected child probe output: stdout={stdout:?} stderr={stderr:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unavailable_store_children_require_exact_marker_and_missing_mode() {
        let root = tempfile::tempdir().unwrap();
        let native_wrong_mode = guard_child_output(
            "config::tests::native_anchor_child_rejects_unavailable_store",
            NATIVE_ANCHOR_CHILD_ROOT_ENV,
            root.path(),
            Some("1"),
            Some("provider"),
        );
        assert_guard_failure(
            &native_wrong_mode,
            "require ASTATINE_QUALIFICATION_MODE=missing",
            "native unavailable child in provider mode",
        );
        let linux_marker_zero = guard_child_output(
            "config::tests::linux_secret_service_unavailable_child_probe",
            LINUX_SECRET_SERVICE_CHILD_ROOT_ENV,
            root.path(),
            Some("0"),
            Some("missing"),
        );
        assert_guard_failure(
            &linux_marker_zero,
            "without ASTATINE_DISPOSABLE_CREDENTIAL_STORE=1",
            "Linux unavailable child with marker 0",
        );
        let linux_wrong_mode = guard_child_output(
            "config::tests::linux_secret_service_unavailable_child_probe",
            LINUX_SECRET_SERVICE_CHILD_ROOT_ENV,
            root.path(),
            Some("1"),
            Some("provider"),
        );
        assert_guard_failure(
            &linux_wrong_mode,
            "require ASTATINE_QUALIFICATION_MODE=missing",
            "Linux unavailable child in provider mode",
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn untrusted_store_child_requires_locked_or_missing_mode() {
        let root = tempfile::tempdir().unwrap();
        let child = guard_child_output(
            "config::tests::linux_secret_service_untrusted_child_probe",
            LINUX_SECRET_SERVICE_CHILD_ROOT_ENV,
            root.path(),
            Some("1"),
            Some("provider"),
        );
        assert_guard_failure(
            &child,
            "only permits locked or missing",
            "untrusted child in provider mode",
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_secret_service_unavailable_fails_closed_without_native_keyring() {
        let root = tempfile::tempdir().unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "config::tests::linux_secret_service_unavailable_child_probe",
                "--nocapture",
            ])
            .env(LINUX_SECRET_SERVICE_CHILD_ROOT_ENV, root.path())
            .env(DISPOSABLE_CREDENTIAL_STORE_ENV, "1")
            .env("ASTATINE_QUALIFICATION_MODE", "missing")
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/definitely-unavailable-astatine-test-bus",
            )
            .env("HOME", root.path())
            .env("XDG_CONFIG_HOME", root.path())
            .output()
            .unwrap();
        assert_child_executed_one_test(&child, "isolated Linux Secret Service failure child");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "child probe; invoked by linux_secret_service_untrusted_on_ambient_bus_fails_closed"]
    fn linux_secret_service_untrusted_child_probe() {
        let root = std::env::var_os(LINUX_SECRET_SERVICE_CHILD_ROOT_ENV).expect(
            "Linux Secret Service untrusted child probe requires ASTATINE_LINUX_SECRET_SERVICE_CHILD_ROOT from its parent test",
        );
        ambient_secret_service_qualification_mode();
        let store = ConfigStore::at_root(PathBuf::from(root));
        struct DeleteSyntheticEntry(Option<keyring::Entry>);
        impl Drop for DeleteSyntheticEntry {
            fn drop(&mut self) {
                if let Some(entry) = self.0.take() {
                    let _ = entry.delete_credential();
                }
            }
        }
        let _cleanup = DeleteSyntheticEntry(store.journal_anchor_entry().ok());
        if let Ok(Some(_)) = store.read_journal_anchor_from_os_for_test() {
            panic!("a locked or unavailable Secret Service exposed a checkpoint secret")
        }
        let write_error = store
            .write_journal_anchor_to_os_for_test(b"must-not-persist")
            .expect_err("a locked or unavailable Secret Service must reject checkpoint writes");
        drop(_cleanup);
        assert!(
            !format!("{write_error:#}").is_empty(),
            "a rejected checkpoint write must return a useful error"
        );
        assert!(
            store.read_transaction_journal().unwrap().is_none(),
            "a rejected checkpoint write must not create a plaintext transaction journal"
        );
        eprintln!("linux-secret-service-untrusted-child-fail-closed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a private ambient D-Bus fixture without an unlocked Secret Service; run only from Linux qualification"]
    fn linux_secret_service_untrusted_on_ambient_bus_fails_closed() {
        assert_ambient_secret_service_qualification_state();
        let root = tempfile::tempdir().unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "config::tests::linux_secret_service_untrusted_child_probe",
                "--nocapture",
            ])
            .env(LINUX_SECRET_SERVICE_CHILD_ROOT_ENV, root.path())
            .env(DISPOSABLE_CREDENTIAL_STORE_ENV, "1")
            .env(
                "ASTATINE_QUALIFICATION_MODE",
                std::env::var("ASTATINE_QUALIFICATION_MODE").unwrap(),
            )
            .env("HOME", root.path())
            .env("XDG_CONFIG_HOME", root.path());
        let child = run_child_with_timeout(
            command,
            std::time::Duration::from_secs(15),
            "ambient-bus Secret Service fail-closed child",
        );
        assert_child_executed_one_test(&child, "ambient-bus Secret Service fail-closed child");
        assert!(
            String::from_utf8_lossy(&child.stderr)
                .contains("linux-secret-service-untrusted-child-fail-closed"),
            "the child must execute the fail-closed assertions: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
    }

    #[test]
    fn config_round_trip_preserves_wallet_when_network_changes() {
        let root =
            std::env::temp_dir().join(format!("astatine-config-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = ConfigStore::at_root(PathBuf::from(&root));
        let mut config = AppConfig {
            wallet_address: Some("0x0000000000000000000000000000000000000001".to_owned()),
            ..AppConfig::default()
        };
        store.save(&config).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(root.join("config.toml"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        config.network = Network::Mainnet;
        store.save(&config).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.network, Network::Mainnet);
        assert_eq!(loaded.wallet_address, config.wallet_address);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_file_reads_do_not_follow_symlinks() {
        let root =
            std::env::temp_dir().join(format!("astatine-symlink-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("target.json");
        let symlink = root.join("wallet.json");
        std::fs::write(&target, b"encrypted test data").unwrap();
        std::os::unix::fs::symlink(&target, &symlink).unwrap();

        assert!(read_regular_limited(&symlink, 1_024, false).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_storage_root_does_not_follow_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target");
        let linked_root = temporary.path().join("linked-root");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &linked_root).unwrap();

        let store = ConfigStore::at_root(linked_root);
        assert!(store.prepare_wallet_dir().is_err());
        assert!(!target.join("wallets").exists());
    }

    #[cfg(unix)]
    #[test]
    fn journal_lock_retries_until_a_short_holder_releases() {
        let temporary = tempfile::tempdir().unwrap();
        let store = ConfigStore::at_root(temporary.path().to_path_buf());
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (released_tx, released_rx) = std::sync::mpsc::channel();
        let holder_store = store.clone();
        let holder = std::thread::spawn(move || {
            let lock = holder_store.lock_transaction_journal().unwrap();
            locked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(lock);
            released_tx.send(()).unwrap();
        });
        locked_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let retry_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let observed_retries = std::sync::Arc::clone(&retry_count);
        let _retry_hook = install_journal_lock_retry_hook(move || {
            let retry = observed_retries.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if retry == 1 {
                release_tx.send(()).unwrap();
                released_rx
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .expect("holder must release the lock before the next attempt");
            }
        });
        let acquired = store.lock_transaction_journal();
        drop(_retry_hook);
        assert!(
            (1..=super::JOURNAL_LOCK_RETRY_ATTEMPTS)
                .contains(&retry_count.load(std::sync::atomic::Ordering::SeqCst)),
            "a short holder must be released on the first retry and acquired within the bound"
        );
        holder.join().unwrap();
        let acquired = acquired.expect("lock should be acquired after a short holder releases");
        drop(acquired);
    }

    #[cfg(unix)]
    #[test]
    fn journal_lock_fails_closed_when_held_beyond_the_retry_bound() {
        let temporary = tempfile::tempdir().unwrap();
        let store = ConfigStore::at_root(temporary.path().to_path_buf());
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder_store = store.clone();
        let holder = std::thread::spawn(move || {
            let lock = holder_store.lock_transaction_journal().unwrap();
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(5));
            drop(lock);
        });
        locked_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let retry_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let observed_retries = std::sync::Arc::clone(&retry_count);
        let _retry_hook = install_journal_lock_retry_hook(move || {
            observed_retries.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        let error = store.lock_transaction_journal().unwrap_err();
        drop(_retry_hook);
        assert_eq!(
            retry_count.load(std::sync::atomic::Ordering::SeqCst),
            super::JOURNAL_LOCK_RETRY_ATTEMPTS,
            "the lock must make exactly the configured number of retry attempts"
        );
        let _ = release_tx.send(());
        holder.join().unwrap();
        let error_text = format!("{error:#}");
        assert!(
            error_text.contains("another astatine mining process")
                && error_text.contains("operation would block"),
            "a held journal lock must fail closed through the bounded retry: {error_text}"
        );
        let acquired = store
            .lock_transaction_journal()
            .expect("lock should be acquirable after the holder releases");
        drop(acquired);
    }

    #[cfg(unix)]
    #[test]
    fn journal_lock_fd_is_close_on_exec() {
        use std::os::fd::AsRawFd;

        let temporary = tempfile::tempdir().unwrap();
        let store = ConfigStore::at_root(temporary.path().to_path_buf());
        let lock = store.lock_transaction_journal().unwrap();
        // SAFETY: `lock` owns a valid open descriptor.
        let flags = unsafe { libc::fcntl(lock.as_raw_fd(), libc::F_GETFD) };
        assert!(
            flags >= 0,
            "F_GETFD failed: {}",
            std::io::Error::last_os_error()
        );
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "journal lock must not survive exec"
        );
    }

    #[cfg(unix)]
    const JOURNAL_LOCK_CHILD_ROOT_ENV: &str = "ASTATINE_JOURNAL_LOCK_CHILD_ROOT";

    #[cfg(unix)]
    #[test]
    #[ignore = "child probe; invoked by journal_lock_excludes_a_second_process"]
    fn journal_lock_child_observes_contention() {
        let root = std::env::var_os(JOURNAL_LOCK_CHILD_ROOT_ENV).expect(
            "journal lock child probe requires ASTATINE_JOURNAL_LOCK_CHILD_ROOT from its parent test",
        );
        let store = ConfigStore::at_root(PathBuf::from(root));
        let error = store
            .lock_transaction_journal()
            .expect_err("a second process must not acquire a lock held by the parent process");
        let error_text = format!("{error:#}");
        assert!(
            error_text.contains("another astatine mining process")
                && error_text.contains("operation would block"),
            "a cross-process held journal lock must fail closed through the bounded retry: {error_text}"
        );
        eprintln!("journal-lock-child-observed-contention");
    }

    #[cfg(unix)]
    #[test]
    fn journal_lock_excludes_a_second_process() {
        let temporary = tempfile::tempdir().unwrap();
        let store = ConfigStore::at_root(temporary.path().to_path_buf());
        let lock = store.lock_transaction_journal().unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "config::tests::journal_lock_child_observes_contention",
                "--nocapture",
            ])
            .env(JOURNAL_LOCK_CHILD_ROOT_ENV, temporary.path());
        let child = run_child_with_timeout(
            command,
            std::time::Duration::from_secs(15),
            "cross-process journal lock contention child",
        );
        assert_child_executed_one_test(&child, "cross-process journal lock contention");
        assert!(
            String::from_utf8_lossy(&child.stderr)
                .contains("journal-lock-child-observed-contention"),
            "the child process must execute the contention assertion: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        drop(lock);
        drop(
            store
                .lock_transaction_journal()
                .expect("the parent must reacquire the lock after releasing it"),
        );
    }
}
