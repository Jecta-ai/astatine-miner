use crate::cli::Network;
use alloy_primitives::{Address, U256};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
#[cfg(any(unix, windows))]
use std::fs::File;
use std::{
    env, fs,
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};
use tempfile::{NamedTempFile, PersistError};

const CONFIG_FILE: &str = "config.toml";
const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_KEYSTORE_BYTES: u64 = 64 * 1024;
const MAX_TRANSACTION_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TRANSACTION_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024;
const WEI_PER_INJ: u128 = 1_000_000_000_000_000_000;
const DEFAULT_TRANSACTION_CONFIRMATIONS: u8 = 2;
const MAX_TRANSACTION_CONFIRMATIONS: u8 = 12;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub schema_version: u32,
    pub network: Network,
    pub wallet_address: Option<String>,
    pub cpu_threads: usize,
    pub minimum_reserve_inj: String,
    pub per_session_spending_limit_inj: String,
    #[serde(default = "default_transaction_confirmations")]
    pub transaction_confirmations: u8,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            network: Network::Testnet,
            wallet_address: None,
            cpu_threads: conservative_thread_budget(),
            minimum_reserve_inj: "0.1".to_owned(),
            per_session_spending_limit_inj: "0".to_owned(),
            transaction_confirmations: DEFAULT_TRANSACTION_CONFIRMATIONS,
        }
    }
}

impl AppConfig {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
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
        Ok(())
    }
}

fn default_transaction_confirmations() -> u8 {
    DEFAULT_TRANSACTION_CONFIRMATIONS
}

#[derive(Clone, Debug)]
pub struct ConfigStore {
    root: PathBuf,
}

impl ConfigStore {
    pub fn system_default() -> Result<Self> {
        Ok(Self {
            root: system_config_dir()?,
        })
    }

    #[cfg(test)]
    pub(crate) fn at_root(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn wallet_dir(&self) -> PathBuf {
        self.root.join("wallets")
    }

    pub fn prepare_wallet_dir(&self) -> Result<PathBuf> {
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

    pub(crate) fn write_transaction_journal(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() || data.len() as u64 > MAX_TRANSACTION_JOURNAL_BYTES {
            bail!("transaction journal is empty or exceeds its 8 MiB size limit");
        }
        let path = self.transaction_journal_path()?;
        atomic_write(&path, data, true).context("atomically write private transaction journal")
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
                    .context("atomically create private transaction archive")
            }
            Err(error) => Err(error).context("inspect private transaction archive"),
        }
    }

    pub(crate) fn read_transaction_archive(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.transaction_archive_path(name)?;
        read_regular_limited(&path, MAX_TRANSACTION_ARCHIVE_BYTES, true)
            .context("read private transaction archive")
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
            restrict_windows_acl(&file, false)?;
        }
        file.try_lock()
            .context("another astatine mining process already holds the transaction journal")?;
        Ok(file)
    }

    fn transaction_journal_path(&self) -> Result<PathBuf> {
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
        let directory = self.root.join("transactions").join("archives");
        ensure_private_directory(&directory)?;
        Ok(directory.join(name))
    }
}

fn system_config_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Some(app_data) = env::var_os("APPDATA").filter(|value| !value.is_empty()) {
            return Ok(PathBuf::from(app_data).join("Astatine"));
        }
        bail!("APPDATA is not set; cannot locate the user configuration directory");
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
        if let Some(config_home) = env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty())
        {
            let config_home = PathBuf::from(config_home);
            if config_home.is_absolute() {
                return Ok(config_home.join("astatine"));
            }
        }
        let home = env::var_os("HOME").filter(|value| !value.is_empty());
        let home =
            home.context("HOME is not set; cannot locate the user configuration directory")?;
        Ok(PathBuf::from(home).join(".config").join("astatine"))
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
    if metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
    {
        bail!("sensitive storage path is a Windows reparse point; refusing to follow it");
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
    #[cfg(windows)]
    restrict_windows_directory(path)?;
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
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

fn open_regular_file(path: &Path, restrict_windows_permissions: bool) -> Result<File> {
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
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, WRITE_DAC,
        };
        let access_mode = if restrict_windows_permissions {
            FILE_GENERIC_READ | WRITE_DAC
        } else {
            FILE_GENERIC_READ
        };
        options
            .access_mode(access_mode)
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
        if restrict_windows_permissions {
            restrict_windows_acl(&file, false)?;
        }
    }
    #[cfg(not(windows))]
    let _ = restrict_windows_permissions;

    Ok(file)
}

#[cfg(windows)]
fn restrict_windows_directory(path: &Path) -> Result<()> {
    use std::{
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        ptr::null_mut,
    };
    use windows_sys::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
        },
    };

    let path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .context("open sensitive directory without following reparse points");
    }
    let directory = unsafe { File::from_raw_handle(handle) };
    let metadata = directory
        .metadata()
        .context("inspect opened sensitive directory")?;
    use std::os::windows::fs::MetadataExt;
    if !metadata.is_dir()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    {
        bail!("sensitive storage path changed to a non-directory or reparse point");
    }
    restrict_windows_acl(&directory, true)
}

#[cfg(windows)]
fn restrict_windows_acl(file: &File, directory: bool) -> Result<()> {
    use std::{
        os::windows::io::AsRawHandle,
        ptr::{null, null_mut},
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
            SetSecurityInfo,
        },
        Security::{
            ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        },
    };

    struct LocalDescriptor(PSECURITY_DESCRIPTOR);
    impl Drop for LocalDescriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    let sddl = if directory {
        "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)"
    } else {
        "D:P(A;;FA;;;OW)(A;;FA;;;SY)"
    };
    let sddl = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("create a user-restricted Windows security descriptor");
    }
    let descriptor = LocalDescriptor(descriptor);
    let mut dacl_present = 0;
    let mut dacl: *mut ACL = null_mut();
    let mut dacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || dacl.is_null()
    {
        return Err(std::io::Error::last_os_error()).context("read the Windows storage DACL");
    }
    let result = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result as i32))
            .context("restrict Windows storage access to the owner and SYSTEM");
    }
    Ok(())
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
    #[cfg(windows)]
    {
        drop(open_regular_file(temporary.path(), true)?);
    }
    temporary.write_all(data).context("write staged file")?;
    temporary
        .as_file()
        .sync_all()
        .context("flush staged file")?;
    if replace {
        persist_replace(temporary, path)?;
    } else {
        persist_create(temporary, path)?;
    }
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("flush containing directory")?;
    Ok(())
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
    use super::{AppConfig, ConfigStore, parse_inj_wei, read_regular_limited};
    use crate::cli::Network;
    use alloy_primitives::U256;
    use std::path::PathBuf;

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
        assert!(config.validate().is_ok());
        let invalid = AppConfig {
            transaction_confirmations: 13,
            ..config
        };
        assert!(invalid.validate().is_err());
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
}
