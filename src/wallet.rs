use crate::{
    cli::ImportArgs,
    config::{AppConfig, ConfigStore, read_regular_limited},
    startup::StartupProgress,
};
use aes::{
    Aes128,
    cipher::{KeyIvInit, StreamCipher},
};
use alloy_primitives::{Address, hex, keccak256};
use anyhow::{Context, Result, bail};
use bip32::secp256k1::ecdsa::SigningKey;
use bip32::{DerivationPath, XPrv};
use bip39::{Language, Mnemonic, WordCount};
use ctr::Ctr128BE;
use pbkdf2::pbkdf2_hmac;
use qrcodegen::{QrCode, QrCodeEcc};
use rand::{RngCore, thread_rng};
use scrypt::{Params as ScryptParams, scrypt};
use serde_json::Value;
use sha2::Sha256;
use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::Path,
    str::FromStr,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const DEFAULT_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";
const NEW_WALLET_PASSWORD_MIN_CHARS: usize = 12;
const SHORT_WALLET_PASSWORD_WARNING_CHARS: usize = 16;
const MAX_PASSWORD_BYTES: usize = 1_024;
const MAX_KEYSTORE_BYTES: u64 = 64 * 1024;
const MAX_SCRYPT_N: u64 = 262_144;
const MAX_PBKDF2_ROUNDS: u64 = 2_000_000;
const NEW_KEYSTORE_SCRYPT_LOG_N: u8 = 18;
const NEW_KEYSTORE_SCRYPT_R: u32 = 8;
const NEW_KEYSTORE_SCRYPT_P: u32 = 1;

type Aes128Ctr = Ctr128BE<Aes128>;

pub fn create_interactive(store: &ConfigStore, config: &mut AppConfig) -> Result<Address> {
    create_interactive_with_persistence(store, config, true)
}

pub(crate) fn create_interactive_staged(
    store: &ConfigStore,
    config: &mut AppConfig,
) -> Result<Address> {
    create_interactive_with_persistence(store, config, false)
}

fn create_interactive_with_persistence(
    store: &ConfigStore,
    config: &mut AppConfig,
    persist_config: bool,
) -> Result<Address> {
    create_interactive_with_secret_terminal(
        store,
        config,
        persist_config,
        secret_terminal_available(),
        || {
            Mnemonic::generate_in_with(&mut thread_rng(), Language::English, WordCount::Words24)
                .context("generate a BIP-39 recovery phrase")
        },
        disclose_and_confirm_recovery_phrase,
    )
}

fn disclose_and_confirm_recovery_phrase(phrase: &str) -> Result<()> {
    println!("Recovery phrase — write it down and keep it offline. It will not be stored:");
    println!("\n{}\n", phrase);
    confirm_backup()
}

fn secret_terminal_available() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn create_interactive_with_secret_terminal<F, G>(
    store: &ConfigStore,
    config: &mut AppConfig,
    persist_config: bool,
    secret_terminal: bool,
    generate_mnemonic: F,
    disclose_and_confirm: G,
) -> Result<Address>
where
    F: FnOnce() -> Result<Mnemonic>,
    G: FnOnce(&str) -> Result<()>,
{
    if !secret_terminal {
        bail!(
            "wallet creation requires an interactive terminal; refusing to generate or display a recovery phrase when stdin or stdout is redirected or unavailable. Run wallet initialization directly in a private terminal on a trusted machine"
        );
    }
    eprintln!(
        "Security warning: an interactive terminal is not a privacy guarantee. SSH sessions, terminal logging, screen capture, or a compromised host can still record the recovery phrase; create it only on a trusted, non-recorded machine."
    );

    let mnemonic = generate_mnemonic()?;
    let phrase = Zeroizing::new(mnemonic.to_string());
    disclose_and_confirm(phrase.as_str())?;

    let signer = derive_signer(phrase.as_str(), "", DEFAULT_DERIVATION_PATH)?;
    let password = prompt_new_password()?;
    let address = store_signer(store, config, &signer, password.as_bytes(), persist_config)?;
    println!("Encrypted Ethereum V3 wallet created: {address:#x}");
    Ok(address)
}

pub fn import_interactive(
    store: &ConfigStore,
    config: &mut AppConfig,
    args: ImportArgs,
) -> Result<Address> {
    import_interactive_with_persistence(store, config, args, true)
}

pub(crate) fn import_interactive_staged(
    store: &ConfigStore,
    config: &mut AppConfig,
    args: ImportArgs,
) -> Result<Address> {
    import_interactive_with_persistence(store, config, args, false)
}

fn import_interactive_with_persistence(
    store: &ConfigStore,
    config: &mut AppConfig,
    args: ImportArgs,
    persist_config: bool,
) -> Result<Address> {
    if let Some(path) = args.keystore {
        return import_keystore(store, config, &path, persist_config);
    }

    let phrase = Zeroizing::new(rpassword::prompt_password(
        "Recovery phrase (input hidden): ",
    )?);
    if phrase.is_empty() {
        bail!("recovery phrase cannot be empty");
    }
    let bip39_passphrase = Zeroizing::new(rpassword::prompt_password(
        "Optional BIP-39 passphrase (input hidden; empty if unused): ",
    )?);
    if bip39_passphrase.len() > MAX_PASSWORD_BYTES {
        bail!("BIP-39 passphrase exceeds the supported 1024-byte limit");
    }

    let signer = derive_signer(
        phrase.as_str(),
        bip39_passphrase.as_str(),
        &args.derivation_path,
    )?;
    let password = prompt_new_password()?;
    let address = store_signer(store, config, &signer, password.as_bytes(), persist_config)?;
    println!("Encrypted Ethereum V3 wallet imported: {address:#x}");
    Ok(address)
}

pub fn selected_address(config: &AppConfig) -> Result<Address> {
    let value = config
        .wallet_address
        .as_deref()
        .context("no wallet is selected; run `astatine init` or `astatine wallet create`")?;
    Address::from_str(value).context("configured wallet address is invalid")
}

pub(crate) fn unlock_selected_interactive(
    store: &ConfigStore,
    config: &AppConfig,
) -> Result<SigningKey> {
    unlock_selected_interactive_inner(store, config, None)
}

pub(crate) fn unlock_selected_interactive_with_progress(
    store: &ConfigStore,
    config: &AppConfig,
    progress: &StartupProgress,
) -> Result<SigningKey> {
    unlock_selected_interactive_inner(store, config, Some(progress))
}

fn unlock_selected_interactive_inner(
    store: &ConfigStore,
    config: &AppConfig,
    progress: Option<&StartupProgress>,
) -> Result<SigningKey> {
    let address = selected_address(config)?;
    let keyfile = store.read_keystore(address)?;
    if validate_v3_keystore(&keyfile)? != address {
        bail!("selected wallet keyfile address does not match configuration");
    }
    if let Some(progress) = progress {
        progress.pause_for_prompt("Unlock wallet");
    }
    let password = Zeroizing::new(rpassword::prompt_password(
        "Ethereum V3 keystore password (input hidden): ",
    )?);
    if let Some(progress) = progress {
        progress.resume_after_prompt("Decrypting Ethereum V3 keystore");
    }
    let private_key = decrypt_v3_keystore(&keyfile, password.as_bytes())?;
    let signer = SigningKey::from_slice(private_key.as_slice())
        .context("decrypted V3 keyfile does not contain a valid secp256k1 private key")?;
    if signer_address(&signer) != address {
        bail!("decrypted private key does not match the selected wallet address");
    }
    Ok(signer)
}

pub fn print_address(store: &ConfigStore, config: &AppConfig) -> Result<()> {
    let address = selected_address(config)?;
    let keyfile = store.read_keystore(address)?;
    if validate_v3_keystore(&keyfile)? != address {
        bail!("selected wallet keyfile address does not match configuration");
    }
    println!("Wallet: {address:#x}");
    print_address_qr(address)?;
    Ok(())
}

fn qr_modules(address: Address) -> Result<Vec<Vec<bool>>> {
    const QUIET_ZONE: usize = 4;
    let payload = format!("{address:#x}");
    let qr = QrCode::encode_text(&payload, QrCodeEcc::Medium)
        .map_err(|_| anyhow::anyhow!("wallet address is too long to encode as a QR code"))?;
    let qr_size = usize::try_from(qr.size()).context("QR code size is invalid")?;
    let size = qr_size + QUIET_ZONE * 2;
    let mut modules = vec![vec![false; size]; size];
    for (y, row) in modules.iter_mut().enumerate() {
        for (x, module) in row.iter_mut().enumerate() {
            let qr_x = i32::try_from(x).context("QR code coordinate is out of range")?
                - i32::try_from(QUIET_ZONE).expect("quiet zone fits in i32");
            let qr_y = i32::try_from(y).context("QR code coordinate is out of range")?
                - i32::try_from(QUIET_ZONE).expect("quiet zone fits in i32");
            *module = qr.get_module(qr_x, qr_y);
        }
    }
    Ok(modules)
}

fn print_address_qr(address: Address) -> Result<()> {
    let stdout = io::stdout();
    if !stdout.is_terminal() || std::env::var("TERM").is_ok_and(|term| term == "dumb") {
        return Ok(());
    }

    let modules = qr_modules(address)?;
    let mut output = stdout.lock();
    writeln!(output, "Scan this QR code to copy the wallet address:")?;
    for y in (0..modules.len()).step_by(2) {
        for x in 0..modules[y].len() {
            let upper = modules[y][x];
            let lower = modules.get(y + 1).is_some_and(|row| row[x]);
            let (style, glyph) = terminal_qr_cell(upper, lower);
            write!(output, "{style}{glyph}")?;
        }
        writeln!(output, "\x1b[0m")?;
    }
    output.flush().context("flush wallet address QR code")
}

fn terminal_qr_cell(upper: bool, lower: bool) -> (&'static str, char) {
    match (upper, lower) {
        (true, true) => ("\x1b[30;40m", '█'),
        (false, false) => ("\x1b[37;47m", ' '),
        (true, false) => ("\x1b[30;47m", '▀'),
        (false, true) => ("\x1b[37;40m", '▄'),
    }
}

fn derive_signer(phrase: &str, passphrase: &str, path: &str) -> Result<SigningKey> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .context("invalid English BIP-39 recovery phrase")?;
    let seed = Zeroizing::new(mnemonic.to_seed(passphrase));
    let path = path
        .parse::<DerivationPath>()
        .context("invalid BIP-44 derivation path")?;
    let extended =
        XPrv::derive_from_path(seed.as_ref(), &path).context("derive BIP-44 Ethereum key")?;
    Ok(extended.private_key().clone())
}

pub(crate) fn signer_address(signer: &SigningKey) -> Address {
    let public_key = signer.verifying_key().to_sec1_point(false);
    let digest = keccak256(&public_key.as_ref()[1..]);
    Address::from_slice(&digest.as_slice()[12..])
}

fn store_signer(
    store: &ConfigStore,
    config: &mut AppConfig,
    signer: &SigningKey,
    password: &[u8],
    persist_config: bool,
) -> Result<Address> {
    let address = signer_address(signer);
    let private_key = Zeroizing::new(signer.to_bytes());
    let contents = encrypt_v3_keystore(private_key.as_slice(), address, password)?;
    if validate_v3_keystore(&contents)? != address {
        bail!("encrypted keyfile address does not match the derived wallet");
    }

    let destination = store.store_keystore(address, &contents)?;
    let previous_wallet = config.wallet_address.replace(format!("{address:#x}"));
    // A failed save can still have renamed the new configuration into place.
    // Retry the previous selection before removing the key so the persisted
    // selection never points at a removed keystore.
    if persist_config && let Err(error) = store.save(config) {
        let mut rollback = config.clone();
        rollback.wallet_address = previous_wallet;
        match store.save(&rollback) {
            Ok(()) => {
                let _ = fs::remove_file(&destination);
                *config = rollback;
                return Err(error).context("save selected wallet configuration");
            }
            Err(rollback_error) => {
                *config = rollback;
                return Err(error).context(format!(
                    "save selected wallet configuration failed and rollback remains pending: {rollback_error:#}"
                ));
            }
        }
    }
    Ok(address)
}

fn import_keystore(
    store: &ConfigStore,
    config: &mut AppConfig,
    source: &Path,
    persist_config: bool,
) -> Result<Address> {
    import_keystore_with_prompts(
        store,
        config,
        source,
        persist_config,
        || {
            Ok(Zeroizing::new(rpassword::prompt_password(
                "Ethereum V3 keystore password (input hidden): ",
            )?))
        },
        prompt_new_password,
    )
}

fn import_keystore_with_prompts<F, G>(
    store: &ConfigStore,
    config: &mut AppConfig,
    source: &Path,
    persist_config: bool,
    read_source_password: F,
    read_new_password: G,
) -> Result<Address>
where
    F: FnOnce() -> Result<Zeroizing<String>>,
    G: FnOnce() -> Result<Zeroizing<String>>,
{
    let contents = read_regular_limited(source, MAX_KEYSTORE_BYTES, false)
        .context("read external Ethereum V3 keyfile")?;
    if contents.is_empty() {
        bail!("keyfile is empty or exceeds the supported size limit");
    }
    let embedded_address = validate_v3_keystore(&contents)?;

    let password = read_source_password()?;
    validate_import_password(&password)?;
    let private_key = decrypt_v3_keystore(&contents, password.as_bytes())?;
    let signer = SigningKey::from_slice(private_key.as_slice())
        .context("decrypted V3 keyfile does not contain a valid secp256k1 private key")?;
    let address = signer_address(&signer);
    if address != embedded_address {
        bail!("decrypted private key does not match the keyfile address");
    }

    let new_password = read_new_password()?;
    validate_new_password(&new_password)?;
    let address = store_signer(
        store,
        config,
        &signer,
        new_password.as_bytes(),
        persist_config,
    )?;
    println!("Encrypted Ethereum V3 wallet imported: {address:#x}");
    Ok(address)
}

fn encrypt_v3_keystore(private_key: &[u8], address: Address, password: &[u8]) -> Result<Vec<u8>> {
    if private_key.len() != 32 {
        bail!("Ethereum private key must be exactly 32 bytes");
    }
    let password_text =
        std::str::from_utf8(password).context("new keystore password must be valid UTF-8")?;
    validate_new_password(password_text)?;
    if password.len() > MAX_PASSWORD_BYTES {
        bail!("keystore password exceeds the supported 1024-byte limit");
    }

    let mut rng = thread_rng();
    let mut salt = [0_u8; 32];
    let mut iv = [0_u8; 16];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    let params = ScryptParams::new(
        NEW_KEYSTORE_SCRYPT_LOG_N,
        NEW_KEYSTORE_SCRYPT_R,
        NEW_KEYSTORE_SCRYPT_P,
    )
    .context("configure Ethereum V3 scrypt parameters")?;
    let mut derived_key = Zeroizing::new(vec![0_u8; 32]);
    scrypt(password, &salt, &params, derived_key.as_mut_slice())
        .context("derive Ethereum V3 encryption key")?;

    let mut ciphertext = private_key.to_vec();
    let mut cipher = Aes128Ctr::new_from_slices(&derived_key[..16], &iv)
        .context("initialize Ethereum V3 AES-128-CTR")?;
    cipher.apply_keystream(&mut ciphertext);

    let mut mac_input = Zeroizing::new(Vec::with_capacity(48));
    mac_input.extend_from_slice(&derived_key[16..]);
    mac_input.extend_from_slice(&ciphertext);
    let mac = keccak256(mac_input.as_slice());
    let address = format!("{address:#x}");
    let address = address.strip_prefix("0x").unwrap_or(&address);
    let keyfile = serde_json::json!({
        "version": 3,
        "id": random_uuid_v4(&mut rng),
        "address": address,
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": { "iv": hex::encode(iv) },
            "ciphertext": hex::encode(ciphertext),
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": 32,
                "n": 1_u64 << NEW_KEYSTORE_SCRYPT_LOG_N,
                "p": NEW_KEYSTORE_SCRYPT_P,
                "r": NEW_KEYSTORE_SCRYPT_R,
                "salt": hex::encode(salt)
            },
            "mac": hex::encode(mac)
        }
    });
    serde_json::to_vec_pretty(&keyfile).context("serialize Ethereum V3 keystore")
}

fn random_uuid_v4(rng: &mut impl RngCore) -> String {
    let mut bytes = [0_u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn decrypt_v3_keystore(contents: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    validate_v3_keystore(contents)?;
    let json: Value = serde_json::from_slice(contents).context("parse Ethereum V3 keyfile")?;
    let crypto = json
        .get("crypto")
        .or_else(|| json.get("Crypto"))
        .context("V3 keyfile has no crypto object")?;
    let params = crypto
        .get("kdfparams")
        .context("V3 keyfile KDF parameters are missing")?;
    let dklen = params
        .get("dklen")
        .and_then(Value::as_u64)
        .context("V3 keyfile KDF output length is invalid")? as usize;
    let salt = hex::decode(
        params
            .get("salt")
            .and_then(Value::as_str)
            .context("V3 keyfile KDF salt is missing")?,
    )
    .context("decode V3 keyfile KDF salt")?;
    let mut derived_key = Zeroizing::new(vec![0_u8; dklen]);
    match crypto.get("kdf").and_then(Value::as_str) {
        Some("scrypt") => {
            let n = params.get("n").and_then(Value::as_u64).unwrap();
            let r = params.get("r").and_then(Value::as_u64).unwrap() as u32;
            let p = params.get("p").and_then(Value::as_u64).unwrap() as u32;
            let scrypt_params = ScryptParams::new(n.trailing_zeros() as u8, r, p)
                .context("configure V3 keyfile scrypt parameters")?;
            scrypt(password, &salt, &scrypt_params, derived_key.as_mut_slice())
                .context("derive V3 keyfile decryption key")?;
        }
        Some("pbkdf2") => {
            let rounds = params.get("c").and_then(Value::as_u64).unwrap() as u32;
            pbkdf2_hmac::<Sha256>(password, &salt, rounds, derived_key.as_mut_slice());
        }
        _ => bail!("V3 keyfile KDF must be scrypt or PBKDF2"),
    }

    let ciphertext = hex::decode(
        crypto
            .get("ciphertext")
            .and_then(Value::as_str)
            .context("V3 keyfile ciphertext is missing")?,
    )
    .context("decode V3 keyfile ciphertext")?;
    let expected_mac = hex::decode(
        crypto
            .get("mac")
            .and_then(Value::as_str)
            .context("V3 keyfile MAC is missing")?,
    )
    .context("decode V3 keyfile MAC")?;
    let mut mac_input = Zeroizing::new(Vec::with_capacity(derived_key.len()));
    mac_input.extend_from_slice(&derived_key[16..]);
    mac_input.extend_from_slice(&ciphertext);
    let actual_mac = keccak256(mac_input.as_slice());
    if expected_mac.ct_eq(actual_mac.as_slice()).unwrap_u8() != 1 {
        bail!("Ethereum V3 keystore password or MAC is invalid");
    }

    let iv = hex::decode(
        crypto
            .get("cipherparams")
            .and_then(|value| value.get("iv"))
            .and_then(Value::as_str)
            .context("V3 keyfile cipher IV is missing")?,
    )
    .context("decode V3 keyfile cipher IV")?;
    let mut plaintext = Zeroizing::new(ciphertext);
    let mut cipher = Aes128Ctr::new_from_slices(&derived_key[..16], &iv)
        .context("initialize V3 keyfile AES-128-CTR")?;
    cipher.apply_keystream(plaintext.as_mut_slice());
    Ok(plaintext)
}

pub(crate) fn validate_v3_keystore(contents: &[u8]) -> Result<Address> {
    let json: Value = serde_json::from_slice(contents).context("parse Ethereum V3 keyfile")?;
    if json.get("version").and_then(Value::as_u64) != Some(3) {
        bail!("only Ethereum Web3 Secret Storage V3 keyfiles are supported");
    }
    let address = json
        .get("address")
        .and_then(Value::as_str)
        .context("V3 keyfile has no public address")?;
    let address = Address::from_str(address).context("V3 keyfile address is invalid")?;
    let crypto = json
        .get("crypto")
        .or_else(|| json.get("Crypto"))
        .context("V3 keyfile has no crypto object")?;
    if crypto.get("cipher").and_then(Value::as_str) != Some("aes-128-ctr") {
        bail!("V3 keyfile cipher must be aes-128-ctr");
    }
    let iv = crypto
        .get("cipherparams")
        .and_then(|params| params.get("iv"))
        .and_then(Value::as_str)
        .context("V3 keyfile cipher IV is missing")?;
    let ciphertext = crypto
        .get("ciphertext")
        .and_then(Value::as_str)
        .context("V3 keyfile ciphertext is missing")?;
    let mac = crypto
        .get("mac")
        .and_then(Value::as_str)
        .context("V3 keyfile MAC is missing")?;
    if hex::decode(iv).context("V3 keyfile IV is malformed")?.len() != 16
        || hex::decode(ciphertext)
            .context("V3 keyfile ciphertext is malformed")?
            .len()
            != 32
        || hex::decode(mac)
            .context("V3 keyfile MAC is malformed")?
            .len()
            != 32
    {
        bail!("V3 keyfile cryptographic fields have invalid lengths");
    }
    let params = crypto
        .get("kdfparams")
        .context("V3 keyfile KDF parameters are missing")?;
    let dklen = params
        .get("dklen")
        .and_then(Value::as_u64)
        .context("V3 keyfile KDF output length is invalid")?;
    if dklen != 32 {
        bail!("V3 keyfile KDF output length is unsupported");
    }
    let salt = params
        .get("salt")
        .and_then(Value::as_str)
        .context("V3 keyfile KDF salt is missing")?;
    if hex::decode(salt)
        .context("V3 keyfile KDF salt is malformed")?
        .len()
        != 32
    {
        bail!("V3 keyfile KDF salt must be 32 bytes");
    }
    match crypto.get("kdf").and_then(Value::as_str) {
        Some("scrypt") => {
            let n = params
                .get("n")
                .and_then(Value::as_u64)
                .context("V3 keyfile scrypt cost is invalid")?;
            let r = params
                .get("r")
                .and_then(Value::as_u64)
                .context("V3 keyfile scrypt block size is invalid")?;
            let p = params
                .get("p")
                .and_then(Value::as_u64)
                .context("V3 keyfile scrypt parallelization is invalid")?;
            if !n.is_power_of_two()
                || !(4_096..=MAX_SCRYPT_N).contains(&n)
                || r != 8
                || !(1..=8).contains(&p)
                || n.saturating_mul(p) > MAX_SCRYPT_N
            {
                bail!("V3 keyfile scrypt parameters exceed supported bounds");
            }
        }
        Some("pbkdf2") => {
            let rounds = params
                .get("c")
                .and_then(Value::as_u64)
                .context("V3 keyfile PBKDF2 rounds are invalid")?;
            if !(1..=MAX_PBKDF2_ROUNDS).contains(&rounds)
                || params.get("prf").and_then(Value::as_str) != Some("hmac-sha256")
            {
                bail!("V3 keyfile PBKDF2 parameters exceed supported bounds");
            }
        }
        _ => bail!("V3 keyfile KDF must be scrypt or PBKDF2"),
    }
    Ok(address)
}

fn prompt_new_password() -> Result<Zeroizing<String>> {
    prompt_new_password_with(|prompt| rpassword::prompt_password(prompt))
}

fn prompt_new_password_with<F>(mut prompt: F) -> Result<Zeroizing<String>>
where
    F: FnMut(&str) -> io::Result<String>,
{
    let password = Zeroizing::new(prompt(
        "Create keystore password (input hidden; use at least 12 characters): ",
    )?);
    validate_new_password(&password)?;
    if should_warn_short_password(&password) {
        eprintln!("Security note: a longer unique passphrase better protects this wallet.");
    }
    let confirmation = Zeroizing::new(prompt("Confirm keystore password (input hidden): ")?);
    validate_password_confirmation(&password, &confirmation)?;
    Ok(password)
}

fn should_warn_short_password(password: &str) -> bool {
    password.chars().count() < SHORT_WALLET_PASSWORD_WARNING_CHARS
}

pub(crate) fn is_password_prompt_interrupted(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::Interrupted)
}

fn validate_new_password(password: &str) -> Result<()> {
    if password.chars().count() < NEW_WALLET_PASSWORD_MIN_CHARS
        || password.len() > MAX_PASSWORD_BYTES
    {
        bail!(
            "new keystore password must be at least 12 Unicode characters and no more than 1024 bytes"
        );
    }
    Ok(())
}

fn validate_password_confirmation(password: &str, confirmation: &str) -> Result<()> {
    if password != confirmation {
        bail!("password confirmation did not match");
    }
    Ok(())
}

fn validate_import_password(password: &str) -> Result<()> {
    if password.len() > MAX_PASSWORD_BYTES {
        bail!("keystore password exceeds the supported 1024-byte limit");
    }
    Ok(())
}

fn confirm_backup() -> Result<()> {
    print!("Type BACKED UP after writing the phrase down: ");
    io::stdout()
        .flush()
        .context("flush recovery phrase confirmation prompt")?;
    let mut confirmation = String::new();
    io::stdin()
        .read_line(&mut confirmation)
        .context("read recovery phrase confirmation")?;
    if confirmation.trim() != "BACKED UP" {
        bail!("wallet creation cancelled; no wallet was stored");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Aes128Ctr, DEFAULT_DERIVATION_PATH, MAX_PASSWORD_BYTES,
        create_interactive_with_secret_terminal, decrypt_v3_keystore, derive_signer,
        import_keystore_with_prompts, prompt_new_password_with, qr_modules,
        should_warn_short_password, signer_address, store_signer, terminal_qr_cell,
        validate_import_password, validate_new_password, validate_password_confirmation,
        validate_v3_keystore,
    };
    use crate::config::{AppConfig, ConfigStore};
    use aes::cipher::{KeyIvInit, StreamCipher};
    use alloy_primitives::{Address, hex, keccak256};
    use anyhow::Result;
    use bip32::secp256k1::ecdsa::SigningKey;
    use bip39::{Language, Mnemonic};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    use std::{io, path::PathBuf, str::FromStr};
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    // Standard public BIP-39 test vector; it is not a user or funded wallet.
    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TEST_PASSWORD: &str = "test-only-keystore-password";
    const NEW_LOCAL_PASSWORD: &str = "new-strong-local-password";

    fn weak_pbkdf2_keyfile(
        signer: &SigningKey,
        password: &str,
        embedded_address: Address,
    ) -> Vec<u8> {
        let mut derived_key = [0_u8; 32];
        let salt = [0x51_u8; 32];
        let iv = [0x27_u8; 16];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 2_048, &mut derived_key);
        let mut ciphertext = signer.to_bytes().to_vec();
        Aes128Ctr::new_from_slices(&derived_key[..16], &iv)
            .unwrap()
            .apply_keystream(&mut ciphertext);
        let mut mac_input = derived_key[16..].to_vec();
        mac_input.extend_from_slice(&ciphertext);
        let mac = keccak256(mac_input);
        let address = format!("{embedded_address:#x}");
        serde_json::to_vec(&serde_json::json!({
            "version": 3,
            "id": "f0e1d2c3-b4a5-4678-89ab-cdef01234567",
            "address": address.strip_prefix("0x").unwrap(),
            "crypto": {
                "cipher": "aes-128-ctr",
                "cipherparams": { "iv": hex::encode(iv) },
                "ciphertext": hex::encode(ciphertext),
                "kdf": "pbkdf2",
                "kdfparams": {
                    "c": 2_048,
                    "dklen": 32,
                    "prf": "hmac-sha256",
                    "salt": hex::encode(salt)
                },
                "mac": hex::encode(mac)
            }
        }))
        .unwrap()
    }

    fn persist_existing_selection(store: &ConfigStore) -> AppConfig {
        let config = AppConfig {
            wallet_address: Some(format!("{:#x}", Address::with_last_byte(0xa1))),
            per_session_spending_limit_inj: "0.5".to_owned(),
            ..AppConfig::default()
        };
        store.save(&config).unwrap();
        config
    }

    fn external_weak_keyfile(root: &std::path::Path, signer: &SigningKey) -> PathBuf {
        let path = root.join("external-weak-v3-keystore.json");
        std::fs::write(
            &path,
            weak_pbkdf2_keyfile(signer, TEST_PASSWORD, signer_address(signer)),
        )
        .unwrap();
        path
    }

    fn import_with_passwords(
        store: &ConfigStore,
        config: &mut AppConfig,
        source: &std::path::Path,
        persist_config: bool,
        source_password: &str,
        new_password: &str,
    ) -> Result<Address> {
        import_keystore_with_prompts(
            store,
            config,
            source,
            persist_config,
            || Ok(Zeroizing::new(source_password.to_owned())),
            || Ok(Zeroizing::new(new_password.to_owned())),
        )
    }

    #[test]
    fn derives_standard_ethereum_bip44_address() {
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        assert_eq!(
            signer_address(&signer),
            Address::from_str("0x9858EfFD232B4033E47d90003D41EC34EcaEda94").unwrap()
        );
    }

    #[test]
    fn wallet_address_qr_has_a_quiet_zone_and_decodes_to_the_exact_address() {
        let address = Address::from_str("0x9858EfFD232B4033E47d90003D41EC34EcaEda94").unwrap();
        let payload = format!("{address:#x}");
        let modules = qr_modules(address).unwrap();
        let size = modules.len();

        assert!(modules.iter().all(|row| row.len() == size));
        assert!(modules[..4].iter().flatten().all(|module| !module));
        assert!(modules[size - 4..].iter().flatten().all(|module| !module));
        assert!(modules.iter().all(|row| {
            row[..4].iter().all(|module| !module) && row[size - 4..].iter().all(|module| !module)
        }));

        let rendered_height = size.div_ceil(2) * 2;
        let mut rendered_modules = vec![vec![false; size]; rendered_height];
        for y in (0..size).step_by(2) {
            for x in 0..size {
                let (_, glyph) =
                    terminal_qr_cell(modules[y][x], modules.get(y + 1).is_some_and(|row| row[x]));
                let (upper, lower) = match glyph {
                    '█' => (true, true),
                    ' ' => (false, false),
                    '▀' => (true, false),
                    '▄' => (false, true),
                    _ => unreachable!("QR renderer emitted an unsupported glyph"),
                };
                rendered_modules[y][x] = upper;
                rendered_modules[y + 1][x] = lower;
            }
        }

        const SCALE: usize = 8;
        let image_width = size * SCALE;
        let image_height = rendered_height * SCALE;
        let mut grayscale = vec![255_u8; image_width * image_height];
        for (y, row) in rendered_modules.iter().enumerate() {
            for (x, dark) in row.iter().copied().enumerate() {
                if dark {
                    for dy in 0..SCALE {
                        for dx in 0..SCALE {
                            grayscale[(y * SCALE + dy) * image_width + x * SCALE + dx] = 0;
                        }
                    }
                }
            }
        }

        let mut scanner = quircs::Quirc::new();
        let decoded = scanner
            .identify(image_width, image_height, &grayscale)
            .find_map(|candidate| {
                candidate
                    .ok()
                    .and_then(|code| code.decode().ok())
                    .and_then(|data| String::from_utf8(data.payload).ok())
            });
        assert_eq!(decoded.as_deref(), Some(payload.as_str()));
    }

    #[test]
    fn encrypted_keystore_round_trip_is_v3_and_contains_no_mnemonic() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let mut config = AppConfig::default();
        store_signer(&store, &mut config, &signer, TEST_PASSWORD.as_bytes(), true).unwrap();

        let keyfile = store.read_keystore(address).unwrap();
        let embedded_address = validate_v3_keystore(&keyfile).unwrap();
        assert_eq!(embedded_address, address);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(store.wallet_dir())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(store.keystore_path(address))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let value: serde_json::Value = serde_json::from_slice(&keyfile).unwrap();
        assert_eq!(
            value.get("version").and_then(serde_json::Value::as_u64),
            Some(3)
        );
        assert_eq!(value["crypto"]["kdf"], "scrypt");
        assert_eq!(value["crypto"]["kdfparams"]["n"], 1_u64 << 18);
        assert_eq!(value["crypto"]["kdfparams"]["r"], 8);
        assert_eq!(value["crypto"]["kdfparams"]["p"], 1);
        assert!(
            !String::from_utf8(keyfile.clone())
                .unwrap()
                .contains(TEST_PHRASE)
        );

        let private_key = decrypt_v3_keystore(&keyfile, TEST_PASSWORD.as_bytes()).unwrap();
        let decrypted = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        assert_eq!(private_key.as_slice(), decrypted.to_bytes().as_slice());
        assert_eq!(signer_address(&decrypted), address);
        assert_eq!(
            config.wallet_address.as_deref(),
            Some(format!("{address:#x}").as_str())
        );
    }

    #[test]
    fn staged_wallet_creation_writes_the_keystore_without_persisting_selection() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let mut config = AppConfig::default();

        store_signer(
            &store,
            &mut config,
            &signer,
            TEST_PASSWORD.as_bytes(),
            false,
        )
        .unwrap();

        assert_eq!(
            config.wallet_address.as_deref(),
            Some(format!("{address:#x}").as_str())
        );
        assert_eq!(store.load().unwrap().wallet_address, None);
        assert_eq!(
            validate_v3_keystore(&store.read_keystore(address).unwrap()).unwrap(),
            address
        );
    }

    #[test]
    fn new_wallet_password_requires_at_least_twelve_unicode_characters() {
        for (password, expected) in [
            ("", false),
            ("abc", false),
            ("12345678901", false),
            ("twelve-chars", true),
            ("longer-unique-passphrase", true),
        ] {
            assert_eq!(
                validate_new_password(password).is_ok(),
                expected,
                "unexpected result for a {}-character password",
                password.chars().count()
            );
        }
    }

    #[test]
    fn new_wallet_password_counts_unicode_characters_and_limits_encoded_bytes() {
        let short_unicode_password = "🔐".repeat(11);
        assert_eq!(short_unicode_password.chars().count(), 11);
        assert!(validate_new_password(&short_unicode_password).is_err());

        let unicode_password = "🔐".repeat(12);
        assert_eq!(unicode_password.chars().count(), 12);
        assert!(unicode_password.len() > unicode_password.chars().count());
        assert!(validate_new_password(&unicode_password).is_ok());

        assert!(validate_new_password(&"x".repeat(MAX_PASSWORD_BYTES)).is_ok());
        assert!(validate_new_password(&"x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
    }

    #[test]
    fn incorrect_new_wallet_password_confirmation_is_rejected() {
        assert!(validate_password_confirmation("abcd", "abce").is_err());
        assert!(validate_password_confirmation("abcd", "abcd").is_ok());
    }

    #[test]
    fn near_minimum_password_warning_uses_unicode_character_count() {
        assert!(should_warn_short_password("twelve-chars"));
        assert!(!should_warn_short_password("sixteen-character"));
        assert!(should_warn_short_password(&"🔐".repeat(12)));
        assert!(!should_warn_short_password(&"🔐".repeat(16)));
    }

    #[test]
    fn interrupted_hidden_password_prompt_is_identified_as_cancellation() {
        let error = anyhow::Error::new(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
        assert!(super::is_password_prompt_interrupted(&error));
        assert!(!super::is_password_prompt_interrupted(&anyhow::anyhow!(
            "bad password"
        )));
    }

    #[test]
    fn twelve_character_password_round_trips_through_ethereum_v3_keystore() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let mut config = AppConfig::default();
        let password = "twelve-chars";
        validate_new_password(password).unwrap();
        store_signer(&store, &mut config, &signer, password.as_bytes(), true).unwrap();

        let keyfile = store.read_keystore(address).unwrap();
        let decrypted = decrypt_v3_keystore(&keyfile, password.as_bytes()).unwrap();
        assert_eq!(decrypted.as_slice(), signer.to_bytes().as_slice());
        assert_eq!(validate_v3_keystore(&keyfile).unwrap(), address);
    }

    #[test]
    fn existing_v3_import_passwords_are_not_subject_to_new_wallet_minimum() {
        assert!(validate_import_password("x").is_ok());
    }

    #[test]
    fn imports_a_standard_pbkdf2_v3_keyfile() {
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let mut derived_key = [0_u8; 32];
        let salt = [0x51_u8; 32];
        let iv = [0x27_u8; 16];
        pbkdf2_hmac::<Sha256>(TEST_PASSWORD.as_bytes(), &salt, 2_048, &mut derived_key);
        let mut ciphertext = signer.to_bytes().to_vec();
        Aes128Ctr::new_from_slices(&derived_key[..16], &iv)
            .unwrap()
            .apply_keystream(&mut ciphertext);
        let mut mac_input = derived_key[16..].to_vec();
        mac_input.extend_from_slice(&ciphertext);
        let mac = keccak256(mac_input);
        let address = format!("{address:#x}");
        let keyfile = serde_json::json!({
            "version": 3,
            "id": "f0e1d2c3-b4a5-4678-89ab-cdef01234567",
            "address": address.strip_prefix("0x").unwrap(),
            "crypto": {
                "cipher": "aes-128-ctr",
                "cipherparams": { "iv": hex::encode(iv) },
                "ciphertext": hex::encode(ciphertext),
                "kdf": "pbkdf2",
                "kdfparams": {
                    "c": 2_048,
                    "dklen": 32,
                    "prf": "hmac-sha256",
                    "salt": hex::encode(salt)
                },
                "mac": hex::encode(mac)
            }
        });
        let keyfile = serde_json::to_vec(&keyfile).unwrap();
        let decrypted = decrypt_v3_keystore(&keyfile, TEST_PASSWORD.as_bytes()).unwrap();
        assert_eq!(decrypted.as_slice(), signer.to_bytes().as_slice());
        assert!(decrypt_v3_keystore(&keyfile, b"wrong").is_err());
    }

    #[test]
    fn imports_existing_ethereum_v3_keyfile_with_its_three_character_password() {
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let password = "old";
        let mut derived_key = [0_u8; 32];
        let salt = [0x61_u8; 32];
        let iv = [0x37_u8; 16];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 2_048, &mut derived_key);
        let mut ciphertext = signer.to_bytes().to_vec();
        Aes128Ctr::new_from_slices(&derived_key[..16], &iv)
            .unwrap()
            .apply_keystream(&mut ciphertext);
        let mut mac_input = derived_key[16..].to_vec();
        mac_input.extend_from_slice(&ciphertext);
        let mac = keccak256(mac_input);
        let address = format!("{address:#x}");
        let keyfile = serde_json::json!({
            "version": 3,
            "id": "f0e1d2c3-b4a5-4678-89ab-cdef01234567",
            "address": address.strip_prefix("0x").unwrap(),
            "crypto": {
                "cipher": "aes-128-ctr",
                "cipherparams": { "iv": hex::encode(iv) },
                "ciphertext": hex::encode(ciphertext),
                "kdf": "pbkdf2",
                "kdfparams": {
                    "c": 2_048,
                    "dklen": 32,
                    "prf": "hmac-sha256",
                    "salt": hex::encode(salt)
                },
                "mac": hex::encode(mac)
            }
        });
        let keyfile = serde_json::to_vec(&keyfile).unwrap();

        validate_import_password(password).unwrap();
        let decrypted = decrypt_v3_keystore(&keyfile, password.as_bytes()).unwrap();
        assert_eq!(decrypted.as_slice(), signer.to_bytes().as_slice());
        assert!(decrypt_v3_keystore(&keyfile, b"bad").is_err());
    }

    #[test]
    fn v3_import_validation_rejects_unsafe_scrypt_costs() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let mut config = AppConfig::default();
        store_signer(&store, &mut config, &signer, TEST_PASSWORD.as_bytes(), true).unwrap();
        let bytes = store.read_keystore(signer_address(&signer)).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["crypto"]["kdfparams"]["n"] = serde_json::Value::from(1_u64 << 30);
        assert!(validate_v3_keystore(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn wallet_creation_without_secret_terminal_fails_before_mnemonic_generation_and_state_changes()
    {
        for persist_config in [true, false] {
            let temp = tempdir().unwrap();
            let store = ConfigStore::at_root(PathBuf::from(temp.path()));
            let existing = persist_existing_selection(&store);
            let mut config = store.load().unwrap();

            let error = create_interactive_with_secret_terminal(
                &store,
                &mut config,
                persist_config,
                false,
                || panic!("recovery phrase must not be generated without a secret terminal"),
                |_| panic!("backup confirmation must not be requested without a secret terminal"),
            )
            .unwrap_err();

            assert!(format!("{error:#}").contains("interactive terminal"));
            assert_eq!(config, existing);
            assert_eq!(store.load().unwrap(), existing);
            assert!(!store.wallet_dir().exists());
        }
    }

    #[test]
    fn wallet_creation_cancelled_at_backup_confirmation_leaves_state_unchanged() {
        for persist_config in [true, false] {
            let temp = tempdir().unwrap();
            let store = ConfigStore::at_root(PathBuf::from(temp.path()));
            let existing = persist_existing_selection(&store);
            let mut config = store.load().unwrap();
            let existing_wallet_path = store.keystore_path(Address::with_last_byte(0xa1));
            let existing_wallet_bytes = b"existing-wallet-file".as_slice();
            store.prepare_wallet_dir().unwrap();
            std::fs::write(&existing_wallet_path, existing_wallet_bytes).unwrap();
            let mut disclosed_phrase = None;

            let error = create_interactive_with_secret_terminal(
                &store,
                &mut config,
                persist_config,
                true,
                || Ok(Mnemonic::parse_in(Language::English, TEST_PHRASE).unwrap()),
                |phrase| {
                    // Capture the public test vector instead of printing it.
                    disclosed_phrase = Some(phrase.to_owned());
                    Err(anyhow::Error::new(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "backup confirmation cancelled",
                    )))
                },
            )
            .unwrap_err();

            assert!(super::is_password_prompt_interrupted(&error));
            assert_eq!(disclosed_phrase.as_deref(), Some(TEST_PHRASE));
            assert_eq!(config, existing);
            assert_eq!(store.load().unwrap(), existing);
            assert_eq!(
                std::fs::read(&existing_wallet_path).unwrap().as_slice(),
                existing_wallet_bytes
            );
            assert_eq!(
                std::fs::read_dir(store.wallet_dir()).unwrap().count(),
                1,
                "cancelled creation must not add wallet files"
            );
        }
    }

    #[test]
    fn weak_pbkdf2_import_is_reencrypted_with_strong_scrypt_and_leaves_source_unchanged() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let source = external_weak_keyfile(temp.path(), &signer);
        let original_source = std::fs::read(&source).unwrap();
        let mut config = store.load().unwrap();

        let imported = import_with_passwords(
            &store,
            &mut config,
            &source,
            true,
            TEST_PASSWORD,
            NEW_LOCAL_PASSWORD,
        )
        .unwrap();

        assert_eq!(imported, address);
        assert_eq!(std::fs::read(&source).unwrap(), original_source);
        assert_eq!(
            config.wallet_address.as_deref(),
            Some(format!("{address:#x}").as_str())
        );
        assert_eq!(store.load().unwrap().wallet_address, config.wallet_address);

        let local = store.read_keystore(address).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&local).unwrap();
        assert_eq!(value["crypto"]["kdf"], "scrypt");
        assert_eq!(value["crypto"]["kdfparams"]["n"], 1_u64 << 18);
        assert_eq!(value["crypto"]["kdfparams"]["r"], 8);
        assert_eq!(value["crypto"]["kdfparams"]["p"], 1);
        let decrypted = decrypt_v3_keystore(&local, NEW_LOCAL_PASSWORD.as_bytes()).unwrap();
        assert_eq!(decrypted.as_slice(), signer.to_bytes().as_slice());
        assert!(decrypt_v3_keystore(&local, TEST_PASSWORD.as_bytes()).is_err());

        let original_decrypted =
            decrypt_v3_keystore(&original_source, TEST_PASSWORD.as_bytes()).unwrap();
        assert_eq!(original_decrypted.as_slice(), signer.to_bytes().as_slice());
    }

    #[test]
    fn staged_import_writes_strong_local_keystore_without_persisting_selection() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let before = persist_existing_selection(&store);
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let source = external_weak_keyfile(temp.path(), &signer);
        let original_source = std::fs::read(&source).unwrap();
        let mut config = store.load().unwrap();
        assert_eq!(config.wallet_address, before.wallet_address);

        let imported = import_with_passwords(
            &store,
            &mut config,
            &source,
            false,
            TEST_PASSWORD,
            NEW_LOCAL_PASSWORD,
        )
        .unwrap();

        assert_eq!(imported, address);
        assert_eq!(
            config.wallet_address.as_deref(),
            Some(format!("{address:#x}").as_str())
        );
        assert_eq!(store.load().unwrap(), before);
        assert_eq!(std::fs::read(&source).unwrap(), original_source);

        let local = store.read_keystore(address).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&local).unwrap();
        assert_eq!(value["crypto"]["kdf"], "scrypt");
        assert_eq!(value["crypto"]["kdfparams"]["n"], 1_u64 << 18);
        assert_eq!(value["crypto"]["kdfparams"]["r"], 8);
        assert_eq!(value["crypto"]["kdfparams"]["p"], 1);
        let decrypted = decrypt_v3_keystore(&local, NEW_LOCAL_PASSWORD.as_bytes()).unwrap();
        assert_eq!(decrypted.as_slice(), signer.to_bytes().as_slice());
    }

    #[test]
    fn import_does_not_overwrite_an_existing_local_keystore_for_the_same_address() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let before = persist_existing_selection(&store);
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let source = external_weak_keyfile(temp.path(), &signer);
        let original_source = std::fs::read(&source).unwrap();

        store.prepare_wallet_dir().unwrap();
        let existing_local = weak_pbkdf2_keyfile(&signer, TEST_PASSWORD, address);
        std::fs::write(store.keystore_path(address), &existing_local).unwrap();
        let mut config = store.load().unwrap();

        let error = import_with_passwords(
            &store,
            &mut config,
            &source,
            true,
            TEST_PASSWORD,
            NEW_LOCAL_PASSWORD,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("store encrypted wallet"));
        assert_eq!(
            std::fs::read(store.keystore_path(address)).unwrap(),
            existing_local
        );
        assert_eq!(store.load().unwrap(), before);
        assert_eq!(config, before);
        assert_eq!(std::fs::read(&source).unwrap(), original_source);
    }

    #[test]
    fn incorrect_source_password_does_not_prompt_for_a_new_password_or_change_state() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let before = persist_existing_selection(&store);
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let source = external_weak_keyfile(temp.path(), &signer);
        let original_source = std::fs::read(&source).unwrap();
        let mut config = store.load().unwrap();

        let error = import_keystore_with_prompts(
            &store,
            &mut config,
            &source,
            true,
            || Ok(Zeroizing::new("incorrect-password".to_owned())),
            || panic!("new password must not be requested after source decryption fails"),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("password or MAC is invalid"));
        assert_eq!(config, before);
        assert_eq!(store.load().unwrap(), before);
        assert!(!store.keystore_path(address).exists());
        assert_eq!(std::fs::read(&source).unwrap(), original_source);
    }

    #[test]
    fn mismatched_new_import_password_confirmation_leaves_selection_and_source_unchanged() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let before = persist_existing_selection(&store);
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let source = external_weak_keyfile(temp.path(), &signer);
        let original_source = std::fs::read(&source).unwrap();
        let mut config = store.load().unwrap();
        let mut replies = [
            Ok::<_, io::Error>(NEW_LOCAL_PASSWORD.to_owned()),
            Ok::<_, io::Error>("different-confirmation".to_owned()),
        ]
        .into_iter();

        let error = import_keystore_with_prompts(
            &store,
            &mut config,
            &source,
            true,
            || Ok(Zeroizing::new(TEST_PASSWORD.to_owned())),
            || prompt_new_password_with(|_| replies.next().unwrap()),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("confirmation did not match"));
        assert_eq!(config, before);
        assert_eq!(store.load().unwrap(), before);
        assert!(!store.keystore_path(address).exists());
        assert_eq!(std::fs::read(&source).unwrap(), original_source);
    }

    #[test]
    fn cancelled_new_import_password_prompt_leaves_selection_and_source_unchanged() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let before = persist_existing_selection(&store);
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let source = external_weak_keyfile(temp.path(), &signer);
        let original_source = std::fs::read(&source).unwrap();
        let mut config = store.load().unwrap();
        let mut replies = [
            Ok::<_, io::Error>(NEW_LOCAL_PASSWORD.to_owned()),
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")),
        ]
        .into_iter();

        let error = import_keystore_with_prompts(
            &store,
            &mut config,
            &source,
            true,
            || Ok(Zeroizing::new(TEST_PASSWORD.to_owned())),
            || prompt_new_password_with(|_| replies.next().unwrap()),
        )
        .unwrap_err();

        assert!(super::is_password_prompt_interrupted(&error));
        assert_eq!(config, before);
        assert_eq!(store.load().unwrap(), before);
        assert!(!store.keystore_path(address).exists());
        assert_eq!(std::fs::read(&source).unwrap(), original_source);
    }

    #[test]
    fn imported_private_key_must_match_the_embedded_keystore_address() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let before = persist_existing_selection(&store);
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let source = temp.path().join("external-mismatched-v3-keystore.json");
        let keyfile = weak_pbkdf2_keyfile(&signer, TEST_PASSWORD, Address::with_last_byte(0x99));
        std::fs::write(&source, &keyfile).unwrap();
        let mut config = store.load().unwrap();

        let error = import_keystore_with_prompts(
            &store,
            &mut config,
            &source,
            true,
            || Ok(Zeroizing::new(TEST_PASSWORD.to_owned())),
            || panic!("new password must not be requested before address validation"),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("does not match the keyfile address"));
        assert_eq!(config, before);
        assert_eq!(store.load().unwrap(), before);
        assert!(!store.keystore_path(address).exists());
        assert_eq!(std::fs::read(&source).unwrap(), keyfile);
    }

    #[test]
    fn keystore_write_failure_does_not_change_selected_wallet_or_source() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let before = persist_existing_selection(&store);
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let source = external_weak_keyfile(temp.path(), &signer);
        let original_source = std::fs::read(&source).unwrap();
        let mut config = store.load().unwrap();
        let destination = store.keystore_path(address);
        store
            .fail_atomic_write_for_test(
                destination.clone(),
                crate::config::AtomicWriteFailPoint::BeforeRename,
            )
            .unwrap();

        let error = import_with_passwords(
            &store,
            &mut config,
            &source,
            true,
            TEST_PASSWORD,
            NEW_LOCAL_PASSWORD,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("store encrypted wallet"));
        assert_eq!(config, before);
        assert_eq!(store.load().unwrap(), before);
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&source).unwrap(), original_source);
    }

    #[test]
    fn keystore_store_failure_after_rename_keeps_selection_and_may_leave_orphan_keystore() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let before = persist_existing_selection(&store);
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let source = external_weak_keyfile(temp.path(), &signer);
        let original_source = std::fs::read(&source).unwrap();
        let mut config = store.load().unwrap();
        let destination = store.keystore_path(address);
        store
            .fail_atomic_write_for_test(
                destination.clone(),
                crate::config::AtomicWriteFailPoint::AfterRename,
            )
            .unwrap();

        let error = import_with_passwords(
            &store,
            &mut config,
            &source,
            true,
            TEST_PASSWORD,
            NEW_LOCAL_PASSWORD,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("store encrypted wallet"));
        assert_eq!(config, before);
        assert_eq!(store.load().unwrap(), before);
        assert_eq!(std::fs::read(&source).unwrap(), original_source);

        // The injected failure happens after the atomic rename, so the new
        // encrypted file can remain as an orphan even though selection was
        // never changed and no existing keystore was overwritten.
        assert!(destination.exists());
        let orphan = std::fs::read(&destination).unwrap();
        assert_eq!(validate_v3_keystore(&orphan).unwrap(), address);
        assert!(decrypt_v3_keystore(&orphan, NEW_LOCAL_PASSWORD.as_bytes()).is_ok());
    }

    #[test]
    fn config_save_failure_removes_new_keystore_and_keeps_selected_wallet() {
        for fail_point in [
            crate::config::AtomicWriteFailPoint::BeforeRename,
            crate::config::AtomicWriteFailPoint::AfterRename,
        ] {
            let temp = tempdir().unwrap();
            let store = ConfigStore::at_root(PathBuf::from(temp.path()));
            let before = persist_existing_selection(&store);
            let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
            let address = signer_address(&signer);
            let source = external_weak_keyfile(temp.path(), &signer);
            let original_source = std::fs::read(&source).unwrap();
            let mut config = store.load().unwrap();
            store
                .fail_atomic_write_for_test(temp.path().join("config.toml"), fail_point)
                .unwrap();

            let error = import_with_passwords(
                &store,
                &mut config,
                &source,
                true,
                TEST_PASSWORD,
                NEW_LOCAL_PASSWORD,
            )
            .unwrap_err();

            assert!(format!("{error:#}").contains("save selected wallet configuration"));
            assert_eq!(config, before);
            assert_eq!(store.load().unwrap(), before);
            assert!(!store.keystore_path(address).exists());
            assert_eq!(std::fs::read(&source).unwrap(), original_source);
        }
    }
}
