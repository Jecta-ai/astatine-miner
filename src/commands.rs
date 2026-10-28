use crate::{
    cli::{Command, InitArgs, Network, WalletCommand},
    config::ConfigStore,
    mining,
    rpc::{NetworkClient, NodeView},
    wallet,
};
use alloy_primitives::{Address, U256};
use anyhow::{Context, Result, bail};
use std::{
    io::{self, Write},
    num::NonZeroUsize,
    path::PathBuf,
    str::FromStr,
};

pub async fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Init(args) => run_init(args).await,
        Command::Mine(args) => mining::run(&ConfigStore::system_default()?, args).await,
        Command::Wallet(WalletCommand::Create) => {
            let store = ConfigStore::system_default()?;
            let mut config = store.load()?;
            wallet::create_interactive(&store, &mut config)?;
            Ok(())
        }
        Command::Wallet(WalletCommand::Import(args)) => {
            let store = ConfigStore::system_default()?;
            let mut config = store.load()?;
            wallet::import_interactive(&store, &mut config, args)?;
            Ok(())
        }
        Command::Wallet(WalletCommand::Address) => {
            let store = ConfigStore::system_default()?;
            let config = store.load()?;
            wallet::print_address(&store, &config)
        }
        Command::NetworkUse(network) => {
            let store = ConfigStore::system_default()?;
            let mut config = store.load()?;
            config.network = network;
            store.save(&config)?;
            println!(
                "Selected {} (chain ID {}). Wallet selection was preserved.",
                network_label(network),
                chain_id(network)
            );
            if network == Network::Mainnet {
                println!(
                    "Mainnet has no configured Astatine mining deployment; transaction signing is unavailable."
                );
            }
            Ok(())
        }
        Command::Nodes => {
            let store = ConfigStore::system_default()?;
            let config = store.load()?;
            let client = NetworkClient::connect(config.network).await?;
            if !client.has_mining_deployment() {
                println!(
                    "{} has no verified Astatine mining deployment.",
                    network_label(config.network)
                );
                return Ok(());
            }
            let snapshot = client.snapshot(None).await?;
            print_nodes(&snapshot.nodes);
            Ok(())
        }
        Command::Status => run_status().await,
        Command::Rewards => run_rewards().await,
        Command::Update(args) if args.check_only => crate::update::run_check().await,
        Command::Update(_) => crate::update::run().await,
    }
}

async fn run_init(args: InitArgs) -> Result<()> {
    let store = ConfigStore::system_default()?;
    let mut config = store.load()?;
    println!("Astatine setup.");
    println!(
        "Automatic permissionless finalization can spend gas on empty windows or windows won by another miner. That maximum exposure counts toward the session cap; the default cap of zero authorizes no transaction spending."
    );

    config.network = match args.network {
        Some(network) => network,
        None => prompt_network(config.network)?,
    };
    config.cpu_threads = match args.threads {
        Some(threads) => threads.get(),
        None => prompt_threads(config.cpu_threads)?,
    };
    config.minimum_reserve_inj = match args.minimum_reserve_inj {
        Some(amount) => amount,
        None => prompt_value("Minimum INJ reserve", &config.minimum_reserve_inj)?,
    };
    config.per_session_spending_limit_inj = match args.spending_limit_inj {
        Some(amount) => amount,
        None => prompt_value(
            "Per-session maximum INJ transaction exposure",
            &config.per_session_spending_limit_inj,
        )?,
    };
    config.transaction_confirmations = match args.transaction_confirmations {
        Some(confirmations) => confirmations,
        None => prompt_value(
            "Transaction confirmation blocks (1-12)",
            &config.transaction_confirmations.to_string(),
        )?
        .parse()
        .context("transaction confirmation blocks must be a number from 1 to 12")?,
    };
    config.validate()?;

    let selected = config
        .wallet_address
        .as_deref()
        .and_then(|address| Address::from_str(address).ok());
    let selected_is_usable = if let Some(address) = selected {
        store
            .read_keystore(address)
            .ok()
            .and_then(|bytes| wallet::validate_v3_keystore(&bytes).ok())
            == Some(address)
    } else {
        false
    };

    if selected_is_usable && prompt_yes_no("Keep the selected wallet?", true)? {
        store.save(&config)?;
    } else {
        println!(
            "Wallet setup: 1) create a new wallet  2) import a mnemonic  3) import an Ethereum V3 keyfile"
        );
        match prompt_choice("Choose 1, 2, or 3", &["1", "2", "3"])? {
            "1" => {
                wallet::create_interactive(&store, &mut config)?;
            }
            "2" => {
                wallet::import_interactive(
                    &store,
                    &mut config,
                    crate::cli::ImportArgs {
                        keystore: None,
                        derivation_path: "m/44'/60'/0'/0/0".to_owned(),
                    },
                )?;
            }
            "3" => {
                let path = prompt_value("Path to encrypted V3 keyfile", "")?;
                wallet::import_interactive(
                    &store,
                    &mut config,
                    crate::cli::ImportArgs {
                        keystore: Some(PathBuf::from(path)),
                        derivation_path: "m/44'/60'/0'/0/0".to_owned(),
                    },
                )?;
            }
            _ => unreachable!("choice parser restricts valid choices"),
        }
    }

    config.validate()?;
    store.save(&config)?;
    println!(
        "Configured {} | {} CPU worker(s) | reserve {} INJ | per-session maximum exposure {} INJ | confirmations {} block(s)",
        network_label(config.network),
        config.cpu_threads,
        config.minimum_reserve_inj,
        config.per_session_spending_limit_inj,
        config.transaction_confirmations
    );
    println!(
        "Wallet address: {}",
        config.wallet_address.as_deref().unwrap_or("not selected")
    );
    println!("A zero per-session limit disables transaction signing and spending.");
    Ok(())
}

async fn run_status() -> Result<()> {
    let store = ConfigStore::system_default()?;
    let config = store.load()?;
    let wallet_address = config
        .wallet_address
        .as_deref()
        .map(Address::from_str)
        .transpose()
        .context("configured wallet address is invalid")?;
    let client = NetworkClient::connect(config.network).await?;
    let snapshot = client.snapshot(wallet_address).await?;
    let eligible = snapshot
        .nodes
        .iter()
        .filter(|node| node.state.as_ref().is_some_and(|state| state.eligible))
        .count();
    println!(
        "{} chain {} | block {} | wallet {} | INJ {} | eligible nodes {}/9",
        network_label(config.network),
        client.manifest.chain_id,
        snapshot.block.number,
        wallet_address
            .map(|address| format!("{address:#x}"))
            .unwrap_or_else(|| "not set".to_owned()),
        format_inj(snapshot.native_balance),
        eligible
    );
    if let Some(error) = snapshot.native_balance_error {
        println!("INJ balance unavailable: {error}");
    }
    if let Some(balance) = snapshot.ast_balance {
        println!(
            "AST wallet balance: {}",
            format_token_units(
                balance,
                client
                    .manifest
                    .ast_token
                    .as_ref()
                    .map(|token| token.decimals)
                    .unwrap_or(9)
            )
        );
    } else if let Some(error) = snapshot.ast_balance_error {
        println!("AST balance unverified: {error}");
    }
    print_nodes(&snapshot.nodes);
    Ok(())
}

async fn run_rewards() -> Result<()> {
    let store = ConfigStore::system_default()?;
    let config = store.load()?;
    let address = wallet::selected_address(&config)?;
    let client = NetworkClient::connect(config.network).await?;
    let snapshot = client.snapshot(Some(address)).await?;
    if !client.verification.token_verified {
        bail!("AST token runtime is not verified; refusing to report a token balance as verified");
    }
    let balance = snapshot
        .ast_balance
        .context("AST wallet balance is unavailable")?;
    let decimals = client
        .manifest
        .ast_token
        .as_ref()
        .map(|token| token.decimals)
        .context("AST token is not configured")?;
    println!(
        "AST wallet balance: {} (token balance; this is not per-window reward attribution)",
        format_token_units(balance, decimals)
    );
    Ok(())
}

fn print_nodes(nodes: &[NodeView]) {
    for node in nodes {
        let code_pin = if node.pin.runtime_verified && node.pin.abi_verified {
            "verified"
        } else {
            "unverified"
        };
        match &node.state {
            Some(state) => {
                let incumbent = state
                    .candidate
                    .as_ref()
                    .map(|candidate| {
                        format!(
                            " incumbent={:#x} miner={:#x} nonce={} submitted_at={} first_valid_solve={}s",
                            candidate.work_hash,
                            candidate.miner,
                            candidate.nonce,
                            candidate.submitted_at,
                            candidate.first_valid_solve_secs
                        )
                    })
                    .unwrap_or_default();
                println!(
                    "node {} {} | window {} | target {:#x} | {}{} | code {}",
                    node.id,
                    node.address,
                    state.work.window_id,
                    state.work.target,
                    if state.eligible {
                        "eligible"
                    } else {
                        state.eligibility_reason
                    },
                    incumbent,
                    code_pin
                );
            }
            None => println!(
                "node {} {} | unavailable | code {} | {}",
                node.id,
                node.address,
                code_pin,
                node.error.as_deref().unwrap_or("state unavailable")
            ),
        }
    }
}

fn prompt_network(current: Network) -> Result<Network> {
    let default = match current {
        Network::Testnet => "testnet",
        Network::Mainnet => "mainnet",
    };
    loop {
        let value = prompt_value("Network (testnet/mainnet)", default)?;
        match value.to_ascii_lowercase().as_str() {
            "testnet" => return Ok(Network::Testnet),
            "mainnet" => return Ok(Network::Mainnet),
            _ => println!("Choose testnet or mainnet."),
        }
    }
}

fn prompt_threads(current: usize) -> Result<usize> {
    loop {
        let value = prompt_value("CPU worker budget (1-256)", &current.to_string())?;
        match value.parse::<NonZeroUsize>() {
            Ok(threads) if threads.get() <= 256 => return Ok(threads.get()),
            _ => println!("Enter a positive worker count no greater than 256."),
        }
    }
}

fn prompt_value(prompt: &str, default: &str) -> Result<String> {
    print!("{prompt} [{default}]: ");
    io::stdout().flush().context("flush input prompt")?;
    let mut value = String::new();
    io::stdin().read_line(&mut value).context("read input")?;
    let value = value.trim();
    Ok(if value.is_empty() {
        default.to_owned()
    } else {
        value.to_owned()
    })
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
    let default = if default_yes { "Y/n" } else { "y/N" };
    loop {
        let value = prompt_value(&format!("{prompt} ({default})"), "")?;
        match value.to_ascii_lowercase().as_str() {
            "" => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Answer y or n."),
        }
    }
}

fn prompt_choice<'a>(prompt: &str, choices: &'a [&'a str]) -> Result<&'a str> {
    loop {
        let value = prompt_value(prompt, "1")?;
        if let Some(choice) = choices.iter().copied().find(|choice| *choice == value) {
            return Ok(choice);
        }
    }
}

fn format_inj(value: Option<U256>) -> String {
    value
        .map(|value| format_token_units(value, 18))
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn format_token_units(value: U256, decimals: u8) -> String {
    let scale = U256::from(10_u8).pow(U256::from(decimals));
    let whole = value / scale;
    let fractional = (value % scale).to_string();
    let width = usize::from(decimals);
    let fractional = format!("{fractional:0>width$}")
        .trim_end_matches('0')
        .to_owned();
    if fractional.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{fractional}")
    }
}

fn network_label(network: Network) -> &'static str {
    match network {
        Network::Testnet => "Testnet",
        Network::Mainnet => "Mainnet",
    }
}

fn chain_id(network: Network) -> u64 {
    match network {
        Network::Testnet => 1439,
        Network::Mainnet => 1776,
    }
}
