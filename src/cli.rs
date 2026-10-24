use clap::{Arg, ArgMatches, Command as ClapCommand};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroUsize, path::PathBuf};

#[cfg(test)]
use std::ffi::OsString;

#[derive(Debug, Eq, PartialEq)]
pub struct Cli {
    pub command: Command,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Init(InitArgs),
    Mine(MineArgs),
    Wallet(WalletCommand),
    NetworkUse(Network),
    Nodes,
    Status,
    Rewards,
}

#[derive(Debug, Eq, PartialEq)]
pub struct MineArgs {
    pub compute_only: bool,
    pub threads: Option<NonZeroUsize>,
    pub nodes: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct InitArgs {
    pub network: Option<Network>,
    pub threads: Option<NonZeroUsize>,
    pub minimum_reserve_inj: Option<String>,
    pub spending_limit_inj: Option<String>,
    pub transaction_confirmations: Option<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum WalletCommand {
    Create,
    Import(ImportArgs),
    Address,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ImportArgs {
    pub keystore: Option<PathBuf>,
    pub derivation_path: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Testnet,
    Mainnet,
}

pub fn parse() -> Cli {
    let matches = command().get_matches();
    Cli {
        command: parse_matches(&matches),
    }
}

#[cfg(test)]
pub fn try_parse_from<I, T>(arguments: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = command().try_get_matches_from(arguments)?;
    Ok(Cli {
        command: parse_matches(&matches),
    })
}

fn command() -> ClapCommand {
    ClapCommand::new("astatine")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A native command-line miner for Astatine")
        .long_about(
            "Astatine is a non-custodial CPU miner. Default mining may sign Testnet proof and finalization transactions within the configured session spending cap. Permissionless finalization can spend gas for empty windows or windows won by another miner. --compute-only never signs or submits transactions. Mainnet transaction signing is disabled.",
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            ClapCommand::new("init")
                .about("Configure the local wallet, network, CPU, spending cap, and confirmation depth")
                .arg(
                    Arg::new("network")
                        .long("network")
                        .value_name("NETWORK")
                        .value_parser(["testnet", "mainnet"]),
                )
                .arg(
                    Arg::new("threads")
                        .long("threads")
                        .value_name("N")
                        .value_parser(clap::value_parser!(NonZeroUsize)),
                )
                .arg(
                    Arg::new("minimum-reserve-inj")
                        .long("minimum-reserve-inj")
                        .value_name("INJ"),
                )
                .arg(
                    Arg::new("spending-limit-inj")
                        .long("spending-limit-inj")
                        .value_name("INJ"),
                )
                .arg(
                    Arg::new("confirmation-blocks")
                        .long("confirmation-blocks")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u8).range(1..=12)),
                ),
        )
        .subcommand(
            ClapCommand::new("mine")
                .about("Mine eligible Astatine work using the local CPU")
                .arg(
                    Arg::new("compute-only")
                        .long("compute-only")
                        .action(clap::ArgAction::SetTrue)
                        .help("Hash verified work locally without signing or sending transactions"),
                )
                .arg(
                    Arg::new("threads")
                        .long("threads")
                        .value_name("N")
                        .value_parser(clap::value_parser!(NonZeroUsize))
                        .help("Maximum number of CPU worker threads to use"),
                )
                .arg(
                    Arg::new("nodes")
                        .long("nodes")
                        .value_name("ID,...")
                        .num_args(1..)
                        .value_delimiter(',')
                        .value_parser(clap::value_parser!(u8).range(1..=9))
                        .help("Restrict mining to comma-separated node IDs (1-9)"),
                ),
        )
        .subcommand(wallet_command())
        .subcommand(network_command())
        .subcommand(ClapCommand::new("nodes").about("Show the configured mining nodes"))
        .subcommand(ClapCommand::new("status").about("Show local miner status"))
        .subcommand(ClapCommand::new("rewards").about("Show the verified AST token balance"))
}

fn wallet_command() -> ClapCommand {
    ClapCommand::new("wallet")
        .about("Manage the local wallet")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(ClapCommand::new("create").about("Create a new encrypted local wallet"))
        .subcommand(
            ClapCommand::new("import")
                .about("Import a mnemonic or encrypted Ethereum V3 keystore")
                .arg(
                    Arg::new("keystore")
                        .long("keystore")
                        .value_name("PATH")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Import an encrypted V3 keyfile; the password is read securely"),
                )
                .arg(
                    Arg::new("derivation-path")
                        .long("derivation-path")
                        .value_name("PATH")
                        .default_value("m/44'/60'/0'/0/0")
                        .help("BIP-44 path used for mnemonic import"),
                ),
        )
        .subcommand(
            ClapCommand::new("address").about("Display the selected wallet's public address"),
        )
}

fn network_command() -> ClapCommand {
    ClapCommand::new("network")
        .about("Select a network profile")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            ClapCommand::new("use")
                .about("Select the network profile")
                .arg(
                    Arg::new("network")
                        .required(true)
                        .value_name("NETWORK")
                        .value_parser(["testnet", "mainnet"]),
                ),
        )
}

fn parse_matches(matches: &ArgMatches) -> Command {
    match matches.subcommand() {
        Some(("init", args)) => Command::Init(InitArgs {
            network: args
                .get_one::<String>("network")
                .map(|value| match value.as_str() {
                    "testnet" => Network::Testnet,
                    "mainnet" => Network::Mainnet,
                    _ => unreachable!("network value parser restricts the accepted values"),
                }),
            threads: args.get_one::<NonZeroUsize>("threads").copied(),
            minimum_reserve_inj: args.get_one::<String>("minimum-reserve-inj").cloned(),
            spending_limit_inj: args.get_one::<String>("spending-limit-inj").cloned(),
            transaction_confirmations: args.get_one::<u8>("confirmation-blocks").copied(),
        }),
        Some(("mine", args)) => Command::Mine(MineArgs {
            compute_only: args.get_flag("compute-only"),
            threads: args.get_one::<NonZeroUsize>("threads").copied(),
            nodes: args
                .get_many::<u8>("nodes")
                .map(|nodes| nodes.copied().collect())
                .unwrap_or_default(),
        }),
        Some(("wallet", args)) => match args.subcommand() {
            Some(("create", _)) => Command::Wallet(WalletCommand::Create),
            Some(("import", args)) => Command::Wallet(WalletCommand::Import(ImportArgs {
                keystore: args.get_one::<PathBuf>("keystore").cloned(),
                derivation_path: args
                    .get_one::<String>("derivation-path")
                    .expect("derivation path has a default")
                    .clone(),
            })),
            Some(("address", _)) => Command::Wallet(WalletCommand::Address),
            _ => unreachable!("wallet requires a known subcommand"),
        },
        Some(("network", args)) => match args.subcommand() {
            Some(("use", args)) => {
                let network = match args
                    .get_one::<String>("network")
                    .expect("network is required")
                    .as_str()
                {
                    "testnet" => Network::Testnet,
                    "mainnet" => Network::Mainnet,
                    _ => unreachable!("network value parser restricts the accepted values"),
                };
                Command::NetworkUse(network)
            }
            _ => unreachable!("network requires a known subcommand"),
        },
        Some(("nodes", _)) => Command::Nodes,
        Some(("status", _)) => Command::Status,
        Some(("rewards", _)) => Command::Rewards,
        _ => unreachable!("top-level command is required and restricted to known commands"),
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, ImportArgs, Network, WalletCommand, try_parse_from};

    #[test]
    fn parses_primary_commands_and_safe_mining_options() {
        let cli = try_parse_from([
            "astatine",
            "mine",
            "--compute-only",
            "--threads",
            "4",
            "--nodes",
            "1,3,5",
        ])
        .expect("planned mine command should parse");

        let Command::Mine(args) = cli.command else {
            panic!("expected mine subcommand");
        };
        assert!(args.compute_only);
        assert_eq!(args.threads.map(|threads| threads.get()), Some(4));
        assert_eq!(args.nodes, [1, 3, 5]);
    }

    #[test]
    fn mine_defaults_to_autonomous_mode_and_keeps_compute_only_opt_in() {
        let cli = try_parse_from(["astatine", "mine"]).expect("mine command should parse");
        let Command::Mine(args) = cli.command else {
            panic!("expected mine subcommand");
        };
        assert!(!args.compute_only);
    }

    #[test]
    fn init_accepts_a_small_confirmation_depth() {
        let cli = try_parse_from([
            "astatine",
            "init",
            "--network",
            "testnet",
            "--confirmation-blocks",
            "4",
        ])
        .expect("init confirmation threshold should parse");
        let Command::Init(args) = cli.command else {
            panic!("expected init subcommand");
        };
        assert_eq!(args.transaction_confirmations, Some(4));
        assert!(try_parse_from(["astatine", "init", "--confirmation-blocks", "0"]).is_err());
        assert!(try_parse_from(["astatine", "init", "--confirmation-blocks", "13"]).is_err());
    }

    #[test]
    fn rejects_zero_threads_and_unknown_nodes() {
        assert!(try_parse_from(["astatine", "mine", "--threads", "0"]).is_err());
        assert!(try_parse_from(["astatine", "mine", "--nodes", "1,10"]).is_err());
    }

    #[test]
    fn parses_wallet_and_network_command_paths() {
        let wallet = try_parse_from(["astatine", "wallet", "import"])
            .expect("wallet import command should parse");
        assert_eq!(
            wallet.command,
            Command::Wallet(WalletCommand::Import(ImportArgs {
                keystore: None,
                derivation_path: "m/44'/60'/0'/0/0".to_owned(),
            }))
        );

        let network = try_parse_from(["astatine", "network", "use", "mainnet"])
            .expect("network selection command should parse");
        assert_eq!(network.command, Command::NetworkUse(Network::Mainnet));
    }
}
