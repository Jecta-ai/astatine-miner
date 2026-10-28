use alloy_primitives::Address;
use clap::{Arg, ArgMatches, Command as ClapCommand};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroUsize, path::PathBuf, str::FromStr};

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
    Devices,
    Benchmark(BenchmarkArgs),
    Update(UpdateArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BenchmarkArgs {
    pub seconds: u8,
    pub threads: Option<NonZeroUsize>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DeviceChoice {
    #[default]
    Cpu,
    Gpu,
    Auto,
}

impl FromStr for DeviceChoice {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "cpu" => Ok(Self::Cpu),
            "gpu" => Ok(Self::Gpu),
            "auto" => Ok(Self::Auto),
            _ => Err("device must be cpu, gpu, or auto".to_owned()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdateArgs {
    pub check_only: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct MineArgs {
    pub device: DeviceChoice,
    pub compute_only: bool,
    pub threads: Option<NonZeroUsize>,
    pub nodes: Vec<u8>,
    pub send_rewards_to: Option<Address>,
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

fn parse_reward_destination(value: &str) -> Result<Address, String> {
    let address =
        Address::from_str(value).map_err(|_| "expected a 20-byte EVM address".to_owned())?;
    if address.is_zero() {
        return Err("reward destination cannot be the zero address".to_owned());
    }
    let body = value.strip_prefix("0x").unwrap_or_default();
    let has_lower = body.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_upper = body.bytes().any(|byte| byte.is_ascii_uppercase());
    if has_lower && has_upper {
        Address::parse_checksummed(value, None).map_err(|_| {
            "mixed-case reward destination has an invalid EIP-55 checksum".to_owned()
        })?;
    }
    Ok(address)
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
            "Astatine is a non-custodial CPU/GPU miner. CPU is the default backend. GPU candidates are checked again by the canonical CPU WorkHasher before entering the bounded proof pipeline. Default mining may sign Testnet proof and finalization transactions within the configured session spending cap. Permissionless finalization can spend gas for empty windows or windows won by another miner. --compute-only never signs or submits transactions. Mainnet transaction signing is disabled.",
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
                .about("Mine eligible Astatine work using the local CPU or a validated GPU")
                .arg(
                    Arg::new("device")
                        .long("device")
                        .value_name("DEVICE")
                        .value_parser(clap::value_parser!(DeviceChoice))
                        .default_value("cpu")
                        .help("Compute backend: cpu (default), gpu, or auto"),
                )
                .arg(
                    Arg::new("compute-only")
                        .long("compute-only")
                        .action(clap::ArgAction::SetTrue)
                        .conflicts_with("send-rewards-to")
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
                )
                .arg(
                    Arg::new("send-rewards-to")
                        .long("send-rewards-to")
                        .value_name("ADDRESS")
                        .value_parser(parse_reward_destination)
                        .help("Forward verified AST rewards earned by this invocation to an EVM address"),
                ),
        )
        .subcommand(wallet_command())
        .subcommand(network_command())
        .subcommand(ClapCommand::new("nodes").about("Show the configured mining nodes"))
        .subcommand(ClapCommand::new("devices").about("List compute devices and run GPU SHA-256d self-tests"))
        .subcommand(
            ClapCommand::new("benchmark")
                .about("Measure canonical CPU/GPU SHA-256d throughput without RPC or transactions")
                .arg(
                    Arg::new("seconds")
                        .long("seconds")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u8).range(1..=60))
                        .default_value("5")
                        .help("Benchmark duration per backend (1-60 seconds)"),
                )
                .arg(
                    Arg::new("threads")
                        .long("threads")
                        .value_name("N")
                        .value_parser(clap::value_parser!(NonZeroUsize))
                        .help("CPU baseline thread count (defaults to the conservative CPU budget)"),
                ),
        )
        .subcommand(ClapCommand::new("status").about("Show local miner status"))
        .subcommand(ClapCommand::new("rewards").about("Show the verified AST token balance"))
        .subcommand(
            ClapCommand::new("update")
                .about("Check for and install an authenticated release update")
                .arg(
                    Arg::new("check")
                        .long("check")
                        .action(clap::ArgAction::SetTrue)
                        .help("Check for a newer authenticated release without installing it"),
                ),
        )
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
            device: args
                .get_one::<DeviceChoice>("device")
                .copied()
                .unwrap_or_default(),
            compute_only: args.get_flag("compute-only"),
            threads: args.get_one::<NonZeroUsize>("threads").copied(),
            nodes: args
                .get_many::<u8>("nodes")
                .map(|nodes| nodes.copied().collect())
                .unwrap_or_default(),
            send_rewards_to: args.get_one::<Address>("send-rewards-to").copied(),
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
        Some(("devices", _)) => Command::Devices,
        Some(("benchmark", args)) => Command::Benchmark(BenchmarkArgs {
            seconds: *args
                .get_one::<u8>("seconds")
                .expect("benchmark duration has a default"),
            threads: args.get_one::<NonZeroUsize>("threads").copied(),
        }),
        Some(("update", args)) => Command::Update(UpdateArgs {
            check_only: args.get_flag("check"),
        }),
        _ => unreachable!("top-level command is required and restricted to known commands"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BenchmarkArgs, Command, DeviceChoice, ImportArgs, Network, NonZeroUsize, WalletCommand,
        try_parse_from,
    };
    use alloy_primitives::Address;

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
        assert_eq!(args.device, DeviceChoice::Cpu);
        assert!(args.compute_only);
        assert_eq!(args.threads.map(|threads| threads.get()), Some(4));
        assert_eq!(args.nodes, [1, 3, 5]);
        assert_eq!(args.send_rewards_to, None);
    }

    #[test]
    fn mine_defaults_to_autonomous_mode_and_keeps_compute_only_opt_in() {
        let cli = try_parse_from(["astatine", "mine"]).expect("mine command should parse");
        let Command::Mine(args) = cli.command else {
            panic!("expected mine subcommand");
        };
        assert!(!args.compute_only);
        assert_eq!(args.device, DeviceChoice::Cpu);
        assert_eq!(args.send_rewards_to, None);
    }

    #[test]
    fn parses_explicit_gpu_device_modes() {
        for (name, expected) in [
            ("cpu", DeviceChoice::Cpu),
            ("gpu", DeviceChoice::Gpu),
            ("auto", DeviceChoice::Auto),
        ] {
            let cli = try_parse_from(["astatine", "mine", "--device", name])
                .expect("device choice should parse");
            let Command::Mine(args) = cli.command else {
                panic!("expected mine subcommand");
            };
            assert_eq!(args.device, expected);
        }
        assert!(try_parse_from(["astatine", "mine", "--device", "cuda"]).is_err());
    }

    #[test]
    fn parses_benchmark_as_a_bounded_read_only_command() {
        assert_eq!(
            try_parse_from(["astatine", "devices"]).unwrap().command,
            Command::Devices
        );
        let default = try_parse_from(["astatine", "benchmark"]).unwrap();
        assert_eq!(
            default.command,
            Command::Benchmark(BenchmarkArgs {
                seconds: 5,
                threads: None
            })
        );
        let explicit =
            try_parse_from(["astatine", "benchmark", "--seconds", "8", "--threads", "4"]).unwrap();
        assert_eq!(
            explicit.command,
            Command::Benchmark(BenchmarkArgs {
                seconds: 8,
                threads: NonZeroUsize::new(4)
            })
        );
        assert!(try_parse_from(["astatine", "benchmark", "--seconds", "0"]).is_err());
        assert!(try_parse_from(["astatine", "benchmark", "--seconds", "61"]).is_err());
    }

    #[test]
    fn parses_reward_destination_and_enforces_mixed_case_checksum() {
        let lowercase = try_parse_from([
            "astatine",
            "mine",
            "--device",
            "gpu",
            "--nodes",
            "1,2,3,4,5,6,7,8,9",
            "--threads",
            "16",
            "--send-rewards-to",
            "0x0000000000000000000000000000000000000001",
        ])
        .expect("lowercase EVM destination should parse");
        let Command::Mine(args) = lowercase.command else {
            panic!("expected mine subcommand");
        };
        assert_eq!(args.device, DeviceChoice::Gpu);
        assert_eq!(args.nodes, (1..=9).collect::<Vec<_>>());
        assert_eq!(args.threads.map(|threads| threads.get()), Some(16));
        assert_eq!(args.send_rewards_to, Some(Address::with_last_byte(1)));

        let gpu_compute = try_parse_from(["astatine", "mine", "--device", "gpu", "--compute-only"])
            .expect("GPU compute-only mode should parse");
        let Command::Mine(args) = gpu_compute.command else {
            panic!("expected mine subcommand");
        };
        assert_eq!(args.device, DeviceChoice::Gpu);
        assert!(args.compute_only);

        let checksummed = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        assert!(try_parse_from(["astatine", "mine", "--send-rewards-to", checksummed]).is_ok());
        assert!(
            try_parse_from([
                "astatine",
                "mine",
                "--send-rewards-to",
                "0xD8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
            ])
            .is_err()
        );
        assert!(
            try_parse_from([
                "astatine",
                "mine",
                "--send-rewards-to",
                "0x0000000000000000000000000000000000000000"
            ])
            .is_err()
        );
        assert!(
            try_parse_from([
                "astatine",
                "mine",
                "--compute-only",
                "--send-rewards-to",
                checksummed
            ])
            .is_err()
        );
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

        let update = try_parse_from(["astatine", "update"]).expect("update command should parse");
        assert_eq!(
            update.command,
            Command::Update(super::UpdateArgs { check_only: false })
        );
        let check = try_parse_from(["astatine", "update", "--check"])
            .expect("update check command should parse");
        assert_eq!(
            check.command,
            Command::Update(super::UpdateArgs { check_only: true })
        );
    }
}
