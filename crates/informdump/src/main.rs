//! informdump: decode inform traffic between access points and a controller.
//!
//! Typical live use on the node running the controller:
//!
//! ```text
//! tcpdump -i any -U -w - 'tcp port 8080' | informdump watch --keys keys.json
//! ```

mod import;
mod report;
mod sanitize;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use wire::capture;
use wire::keys::KeyStore;
use report::{Options, Reporter};

#[derive(Parser)]
#[command(version, about = "Decode inform protocol traffic between access points and their controller")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Decode a single raw inform packet (an HTTP body) from a file.
    Decode {
        file: PathBuf,
        /// Hex authkey to use (otherwise --keys, then the default key, are tried).
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        keys: Option<String>,
    },
    /// Decode every inform exchange in a pcap/pcapng file ("-" for stdin).
    Pcap {
        file: String,
        #[command(flatten)]
        common: Common,
        /// Show every inform and every noop reply, not just changes.
        #[arg(long)]
        all: bool,
    },
    /// Snapshot sites, WLANs and device authkeys from a controller's MongoDB (read-only).
    ///
    /// For a controller in Kubernetes:
    /// `kubectl -n unifi-controller port-forward pod/unifi-controller-0 27117:27117`
    Import {
        #[arg(long, default_value = "mongodb://127.0.0.1:27117")]
        mongo: String,
        #[arg(long, default_value = "ace")]
        db: String,
        /// Output file. Contains secrets, so keep it outside the repository.
        #[arg(long)]
        out: PathBuf,
    },
    /// Write sanitised copies of decoded payload files (fake MACs, SSIDs, hostnames,
    /// IDs and secrets), refusing to write if any original value survives.
    Sanitize {
        /// Directory holding the decoded JSON files (from --save).
        #[arg(long)]
        input: PathBuf,
        /// Output directory for the fixtures.
        #[arg(long)]
        output: PathBuf,
        /// Domain names to replace with example.net (e.g. the controller's DNS name).
        #[arg(long = "domain")]
        domains: Vec<String>,
        /// Device MACs to number first, so APs get stable low fake addresses.
        #[arg(long = "device")]
        devices: Vec<String>,
        /// File names inside --input to sanitise.
        files: Vec<String>,
    },
    /// Follow a live capture on stdin and print config pushes and new devices as they happen.
    Watch {
        #[command(flatten)]
        common: Common,
        /// Show every inform and every noop reply, not just changes.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Args)]
struct Common {
    /// JSON file with device authkeys (a MAC->key map or an import snapshot).
    #[arg(long)]
    keys: Option<String>,
    /// Server ports carrying inform traffic.
    #[arg(long = "port", default_value = "8080")]
    ports: Vec<u16>,
    /// Print the full decoded JSON of every shown message.
    #[arg(long)]
    full: bool,
    /// Print one JSON object per message (for scripting).
    #[arg(long)]
    json: bool,
    /// Save every decoded payload as a JSON file in this directory (unredacted).
    #[arg(long)]
    save: Option<PathBuf>,
    /// Print passwords, PSKs and keys instead of masking them.
    #[arg(long)]
    no_redact: bool,
}

fn load_keys(path: Option<&str>) -> Result<KeyStore> {
    match path {
        Some(p) => {
            let store = KeyStore::load(p)?;
            eprintln!("loaded {} device keys from {p}", store.len());
            Ok(store)
        }
        None => Ok(KeyStore::default()),
    }
}

fn run_capture(input: &str, common: Common, all: bool) -> Result<()> {
    let keys = load_keys(common.keys.as_deref())?;
    let mut reporter = Reporter::new(
        keys,
        Options { all, full: common.full, json: common.json, save: common.save, redact: !common.no_redact },
    );
    capture::run(capture::open_input(input)?, &common.ports, |ev| reporter.handle(ev))
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Decode { file, key, keys } => {
            let body = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let mut store = load_keys(keys.as_deref())?;
            if let Some(k) = key {
                let mac = inform::Header::parse(&body)?.mac;
                store.insert(&mac.to_string(), &k)?;
            }
            let d = wire::decode::decode(&body, &store, None)?;
            eprintln!("{:#?}\nkey used: {:?}", d.header, d.key);
            println!("{}", serde_json::to_string_pretty(&d.payload)?);
            Ok(())
        }
        Cmd::Pcap { file, common, all } => run_capture(&file, common, all),
        Cmd::Watch { common, all } => run_capture("-", common, all),
        Cmd::Sanitize { input, output, domains, devices, files } => {
            sanitize::run(&input, &output, &files, domains, &devices)
        }
        Cmd::Import { mongo, db, out } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(import::run(&mongo, &db, &out)),
    }
}
