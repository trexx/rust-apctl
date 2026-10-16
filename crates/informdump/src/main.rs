//! informdump: decode inform traffic between access points and a controller.
//!
//! Typical live use on the node running the controller:
//!
//! ```text
//! tcpdump -i any -U -w - 'tcp port 8080' | informdump watch --keys keys.json
//! ```

mod demo;
#[cfg(feature = "mongo")]
mod import;
mod report;
mod sanitize;
mod simulate;

use std::io::Write;
use std::path::{Path, PathBuf};

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
    /// Needs a build with the `mongo` feature: `cargo build --release -p informdump --features mongo`.
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
    /// Rehearse against a LOCAL controller: replay the informs in a capture as the
    /// APs (re-encrypted with their keys), adopting pushed configs like an AP.
    Simulate {
        pcap: String,
        #[arg(long)]
        keys: String,
        /// Inform URL of a local controller, e.g. http://127.0.0.1:18180/inform.
        #[arg(long)]
        url: String,
        /// Maximum number of informs to send.
        #[arg(long, default_value = "40")]
        limit: usize,
        /// Seconds to wait between informs (0: as fast as the controller answers).
        #[arg(long, default_value = "0")]
        every: f64,
        /// Server ports carrying inform traffic in the capture.
        #[arg(long = "port", default_value = "8080")]
        ports: Vec<u16>,
    },
    /// Write a made-up site's capture (three APs, their clients, syslog) as pcap to
    /// stdout, for demos and screenshots: `apctl serve --keys <demo-state output>
    /// --shadow-cmd "informdump demo --live"`.
    Demo {
        /// Hours of history before now.
        #[arg(long, default_value = "24")]
        hours: f64,
        /// Keep reporting in real time after the history.
        #[arg(long)]
        live: bool,
    },
    /// Print the made-up site's controller settings and AP keys (for `apctl serve
    /// --keys` and the Settings page) that go with `informdump demo`.
    DemoState,
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

/// A fresh nonce for sealing a packet: random, so it never repeats under one key.
pub fn random_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).expect("system random source");
    iv
}

/// Writes a file only its owner can read (mode 0600): it holds secrets. A file that
/// was already there is made private too before anything is written to it (the mode
/// given when opening only applies to a new file).
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| format!("creating {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600)).with_context(|| format!("making {} private", path.display()))?;
    }
    f.write_all(data)?;
    Ok(())
}

/// Creates a directory (and its parents) only its owner can enter (mode 0700). One
/// that is already there keeps its mode (it may be a shared one, such as /tmp): the
/// files written into it are private themselves.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).with_context(|| format!("creating {}", dir.display()))
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
        Cmd::Demo { hours, live } => demo::run(hours, live, std::io::BufWriter::new(std::io::stdout().lock())),
        Cmd::DemoState => {
            println!("{}", serde_json::to_string_pretty(&demo::state()?)?);
            Ok(())
        }
        Cmd::Simulate { pcap, keys, url, limit, every, ports } => simulate::run(&pcap, &ports, &load_keys(Some(&keys))?, &url, limit, every),
        Cmd::Sanitize { input, output, domains, devices, files } => {
            sanitize::run(&input, &output, &files, domains, &devices)
        }
        #[cfg(feature = "mongo")]
        Cmd::Import { mongo, db, out } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(import::run(&mongo, &db, &out)),
        #[cfg(not(feature = "mongo"))]
        Cmd::Import { .. } => anyhow::bail!(
            "this informdump was built without MongoDB support; rebuild it with `cargo build --release -p informdump --features mongo`"
        ),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn an_existing_file_is_made_private() {
        let path = std::env::temp_dir().join(format!("informdump-private-{}", std::process::id()));
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        super::write_private(&path, b"secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!((mode, text.as_str()), (0o600, "secret"));
    }
}
