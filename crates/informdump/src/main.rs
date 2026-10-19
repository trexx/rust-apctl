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
use std::ops::ControlFlow;
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
        /// Also pass this field, which holds nothing personal (`field`, `parent.field`,
        /// or a config key with its numbers as `n`). Fields not on the allow-list are
        /// replaced as text; the run lists them.
        #[arg(long = "keep")]
        keep: Vec<String>,
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
    /// Save every decoded payload as a JSON file in this directory (unredacted). Files
    /// already there are not overwritten.
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
            for why in store.skipped() {
                eprintln!("warning: {why}");
            }
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
    let end = capture::run(capture::open_input(input)?, &common.ports, |ev| {
        reporter.handle(ev);
        ControlFlow::Continue(())
    })?;
    warn_if_truncated(end);
    Ok(())
}

/// Says so when a capture ended in the middle of a packet.
fn warn_if_truncated(end: capture::End) {
    if end == capture::End::Truncated {
        eprintln!("warning: the capture ends in the middle of a packet (truncated?); ignoring the rest");
    }
}

/// A fresh nonce for sealing a packet: random, so it never repeats under one key.
pub fn random_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).expect("system random source");
    iv
}

/// Creates a file only its owner can read (mode 0600), as it holds secrets. It must not
/// exist yet: in a shared directory, a file or symlink planted under its name would
/// otherwise receive them.
pub fn create_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

/// Writes a file only its owner can read (mode 0600), replacing one that was already
/// there: the data goes into a new file next to it, which is then renamed over it. The
/// rename replaces a symlink instead of following it, and the old file's mode does not
/// carry over.
#[cfg(any(feature = "mongo", test))]
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let name = path.file_name().with_context(|| format!("{} is not a file name", path.display()))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    let written = create_private(&tmp, data).and_then(|()| std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display())));
    if written.is_err() {
        std::fs::remove_file(&tmp).ok();
    }
    written
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
                store.insert_for(mac, &k)?;
            }
            let d = wire::decode::decode(&body, &store, None)?;
            eprintln!("{:#?}\nkey used: {:?}", d.header, d.key);
            println!("{}", report::escape_controls(&serde_json::to_string_pretty(&d.payload)?, true));
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
        Cmd::Sanitize { input, output, domains, devices, keep, files } => {
            sanitize::run(&input, &output, &files, domains, &devices, keep)
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
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("informdump-private-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn an_existing_file_is_replaced_by_a_private_one() {
        let dir = temp_dir("replace");
        let path = dir.join("snapshot.json");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        super::write_private(&path, b"secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let text = std::fs::read_to_string(&path).unwrap();
        let files = std::fs::read_dir(&dir).unwrap().count();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!((mode, text.as_str(), files), (0o600, "secret", 1));
    }

    #[test]
    fn symlinks_are_not_followed() {
        let dir = temp_dir("symlink");
        let target = dir.join("theirs");
        std::fs::write(&target, "theirs").unwrap();
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let created = super::create_private(&link, b"secret");
        super::write_private(&link, b"secret").unwrap();
        let theirs = std::fs::read_to_string(&target).unwrap();
        let replaced = !std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink();
        std::fs::remove_dir_all(&dir).ok();
        assert!(created.is_err(), "create_private refuses a name that is taken");
        assert_eq!((theirs.as_str(), replaced), ("theirs", true), "write_private replaces the link, not its target");
    }
}
