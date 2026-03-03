//! Long-running directory cache daemon.
//!
//! Keeps consensus and microdescriptors as fresh as possible, using the
//! same aggressive schedule that Tor relay directory caches use:
//! fetch a new consensus at a random time in the first half-interval
//! after `fresh_until`.
//!
//! Uses `arti-client` for bootstrapping and circuit management.
//! Parses each consensus to extract microdesc digests and fetches them.
//! Writes files atomically so readers always see consistent state.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use clap::Parser;
use futures::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use base64ct::Encoding as _;
use rand::Rng;
use tor_checkable::{ExternallySigned, Timebound};
use tor_circmgr::DirInfo;
use tor_netdir::Timeliness;
use tor_netdoc::doc::netstatus::MdConsensus;

use arti_client::{TorClient, TorClientConfig};

#[derive(Parser)]
#[command(name = "tor-dir-cache")]
#[command(about = "Long-running Tor directory cache — syncs like a relay")]
struct Cli {
    /// Output directory for cached documents
    #[arg(short, long)]
    output_dir: PathBuf,
}

/// Fetch raw bytes from a directory cache via BEGINDIR stream.
async fn dir_get(
    client: &TorClient<tor_rtcompat::PreferredRuntime>,
    path: &str,
) -> Result<Vec<u8>> {
    let netdir = client
        .dirmgr()
        .netdir(Timeliness::Timely)
        .map_err(|e| anyhow::anyhow!("getting network directory: {}", e))?;

    let dir_tunnel = client
        .circmgr()
        .get_or_launch_dir(DirInfo::Directory(&netdir))
        .await
        .map_err(|e| anyhow::anyhow!("getting dir circuit: {}", e))?;

    let mut stream = dir_tunnel
        .begin_dir_stream()
        .await
        .map_err(|e| anyhow::anyhow!("opening BEGINDIR stream: {}", e))?;

    let request = format!(
        "GET {} HTTP/1.0\r\n\
         Accept-Encoding: deflate, identity, x-tor-lzma, x-zstd\r\n\
         \r\n",
        path
    );
    stream
        .write_all(request.as_bytes())
        .await
        .context("writing request")?;
    stream.flush().await.context("flushing request")?;

    // Parse HTTP/1.0 response
    let mut reader = BufReader::new(stream);
    let mut header_buf = String::new();
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .await
            .context("reading header line")?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        header_buf.push_str(&line);
    }

    let status: u16 = header_buf
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);

    if status != 200 {
        bail!("GET {} returned status {}", path, status);
    }

    // Find Content-Encoding
    let encoding = header_buf
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-encoding"))
        .map(|(_, v)| v.trim().to_string());

    let mut body = Vec::new();
    let _ = reader.read_to_end(&mut body).await;

    decompress(encoding.as_deref(), &body).await
}

async fn decompress(encoding: Option<&str>, data: &[u8]) -> Result<Vec<u8>> {
    use async_compression::futures::bufread::*;

    let mut out = Vec::new();
    match encoding {
        None | Some("identity") => {
            out = data.to_vec();
        }
        Some("deflate") => {
            let mut decoder = ZlibDecoder::new(data);
            decoder
                .read_to_end(&mut out)
                .await
                .context("deflate decode")?;
        }
        Some("x-tor-lzma") => {
            let mut decoder = XzDecoder::new(data);
            decoder.read_to_end(&mut out).await.context("xz decode")?;
        }
        Some("x-zstd") => {
            let mut decoder = ZstdDecoder::new(data);
            decoder
                .read_to_end(&mut out)
                .await
                .context("zstd decode")?;
        }
        Some(other) => bail!("unsupported encoding: {}", other),
    }
    Ok(out)
}

/// Compute the relay-style sync delay: random time in the first half-interval
/// after `fresh_until`.
///
/// Per dir-spec §4: "the cache downloads a new consensus document at a randomly
/// chosen time in the first half-interval after its current consensus stops
/// being fresh."
fn relay_sync_delay(fresh_until: SystemTime, valid_until: SystemTime) -> Duration {
    let half_interval = valid_until
        .duration_since(fresh_until)
        .unwrap_or(Duration::from_secs(1800))
        / 2;
    let offset = rand::rng().random_range(Duration::ZERO..=half_interval);
    let target = fresh_until + offset;
    target
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO)
}

/// Fetch consensus, parse it, fetch all microdescs, write everything to disk.
/// Returns the consensus lifetime for scheduling the next sync.
async fn sync_once(
    client: &TorClient<tor_rtcompat::PreferredRuntime>,
    output_dir: &PathBuf,
) -> Result<tor_netdoc::doc::netstatus::Lifetime> {
    // --- Fetch consensus ---
    tracing::info!("fetching consensus...");
    let consensus_bytes =
        dir_get(client, "/tor/status-vote/current/consensus-microdesc").await?;
    let consensus_text =
        String::from_utf8(consensus_bytes).context("consensus is not valid UTF-8")?;

    // --- Parse consensus ---
    let (_signed, _remainder, unchecked) =
        MdConsensus::parse(&consensus_text).context("parsing consensus")?;
    let consensus = unchecked
        .dangerously_assume_timely()
        .dangerously_assume_wellsigned();

    let lifetime = consensus.lifetime().clone();
    let num_relays = consensus.relays().len();
    tracing::info!(
        "consensus: {} relays, valid_after={}, fresh_until={}, valid_until={}",
        num_relays,
        humantime::format_rfc3339(lifetime.valid_after()),
        humantime::format_rfc3339(lifetime.fresh_until()),
        humantime::format_rfc3339(lifetime.valid_until()),
    );

    // --- Extract microdesc digests ---
    let digests: Vec<_> = consensus
        .relays()
        .iter()
        .map(|rs| *rs.md_digest())
        .collect();

    // --- Fetch microdescs in batches ---
    let batch_size = 500;
    let total_batches = (digests.len() + batch_size - 1) / batch_size;
    let mut all_microdescs = Vec::new();

    for (batch_idx, batch) in digests.chunks(batch_size).enumerate() {
        tracing::info!(
            "fetching microdescs batch {}/{}...",
            batch_idx + 1,
            total_batches,
        );

        // Build the /tor/micro/d/<d1>-<d2>-... path
        let digests_str: Vec<String> = batch
            .iter()
            .map(|d| base64ct::Base64Unpadded::encode_string(d))
            .collect();
        let path = format!("/tor/micro/d/{}", digests_str.join("-"));

        match dir_get(client, &path).await {
            Ok(bytes) => {
                all_microdescs.extend_from_slice(&bytes);
            }
            Err(e) => {
                tracing::warn!("microdesc batch {} failed: {}", batch_idx + 1, e);
            }
        }
    }

    tracing::info!(
        "fetched {} bytes of microdescriptors",
        all_microdescs.len()
    );

    // --- Write files atomically (write to .tmp, then rename) ---
    let consensus_path = output_dir.join("consensus-microdesc");
    let consensus_tmp = output_dir.join("consensus-microdesc.tmp");
    std::fs::write(&consensus_tmp, &consensus_text)
        .with_context(|| format!("writing {:?}", consensus_tmp))?;
    std::fs::rename(&consensus_tmp, &consensus_path)
        .with_context(|| format!("renaming {:?}", consensus_path))?;
    tracing::info!(
        "wrote {} ({} bytes)",
        consensus_path.display(),
        consensus_text.len()
    );

    let microdescs_path = output_dir.join("microdescs");
    let microdescs_tmp = output_dir.join("microdescs.tmp");
    std::fs::write(&microdescs_tmp, &all_microdescs)
        .with_context(|| format!("writing {:?}", microdescs_tmp))?;
    std::fs::rename(&microdescs_tmp, &microdescs_path)
        .with_context(|| format!("renaming {:?}", microdescs_path))?;
    tracing::info!(
        "wrote {} ({} bytes)",
        microdescs_path.display(),
        all_microdescs.len()
    );

    let metadata = serde_json::json!({
        "consensus_flavor": "microdesc",
        "valid_after": humantime::format_rfc3339(lifetime.valid_after()).to_string(),
        "fresh_until": humantime::format_rfc3339(lifetime.fresh_until()).to_string(),
        "valid_until": humantime::format_rfc3339(lifetime.valid_until()).to_string(),
        "num_relays": num_relays,
        "num_microdescs_requested": digests.len(),
        "microdescs_bytes": all_microdescs.len(),
        "synced_at": humantime::format_rfc3339(SystemTime::now()).to_string(),
    });
    let metadata_path = output_dir.join("metadata.json");
    let metadata_tmp = output_dir.join("metadata.json.tmp");
    std::fs::write(&metadata_tmp, serde_json::to_string_pretty(&metadata)?)
        .with_context(|| format!("writing {:?}", metadata_tmp))?;
    std::fs::rename(&metadata_tmp, &metadata_path)
        .with_context(|| format!("renaming {:?}", metadata_path))?;

    Ok(lifetime)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    std::fs::create_dir_all(&cli.output_dir)
        .with_context(|| format!("creating output dir {:?}", cli.output_dir))?;

    tracing::info!("bootstrapping TorClient...");
    let config = TorClientConfig::default();
    let client = TorClient::create_bootstrapped(config)
        .await
        .context("bootstrapping TorClient")?;
    tracing::info!("TorClient bootstrapped");

    loop {
        match sync_once(&client, &cli.output_dir).await {
            Ok(lifetime) => {
                let delay = relay_sync_delay(lifetime.fresh_until(), lifetime.valid_until());
                tracing::info!(
                    "next sync in {} (at ~{})",
                    humantime::format_duration(delay),
                    humantime::format_rfc3339(SystemTime::now() + delay),
                );
                tokio::time::sleep(delay).await;
            }
            Err(e) => {
                tracing::error!("sync failed: {:#}", e);
                let retry = Duration::from_secs(60);
                tracing::info!("retrying in {}", humantime::format_duration(retry));
                tokio::time::sleep(retry).await;
            }
        }
    }
}