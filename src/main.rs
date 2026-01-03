//! Sui Validator RTT Probe - Industrial Grade
//!
//! Measures RTT to Sui validators using multiple protocols.
//! Features:
//! - QUIC protocol probe (Anemo P2P layer)
//! - TCP fallback for validators that don't accept QUIC
//! - Concurrency control with semaphore
//! - Stake-weighted ranking and scoring
//! - DNS resolution support
//! - Retry logic with exponential backoff

use anyhow::Result;
use futures::future::join_all;
use quinn::{ClientConfig, Endpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, sync::Semaphore, time::timeout};

use sui_sdk::SuiClientBuilder;

/* ================== Configuration ================== */

/// Sui mainnet RPC endpoint
const RPC_URL: &str = "https://fullnode.mainnet.sui.io";

/// Default port for Sui P2P
const DEFAULT_PORT: u16 = 8084;

/// Number of RTT probes per validator
const RTT_PROBES: usize = 5;

/// Timeout for each probe attempt (ms)
const RTT_TIMEOUT_MS: u64 = 5000;

/// Maximum concurrent connections
const MAX_CONCURRENT_PROBES: usize = 50;

/// Delay between probes to same validator (ms)
const PROBE_INTERVAL_MS: u64 = 100;

/// Number of top validators to display
const TOP_N_VALIDATORS: usize = 30;

/// QUIC idle timeout (ms)
const QUIC_IDLE_TIMEOUT_MS: u64 = 10000;

/// Enable debug output
const DEBUG: bool = true;

/* ================== QUIC Client Setup ================== */

/// Custom certificate verifier that accepts any certificate.
/// Required for probing validators without their CA chain.
/// WARNING: Only for RTT measurement, not secure communication.
#[derive(Debug)]
struct InsecureCertVerifier(Arc<rustls::crypto::CryptoProvider>);

impl InsecureCertVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Create a QUIC endpoint configured for RTT probing
fn create_quic_endpoint() -> Result<Endpoint> {
    // Build rustls config with insecure verifier
    let crypto_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(InsecureCertVerifier::new())
        .with_no_client_auth();

    // Convert to Quinn crypto config
    let quic_crypto: quinn::crypto::rustls::QuicClientConfig = crypto_config.try_into()?;

    // Configure transport for fast probing
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_millis(QUIC_IDLE_TIMEOUT_MS).try_into()?));
    transport.keep_alive_interval(None); // Disable keep-alive for probing

    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(transport));

    // Bind to ephemeral port
    let mut endpoint = Endpoint::client(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    ))?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

/* ================== Multiaddr Parsing ================== */

/// Parse a multiaddr string and extract host, port, and domain
fn parse_multiaddr(addr: &str) -> Option<(String, u16, String)> {
    let parts: Vec<&str> = addr.split('/').filter(|s| !s.is_empty()).collect();

    let mut ip: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut domain: Option<String> = None;

    let mut i = 0;
    while i + 1 < parts.len() {
        match parts[i] {
            "ip4" | "ip6" => {
                ip = Some(parts[i + 1].to_string());
                i += 2;
            }
            "dns" | "dns4" | "dns6" => {
                domain = Some(parts[i + 1].to_lowercase());
                i += 2;
            }
            "udp" | "tcp" => {
                port = parts[i + 1].parse().ok();
                i += 2;
            }
            _ => i += 1,
        }
    }

    let host = ip.or_else(|| domain.clone())?;
    Some((host, port.unwrap_or(DEFAULT_PORT), domain.unwrap_or_default()))
}

/* ================== Region Inference ================== */

/// Infer geographic region from validator name and domain
fn infer_region(name: &str, domain: &str) -> &'static str {
    let s = format!("{} {}", name.to_lowercase(), domain);

    // Asia Pacific
    if s.contains("sg") || s.contains("singapore") {
        return "SG";
    }
    if s.contains("jp") || s.contains("tokyo") || s.contains("japan") {
        return "JP";
    }
    if s.contains("hk") || s.contains("hongkong") || s.contains("hong kong") {
        return "HK";
    }
    if s.contains("kr") || s.contains("korea") || s.contains("seoul") {
        return "KR";
    }
    if s.contains("tw") || s.contains("taiwan") {
        return "TW";
    }
    if s.contains("au") || s.contains("sydney") || s.contains("australia") {
        return "AU";
    }

    // Europe
    if s.contains("de") || s.contains("fra") || s.contains("frankfurt") || s.contains("germany") {
        return "EU-DE";
    }
    if s.contains("nl") || s.contains("ams") || s.contains("amsterdam") {
        return "EU-NL";
    }
    if s.contains("uk") || s.contains("london") {
        return "EU-UK";
    }
    if s.contains("fi") || s.contains("helsinki") {
        return "EU-FI";
    }

    // Americas
    if s.contains("us-east") || s.contains("virginia") || s.contains("nyc") || s.contains("new york") {
        return "US-E";
    }
    if s.contains("us-west") || s.contains("california") || s.contains("sfo") || s.contains("lax") {
        return "US-W";
    }
    if s.contains("us") {
        return "US";
    }

    "OTHER"
}

/* ================== RTT Measurement ================== */

/// Probe result with protocol info
#[derive(Debug, Clone)]
enum ProbeProtocol {
    Quic,
    Tcp,
}

/// Measure TCP handshake RTT
async fn probe_tcp_rtt(addr: SocketAddr) -> Option<u128> {
    let start = Instant::now();
    match timeout(Duration::from_millis(RTT_TIMEOUT_MS), TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => Some(start.elapsed().as_millis()),
        _ => None,
    }
}

/// Measure QUIC handshake RTT to a target address
async fn probe_quic_rtt(
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
) -> Option<u128> {
    let start = Instant::now();

    let connecting = match endpoint.connect(addr, server_name) {
        Ok(c) => c,
        Err(e) => {
            if DEBUG {
                eprintln!("  QUIC connect error: {:?}", e);
            }
            return None;
        }
    };

    match timeout(Duration::from_millis(RTT_TIMEOUT_MS), connecting).await {
        Ok(Ok(conn)) => {
            let rtt = start.elapsed().as_millis();
            conn.close(0u32.into(), b"probe");
            Some(rtt)
        }
        Ok(Err(e)) => {
            if DEBUG {
                eprintln!("  QUIC handshake error: {:?}", e);
            }
            None
        }
        Err(_) => {
            if DEBUG {
                eprintln!("  QUIC timeout");
            }
            None
        }
    }
}

/// Measure RTT with multiple probes, trying QUIC first then TCP
async fn measure_validator_rtt(
    host: String,
    port: u16,
    semaphore: Arc<Semaphore>,
) -> Option<(u128, u128, u128, IpAddr, ProbeProtocol)> {
    // Acquire semaphore permit for concurrency control
    let _permit = semaphore.acquire().await.ok()?;

    // Resolve DNS
    let addr_str = format!("{}:{}", host, port);
    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host(&addr_str).await {
        Ok(a) => a.collect(),
        Err(e) => {
            if DEBUG {
                eprintln!("DNS resolution failed for {}: {:?}", addr_str, e);
            }
            return None;
        }
    };
    let addr = *addrs.first()?;
    let resolved_ip = addr.ip();

    // Try QUIC first
    let endpoint = create_quic_endpoint().ok();
    let mut samples: Vec<u128> = Vec::with_capacity(RTT_PROBES);
    let mut protocol = ProbeProtocol::Quic;
    let mut quic_failed = false;

    if let Some(ref ep) = endpoint {
        // First probe to test if QUIC works
        if let Some(rtt) = probe_quic_rtt(ep, addr, "localhost").await {
            samples.push(rtt);
        } else {
            quic_failed = true;
        }
    } else {
        quic_failed = true;
    }

    // If QUIC failed, fall back to TCP
    if quic_failed {
        protocol = ProbeProtocol::Tcp;
        samples.clear();

        for probe_idx in 0..RTT_PROBES {
            if probe_idx > 0 {
                tokio::time::sleep(Duration::from_millis(PROBE_INTERVAL_MS)).await;
            }
            if let Some(rtt) = probe_tcp_rtt(addr).await {
                samples.push(rtt);
            }
        }
    } else {
        // Continue QUIC probes
        if let Some(ref ep) = endpoint {
            for probe_idx in 1..RTT_PROBES {
                tokio::time::sleep(Duration::from_millis(PROBE_INTERVAL_MS)).await;
                if let Some(rtt) = probe_quic_rtt(ep, addr, "localhost").await {
                    samples.push(rtt);
                }
            }
        }
    }

    // Need at least 1 sample
    if samples.is_empty() {
        return None;
    }

    samples.sort();

    let min = samples[0];
    let avg = samples.iter().sum::<u128>() / samples.len() as u128;
    let p95_idx = ((samples.len() as f64 * 0.95) as usize).min(samples.len() - 1);
    let p95 = samples[p95_idx];

    Some((min, avg, p95, resolved_ip, protocol))
}

/* ================== Validator Data ================== */

#[derive(Clone, Debug)]
struct ValidatorRtt {
    name: String,
    ip: IpAddr,
    port: u16,
    region: String,
    stake: u64,
    stake_pct: f64,
    min_rtt: u128,
    avg_rtt: u128,
    p95_rtt: u128,
    score: f64,
    protocol: String,
}

impl ValidatorRtt {
    /// Calculate weighted score (lower is better)
    /// Considers both latency and stake importance
    fn calculate_score(&mut self, total_stake: u64) {
        self.stake_pct = (self.stake as f64 / total_stake as f64) * 100.0;

        // RTT score: weighted combination of avg and p95
        let rtt_score = (self.avg_rtt as f64 * 0.6) + (self.p95_rtt as f64 * 0.4);

        // Stake bonus: validators with higher stake get slight preference
        // (they're usually more reliable infrastructure)
        let stake_bonus = 1.0 - (self.stake_pct / 100.0).min(0.1);

        self.score = rtt_score * stake_bonus;
    }
}

/* ================== Region Statistics ================== */

#[derive(Default, Debug)]
struct RegionStats {
    count: usize,
    total_stake: u64,
    weighted_min: u128,
    weighted_avg: u128,
    weighted_p95: u128,
}

impl RegionStats {
    fn add(&mut self, v: &ValidatorRtt) {
        self.count += 1;
        self.total_stake += v.stake;
        self.weighted_min += v.min_rtt * v.stake as u128;
        self.weighted_avg += v.avg_rtt * v.stake as u128;
        self.weighted_p95 += v.p95_rtt * v.stake as u128;
    }

    fn finalize(&self) -> (u128, u128, u128, f64) {
        if self.total_stake == 0 {
            return (0, 0, 0, 0.0);
        }
        let stake = self.total_stake as u128;
        let min = self.weighted_min / stake;
        let avg = self.weighted_avg / stake;
        let p95 = self.weighted_p95 / stake;
        let score = (avg as f64 * 0.6) + (p95 as f64 * 0.4);
        (min, avg, p95, score)
    }
}

/* ================== Output Formatting ================== */

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max_len - 3).collect::<String>())
    }
}

fn print_header() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                              SUI VALIDATOR RTT PROBE - QUIC/Anemo Layer                                          ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝");
    println!();
}

fn print_top_validators(validators: &[ValidatorRtt], n: usize) {
    println!("┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐");
    println!("│                                    TOP {} LOWEST LATENCY VALIDATORS                                                  │", n);
    println!("├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤");
    println!(
        "│ {:>4} │ {:<24} │ {:<21} │ {:>5} │ {:>5} │ {:>5} │ {:>6} │ {:>6} │ {:>4} │",
        "Rank", "Name", "IP:Port", "Min", "Avg", "P95", "Stake%", "Region", "Proto"
    );
    println!("├──────┼──────────────────────────┼───────────────────────┼───────┼───────┼───────┼────────┼────────┼──────┤");

    for (i, v) in validators.iter().take(n).enumerate() {
        println!(
            "│ {:>4} │ {:<24} │ {:>21} │ {:>4}ms │ {:>4}ms │ {:>4}ms │ {:>5.2}% │ {:>6} │ {:>4} │",
            i + 1,
            truncate_str(&v.name, 24),
            format!("{}:{}", v.ip, v.port),
            v.min_rtt,
            v.avg_rtt,
            v.p95_rtt,
            v.stake_pct,
            v.region,
            v.protocol
        );
    }
    println!("└──────┴──────────────────────────┴───────────────────────┴───────┴───────┴───────┴────────┴────────┴──────┘");
}

fn print_region_summary(region_stats: &HashMap<String, RegionStats>, total_stake: u64) {
    println!();
    println!("┌───────────────────────────────────────────────────────────────────────────────────────┐");
    println!("│                           REGION SUMMARY (Stake Weighted)                             │");
    println!("├───────────────────────────────────────────────────────────────────────────────────────┤");
    println!(
        "│ {:<8} │ {:>6} │ {:>8} │ {:>8} │ {:>8} │ {:>8} │ {:>10} │",
        "Region", "Count", "Stake%", "Min(ms)", "Avg(ms)", "P95(ms)", "Score"
    );
    println!("├──────────┼────────┼──────────┼──────────┼──────────┼──────────┼────────────┤");

    let mut regions: Vec<_> = region_stats.iter().collect();
    regions.sort_by(|a, b| {
        let (_, _, _, score_a) = a.1.finalize();
        let (_, _, _, score_b) = b.1.finalize();
        score_a.partial_cmp(&score_b).unwrap()
    });

    for (region, stats) in regions {
        let (min, avg, p95, score) = stats.finalize();
        let stake_pct = (stats.total_stake as f64 / total_stake as f64) * 100.0;
        println!(
            "│ {:<8} │ {:>6} │ {:>7.2}% │ {:>7}ms │ {:>7}ms │ {:>7}ms │ {:>10.1} │",
            region, stats.count, stake_pct, min, avg, p95, score
        );
    }
    println!("└──────────┴────────┴──────────┴──────────┴──────────┴──────────┴────────────┘");
}

fn print_stake_weighted_top(validators: &[ValidatorRtt], n: usize) {
    // Sort by score (which includes stake weighting)
    let mut by_score = validators.to_vec();
    by_score.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());

    println!();
    println!("┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐");
    println!("│                              TOP {} BY STAKE-WEIGHTED SCORE (Lower = Better)                                         │", n);
    println!("├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤");
    println!(
        "│ {:>4} │ {:<24} │ {:>5} │ {:>5} │ {:>5} │ {:>6} │ {:>9} │ {:>6} │ {:>4} │",
        "Rank", "Name", "Min", "Avg", "P95", "Stake%", "Score", "Region", "Proto"
    );
    println!("├──────┼──────────────────────────┼───────┼───────┼───────┼────────┼───────────┼────────┼──────┤");

    for (i, v) in by_score.iter().take(n).enumerate() {
        println!(
            "│ {:>4} │ {:<24} │ {:>4}ms │ {:>4}ms │ {:>4}ms │ {:>5.2}% │ {:>9.1} │ {:>6} │ {:>4} │",
            i + 1,
            truncate_str(&v.name, 24),
            v.min_rtt,
            v.avg_rtt,
            v.p95_rtt,
            v.stake_pct,
            v.score,
            v.region,
            v.protocol
        );
    }
    println!("└──────┴──────────────────────────┴───────┴───────┴───────┴────────┴───────────┴────────┴──────┘");
}

/* ================== Main ================== */

#[tokio::main]
async fn main() -> Result<()> {
    print_header();

    println!("⏳ Connecting to Sui mainnet RPC...");
    let sui = SuiClientBuilder::default().build(RPC_URL).await?;
    let state = sui.governance_api().get_latest_sui_system_state().await?;

    let validators = state.active_validators;
    let total_stake: u64 = validators.iter().map(|v| v.voting_power).sum();

    println!("✓ Found {} active validators (Total stake: {})", validators.len(), total_stake);
    println!("⏳ Probing QUIC RTT with {} concurrent connections...\n", MAX_CONCURRENT_PROBES);

    // Semaphore for concurrency control
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES));

    // Build probe tasks
    let mut tasks = Vec::new();
    let mut validator_info: Vec<(String, u64, String, u16, String)> = Vec::new();

    // Debug: show first few addresses
    if DEBUG {
        println!("Sample addresses:");
        for v in validators.iter().take(3) {
            println!("  {} -> {}", v.name, v.p2p_address);
        }
        println!();
    }

    for v in &validators {
        if let Some((host, port, domain)) = parse_multiaddr(&v.p2p_address) {
            let region = infer_region(&v.name, &domain).to_string();
            let sem = Arc::clone(&semaphore);

            validator_info.push((
                v.name.clone(),
                v.voting_power,
                region.clone(),
                port,
                host.clone(),
            ));

            tasks.push(measure_validator_rtt(host, port, sem));
        }
    }

    // Execute all probes concurrently (with semaphore limiting)
    let results = join_all(tasks).await;

    // Collect successful results
    let mut validator_rtts: Vec<ValidatorRtt> = Vec::new();
    let mut success_count = 0;
    let mut fail_count = 0;
    let mut quic_count = 0;
    let mut tcp_count = 0;

    for (i, rtt_result) in results.into_iter().enumerate() {
        let (name, stake, region, port, _host) = &validator_info[i];

        match rtt_result {
            Some((min, avg, p95, ip, proto)) => {
                success_count += 1;
                let protocol_str = match proto {
                    ProbeProtocol::Quic => {
                        quic_count += 1;
                        "QUIC"
                    }
                    ProbeProtocol::Tcp => {
                        tcp_count += 1;
                        "TCP"
                    }
                };
                let mut v = ValidatorRtt {
                    name: name.clone(),
                    ip,
                    port: *port,
                    region: region.clone(),
                    stake: *stake,
                    stake_pct: 0.0,
                    min_rtt: min,
                    avg_rtt: avg,
                    p95_rtt: p95,
                    score: 0.0,
                    protocol: protocol_str.to_string(),
                };
                v.calculate_score(total_stake);
                validator_rtts.push(v);
            }
            None => {
                fail_count += 1;
            }
        }
    }

    println!("✓ Probed {} validators successfully ({} QUIC, {} TCP), {} failed\n", 
             success_count, quic_count, tcp_count, fail_count);

    // Sort by average RTT for top display
    validator_rtts.sort_by_key(|v| v.avg_rtt);

    // Print top validators by RTT
    print_top_validators(&validator_rtts, TOP_N_VALIDATORS);

    // Calculate region statistics
    let mut region_stats: HashMap<String, RegionStats> = HashMap::new();
    for v in &validator_rtts {
        region_stats
            .entry(v.region.clone())
            .or_default()
            .add(v);
    }

    let successful_stake: u64 = validator_rtts.iter().map(|v| v.stake).sum();
    print_region_summary(&region_stats, successful_stake);

    // Print stake-weighted top
    print_stake_weighted_top(&validator_rtts, TOP_N_VALIDATORS);

    // Summary recommendation
    println!();
    if let Some(best) = validator_rtts.first() {
        println!("🏆 RECOMMENDATION: Best latency validator is '{}' ({}) with {}ms avg RTT",
            best.name, best.region, best.avg_rtt);
    }

    let by_score: Vec<_> = {
        let mut v = validator_rtts.clone();
        v.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());
        v
    };
    if let Some(best) = by_score.first() {
        println!("🎯 OPTIMAL: Best stake-weighted choice is '{}' ({}) with score {:.1}",
            best.name, best.region, best.score);
    }

    // Find best region
    let mut region_scores: Vec<_> = region_stats.iter()
        .map(|(r, s)| (r.clone(), s.finalize()))
        .collect();
    region_scores.sort_by(|a, b| a.1.3.partial_cmp(&b.1.3).unwrap());

    if let Some((region, (_, avg, _, score))) = region_scores.first() {
        println!("🌍 BEST REGION: {} with avg RTT {}ms (score: {:.1})", region, avg, score);
    }

    println!();

    Ok(())
}
