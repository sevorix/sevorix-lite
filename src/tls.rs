// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! TLS MITM infrastructure: CA lifecycle and per-hostname cert generation.
//!
//! [`CaStore`] owns the local CA certificate and key, loading them from disk
//! or generating new ones on first run.
//!
//! [`TlsContext`] is shared across connections (held in `Arc`) and provides
//! a cached `rustls::ServerConfig` per hostname (leaf cert signed by the CA).

use std::{fs, io::Write as _, path::Path, sync::Arc};

use anyhow::{Context, Result};
use dashmap::DashMap;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

// ---------------------------------------------------------------------------
// CaStore
// ---------------------------------------------------------------------------

/// Owns the local CA certificate and key pair used to sign leaf certificates.
pub struct CaStore {
    /// Parsed rcgen certificate (needed to sign leaf certs).
    ca_cert: rcgen::Certificate,
    /// Key pair for the CA (needed for signing).
    key_pair: KeyPair,
    /// PEM-encoded CA certificate, cached for export.
    cert_pem: String,
}

impl CaStore {
    /// Load the CA from `{dir}/ca.crt` and `{dir}/ca.key`, or generate a new
    /// self-signed CA and persist it if either file is missing.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let cert_path = dir.join("ca.crt");
        let key_path = dir.join("ca.key");

        if cert_path.exists() && key_path.exists() {
            // Load existing CA.
            let cert_pem = fs::read_to_string(&cert_path)
                .with_context(|| format!("reading {}", cert_path.display()))?;
            let key_pem = fs::read_to_string(&key_path)
                .with_context(|| format!("reading {}", key_path.display()))?;

            let key_pair = KeyPair::from_pem(&key_pem).context("parsing CA key pair from PEM")?;

            // Re-parse the params from the cert so we can sign with them.
            let ca_params = CertificateParams::from_ca_cert_pem(&cert_pem)
                .context("parsing CA cert params from PEM")?;

            let ca_cert = ca_params
                .self_signed(&key_pair)
                .context("re-creating CA cert from loaded params")?;

            Ok(Self {
                ca_cert,
                key_pair,
                cert_pem,
            })
        } else {
            // Generate a new CA.
            fs::create_dir_all(dir).with_context(|| format!("creating dir {}", dir.display()))?;

            Self::generate_and_persist(dir)
        }
    }

    /// Generate a new self-signed CA, write it to disk, and return a `CaStore`.
    fn generate_and_persist(dir: &Path) -> Result<Self> {
        let key_pair = KeyPair::generate().context("generating CA key pair")?;

        let mut params = CertificateParams::default();

        // 10-year validity from now
        let now = time::OffsetDateTime::now_utc();
        let ten_years = time::Duration::days(3650);
        params.not_before = now;
        params.not_after = now + ten_years;

        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Sevorix Watchtower MITM CA");

        let ca_cert = params
            .self_signed(&key_pair)
            .context("self-signing CA certificate")?;

        let cert_pem = ca_cert.pem();
        let key_pem = key_pair.serialize_pem();

        let cert_path = dir.join("ca.crt");
        let key_path = dir.join("ca.key");

        fs::write(&cert_path, &cert_pem)
            .with_context(|| format!("writing {}", cert_path.display()))?;

        // Write the private key with restricted permissions (0o600 — owner-only).
        {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key_path)
                .with_context(|| format!("opening {} for write", key_path.display()))?
                .write_all(key_pem.as_bytes())
                .with_context(|| format!("writing {}", key_path.display()))?;
        }

        Ok(Self {
            ca_cert,
            key_pair,
            cert_pem,
        })
    }

    /// Return the PEM-encoded CA certificate (for trust store injection).
    pub fn ca_cert_pem(&self) -> &str {
        &self.cert_pem
    }
}

// ---------------------------------------------------------------------------
// TlsContext
// ---------------------------------------------------------------------------

/// Shared TLS context held in an `Arc`.  Caches per-hostname `ServerConfig`
/// values so leaf certificates are only generated once per hostname.
pub struct TlsContext {
    ca: CaStore,
    server_config_cache: DashMap<String, Arc<ServerConfig>>,
}

impl TlsContext {
    /// Create a new `TlsContext` wrapping the given `CaStore`.
    pub fn new(ca: CaStore) -> Self {
        Self {
            ca,
            server_config_cache: DashMap::new(),
        }
    }

    /// Return a `rustls::ServerConfig` for `hostname`.
    ///
    /// On the first call for a given hostname a leaf certificate signed by the
    /// CA is generated; subsequent calls return the cached config.
    pub fn server_config_for(&self, hostname: &str) -> Result<Arc<ServerConfig>> {
        if let Some(cfg) = self.server_config_cache.get(hostname) {
            return Ok(Arc::clone(&*cfg));
        }

        let cfg = self.build_server_config(hostname)?;
        let arc = Arc::new(cfg);
        self.server_config_cache
            .insert(hostname.to_string(), Arc::clone(&arc));
        Ok(arc)
    }

    fn build_server_config(&self, hostname: &str) -> Result<ServerConfig> {
        // Generate leaf key pair.
        let leaf_key = KeyPair::generate().context("generating leaf key pair")?;

        // Build leaf cert params.
        let mut params = CertificateParams::new(vec![hostname.to_string()])
            .context("building leaf cert params")?;

        // Choose the correct SAN type: IpAddress for IPs, DnsName for hostnames.
        let san = if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
            SanType::IpAddress(ip)
        } else {
            SanType::DnsName(
                hostname
                    .to_string()
                    .try_into()
                    .context("invalid hostname for SAN")?,
            )
        };
        params.subject_alt_names = vec![san];

        params.is_ca = IsCa::NoCa;

        // 1-year validity from now
        let now = time::OffsetDateTime::now_utc();
        let one_year = time::Duration::days(365);
        params.not_before = now;
        params.not_after = now + one_year;

        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname);

        // Sign with CA.
        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca.ca_cert, &self.ca.key_pair)
            .context("signing leaf cert with CA")?;

        // Convert to rustls types.
        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(leaf_key.serialize_der())
            .map_err(|e| anyhow::anyhow!("converting private key: {e}"))?;

        // Build ServerConfig.
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .context("building rustls ServerConfig")?;

        Ok(server_config)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ca_generates_on_first_call() {
        let dir = tempdir().expect("creating tempdir");
        CaStore::load_or_create(dir.path()).expect("load_or_create failed");

        assert!(dir.path().join("ca.crt").exists(), "ca.crt should exist");
        assert!(dir.path().join("ca.key").exists(), "ca.key should exist");
    }

    #[test]
    fn test_ca_loads_existing() {
        let dir = tempdir().expect("creating tempdir");

        let ca1 = CaStore::load_or_create(dir.path()).expect("first load_or_create failed");
        let pem1 = ca1.ca_cert_pem().to_string();

        let ca2 = CaStore::load_or_create(dir.path()).expect("second load_or_create failed");
        let pem2 = ca2.ca_cert_pem().to_string();

        assert_eq!(pem1, pem2, "PEM content should be identical on second load");
    }

    #[test]
    fn test_cert_for_hostname() {
        let dir = tempdir().expect("creating tempdir");
        let ca = CaStore::load_or_create(dir.path()).expect("load_or_create failed");
        let ctx = TlsContext::new(ca);

        let result = ctx.server_config_for("example.com");
        assert!(
            result.is_ok(),
            "server_config_for should return Ok: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_cert_cached() {
        let dir = tempdir().expect("creating tempdir");
        let ca = CaStore::load_or_create(dir.path()).expect("load_or_create failed");
        let ctx = TlsContext::new(ca);

        ctx.server_config_for("example.com")
            .expect("first call failed");
        ctx.server_config_for("example.com")
            .expect("second call failed");

        assert_eq!(
            ctx.server_config_cache.len(),
            1,
            "cache should have exactly 1 entry"
        );
    }

    #[test]
    fn test_ca_cert_pem_format() {
        let dir = tempdir().expect("creating tempdir");
        let ca = CaStore::load_or_create(dir.path()).expect("load_or_create failed");

        assert!(
            ca.ca_cert_pem().starts_with("-----BEGIN CERTIFICATE-----"),
            "CA cert PEM should start with '-----BEGIN CERTIFICATE-----'"
        );
    }
}
