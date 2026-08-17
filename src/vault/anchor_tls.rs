//! rustls helpers for the loopback ADR 0015 reference CAS.
//!
//! Certificates and keys are operator-provided PEM files. This module does
//! not generate keys, does not talk to a public CA, and does not weaken
//! hostname verification.

use std::{
    fs::File,
    io::BufReader,
    path::Path,
    sync::{Arc, Once},
};

use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};

use crate::vault::VaultError;

static INSTALL_PROVIDER: Once = Once::new();

/// rustls server configuration from a certificate chain and private key.
pub(super) fn server_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<ServerConfig>, VaultError> {
    install_crypto_provider();
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| VaultError::InvalidFormat)?;
    Ok(Arc::new(config))
}

/// rustls client configuration that trusts one PEM CA / server certificate.
pub(super) fn client_config(ca_path: &Path) -> Result<Arc<ClientConfig>, VaultError> {
    install_crypto_provider();
    let certs = load_certs(ca_path)?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(|_| VaultError::InvalidFormat)?;
    }
    if roots.is_empty() {
        return Err(VaultError::InvalidFormat);
    }
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// Server name used to verify loopback certificates.
///
/// Certificates must include SAN `DNS:localhost`. Connecting to `127.0.0.1`
/// still presents this name so a loopback IP does not disable verification.
pub(super) fn loopback_server_name() -> Result<ServerName<'static>, VaultError> {
    ServerName::try_from("localhost").map_err(|_| VaultError::InvalidFormat)
}

fn install_crypto_provider() {
    INSTALL_PROVIDER.call_once(|| {
        let _ignored = rustls::crypto::ring::default_provider().install_default();
    });
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, VaultError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| VaultError::InvalidFormat)?;
    if certs.is_empty() {
        return Err(VaultError::InvalidFormat);
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, VaultError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|_| VaultError::InvalidFormat)?
        .ok_or(VaultError::InvalidFormat)
}

#[cfg(test)]
pub(super) fn write_loopback_self_signed(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
    std::fs::write(cert_path, certified.cert.pem())?;
    std::fs::write(key_path, certified.key_pair.serialize_pem())?;
    Ok(())
}
