use std::{path::Path, sync::Arc};

use log::{debug, error};
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_name,
    },
    crypto::{
        aws_lc_rs, verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms,
    },
    pki_types::{pem::PemObject, CertificateDer, ServerName},
    server::ParsedCertificate,
    CertificateError, SignatureScheme,
};

#[derive(Debug)]
pub struct PmzCertVerifier {
    supported: WebPkiSupportedAlgorithms,
}

impl PmzCertVerifier {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            supported: aws_lc_rs::default_provider().signature_verification_algorithms,
        })
    }
}

impl ServerCertVerifier for PmzCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        debug!("end entity: {end_entity:?}");
        debug!("server name: {server_name:?}");
        debug!("now: {now:?}");

        let home_dir = std::env::var("HOME").expect("Failed to retrieve HOME env.");
        let cert_path = Path::new(&home_dir).join(".config/pmz/certs/pmz.crt");

        match CertificateDer::from_pem_file(&cert_path) {
            Ok(local_entity) => {
                debug!("Local certificate loaded from: {:?}", cert_path);

                if local_entity.eq(end_entity) {
                    let cert = ParsedCertificate::try_from(end_entity)?;
                    verify_server_name(&cert, server_name)?;
                    debug!("Certificate verified successfully.");
                    Ok(ServerCertVerified::assertion())
                } else {
                    error!(
                        "Certificate mismatch. Expected: {:?}, Received: {:?}",
                        local_entity, end_entity
                    );
                    Err(CertificateError::BadEncoding.into())
                }
            }
            Err(e) => {
                error!(
                    "Failed to load local certificate from {:?}: {}",
                    cert_path, e
                );
                Err(CertificateError::ApplicationVerificationFailure.into())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}
