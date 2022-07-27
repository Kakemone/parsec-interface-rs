// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! # AttestKey operation
//!
//! Produce an attestation token as proof that the given
//! key was produced and is stored in the hardware backend.
use derivative::Derivative;
use zeroize::Zeroizing;

/// Native operation for key attestation
#[derive(Derivative)]
#[derivative(Debug)]
#[non_exhaustive]
pub enum Operation {
    /// Attestation via TPM 2.0 ActivateCredential operation
    ActivateCredential {
        /// Name of key to be attested
        attested_key_name: String,
        /// Blob of data representing the encrypted credential
        #[derivative(Debug = "ignore")]
        credential_blob: Zeroizing<Vec<u8>>,
        /// Blob of data representing the encrypted secret
        #[derivative(Debug = "ignore")]
        secret: Zeroizing<Vec<u8>>,
        /// Name of key to be used for attesting
        attesting_key_name: Option<String>,
    },
    ///Key and platform attestation
    CertifyAndQuote {
        /// Name of key to be attested
        attested_key_name: String,
        /// The nonce to be used in the TLS handshake
        #[derivative(Debug = "ignore")]
        nonce: Vec<u8>,
        /// Name of key to be used for attesting
        attesting_key_name: Option<String>,
    },
}

/// Native result of key attestation
#[derive(Derivative)]
#[derivative(Debug)]
#[non_exhaustive]
pub enum Result {
    /// Result of attestation via TPM 2.0 ActivateCredential operation
    ActivateCredential {
        /// Decrypted credential
        #[derivative(Debug = "ignore")]
        credential: Zeroizing<Vec<u8>>,
    },
    ///Result of key and platform attestation
    CertifyAndQuote {
        ///Key attestation certificate
        #[derivative(Debug = "ignore")]
        key_attestation_certificate: Zeroizing<Vec<u8>>,
        ///Platform attestation certificate
        #[derivative(Debug = "ignore")]
        platform_attestation_certificate: Zeroizing<Vec<u8>>,
    },
}
