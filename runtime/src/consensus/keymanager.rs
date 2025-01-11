use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use thiserror::Error;

use crate::common::{
    crypto::{
        signature::{Signature, SignatureBundle, Signer},
        x25519,
    },
    namespace::Namespace,
    sgx::EnclaveIdentity,
};

use super::beacon::EpochTime;

pub mod churp;

/// Context used to sign key manager policies.
const POLICY_SIGNATURE_CONTEXT: &[u8] = b"oasis-core/keymanager: policy";

/// Context used to sign encrypted key manager master secrets.
const ENCRYPTED_MASTER_SECRET_SIGNATURE_CONTEXT: &[u8] =
    b"oasis-core/keymanager: encrypted master secret";

/// Context used to sign encrypted key manager ephemeral secrets.
const ENCRYPTED_EPHEMERAL_SECRET_SIGNATURE_CONTEXT: &[u8] =
    b"oasis-core/keymanager: encrypted ephemeral secret";

/// Errors emitted by the key manager module.
#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid signature")]
    InvalidSignature,
}

/// Key manager access control policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct PolicySGX {
    pub serial: u32,
    pub id: Namespace,
    pub enclaves: HashMap<EnclaveIdentity, EnclavePolicySGX>,
    #[cbor(optional)]
    pub master_secret_rotation_interval: EpochTime,
    #[cbor(optional)]
    pub max_ephemeral_secret_age: EpochTime,
}

/// Per enclave key manager access control policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct EnclavePolicySGX {
    /// A map of runtime IDs to the vector of enclave IDs that may query
    /// private key material.
    pub may_query: HashMap<Namespace, Vec<EnclaveIdentity>>,

    /// A vector of enclave IDs that may retrieve the master secret.
    ///
    /// NOTE: Each enclave ID may always implicitly replicate from other
    /// instances of itself.
    pub may_replicate: Vec<EnclaveIdentity>,
}

/// Signed key manager access control policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct SignedPolicySGX {
    pub policy: PolicySGX,
    pub signatures: Vec<SignatureBundle>,
}

impl SignedPolicySGX {
    /// Verify the signatures.
    pub fn verify(&self) -> Result<&PolicySGX> {
        let raw_policy = cbor::to_vec(self.policy.clone());
        for sig in &self.signatures {
            sig.signature
                .verify(&sig.public_key, POLICY_SIGNATURE_CONTEXT, &raw_policy)
                .map_err(|_| Error::InvalidSignature)?;
        }

        Ok(&self.policy)
    }
}

/// A secret encrypted with Deoxys-II MRAE algorithm.
#[derive(Clone, Default, Debug, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct EncryptedSecret {
    /// Checksum for validating decrypted secret.
    pub checksum: Vec<u8>,
    /// Public key to derive the symmetric key for decryption.
    pub pub_key: x25519::PublicKey,
    /// A map of REK encrypted secrets.
    pub ciphertexts: HashMap<x25519::PublicKey, Vec<u8>>,
}

/// Encrypted master secret.
#[derive(Clone, Default, Debug, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct EncryptedMasterSecret {
    /// Runtime ID of the key manager.
    pub runtime_id: Namespace,
    /// Generation of the secret.
    pub generation: u64,
    /// Epoch time in which the secret was created.
    pub epoch: EpochTime,
    /// Encrypted secret.
    pub secret: EncryptedSecret,
}

/// Encrypted ephemeral secret.
#[derive(Clone, Default, Debug, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct EncryptedEphemeralSecret {
    /// Runtime ID of the key manager.
    pub runtime_id: Namespace,
    /// Epoch time to which the ephemeral secret belongs.
    pub epoch: EpochTime,
    /// Encrypted secret.
    pub secret: EncryptedSecret,
}

/// Signed encrypted master secret (RAK).
#[derive(Clone, Default, Debug, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct SignedEncryptedMasterSecret {
    /// Encrypted master secret.
    pub secret: EncryptedMasterSecret,
    /// Signature of the encrypted master secret.
    pub signature: Signature,
}

impl SignedEncryptedMasterSecret {
    pub fn new(secret: EncryptedMasterSecret, signer: &Arc<dyn Signer>) -> Result<Self> {
        let signature = signer.sign(
            ENCRYPTED_MASTER_SECRET_SIGNATURE_CONTEXT,
            &cbor::to_vec(secret.clone()),
        )?;
        Ok(Self { secret, signature })
    }
}

/// Signed encrypted ephemeral secret (RAK).
#[derive(Clone, Default, Debug, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct SignedEncryptedEphemeralSecret {
    /// Encrypted ephemeral secret.
    pub secret: EncryptedEphemeralSecret,
    /// Signature of the encrypted ephemeral secret.
    pub signature: Signature,
}

impl SignedEncryptedEphemeralSecret {
    pub fn new(secret: EncryptedEphemeralSecret, signer: &Arc<dyn Signer>) -> Result<Self> {
        let signature = signer.sign(
            ENCRYPTED_EPHEMERAL_SECRET_SIGNATURE_CONTEXT,
            &cbor::to_vec(secret.clone()),
        )?;
        Ok(Self { secret, signature })
    }
}
