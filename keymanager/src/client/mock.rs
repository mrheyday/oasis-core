//! Mock key manager client which stores everything locally.
use std::{collections::HashMap, sync::Mutex};

use async_trait::async_trait;

use oasis_core_runtime::{
    common::{
        crypto::signature::{PublicKey, Signature},
        namespace::Namespace,
    },
    consensus::beacon::EpochTime,
};

use crate::{
    api::KeyManagerError,
    churp::EncodedVerifiableSecretShare,
    crypto::{KeyPair, KeyPairId, Secret, SignedPublicKey, StateKey, VerifiableSecret},
};

use super::KeyManagerClient;

/// Mock key manager client which stores everything locally.
#[derive(Default)]
pub struct MockClient {
    longterm_keys: Mutex<HashMap<(KeyPairId, u64), KeyPair>>,
    ephemeral_keys: Mutex<HashMap<(KeyPairId, EpochTime), KeyPair>>,
}

impl MockClient {
    /// Create a new mock key manager client.
    pub fn new() -> Self {
        Self {
            longterm_keys: Mutex::new(HashMap::new()),
            ephemeral_keys: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl KeyManagerClient for MockClient {
    fn runtime_id(&self) -> Option<Namespace> {
        Some(Namespace::default())
    }

    fn runtime_signing_key(&self) -> Option<PublicKey> {
        None
    }

    fn clear_cache(&self) {}

    async fn get_or_create_keys(
        &self,
        key_pair_id: KeyPairId,
        generation: u64,
    ) -> Result<KeyPair, KeyManagerError> {
        let mut keys = self.longterm_keys.lock().unwrap();
        let key = keys
            .entry((key_pair_id, generation))
            .or_insert_with(KeyPair::generate_mock)
            .clone();

        Ok(key)
    }

    async fn get_public_key(
        &self,
        key_pair_id: KeyPairId,
        generation: u64,
    ) -> Result<SignedPublicKey, KeyManagerError> {
        let ck = self.get_or_create_keys(key_pair_id, generation).await?;
        Ok(SignedPublicKey {
            key: ck.input_keypair.pk,
            checksum: vec![],
            signature: Signature::default(),
            expiration: None,
        })
    }

    async fn get_or_create_ephemeral_keys(
        &self,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> Result<KeyPair, KeyManagerError> {
        let mut keys = self.ephemeral_keys.lock().unwrap();
        let key = keys
            .entry((key_pair_id, epoch))
            .or_insert_with(KeyPair::generate_mock)
            .clone();

        Ok(key)
    }

    async fn get_public_ephemeral_key(
        &self,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> Result<SignedPublicKey, KeyManagerError> {
        let ck = self
            .get_or_create_ephemeral_keys(key_pair_id, epoch)
            .await?;
        Ok(SignedPublicKey {
            key: ck.input_keypair.pk,
            checksum: vec![],
            signature: Signature::default(),
            expiration: None,
        })
    }

    async fn replicate_master_secret(
        &self,
        _generation: u64,
        _nodes: Vec<PublicKey>,
    ) -> Result<VerifiableSecret, KeyManagerError> {
        unimplemented!();
    }

    async fn replicate_ephemeral_secret(
        &self,
        _epoch: EpochTime,
        _nodes: Vec<PublicKey>,
    ) -> Result<Secret, KeyManagerError> {
        unimplemented!();
    }

    async fn churp_verification_matrix(
        &self,
        _churp_id: u8,
        _epoch: EpochTime,
        _nodes: Vec<PublicKey>,
    ) -> Result<Vec<u8>, KeyManagerError> {
        unimplemented!();
    }

    async fn churp_share_reduction_point(
        &self,
        _churp_id: u8,
        _epoch: EpochTime,
        _node_id: PublicKey,
        _nodes: Vec<PublicKey>,
    ) -> Result<Vec<u8>, KeyManagerError> {
        unimplemented!();
    }

    async fn churp_share_distribution_point(
        &self,
        _churp_id: u8,
        _epoch: EpochTime,
        _node_id: PublicKey,
        _nodes: Vec<PublicKey>,
    ) -> Result<Vec<u8>, KeyManagerError> {
        unimplemented!();
    }

    async fn churp_bivariate_share(
        &self,
        _churp_id: u8,
        _epoch: EpochTime,
        _node_id: PublicKey,
        _nodes: Vec<PublicKey>,
    ) -> Result<EncodedVerifiableSecretShare, KeyManagerError> {
        unimplemented!();
    }

    async fn churp_state_key(
        &self,
        _churp_id: u8,
        _key_id: KeyPairId,
    ) -> Result<StateKey, KeyManagerError> {
        unimplemented!();
    }
}
