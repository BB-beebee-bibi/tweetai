use crate::error::Error;
use crate::models::{EncryptionSession, PreKey, SignedPreKey, User};
use rand::rngs::OsRng;
use libsignal_protocol::{
    IdentityKey, IdentityKeyPair, PreKeyBundle, PreKeyId, PreKeyRecord, SessionBuilder,
    SessionCipher, SessionRecord, SignedPreKeyId, SignedPreKeyRecord,
};
use sqlx::PgPool;

use crate::repositories::user_repository::UserRepository;
use crate::repositories::encryption_repository::EncryptionRepository;

pub struct EncryptionService {
    pub db_pool: PgPool,
}

impl EncryptionService {
    pub fn new(db_pool: PgPool) -> Self {
        Self { db_pool }
    }

    // Encrypt a message using Signal Protocol
    pub async fn encrypt_message(
        &self,
        from_user_id: i64,
        to_user_id: i64,
        content: &str,
    ) -> Result<Vec<u8>, Error> {
        // Get sender's identity and keys
        let sender = UserRepository::find_by_id(&self.db_pool, from_user_id)
            .await?
            .ok_or_else(|| Error::NotFound("Sender not found".into()))?;

        // Get recipient's identity and keys
        let recipient = UserRepository::find_by_id(&self.db_pool, to_user_id)
            .await?
            .ok_or_else(|| Error::NotFound("Recipient not found".into()))?;

        // Get or create Signal session
        let session = self.get_or_create_session(from_user_id, to_user_id).await?;

        // Load sender identity
        let sender_identity = IdentityKeyPair::deserialize(&sender.identity_key_pair)
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        // Load recipient identity
        let recipient_identity = IdentityKey::deserialize(&recipient.public_identity_key)
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        // Create session cipher
        let cipher = SessionCipher::new(
            &session,
            &sender_identity,
            &recipient_identity,
        );

        // Encrypt message
        let cipher_message = cipher
            .encrypt(content.as_bytes())
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        let serialized = cipher_message
            .serialize()
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        // Update session after encryption
        self.update_session(from_user_id, to_user_id, &session).await?;

        Ok(serialized)
    }

    // Decrypt a message using Signal Protocol
    pub async fn decrypt_message(
        &self,
        for_user_id: i64,
        from_user_id: i64,
        encrypted_content: &[u8],
    ) -> Result<String, Error> {
        // Get user's identity and keys
        let user = UserRepository::find_by_id(&self.db_pool, for_user_id)
            .await?
            .ok_or_else(|| Error::NotFound("User not found".into()))?;

        // Get sender's identity and keys
        let sender = UserRepository::find_by_id(&self.db_pool, from_user_id)
            .await?
            .ok_or_else(|| Error::NotFound("Sender not found".into()))?;

        // Get session
        let session = self
            .get_or_create_session(for_user_id, from_user_id)
            .await?;

        // Load user identity
        let user_identity = IdentityKeyPair::deserialize(&user.identity_key_pair)
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        // Load sender identity
        let sender_identity = IdentityKey::deserialize(&sender.public_identity_key)
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        // Create session cipher
        let cipher = SessionCipher::new(
            &session,
            &user_identity,
            &sender_identity,
        );

        // Deserialize cipher message
        let cipher_message = libsignal_protocol::CipherMessage::deserialize(encrypted_content)
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        // Decrypt message
        let decrypted = cipher
            .decrypt(&cipher_message)
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        // Update session after decryption
        self.update_session(for_user_id, from_user_id, &session).await?;

        // Convert bytes to string
        let content = String::from_utf8(decrypted)
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        Ok(content)
    }

    // Handle session management
    async fn get_or_create_session(
        &self,
        user_id: i64,
        other_user_id: i64,
    ) -> Result<SessionRecord, Error> {
        // Try to get existing session
        if let Some(session_data) = EncryptionRepository::find_session(
            &self.db_pool,
            user_id,
            other_user_id,
        )
        .await?
        {
            // Deserialize existing session
            return SessionRecord::deserialize(&session_data.session_data)
                .map_err(|e| Error::SignalProtocolError(e.to_string()));
        }

        // No existing session, create a new one
        let user = UserRepository::find_by_id(&self.db_pool, user_id)
            .await?
            .ok_or_else(|| Error::NotFound("User not found".into()))?;

        let other_user = UserRepository::find_by_id(&self.db_pool, other_user_id)
            .await?
            .ok_or_else(|| Error::NotFound("Other user not found".into()))?;

        // Get pre-key for other user
        let pre_key = EncryptionRepository::get_pre_key(&self.db_pool, other_user_id)
            .await?
            .ok_or_else(|| Error::NotFound("Pre-key not found".into()))?;

        // Get signed pre-key for other user
        let signed_pre_key =
            EncryptionRepository::get_signed_pre_key(&self.db_pool, other_user_id)
                .await?
                .ok_or_else(|| Error::NotFound("Signed pre-key not found".into()))?;

        // Create pre-key bundle for other user
        let pre_key_record = PreKeyRecord::deserialize(&pre_key.private_key)
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        let signed_pre_key_record = SignedPreKeyRecord::deserialize(&signed_pre_key.private_key)
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        let other_identity = IdentityKey::deserialize(&other_user.public_identity_key)
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        let pre_key_bundle = PreKeyBundle::new(
            1, // Registration ID (fixed for simplicity)
            other_user_id as u32,
            PreKeyId::from(pre_key.key_id as u32),
            &pre_key_record,
            SignedPreKeyId::from(signed_pre_key.key_id as u32),
            &signed_pre_key_record,
            &signed_pre_key.signature,
            &other_identity,
        )
        .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        // Create session
        let user_identity = IdentityKeyPair::deserialize(&user.identity_key_pair)
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        let mut session = SessionRecord::new();
        let builder = SessionBuilder::new(&user_identity);

        builder
            .process_pre_key_bundle(&pre_key_bundle, &mut session)
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        // Store session
        let serialized_session = session
            .serialize()
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        EncryptionRepository::create_session(
            &self.db_pool,
            user_id,
            other_user_id,
            &serialized_session,
        )
        .await?;

        Ok(session)
    }

    // Update session after encryption/decryption
    async fn update_session(
        &self,
        user_id: i64,
        other_user_id: i64,
        session: &SessionRecord,
    ) -> Result<(), Error> {
        let serialized_session = session
            .serialize()
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        EncryptionRepository::update_session(
            &self.db_pool,
            user_id,
            other_user_id,
            &serialized_session,
        )
        .await?;

        Ok(())
    }

    // Generate pre-keys for a user
    pub async fn generate_pre_keys(&self, user_id: i64) -> Result<(), Error> {
        let user = UserRepository::find_by_id(&self.db_pool, user_id)
            .await?
            .ok_or_else(|| Error::NotFound("User not found".into()))?;

        let identity_key_pair = IdentityKeyPair::deserialize(&user.identity_key_pair)
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        // Generate a pre-key
        let pre_key_id = 1; // For simplicity, use a fixed ID
        let pre_key = PreKeyRecord::generate(PreKeyId::from(pre_key_id), &mut OsRng);
        let serialized_pre_key = pre_key
            .serialize()
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;
        let public_pre_key = pre_key
            .public_key()
            .serialize()
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;

        // Generate a signed pre-key
        let signed_pre_key_id = 1; // For simplicity, use a fixed ID
        let signed_pre_key = SignedPreKeyRecord::generate(
            SignedPreKeyId::from(signed_pre_key_id),
            &mut OsRng,
            &identity_key_pair,
        );
        let serialized_signed_pre_key = signed_pre_key
            .serialize()
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;
        let public_signed_pre_key = signed_pre_key
            .public_key()
            .serialize()
            .map_err(|e| Error::SignalProtocolError(e.to_string()))?;
        let signature = signed_pre_key
            .signature()
            .to_vec();

        // Store pre-key
        EncryptionRepository::create_pre_key(
            &self.db_pool,
            user_id,
            pre_key_id,
            &public_pre_key,
            &serialized_pre_key,
        )
        .await?;

        // Store signed pre-key
        EncryptionRepository::create_signed_pre_key(
            &self.db_pool,
            user_id,
            signed_pre_key_id,
            &public_signed_pre_key,
            &serialized_signed_pre_key,
            &signature,
        )
        .await?;

        Ok(())
    }
}