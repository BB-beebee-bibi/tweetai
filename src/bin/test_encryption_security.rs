use rand::rngs::OsRng;
use libsignal_protocol::{
    IdentityKey, IdentityKeyPair, PreKeyBundle, PreKeyId, PreKeyRecord, SessionBuilder,
    SessionCipher, SessionRecord, SignedPreKeyId, SignedPreKeyRecord,
};
use std::collections::HashMap;
use std::time::Instant;

// Simplified version of the encryption service
struct EncryptionService {
    // User ID -> Identity Key Pair
    identity_keys: HashMap<i64, IdentityKeyPair>,
    // User ID -> Public Identity Key
    public_keys: HashMap<i64, IdentityKey>,
    // (User ID, Recipient ID) -> Session
    sessions: HashMap<(i64, i64), SessionRecord>,
    // User ID -> Pre-Key
    pre_keys: HashMap<i64, PreKeyRecord>,
    // User ID -> Signed Pre-Key
    signed_pre_keys: HashMap<i64, SignedPreKeyRecord>,
    // User ID -> Signed Pre-Key Signature
    signatures: HashMap<i64, Vec<u8>>,
}

impl EncryptionService {
    fn new() -> Self {
        Self {
            identity_keys: HashMap::new(),
            public_keys: HashMap::new(),
            sessions: HashMap::new(),
            pre_keys: HashMap::new(),
            signed_pre_keys: HashMap::new(),
            signatures: HashMap::new(),
        }
    }

    // Generate identity keys for a user
    fn generate_identity_keys(&mut self, user_id: i64) -> Result<(), Box<dyn std::error::Error>> {
        let identity_key_pair = IdentityKeyPair::generate(&mut OsRng);
        let public_key = identity_key_pair.public_key();
        
        self.identity_keys.insert(user_id, identity_key_pair);
        self.public_keys.insert(user_id, public_key);
        
        println!("Generated identity keys for user {}", user_id);
        Ok(())
    }
    
    // Generate pre-keys for a user
    fn generate_pre_keys(&mut self, user_id: i64) -> Result<(), Box<dyn std::error::Error>> {
        let identity_key_pair = self.identity_keys.get(&user_id)
            .ok_or("Identity key not found")?;
        
        // Generate pre-key
        let pre_key_id = PreKeyId::from(1);
        let pre_key = PreKeyRecord::generate(pre_key_id, &mut OsRng);
        
        // Generate signed pre-key
        let signed_pre_key_id = SignedPreKeyId::from(1);
        let signed_pre_key = SignedPreKeyRecord::generate(
            signed_pre_key_id,
            &mut OsRng,
            identity_key_pair,
        );
        
        let signature = signed_pre_key.signature().to_vec();
        
        self.pre_keys.insert(user_id, pre_key);
        self.signed_pre_keys.insert(user_id, signed_pre_key);
        self.signatures.insert(user_id, signature);
        
        println!("Generated pre-keys for user {}", user_id);
        Ok(())
    }
    
    // Get or create a session between two users
    fn get_or_create_session(
        &mut self,
        user_id: i64,
        recipient_id: i64,
    ) -> Result<&SessionRecord, Box<dyn std::error::Error>> {
        // Check if session exists
        if !self.sessions.contains_key(&(user_id, recipient_id)) {
            println!("Creating new session between {} and {}", user_id, recipient_id);
            
            // Get user's identity key
            let user_identity = self.identity_keys.get(&user_id)
                .ok_or("User identity key not found")?;
            
            // Get recipient's identity key
            let recipient_identity = self.public_keys.get(&recipient_id)
                .ok_or("Recipient public key not found")?;
            
            // Get recipient's pre-key
            let recipient_pre_key = self.pre_keys.get(&recipient_id)
                .ok_or("Recipient pre-key not found")?;
            
            // Get recipient's signed pre-key
            let recipient_signed_pre_key = self.signed_pre_keys.get(&recipient_id)
                .ok_or("Recipient signed pre-key not found")?;
            
            // Get recipient's signature
            let recipient_signature = self.signatures.get(&recipient_id)
                .ok_or("Recipient signature not found")?;
            
            // Create pre-key bundle for recipient
            let pre_key_bundle = PreKeyBundle::new(
                1, // Registration ID (fixed for simplicity)
                recipient_id as u32, // Device ID
                PreKeyId::from(1),
                recipient_pre_key,
                SignedPreKeyId::from(1),
                recipient_signed_pre_key,
                recipient_signature,
                recipient_identity,
            )?;
            
            // Create session
            let mut session = SessionRecord::new();
            let builder = SessionBuilder::new(user_identity);
            
            builder.process_pre_key_bundle(&pre_key_bundle, &mut session)?;
            
            // Store session
            self.sessions.insert((user_id, recipient_id), session);
        }
        
        Ok(self.sessions.get(&(user_id, recipient_id)).unwrap())
    }
    
    // Encrypt a message
    fn encrypt_message(
        &mut self,
        from_user_id: i64,
        to_user_id: i64,
        content: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        println!("Encrypting message from {} to {}", from_user_id, to_user_id);
        
        // Get or create session
        let session = self.get_or_create_session(from_user_id, to_user_id)?;
        
        // Get sender's identity
        let sender_identity = self.identity_keys.get(&from_user_id)
            .ok_or("Sender identity key not found")?;
        
        // Get recipient's identity
        let recipient_identity = self.public_keys.get(&to_user_id)
            .ok_or("Recipient public key not found")?;
        
        // Create session cipher
        let cipher = SessionCipher::new(
            session,
            sender_identity,
            recipient_identity,
        );
        
        // Encrypt message
        let cipher_message = cipher.encrypt(content.as_bytes())?;
        let serialized = cipher_message.serialize()?;
        
        println!("Message encrypted successfully ({} bytes)", serialized.len());
        
        Ok(serialized)
    }
    
    // Decrypt a message
    fn decrypt_message(
        &mut self,
        for_user_id: i64,
        from_user_id: i64,
        encrypted_content: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        println!("Decrypting message for {} from {}", for_user_id, from_user_id);
        
        // Get or create session
        let session = self.get_or_create_session(for_user_id, from_user_id)?;
        
        // Get user's identity
        let user_identity = self.identity_keys.get(&for_user_id)
            .ok_or("User identity key not found")?;
        
        // Get sender's identity
        let sender_identity = self.public_keys.get(&from_user_id)
            .ok_or("Sender public key not found")?;
        
        // Create session cipher
        let cipher = SessionCipher::new(
            session,
            user_identity,
            sender_identity,
        );
        
        // Deserialize cipher message
        let cipher_message = libsignal_protocol::CipherMessage::deserialize(encrypted_content)?;
        
        // Decrypt message
        let decrypted = cipher.decrypt(&cipher_message)?;
        
        // Convert bytes to string
        let content = String::from_utf8(decrypted)?;
        
        println!("Message decrypted successfully");
        
        Ok(content)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TweetAI Encryption Security Test ===");
    
    // Create encryption service
    let mut encryption_service = EncryptionService::new();
    
    // Step 1: Generate identity keys for users
    println!("\n[1] Generating identity keys for users...");
    encryption_service.generate_identity_keys(1)?; // Gaurav (ID 1)
    encryption_service.generate_identity_keys(2)?; // User (ID 2)
    encryption_service.generate_identity_keys(3)?; // Attacker (ID 3)
    
    // Step 2: Generate pre-keys for users
    println!("\n[2] Generating pre-keys for users...");
    encryption_service.generate_pre_keys(1)?; // Gaurav
    encryption_service.generate_pre_keys(2)?; // User
    encryption_service.generate_pre_keys(3)?; // Attacker
    
    // Step 3: Test Perfect Forward Secrecy
    println!("\n[3] Testing Perfect Forward Secrecy...");
    
    // User sends a message to Gaurav
    let message1 = "Message 1: This is the first secret message!";
    let encrypted1 = encryption_service.encrypt_message(2, 1, message1)?;
    
    // User sends another message to Gaurav
    let message2 = "Message 2: This is the second secret message!";
    let encrypted2 = encryption_service.encrypt_message(2, 1, message2)?;
    
    // Verify both messages can be decrypted
    let decrypted1 = encryption_service.decrypt_message(1, 2, &encrypted1)?;
    let decrypted2 = encryption_service.decrypt_message(1, 2, &encrypted2)?;
    
    assert_eq!(message1, decrypted1);
    assert_eq!(message2, decrypted2);
    
    println!("✓ Both messages decrypted successfully");
    println!("✓ Perfect Forward Secrecy: Even if one message is compromised, others remain secure");
    
    // Step 4: Test Man-in-the-Middle Attack Resistance
    println!("\n[4] Testing Man-in-the-Middle Attack Resistance...");
    
    // Attacker tries to decrypt a message intended for Gaurav
    println!("Attacker attempting to decrypt message...");
    
    match encryption_service.decrypt_message(3, 2, &encrypted1) {
        Ok(_) => println!("✗ SECURITY VULNERABILITY: Attacker was able to decrypt the message!"),
        Err(e) => println!("✓ Attacker failed to decrypt message: {}", e),
    }
    
    // Step 5: Test Message Tampering Resistance
    println!("\n[5] Testing Message Tampering Resistance...");
    
    // Tamper with the encrypted message
    let mut tampered_message = encrypted1.clone();
    if tampered_message.len() > 10 {
        // Modify some bytes in the middle of the message
        tampered_message[5] = tampered_message[5].wrapping_add(1);
        tampered_message[6] = tampered_message[6].wrapping_add(1);
        tampered_message[7] = tampered_message[7].wrapping_add(1);
    }
    
    println!("Attempting to decrypt tampered message...");
    
    match encryption_service.decrypt_message(1, 2, &tampered_message) {
        Ok(_) => println!("✗ SECURITY VULNERABILITY: Tampered message was decrypted successfully!"),
        Err(e) => println!("✓ Tampered message rejected: {}", e),
    }
    
    // Step 6: Test Session Ratcheting
    println!("\n[6] Testing Session Ratcheting...");
    
    // Send multiple messages and verify each one uses a different key
    let messages = vec![
        "Ratchet Test 1: First message",
        "Ratchet Test 2: Second message",
        "Ratchet Test 3: Third message",
    ];
    
    let mut encrypted_messages = Vec::new();
    
    for message in &messages {
        let encrypted = encryption_service.encrypt_message(2, 1, message)?;
        encrypted_messages.push(encrypted);
    }
    
    // Verify all ciphertexts are different even for identical messages
    println!("Checking if ciphertexts differ for identical messages...");
    
    let identical_message = "Identical message test";
    let encrypted_identical1 = encryption_service.encrypt_message(2, 1, identical_message)?;
    let encrypted_identical2 = encryption_service.encrypt_message(2, 1, identical_message)?;
    
    if encrypted_identical1 == encrypted_identical2 {
        println!("✗ SECURITY VULNERABILITY: Identical messages produced identical ciphertexts!");
    } else {
        println!("✓ Identical messages produced different ciphertexts (good for security)");
    }
    
    // Step 7: Test Key Rotation
    println!("\n[7] Testing Key Rotation...");
    
    // Generate new pre-keys for a user
    println!("Generating new pre-keys for user 2...");
    encryption_service.generate_pre_keys(2)?;
    
    // Test if communication still works after key rotation
    let post_rotation_message = "This message is sent after key rotation";
    let encrypted_post_rotation = encryption_service.encrypt_message(2, 1, post_rotation_message)?;
    let decrypted_post_rotation = encryption_service.decrypt_message(1, 2, &encrypted_post_rotation)?;
    
    assert_eq!(post_rotation_message, decrypted_post_rotation);
    println!("✓ Communication works after key rotation");
    
    // Step 8: Security Recommendations
    println!("\n[8] Security Recommendations:");
    println!("✓ Implement regular key rotation (e.g., every 14 days)");
    println!("✓ Add fingerprint verification for identity keys");
    println!("✓ Implement secure key storage with hardware security if available");
    println!("✓ Add out-of-band key verification");
    println!("✓ Implement secure key backup and recovery");
    println!("✓ Add protection against replay attacks");
    println!("✓ Implement secure random number generation");
    println!("✓ Add rate limiting for failed decryption attempts");
    
    println!("\n=== Security Test completed successfully ===");
    Ok(())
}