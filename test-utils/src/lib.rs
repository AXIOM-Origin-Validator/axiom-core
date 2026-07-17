//! AXIOM Test Utilities
//!
//! Provides utilities for testing:
//! - Keypair generation
//! - Transaction signing
//! - Genesis wallet creation
//! - Test fixtures

use axiom_core_logic::types::{Transaction, TxKind, WalletState, WitnessSig, GenesisWallet};
use axiom_core_logic::genesis::{compute_genesis_state_id, create_genesis_wallet};
use axiom_core_logic::wallet_id::{generate_wallet_id, generate_wallet_id_with_secret};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use rand::rngs::OsRng;

/// A wallet with its keypair for testing
#[derive(Clone)]
pub struct TestWallet {
    /// Ed25519 signing key (private)
    pub signing_key: SigningKey,

    /// Ed25519 verifying key (public)
    pub verifying_key: VerifyingKey,

    /// Current balance
    pub balance: u64,

    /// Current wallet sequence
    pub wallet_seq: u64,

    /// Current state ID
    pub state_id: [u8; 32],

    /// Email for wallet address
    pub email: String,

    /// Wallet ID suffix (hex8) — from WALLET_IDENTITY_KEY path.
    /// Used for CL1 receiver_wallet_id (anti-typo validation via extract_security_level).
    pub wallet_id: String,

    /// Wallet secret (for CL5 receiver identity binding).
    /// Used with verify_wallet_id_with_secret to prove receiver owns the wallet_id.
    pub wallet_secret: [u8; 32],

    /// Wallet ID suffix (hex8) — from wallet_secret path (binds pk to wallet_id).
    /// Used for CL5 redeem: verify_wallet_id_with_secret checks this checksum.
    pub wallet_id_secret: String,
}

impl TestWallet {
    /// Generate a new random wallet
    pub fn generate(email: &str, initial_balance: u64) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);

        // Compute genesis state ID
        let pk_bytes: [u8; 32] = verifying_key.to_bytes();
        let state_id = compute_genesis_state_id(&pk_bytes, initial_balance);

        // Generate wallet_id with pk binding (hex10 format: checksum6 + pk_bind2 + salt2)
        let full_wallet_id = generate_wallet_id(email, "42", &pk_bytes)
            .expect("Failed to generate wallet ID");
        let wallet_id_suffix = full_wallet_id
            .rsplit('/')
            .next()
            .unwrap_or("0000000042")
            .to_string();

        // wallet_secret path — passes verify_wallet_id_with_secret (CL5 identity binding)
        let wallet_secret: [u8; 32] = {
            let mut data = b"TEST_WALLET_SECRET".to_vec();
            data.extend_from_slice(&signing_key.to_bytes());
            *blake3::hash(&data).as_bytes()
        };
        let full_wallet_id_secret = generate_wallet_id_with_secret(
            email, "42", &wallet_secret, &pk_bytes,
        ).expect("Failed to generate wallet ID with secret");
        let wallet_id_secret_suffix = full_wallet_id_secret
            .rsplit('/')
            .next()
            .unwrap_or("00000042")
            .to_string();

        Self {
            signing_key,
            verifying_key,
            balance: initial_balance,
            wallet_seq: 0,
            state_id,
            email: email.to_string(),
            wallet_id: wallet_id_suffix,
            wallet_secret,
            wallet_id_secret: wallet_id_secret_suffix,
        }
    }
    
    /// Get the public key as bytes
    pub fn public_key(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }
    
    /// Get the full wallet address (email/wallet_id) — WALLET_IDENTITY_KEY path.
    /// Use for CL1 receiver_wallet_id (passes extract_security_level anti-typo check).
    pub fn address(&self) -> String {
        format!("{}/{}", self.email, self.wallet_id)
    }

    /// Get the wallet address for CL5 redeem — wallet_secret path.
    /// Use for CL5 receiver_wallet_id (passes verify_wallet_id_with_secret binding).
    pub fn redeem_address(&self) -> String {
        format!("{}/{}", self.email, self.wallet_id_secret)
    }
    
    /// Get wallet state for validation
    pub fn wallet_state(&self) -> WalletState {
        WalletState {
            public_key: self.public_key(),
            balance: self.balance,
            wallet_seq: self.wallet_seq,
            state_id: self.state_id,
            auth_hash: None,
            wallet_id: None,
            group_members: None,
            hibernation_until: 0,
        }
    }

    /// Create a genesis wallet from this test wallet
    pub fn genesis_wallet(&self) -> GenesisWallet {
        let pk_bytes: [u8; 32] = self.verifying_key.to_bytes();
        create_genesis_wallet(pk_bytes, self.balance)
    }
    
    /// Sign a transaction
    pub fn sign_transaction(&self, tx: &mut Transaction) {
        // Set the public key
        tx.client_pk = self.public_key();
        
        // Compute signing message (same as in validation.rs)
        let message = compute_signing_message(tx);
        
        // Sign
        let signature = self.signing_key.sign(&message);
        tx.client_sig = signature.to_bytes().to_vec();
    }
    
    /// Create and sign a transaction to send funds
    pub fn create_transaction(
        &self,
        receiver_wallet_id: &str,
        amount: u64,
        reference: &str,
        nonce: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            consumed_state_id: self.state_id,
            client_pk: self.public_key(),
            sender_wallet_id: String::new(),
            wallet_seq: self.wallet_seq + 1, // Next sequence
            receiver_wallet_id: receiver_wallet_id.to_string(),
            receiver_address: None, // Use email from wallet_id
            amount,
            reference: reference.to_string(),
            nonce,
            epoch: 1, // Fixed epoch for testing
            client_sig: vec![], // Will be filled by sign_transaction
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            recall_target_tx_id: None,
            oracle_claim: None,
            required_k: 0,
            proof_type: 0,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
        };

        self.sign_transaction(&mut tx);
        tx
    }
    
    /// Update wallet state after successful transaction
    pub fn apply_send(&mut self, amount: u64, new_state_id: [u8; 32]) {
        self.balance = self.balance.saturating_sub(amount);
        self.wallet_seq += 1;
        self.state_id = new_state_id;
    }
    
    /// Update wallet state after receiving funds
    pub fn apply_receive(&mut self, amount: u64, new_state_id: [u8; 32]) {
        self.balance += amount;
        self.state_id = new_state_id;
    }
}

/// Compute the message that gets signed (matches validation.rs)
fn compute_signing_message(tx: &Transaction) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&tx.consumed_state_id);
    message.extend_from_slice(&tx.wallet_seq.to_le_bytes());
    message.extend_from_slice(tx.sender_wallet_id.as_bytes());
    message.extend_from_slice(tx.receiver_wallet_id.as_bytes());
    message.extend_from_slice(&tx.amount.to_le_bytes());
    message.extend_from_slice(tx.reference.as_bytes());
    message.extend_from_slice(&tx.nonce.to_le_bytes());
    message.extend_from_slice(&tx.epoch.to_le_bytes());
    // MEDIUM-4: bind burn_target_tx_id (zero bytes for non-burn TXs)
    message.extend_from_slice(tx.burn_target_tx_id.as_ref().unwrap_or(&[0u8; 32]));
    // Protocol version binding — prevents cross-network and cross-version replay.
    message.extend_from_slice(axiom_core_logic::types::AXIOM_PROTOCOL_VERSION.as_bytes());
    message
}

/// Test fixture: Alice, Bob, and Charlie with initial balances
pub struct TestFixture {
    pub alice: TestWallet,
    pub bob: TestWallet,
    pub charlie: TestWallet,
}

impl TestFixture {
    /// Create test fixture with default balances
    pub fn new() -> Self {
        Self {
            alice: TestWallet::generate("alice@test.com", 1_000_000_000_000), // 1T atoms
            bob: TestWallet::generate("bob@test.com", 500_000_000_000),       // 500B atoms
            charlie: TestWallet::generate("charlie@test.com", 250_000_000_000), // 250B atoms
        }
    }
    
    /// Create test fixture with custom balances
    pub fn with_balances(alice_balance: u64, bob_balance: u64, charlie_balance: u64) -> Self {
        Self {
            alice: TestWallet::generate("alice@test.com", alice_balance),
            bob: TestWallet::generate("bob@test.com", bob_balance),
            charlie: TestWallet::generate("charlie@test.com", charlie_balance),
        }
    }
}

impl Default for TestFixture {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a mock witness signature (for testing validator consensus)
pub fn create_mock_witness_sig(validator_key: &SigningKey, tx: &Transaction) -> WitnessSig {
    let verifying_key = VerifyingKey::from(validator_key);
    
    // Sign the transaction hash
    let tx_json = serde_json::to_vec(tx).unwrap_or_default();
    let tx_hash = blake3::hash(&tx_json);
    let signature = validator_key.sign(tx_hash.as_bytes());
    
    // Derive validator_id from public key
    let validator_id = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_VALIDATOR_ID");
        hasher.update(verifying_key.as_bytes());
        *hasher.finalize().as_bytes()
    };
    
    WitnessSig {
        validator_id,
        validator_pk: verifying_key.to_bytes().to_vec(),
        vbc_bundle: None,
        carrier_type: "test".to_string(),
        carrier_address: "test-validator".to_string(),
        signature: signature.to_bytes().to_vec(),
        execution_proof: vec![], // Empty for mock
        proof_type: 1, // DMAP (default)
        availability_attestation: None,
        validator_hints: vec![], // Empty for test - real validators MUST provide 1-3
        fact_signature: None, // Test mock — no FACT signing
        checkpoint_sig: None, // SEC-07: test mock — no checkpoint endorsement
        receipt_signature: None, // Test mock — no Nabla receipt signing
        receipt_commitment_sig: None, // Test mock — no receipt commitment signing
        rate_bps: 0,
        slot_amount: 0,
    }
}

/// Create k mock witness signatures for a transaction
pub fn create_mock_witnesses(tx: &Transaction, k: usize) -> Vec<WitnessSig> {
    (0..k)
        .map(|_| {
            let key = SigningKey::generate(&mut OsRng);
            create_mock_witness_sig(&key, tx)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_core_logic::verify::verify_ed25519;
    
    #[test]
    fn test_wallet_generation() {
        let wallet = TestWallet::generate("test@example.com", 1000);
        
        assert_eq!(wallet.balance, 1000);
        assert_eq!(wallet.wallet_seq, 0);
        assert_eq!(wallet.public_key().len(), 32);
        assert!(!wallet.wallet_id.is_empty());
    }
    
    #[test]
    fn test_transaction_signing() {
        let wallet = TestWallet::generate("sender@test.com", 10000);
        let receiver = TestWallet::generate("receiver@test.com", 0);
        
        let tx = wallet.create_transaction(
            &receiver.address(),
            1000,
            "test payment",
            1,
        );
        
        // Verify signature
        let message = compute_signing_message(&tx);
        let result = verify_ed25519(&tx.client_pk, &message, &tx.client_sig);
        
        assert!(result.is_ok(), "Signature should be valid");
    }
    
    #[test]
    fn test_genesis_state_id_matches() {
        let wallet = TestWallet::generate("test@example.com", 1000);
        let genesis = wallet.genesis_wallet();
        
        // State ID should match genesis state ID
        assert_eq!(wallet.state_id, genesis.genesis_state_id);
    }
    
    #[test]
    fn test_fixture() {
        let fixture = TestFixture::new();
        
        assert!(fixture.alice.balance > 0);
        assert!(fixture.bob.balance > 0);
        assert!(fixture.charlie.balance > 0);
        
        // All should have different keys
        assert_ne!(fixture.alice.public_key(), fixture.bob.public_key());
        assert_ne!(fixture.bob.public_key(), fixture.charlie.public_key());
    }
    
    #[test]
    fn test_mock_witnesses() {
        let wallet = TestWallet::generate("sender@test.com", 10000);
        let receiver = TestWallet::generate("receiver@test.com", 0);
        
        let tx = wallet.create_transaction(&receiver.address(), 1000, "test", 1);
        
        let witnesses = create_mock_witnesses(&tx, 3);
        
        assert_eq!(witnesses.len(), 3);
        
        // All should have different validator keys
        let pks: Vec<_> = witnesses.iter().map(|w| &w.validator_pk).collect();
        assert_ne!(pks[0], pks[1]);
        assert_ne!(pks[1], pks[2]);
    }
}
