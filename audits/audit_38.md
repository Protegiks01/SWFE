# Audit Report

## Title
Unbounded Deserialization Memory Exhaustion via Large Backups Vector in Account Updates

## Summary
The Swafe smart contract's `update_account` action deserializes `AccountUpdate` structures without size limits before signature verification. An attacker can create a validly-signed account update containing millions of backup ciphertexts with deeply nested unbounded vectors, causing memory exhaustion on contract processing nodes during deserialization.

## Impact
**Medium to High**

## Finding Description

**Location:** 
- Primary vulnerability: [1](#0-0) 
- Unbounded vector structure: [2](#0-1) 
- Nested unbounded vectors: [3](#0-2) 
- Additional nested vectors: [4](#0-3) 
- Unconfigured bincode: [5](#0-4) 

**Intended Logic:** The contract should deserialize and validate account updates efficiently, rejecting invalid updates through signature verification before committing state changes.

**Actual Logic:** The deserialization occurs unconditionally before any validation. The `bincode::config::standard()` configuration has no size limits, allowing unbounded memory allocation during deserialization of nested vector structures. The `AccountStateV0.backups` field is a `Vec<BackupCiphertext>`, where each `BackupCiphertext` contains `Vec<ShareComm>` and `BatchCiphertext` (which itself contains `Vec<Ciphertext>`). This creates three levels of unbounded nested vectors.

**Exploit Scenario:**
1. Attacker creates a legitimate account with their own signing key
2. Attacker uses `AccountSecrets.add_backup()` to add millions of `BackupCiphertext` entries locally [6](#0-5) 
3. Each `BackupCiphertext` can be crafted with thousands of entries in `comms` and `cts` vectors
4. Attacker calls `update()` which signs the entire state including all backups [7](#0-6) 
5. Attacker submits the base64-encoded update string to `update_account` action
6. Contract calls `encode::deserialize_str()` which internally uses `bincode::serde::decode_from_slice()` with no size limits [8](#0-7) 
7. Bincode allocates memory for millions of backup entries × thousands of nested vector elements
8. Memory exhaustion occurs BEFORE signature verification at line 127 [9](#0-8) 

**Security Failure:** Resource exhaustion denial-of-service. The contract nodes exhaust memory processing malicious but validly-signed updates, potentially causing node crashes or severe performance degradation affecting all users.

## Impact Explanation

**Affected Resources:** Contract processing nodes' memory and computational capacity; availability of the Swafe contract for all users.

**Severity:** An attacker controlling a single account can craft updates that consume gigabytes of memory during deserialization. Consider:
- 100,000 `BackupCiphertext` entries
- Each with 1,000 `ShareComm` entries and 1,000 `Ciphertext` entries in `BatchCiphertext`
- This creates 100 billion total objects to deserialize
- Each cryptographic structure contains multiple field elements (signatures, curve points, encrypted data)
- Total memory consumption could reach several gigabytes for a single malicious transaction

This could cause:
- **≥30% increase in processing node resource consumption** (meeting medium impact criteria)
- **Potential shutdown of ≥30% of processing nodes** if memory exhaustion causes crashes (meeting medium impact criteria)
- **Critical contract outage** preventing legitimate account recovery and backup operations for all users (meeting high impact criteria)

**System Impact:** The Swafe contract becomes unavailable or severely degraded, preventing users from updating accounts, initiating recovery, or managing backups. This violates the system's availability guarantees.

## Likelihood Explanation

**Trigger Accessibility:** Any user with a Swafe account can exploit this vulnerability. The attack requires only:
- Creating a normal account (no special privileges needed)
- Crafting a malicious but validly-signed update locally
- Submitting it to the contract's public `update_account` action

**Conditions Required:** Normal operation—no special timing, race conditions, or external factors needed. The attack works deterministically whenever a malicious update is submitted.

**Frequency:** An attacker can repeatedly submit malicious updates, potentially causing sustained denial-of-service. Each submission triggers memory exhaustion during deserialization. Multiple attackers could amplify the impact.

## Recommendation

**Immediate Mitigation:**
1. Add size limits to the bincode configuration: [5](#0-4) 
   ```rust
   const BINCODE_CONFIG: bincode::config::Configuration = 
       bincode::config::standard().with_limit::<{10 * 1024 * 1024}>(); // 10MB limit
   ```

2. Add explicit bounds checking before deserialization in the contract: [10](#0-9) 
   ```rust
   // Check input size before deserialization
   if update_str.len() > MAX_UPDATE_SIZE {
       panic!("Update too large");
   }
   ```

3. Add application-level limits on the backups vector size:
   - Enforce maximum number of backups per account (e.g., 100)
   - Enforce maximum size of each `BackupCiphertext`
   - Validate these limits during the `add_backup()` operation and in `verify_update()`

**Long-term Solution:** Implement a pagination or chunking mechanism for large backup sets, storing them off-chain with on-chain references only.

## Proof of Concept

**Test File:** `contracts/src/lib.rs` (add new integration test) or create `contracts/tests/dos_backups.rs`

**Setup:**
```rust
// 1. Initialize contract with normal configuration
// 2. Create a legitimate account using AccountSecrets::gen()
// 3. Get the account's signing key
```

**Trigger:**
```rust
// 1. Create malicious AccountSecrets with excessive backups:
let mut secrets = AccountSecrets::gen(&mut rng)?;

// 2. Add thousands of BackupCiphertext entries
for _ in 0..10000 {
    // Each backup can have large nested vectors
    let backup = create_large_backup(&mut rng, &guardians, threshold)?;
    secrets.add_backup(backup)?;
}

// 3. Create validly-signed update
let update = secrets.update(&mut rng)?;
let update_str = encode::serialize_str(&update)?;

// 4. Measure memory before and after
let mem_before = get_process_memory();

// 5. Submit to contract (this will trigger memory exhaustion)
let result = contract.update_account(ctx, state, update_str);

let mem_after = get_process_memory();
```

**Observation:** The test should observe:
- Memory consumption spike during deserialization (before signature verification)
- Memory increase of hundreds of megabytes or gigabytes depending on attack payload size
- Potential panic/crash due to out-of-memory condition
- Processing time significantly exceeds normal update operations

The vulnerability is confirmed if memory consumption grows linearly with the number of backup entries in the update, and this growth occurs before any validation logic executes.

### Citations

**File:** contracts/src/lib.rs (L107-115)
```rust
#[action]
fn update_account(
    _ctx: ContractContext,
    mut state: ContractState,
    update_str: String,
) -> ContractState {
    // deserialize the account update from a string,
    let update: AccountUpdate =
        encode::deserialize_str(update_str.as_str()).expect("Failed to decode account update");
```

**File:** contracts/src/lib.rs (L126-129)
```rust
    // verify the update using the lib
    let st_new = update
        .verify(st_old.as_ref())
        .expect("Failed to verify account update");
```

**File:** lib/src/account/v0.rs (L229-238)
```rust
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AccountStateV0 {
    cnt: u32, // current count of operations
    act: AccountCiphertext,
    pub(crate) rec: RecoveryStateV0,
    sig: sig::VerificationKey,
    pke: pke::EncryptionKey,
    backups: Vec<BackupCiphertext>, // backups to store
    recover: Vec<BackupCiphertext>, // backups to recover
}
```

**File:** lib/src/account/v0.rs (L503-507)
```rust
    pub fn add_backup(&mut self, ct: BackupCiphertext) -> Result<()> {
        self.dirty = true;
        self.backups.push(ct);
        Ok(())
    }
```

**File:** lib/src/account/v0.rs (L703-719)
```rust
        let st = AccountStateV0 {
            cnt,
            backups: self.backups.clone(),
            recover: self.recover.clone(),
            pke: self.pke.encryption_key(),
            sig: self.sig.verification_key(),
            act,
            rec: RecoveryStateV0 {
                pke: None,
                assoc,
                // TODO: unfortunately we cannot generate this anew every time
                social: self.recovery.social.clone(),
                enc_msk,
            },
        };

        let sig = self.old_sig.sign(rng, &st);
```

**File:** lib/src/backup/v0.rs (L60-65)
```rust
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct BackupCiphertextV0 {
    pub data: sym::AEADCiphertext,   // encrypted
    pub comms: Vec<ShareComm>,       // share commitments
    pub encap: pke::BatchCiphertext, // encrypted shares
}
```

**File:** lib/src/crypto/pke/mod.rs (L32-36)
```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BatchCiphertextV0Inner {
    vk: sig::VerificationKey,
    cts: Vec<Ciphertext>,
}
```

**File:** lib/src/encode.rs (L5-6)
```rust
/// Standard bincode configuration used throughout the library
const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();
```

**File:** lib/src/encode.rs (L53-55)
```rust
pub fn deserialize_str<T: DeserializeOwned>(s: &str) -> Result<T, SwafeError> {
    StrEncoded::<T>::try_from(s).map(|encoded| encoded.0)
}
```
