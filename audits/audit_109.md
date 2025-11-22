# Audit Report

## Title
Panic in Backup Creation with Threshold=0 and Non-Zero Guardians

## Summary
The `BackupCiphertextV0::new()` function panics when called with `threshold=0` and a non-empty guardians array due to an index out of bounds error. This vulnerability exists in the core library's Shamir secret sharing integration and can be triggered through normal backup creation or account recovery setup operations.

## Impact
**Medium**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The backup system should gracefully handle threshold=0 cases where only the master secret key is needed for recovery, regardless of the guardian count. The validation at line 368 is intended to ensure sufficient guardians exist to meet the threshold requirement.

**Actual Logic:** 
When threshold=0, the Shamir secret sharing function returns an empty vector of shares: [2](#0-1) 

However, the backup creation code at lines 383-388 attempts to access `shares[i]` for each guardian index, and again at lines 394-399 when forming commitments. Since `shares` is empty but `guardians.len()` is non-zero, this causes an index out of bounds panic.

**Exploit Scenario:**
1. A user creates an account and calls `update_recovery()` with threshold=0 and a non-empty guardians array [3](#0-2) 

2. This internally calls `create_recovery()` which invokes `BackupCiphertextV0::new()` [4](#0-3) 

3. The validation passes since `guardians.len() < 0` is false
4. The code panics when accessing the empty shares vector, crashing the process

**Security Failure:** 
This violates availability - the panic causes immediate process termination, creating a denial of service for backup and recovery functionality. In a smart contract context, this would crash contract execution.

## Impact Explanation

**Affected Processes:**
- Backup creation via `AccountSecrets::backup()`
- Account recovery setup via `AccountSecrets::update_recovery()`
- Any contract or API endpoint invoking these functions

**Severity:**
The panic causes immediate termination, preventing users from:
- Creating new backups with misconfigured threshold parameters
- Setting up or updating account recovery configurations
- Completing any transaction that includes these operations

In a Partisia smart contract context, this panic would cause the contract execution to fail, potentially freezing the contract state or preventing valid operations from completing. This constitutes unintended smart contract behavior and temporary freezing of recovery operations.

## Likelihood Explanation

**Trigger Conditions:**
Any user can trigger this by calling backup or recovery functions with threshold=0 and non-zero guardians. This is a straightforward input combination that:
- Requires no special privileges
- Can occur during normal operation (user error or intentional testing)
- Does not require complex timing or state manipulation

**Frequency:**
While threshold=0 with guardians is logically inconsistent (if no guardians are needed, why specify them?), the code accepts this input combination during validation, making it easily triggerable. Users experimenting with different threshold configurations or making configuration errors could inadvertently trigger this.

## Recommendation

Add explicit validation to reject threshold=0 with non-empty guardians, or handle this case gracefully by ignoring guardians when threshold=0:

```rust
// Option 1: Reject invalid combination
if threshold == 0 && !guardians.is_empty() {
    return Err(SwafeError::InvalidThreshold(
        "Threshold 0 requires empty guardians array".to_string()
    ));
}

// Option 2: Handle gracefully (use empty guardians when threshold=0)
let guardians = if threshold == 0 { &[] } else { guardians };
```

This validation should be added at the start of `BackupCiphertextV0::new()` before the existing validation check.

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** Add the following test to demonstrate the panic:

```rust
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_backup_threshold_zero_with_guardians_panics() {
    let mut rng = OsRng;
    
    // Create owner and one guardian
    let owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian = AccountSecrets::gen(&mut rng).unwrap();
    let guardian_state = guardian.state(&mut rng).unwrap();
    
    let test_data = TestData {
        value: "test data".to_string(),
    };
    
    // This will panic: threshold=0 with non-empty guardians
    let _backup = owner.backup(
        &mut rng,
        &test_data,
        Metadata::new("Test".to_string(), "Test backup".to_string()),
        &[guardian_state], // Non-empty guardians
        0,                 // threshold=0
    );
    // Panic occurs here with: "index out of bounds: the len is 0 but the index is 0"
}
```

**Setup:** The test creates an owner account and one guardian account with their public states.

**Trigger:** Calls `owner.backup()` with threshold=0 and a non-empty guardians array.

**Observation:** The code panics with an index out of bounds error when attempting to access `shares[0]` from an empty vector. This confirms the vulnerability - the code should return an error instead of panicking.

### Citations

**File:** lib/src/backup/v0.rs (L356-399)
```rust
    pub fn new<R: Rng + CryptoRng, M: Tagged, A: Tagged>(
        rng: &mut R,
        data: &M,
        aad: &A,
        meta: Metadata,
        sym_key: &sym::Key,
        guardians: &[AccountState],
        threshold: usize,
    ) -> Result<Self, SwafeError> {
        // check if there are enough guardians to meet the threshold
        // note that the threshold MAY be 0: in which case
        // only the msk is required to recover the secret
        if guardians.len() < threshold {
            return Err(SwafeError::InsufficientShares);
        }

        // shuffle guardians to prevent leaking the ordering
        let mut guardians = guardians.to_vec();
        guardians.shuffle(rng);

        // obtain current public keys for the guardians
        let pks = guardians.iter().map(|guardian| guardian.encryption_key());

        // create a shamir secret sharing
        let (secret, shares) = sss::share(rng, threshold, guardians.len());

        // plaintexts - use shuffled indices
        let pts: Vec<BackupShareV0> = (0..guardians.len())
            .map(|i| BackupShareV0 {
                sk: sig::SigningKey::gen(rng),
                share: shares[i].clone(),
            })
            .collect();

        // Form commitments to each share
        // note: this is fine because they have high entropy
        // and hence it is hiding if we assume that hash
        // can be modelled as a random oracle
        let comms: Vec<ShareComm> = (0..guardians.len())
            .map(|i| ShareComm {
                vk: pts[i].sk.verification_key(),
                hash: hash(&ShareHash { share: &shares[i] }),
            })
            .collect();
```

**File:** lib/src/crypto/sss.rs (L38-40)
```rust
    if t == 0 {
        return (Secret(pp::Fr::ZERO), vec![]);
    }
```

**File:** lib/src/account/v0.rs (L373-393)
```rust
fn create_recovery<R: Rng + CryptoRng>(
    rng: &mut R,
    acc: AccountId,
    msk_ss_rik: &MskSecretShareRik,
    msk_ss_social: &MskSecretShareSocial,
    guardians: &[AccountState],
    threshold: usize,
) -> Result<BackupCiphertext> {
    BackupCiphertextV0::new(
        rng,
        msk_ss_social,
        &AADRecovery { acc },
        crate::backup::Metadata::new(
            "RIK Social Recovery".to_string(),
            "MSK secret share for social recovery".to_string(),
        ),
        msk_ss_rik.as_bytes(),
        guardians,
        threshold,
    )
    .map(BackupCiphertext::V0)
```

**File:** lib/src/account/v0.rs (L532-553)
```rust
    pub fn update_recovery<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        guardians: &[AccountState],
        threshold: usize,
    ) -> Result<()> {
        // mark dirty
        self.dirty = true;

        // generate fresh "social secret"
        self.recovery.msk_ss_social = MskSecretShareSocial::gen(rng);

        // generate new ciphertext
        self.recovery.social = create_recovery(
            rng,
            self.acc,
            &self.recovery.msk_ss_rik,
            &self.recovery.msk_ss_social,
            guardians,
            threshold,
        )?;
        Ok(())
```
