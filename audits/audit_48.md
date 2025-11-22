# Audit Report

## Title
Threshold Bypass via Duplicate Guardian Entries in Social Recovery Setup

## Summary
The `BackupCiphertextV0::new()` function does not validate that guardians in the recovery setup are unique. This allows a user (or attacker with temporary MSK access) to configure social recovery with duplicate guardian entries, enabling a single guardian to satisfy the threshold requirement alone and bypass the multi-party security model.

## Impact
**High**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The social recovery system uses Shamir Secret Sharing with a threshold scheme where `threshold` distinct guardians must cooperate to recover the Master Secret Key (MSK). When a user sets up recovery with, for example, 3 guardians and threshold=2, the expectation is that any 2 of the 3 distinct guardians must provide their shares to complete recovery.

**Actual Logic:** 
The code validates only that `guardians.len() >= threshold` but does not check if the guardian list contains duplicate `AccountState` entries. If the same guardian appears multiple times (e.g., `[G1, G1, G1]` with threshold=2), the Shamir Secret Sharing algorithm creates multiple distinct shares that are all encrypted to the same guardian's public key. That single guardian can then decrypt all their shares and provide any `threshold` number of them to complete recovery alone. [2](#0-1) 

**Exploit Scenario:**
1. User sets up recovery with guardians `[G1, G2, G3]` and threshold=2 (2-of-3 security)
2. Attacker temporarily compromises user's device and gains access to MSK
3. Attacker calls `update_recovery()` with `[AttackerGuardian, AttackerGuardian, AttackerGuardian]` and threshold=2
4. Attacker uploads the modified account state to the contract
5. Later, even after losing direct access to MSK, the attacker can:
   - Initiate recovery using a stolen/obtained RIK
   - As the single AttackerGuardian, decrypt all 3 shares
   - Provide any 2 of the 3 shares to meet the threshold
   - Complete recovery and regain full control of the account [3](#0-2) 

**Security Failure:** 
The threshold security invariant is violated. The system silently accepts a configuration where a single party can satisfy a multi-party threshold requirement, completely defeating the purpose of social recovery's distributed trust model.

## Impact Explanation

**Assets Affected:** 
- Master Secret Key (MSK) and all secrets derived from it
- Account ownership and control
- All backups and associations managed by the account

**Severity of Damage:**
- An attacker who temporarily compromises an account can permanently weaken its recovery security by replacing legitimate guardians with duplicates of a guardian they control
- Users who accidentally add duplicate guardians (e.g., through UI bugs) will have false confidence in their security posture, believing they have proper threshold protection when a single guardian can compromise their account
- The compromise can happen even after the initial attack, as the weakened guardian configuration persists

**System Impact:**
This undermines the core security promise of social recovery. Users trust that threshold recovery requires cooperation from multiple distinct parties. This vulnerability allows that trust model to be silently violated, potentially leading to unauthorized account recoveries and loss of private keys.

## Likelihood Explanation

**Who Can Trigger:**
- Any account owner can configure their own recovery with duplicate guardians (potentially by accident)
- An attacker with temporary access to an account's MSK can reconfigure recovery to use duplicate guardians they control

**Conditions Required:**
- For malicious exploitation: attacker needs temporary access to victim's MSK (e.g., through device compromise, stolen backup, or social engineering)
- For accidental occurrence: client software bug or user error when selecting guardians

**Frequency:**
- High likelihood in practice because:
  - No validation prevents this configuration
  - Users/clients have no warning that they're creating insecure setups
  - Attackers with brief access can permanently weaken accounts
  - The vulnerability persists across all future recovery attempts

## Recommendation

Add validation in `BackupCiphertextV0::new()` to ensure guardian uniqueness before creating shares:

```rust
// After line 370, add:
// Check for duplicate guardians by comparing encryption keys
let mut unique_keys = std::collections::HashSet::new();
for guardian in guardians.iter() {
    let key_bytes = encode::serialize(&guardian.encryption_key())?;
    if !unique_keys.insert(key_bytes) {
        return Err(SwafeError::InvalidParameter(
            "Duplicate guardians detected in recovery setup".to_string()
        ));
    }
}
```

Additionally, consider adding similar validation in `AccountSecrets::update_recovery()` for defense in depth.

## Proof of Concept

**File:** `lib/src/account/tests.rs`

**Test Function:** `test_duplicate_guardian_threshold_bypass`

**Setup:**
1. Create an account with MSK
2. Create a single guardian account (G1)
3. Set up recovery using G1 three times in the guardian list: `[G1, G1, G1]` with threshold=2
4. Initiate recovery using RIK
5. Have G1 decrypt and provide shares

**Trigger:**
```rust
#[test]
fn test_duplicate_guardian_threshold_bypass() {
    let mut rng = OsRng;
    
    // Create account
    let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();
    let original_msk = account_secrets.msk().clone();
    let account_id = *account_secrets.acc();
    
    // Create only ONE guardian
    let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian1_state = guardian1.state(&mut rng).unwrap();
    
    // Setup recovery with DUPLICATE guardians (threshold 2-of-3, but all same guardian)
    let duplicate_guardians = [
        guardian1_state.clone(),
        guardian1_state.clone(), 
        guardian1_state.clone(),
    ];
    
    // This should fail but currently succeeds
    account_secrets
        .update_recovery(&mut rng, &duplicate_guardians, 2)
        .unwrap();
    let rik = account_secrets.add_association(&mut rng).unwrap();
    
    // Publish account state
    let account_state = account_secrets.state(&mut rng).unwrap();
    
    // Initiate recovery
    let (recovery_request, recovery_secrets) = account_state
        .initiate_recovery(&mut rng, account_id, &rik)
        .unwrap();
    let updated_state = recovery_request.verify(Some(&account_state)).unwrap();
    
    // Single guardian decrypts ALL shares
    let share1 = guardian1.check_for_recovery(&mut rng, account_id, &updated_state)
        .unwrap().expect("Guardian should find recovery");
    let share2 = guardian1.check_for_recovery(&mut rng, account_id, &updated_state)
        .unwrap().expect("Guardian should find recovery again");
    
    // Single guardian provides 2 shares to meet threshold
    let shares = vec![share1, share2];
    let recovered_msk = recovery_secrets.complete(&shares).unwrap();
    
    // VULNERABILITY: Single guardian bypassed 2-of-3 threshold
    assert_eq!(recovered_msk, original_msk);
}
```

**Observation:**
The test demonstrates that a single guardian can successfully complete a 2-of-3 threshold recovery when configured with duplicate entries. The `complete()` call succeeds even though only one distinct party provided shares, violating the threshold security model. This test would fail on properly secured code that validates guardian uniqueness.

### Citations

**File:** lib/src/backup/v0.rs (L356-370)
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
```

**File:** lib/src/backup/v0.rs (L376-387)
```rust
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
