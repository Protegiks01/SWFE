## Title
Missing Threshold Validation Allows Creation of Permanently Unrecoverable Backups

## Summary
The Swafe protocol fails to validate that backup threshold values do not exceed the number of guardians during deserialization and contract-level verification. While client-side creation validates this invariant, malicious users can bypass it by deserializing crafted backup data with `threshold > guardians.len()`, creating permanently unrecoverable backups that can freeze user secrets indefinitely.

## Impact
**High**

## Finding Description

**Location:** 
- Primary validation: [1](#0-0) 
- Recovery logic (no threshold upper-bound check): [2](#0-1) 
- Contract verification (no backup validation): [3](#0-2) 
- Account update verification (no backup structure checks): [4](#0-3) 
- Deserialization without validation: [5](#0-4) 

**Intended Logic:** 
The system should enforce that for any backup, the threshold (minimum guardians needed for recovery) never exceeds the total number of guardians. This invariant is critical because Shamir's Secret Sharing requires at least `threshold` shares to reconstruct a secret, and you can only obtain shares from existing guardians.

**Actual Logic:** 
The validation only occurs in `BackupCiphertextV0::new()` during client-side creation. However:
1. `BackupCiphertextV0` derives `Serialize, Deserialize` without custom validation logic
2. Users can deserialize arbitrary `BackupCiphertext` objects using `encode::deserialize()` or `encode::deserialize_str()`
3. The contract's `update_account` action only verifies signatures and version numbers, not backup structure invariants
4. During recovery, the system checks `shares.len() < meta.threshold` but never validates `meta.threshold <= self.comms.len()`

**Exploit Scenario:**
1. Attacker creates a legitimate backup with N guardians and threshold T (where T ≤ N) using normal API
2. Attacker serializes the backup to bytes
3. Attacker manipulates the serialized data or manually constructs encrypted metadata where the threshold field exceeds the number of commitments in `comms` vector
4. Attacker deserializes this malformed backup (succeeds due to lack of validation)
5. Attacker adds the backup to their account using [6](#0-5)  (no validation)
6. Attacker creates an AccountUpdate and submits to contract (passes verification)
7. Later, when attempting recovery, the system requires `threshold` shares but only `comms.len() < threshold` guardians exist, making recovery mathematically impossible

**Security Failure:** 
Violation of the critical invariant that `threshold ≤ guardians.len()`, resulting in permanent freezing of backup secrets. The backup becomes permanently unrecoverable because you cannot collect enough shares to meet the threshold requirement.

## Impact Explanation

**Affected Assets:**
- User secrets stored in malformed backups become permanently frozen
- If applied to the social recovery backup in [7](#0-6) , the entire account becomes unrecoverable upon MSK loss
- Master Secret Keys can be permanently lost if the social recovery mechanism is compromised

**Severity:**
- **Permanent data loss**: Secrets in affected backups can never be recovered
- **Account freezing**: If social recovery backup is malformed, users who lose their MSK are permanently locked out
- **No remediation**: Once stored on-chain, these backups cannot be fixed without manual intervention or hard fork

**System Impact:**
This directly matches the in-scope impact criterion: "Permanent freezing of secrets or accounts (requiring a hard fork or intervention to fix)." Users could accidentally or maliciously create backups that are mathematically impossible to recover, resulting in permanent loss of encrypted data.

## Likelihood Explanation

**Who can trigger:** Any user of the Swafe system with access to serialization/deserialization functions.

**Conditions required:**
- User must manipulate serialized backup data or manually construct encrypted metadata
- Requires understanding of bincode serialization format and the backup structure
- Must have access to their own account credentials to sign the AccountUpdate

**Frequency:**
- **Accidental:** Low - requires deliberate manipulation of serialized data
- **Malicious:** Medium - a determined attacker could exploit this to create unrecoverable backups for themselves or encourage others to use malformed backups
- **Self-harm:** High impact if exploited, as recovery becomes permanently impossible

The vulnerability is exploitable in normal network operation without requiring any special privileges beyond having a valid account.

## Recommendation

1. **Add validation during deserialization**: Implement a custom `Deserialize` implementation for `BackupCiphertextV0` that validates `threshold ≤ comms.len()` after deserializing the structure.

2. **Add contract-level validation**: In the contract's `update_account` action or in `AccountUpdate::verify()`, validate that all backups in the account state maintain the invariant `threshold ≤ guardians.len()`. This requires deserializing the encrypted metadata during verification or storing the threshold separately.

3. **Add recovery-time validation**: In `BackupCiphertextV0::recover()`, add a check after decrypting metadata:
   ```rust
   if meta.threshold as usize > self.comms.len() {
       return Err(SwafeError::InvalidBackupStructure);
   }
   ```

4. **Validate during add_backup**: Add validation in the `add_backup()` method to decrypt and verify the threshold before accepting the backup into account state.

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** `test_backup_threshold_exceeds_guardians_via_deserialization`

**Setup:**
1. Create an account owner with MSK
2. Create 1 guardian account
3. Create a valid backup with threshold=1, guardians=1 using normal API
4. Serialize the backup to bytes

**Trigger:**
1. Manually modify the serialized backup data to reduce `comms` vector length to 0 while keeping encrypted metadata unchanged (or vice versa - increase threshold in metadata while keeping comms small)
2. Alternatively, manually construct a `BackupCiphertextV0` with inconsistent threshold and guardian count using raw crypto functions
3. Deserialize the malformed backup (should succeed due to missing validation)
4. Add to account using `add_backup()`
5. Generate AccountUpdate and verify it passes contract validation
6. Attempt recovery with all available guardian shares

**Observation:**
- The malformed backup is successfully deserialized
- Contract accepts the AccountUpdate containing the malformed backup
- Recovery fails with `InsufficientShares` even when all guardians provide shares
- The backup is permanently unrecoverable because `threshold > available_guardians`
- Test demonstrates that the invariant `threshold ≤ guardians.len()` is not enforced at any validation point after client-side creation

The test should demonstrate that a backup with `threshold=2` and `comms.len()=1` can be created, stored on-chain, and becomes permanently unrecoverable, confirming the vulnerability.

### Citations

**File:** lib/src/backup/v0.rs (L289-340)
```rust
impl BackupCiphertextV0 {
    pub fn recover<M: Tagged + DeserializeOwned, A: Tagged>(
        &self,
        dke: &pke::DecryptionKey,
        sym: &sym::Key,
        aad: &A,
        shares: &[GuardianShare],
    ) -> Result<M, SwafeError> {
        // Verify and decrypt each share
        // Ignore invalid and duplicate shares
        let shares: Vec<(u32, Share)> = shares
            .iter()
            .filter_map(|share| {
                let GuardianShare::V0(share_v0) = share;
                let id = self.verify(share_v0).ok()?;
                let share: Share = dke.decrypt(&share_v0.ct, aad).ok()?;
                if self.comms[id as usize].hash == hash(&ShareHash { share: &share }) {
                    Some((id, share))
                } else {
                    None
                }
            })
            .collect::<BTreeMap<u32, Share>>()
            .into_iter()
            .collect();

        // derive the metadata key
        let key_meta: sym::Key = kdfn(sym, &KDFMetakey { comms: &self.comms });

        // decrypt the metadata
        let meta: BackupMetadata = sym::open(&key_meta, &self.data, &sym::EmptyAD)?;

        // check that we have enough shares to meet the threshold
        if shares.len() < meta.threshold as usize {
            return Err(SwafeError::InsufficientShares);
        }

        // recover the secret using Shamir's Secret Sharing
        let secret: sss::Secret = sss::recover(
            &shares
                .into_iter()
                .take(meta.threshold as usize)
                .map(|(idx, share)| (idx as usize, share))
                .collect::<Vec<_>>()[..],
        );

        // derive the data encryption key
        let key_data: sym::Key = kdfn(&BackupKDFInput { key: sym, secret }, &EmptyInfo);

        // decrypt the data
        sym::open(&key_data, &meta.data, &sym::EmptyAD)
    }
```

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

**File:** contracts/src/lib.rs (L108-134)
```rust
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

**File:** lib/src/account/v0.rs (L101-106)
```rust
pub(crate) struct RecoveryStateV0 {
    pub pke: Option<pke::EncryptionKey>, // this is set iff. recovery has been started
    pub(crate) assoc: Vec<AssociationsV0>, // encryption of the recovery authorization key
    pub(crate) social: BackupCiphertext, // social backup ciphertext
    pub(crate) enc_msk: sym::AEADCiphertext, // encrypted MSK (encrypted with key derived from RIK and social shares)
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

**File:** lib/src/account/v0.rs (L787-834)
```rust
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
            AccountMessageV0::Recovery(recovery) => {
                // Handle recovery update: set the recovery pke field in the account state
                let mut new_state = old.clone();

                {
                    let rec = &mut new_state.rec;
                    // Verify the recovery request signature
                    let recovery_msg = RecoveryRequestMessage {
                        account_id: self.acc,
                        recovery_pke: recovery.pke.clone(),
                    };

                    // Find the matching association and verify signature
                    let mut verified = false;
                    for assoc in &rec.assoc {
                        // Verify signature using the recovery signing key from associations
                        if assoc.sig.verify(&recovery.sig, &recovery_msg).is_ok() {
                            verified = true;
                            break;
                        }
                    }

                    if !verified {
                        return Err(SwafeError::InvalidSignature);
                    }

                    // Set the recovery PKE to indicate recovery has been initiated
                    rec.pke = Some(recovery.pke);
                }
                Ok(new_state)
            }
        }
    }
```

**File:** lib/src/encode.rs (L62-74)
```rust
pub fn deserialize<T>(bytes: &[u8]) -> Result<T, SwafeError>
where
    T: serde::de::DeserializeOwned,
{
    bincode::serde::decode_from_slice::<T, _>(bytes, BINCODE_CONFIG)
        .map(|(data, _)| data)
        .map_err(|_| {
            SwafeError::SerializationError(format!(
                "Failed to deserialize {}",
                std::any::type_name::<T>()
            ))
        })
}
```
