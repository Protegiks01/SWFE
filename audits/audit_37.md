## Title
Off-by-One Error in BackupCiphertext Verification Causes Panic in Guardian Share Upload

## Summary
The `verify()` method in `BackupCiphertextV0` contains an off-by-one boundary check error that allows guardian shares with index equal to the commitments vector length to pass validation, but then triggers a panic when accessing the array. This vulnerability can be exploited by creating malformed backup ciphertexts on-chain that cause the contract's share upload endpoint to panic, blocking legitimate recovery operations. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** The vulnerability exists in the `verify()` method of `BackupCiphertextV0` in `lib/src/backup/v0.rs`, specifically the boundary check at line 343 and the array access at line 346. [1](#0-0) 

**Intended Logic:** The verification method should validate that a guardian share's index is within the valid range of the commitments vector (0 to `comms.len() - 1`) before accessing the commitment at that index. For a vector with length `n`, valid indices are 0 through `n-1`.

**Actual Logic:** The boundary check uses strict inequality (`share.idx > self.comms.len()`) instead of greater-than-or-equal (`share.idx >= self.comms.len()`). This allows a share with `idx == comms.len()` to pass the validation check, but the subsequent array access at `self.comms[share.idx as usize]` triggers an out-of-bounds panic since that index doesn't exist.

**Exploit Scenario:**
1. An attacker creates an account and constructs a malformed `BackupCiphertext` where the `comms` vector has been truncated or deliberately sized smaller than expected (e.g., `comms.len() = 2`).
2. The attacker adds this malformed backup to their `AccountState` and submits an `AccountUpdate` to the blockchain contract.
3. The contract's `update_account` action verifies signatures but does not validate the internal structure of `BackupCiphertext` objects, so the malformed state is stored on-chain. [2](#0-1) 

4. A guardian (who may have received a legitimate share with `idx = 2` from an earlier version of the backup, or the attacker crafts such a share) attempts to upload their share via the `/reconstruction/upload_share` HTTP endpoint.
5. The endpoint handler retrieves the malformed `BackupCiphertext` from on-chain storage and calls `backup.verify(&request.share)`. [3](#0-2) 

6. The `verify()` method checks if `2 > 2`, which is false, so it proceeds to access `self.comms[2]`.
7. Since `comms.len() = 2`, accessing index 2 is out-of-bounds, causing a panic.
8. The panic crashes the request handler, blocking the guardian from uploading their share.

**Security Failure:** This breaks the availability and reliability of the recovery system. Guardians cannot upload their shares to the contract, which prevents legitimate account recovery operations. If the threshold number of guardians are blocked from uploading shares, the account owner's recovery becomes permanently impossible.

## Impact Explanation

**Affected Components:**
- Guardian share upload operations via the contract's HTTP endpoint
- Account recovery flows that depend on collecting threshold shares
- Contract request handlers that may crash on panics

**Severity:**
- Guardians are prevented from uploading shares for recovery, blocking legitimate recovery operations
- If enough guardians are affected (below the recovery threshold), the account owner cannot recover their master secret key
- The panic occurs in the contract's off-chain HTTP handler, which may cause the processing node to crash or enter an error state
- Multiple users could be affected if attackers create many accounts with malformed backups and trigger guardian share uploads

**System Impact:**
This vulnerability allows an attacker to freeze recovery operations by causing panics in the contract infrastructure, meeting the impact criterion of "Temporary freezing of transactions or recovery operations" and potentially "Shutdown of ≥10% but <30% of processing nodes" if panics propagate to crash handlers.

## Likelihood Explanation

**Trigger Conditions:**
- Any user can create an account with a malformed `BackupCiphertext` by manipulating their local `AccountSecrets` before generating an update
- The malformed state can be uploaded to the blockchain through normal `AccountUpdate` operations
- Guardian share uploads are common during recovery operations

**Accessibility:**
- Any account holder can create the vulnerable state on-chain
- The vulnerability is triggered during standard guardian share upload operations
- No special privileges are required beyond normal account operations

**Frequency:**
- While not likely to occur accidentally (the `BackupCiphertext::new()` method creates valid structures), an attacker can deliberately construct malformed backups
- Once deployed on-chain, the malformed backup persists and can trigger panics repeatedly
- Each guardian attempting to upload a share with an out-of-bounds index will trigger the panic

## Recommendation

Change the boundary check in the `verify()` method from strict inequality to greater-than-or-equal:

```rust
if share.idx >= self.comms.len() as u32 {
    return Err(SwafeError::InvalidShare);
}
```

Additionally, consider adding validation during `AccountUpdate` processing to ensure that `BackupCiphertext` objects have internally consistent structures:
- Verify that `comms.len()` matches the number of ciphertexts in `encap`
- Ensure that all vector lengths are reasonable and non-zero when expected
- Add these checks in the `verify_update()` or `verify_allocation()` methods [4](#0-3) 

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** Add a new test function `test_backup_verify_oob_panic`:

**Setup:**
1. Create an owner account and 3 guardian accounts
2. Generate a legitimate `BackupCiphertext` with 3 guardians (threshold 2)
3. Each guardian decrypts their share and creates a valid `GuardianShare`
4. Manually construct a malformed `BackupCiphertext` by deserializing the original, truncating the `comms` vector to length 2, and re-serializing it

**Trigger:**
1. Call `malformed_backup.verify(&guardian_share_2)` where `guardian_share_2.idx = 2`
2. The verify method will check `2 > 2` (false) and proceed to access `comms[2]`

**Observation:**
The test should catch a panic at the line accessing `self.comms[share.idx as usize]`. The panic message will indicate an index out of bounds error. This confirms that a share with `idx == comms.len()` can bypass the validation check but causes a panic during verification.

The test demonstrates that:
- A malformed `BackupCiphertext` with truncated `comms` can be constructed
- A legitimate `GuardianShare` with valid signatures can trigger a panic
- This panic would occur in the contract endpoint when processing share uploads

### Citations

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

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L48-55)
```rust
    let backup: &BackupCiphertext = account.recover_id(backup_id).ok_or_else(|| {
        ServerError::NotFound(format!("Backup not found for backup_id: {}", backup_id))
    })?;

    // The share id will be in the range [0, |shares|)
    let share_id = backup
        .verify(&request.share.0)
        .map_err(|_| ServerError::InvalidParameter("Invalid guardian share".to_string()))?;
```

**File:** lib/src/account/v0.rs (L786-834)
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
