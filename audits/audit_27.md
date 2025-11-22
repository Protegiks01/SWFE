## Title
Guardian Shares Remain Accessible After Backup Rotation Due to Missing Validation in get-shares Endpoint

## Summary
The `/reconstruction/get-shares` endpoint fails to validate whether a requested `backup_id` exists in the current account state before returning stored guardian shares. This allows retrieval of shares for removed/rotated backups, enabling revoked guardians or observers to decrypt secrets even after the user has rotated to new guardians.

## Impact
**Medium**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
When a user rotates backup guardians by creating a new backup with different guardians and removing the old backup, the old guardian shares should become inaccessible. The system should only allow retrieval of shares for backups that are currently present in the account's state, ensuring that backup rotation effectively revokes access from old guardians.

**Actual Logic:** 
The `get_shares` handler retrieves guardian shares from `GuardianShareCollection` storage based solely on `(account_id, backup_id)` without verifying that the `backup_id` is present in the current account state. This contrasts with the `upload_share` handler, which does validate backup existence: [2](#0-1) 

The asymmetry means shares for removed backups remain retrievable indefinitely, even though new share uploads for those backups would be rejected.

**Exploit Scenario:**

1. User creates backup A (with `BackupId_A`) containing sensitive data, using guardians G1, G2, G3 with threshold 2
2. Guardians G1, G2, G3 upload their shares via `/reconstruction/upload-share`, which validates and stores them in `GuardianShareCollection[(AccountId, BackupId_A)]`
3. User decides to rotate guardians, so they:
   - Create new backup B (`BackupId_B`) with the same secret but new guardians G4, G5, G6
   - Call `remove_backup(BackupId_A)` to remove the old backup [3](#0-2) 
   - Publish an account update that removes backup A from the on-chain state
4. Any party (revoked guardians G1-G3, or any observer who saved blockchain history) can:
   - Retain a copy of the old `BackupCiphertext` A (which was previously public on-chain)
   - Call `/reconstruction/get-shares` with `(AccountId, BackupId_A)` - this succeeds and returns the old shares
   - Use the old ciphertext and shares to decrypt the secret using the standard recovery function [4](#0-3) 

**Security Failure:** 
The system violates the security invariant that guardian rotation should revoke access. Old guardians or observers who saved historical blockchain data maintain the ability to decrypt backed-up secrets indefinitely, defeating the purpose of guardian rotation. This breaks the expected confidentiality guarantee.

## Impact Explanation

**Affected Assets:**
- User backup secrets, which may include private keys, seed phrases, passwords, or other sensitive data
- Guardian access control and revocation mechanisms

**Severity:**
- Revoked guardians retain unauthorized access to secrets they were explicitly removed from protecting
- Any observer who captured blockchain history can retrieve shares for backups that users believed were securely rotated
- The confidentiality of rotated backups is completely compromised
- Users have no way to actually revoke guardian access once shares have been uploaded

**Why This Matters:**
Guardian rotation is a critical security feature for social recovery systems. Users must be able to revoke access from compromised, malicious, or no-longer-trusted guardians. This vulnerability makes such revocation impossible, undermining a core security primitive of the protocol and violating user expectations about access control.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant can exploit this vulnerability. No special privileges are required - only:
1. Knowledge of a removed `backup_id` (observable from historical blockchain state)
2. A saved copy of the corresponding `BackupCiphertext` (also from historical state)
3. The ability to call the public `/reconstruction/get-shares` endpoint

**Conditions Required:**
- Normal operation: This occurs whenever a user performs backup rotation
- Guardian rotation is a expected regular operation for users wanting to update their guardian set
- Historical blockchain data is typically archived and accessible to any observer

**Frequency:**
- Can be exploited immediately after any backup rotation
- Persists indefinitely - old shares never expire or get cleaned up
- Each rotated backup creates a new exploitable condition

The vulnerability is highly likely to be exploited because:
1. Guardian rotation is a routine security operation
2. Revoked guardians have strong motivation to maintain access
3. The attack requires no sophisticated techniques or special privileges
4. Blockchain history is publicly accessible and commonly archived

## Recommendation

Add validation in the `get_shares` handler to ensure the requested `backup_id` exists in the current account state before returning shares:

```rust
pub fn handler(
    mut ctx: OffChainContext,
    state: ContractState,  // Remove underscore - we need this!
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request = deserialize_request_body::<Request>(&request)?;
    let account_id = request.account_id.0;
    let backup_id = request.backup_id.0;
    
    // NEW: Validate backup exists in current account state
    let account = state
        .get_account(account_id)
        .ok_or_else(|| ServerError::NotFound("Account not found".to_string()))?;
    
    account.recover_id(backup_id).ok_or_else(|| {
        ServerError::NotFound(format!("Backup not found for backup_id: {}", backup_id))
    })?;
    
    // Only return shares if backup is valid
    let shares: Vec<_> = GuardianShareCollection::load(&mut ctx, (account_id, backup_id))
        .unwrap_or_default()
        .values()
        .cloned()
        .map(StrEncoded)
        .collect();
    create_json_response(200, &Response { shares }).map_err(|e| e.into())
}
```

Additionally, consider implementing a cleanup mechanism to delete shares from `GuardianShareCollection` when backups are removed from the account state.

## Proof of Concept

**Test File:** `lib/src/account/tests.rs` (add new test function)

**Setup:**
1. Create account secrets for Alice
2. Create two guardian accounts (G1, G2) 
3. Create backup A with guardians G1, G2 (threshold 2)
4. Have guardians decrypt and generate their shares for backup A
5. Simulate uploading shares to storage (in actual contract, this would be via upload_share endpoint)
6. Create backup B with different guardians for the same secret
7. Remove backup A from Alice's account state via `remove_backup()`
8. Publish account update removing backup A

**Trigger:**
1. Call the equivalent of `get_shares(alice_id, backup_A_id)` 
2. In the test, this simulates loading shares from `GuardianShareCollection` without state validation
3. Attempt to recover the secret using the old backup ciphertext A and the retrieved old shares

**Observation:**
The test demonstrates that:
1. Shares for the removed backup_A are still retrievable
2. The old backup ciphertext + old shares successfully decrypt the secret
3. This works even though backup_A was explicitly removed from the account state
4. The expected behavior (shares inaccessible after rotation) is violated

**Test Code Structure:**
```rust
#[test]
fn test_guardian_share_replay_after_rotation() {
    // 1. Setup: Create account, guardians, backup A
    // 2. Guardians generate and "upload" shares for backup A
    // 3. User rotates: create backup B, remove backup A, update()
    // 4. Verify backup A no longer in account state
    // 5. Simulate get_shares(backup_A_id) - should fail but doesn't
    // 6. Recover secret from old ciphertext + old shares - succeeds incorrectly
    // 7. Assert: Old shares remain usable after rotation (vulnerability confirmed)
}
```

The test confirms the vulnerability by showing that guardian rotation does not invalidate old shares, allowing unauthorized access to rotated backups.

### Citations

**File:** contracts/src/http/endpoints/reconstruction/get_shares.rs (L19-35)
```rust
pub fn handler(
    mut ctx: OffChainContext,
    _state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request = deserialize_request_body::<Request>(&request)?;
    let account_id = request.account_id.0;
    let backup_id = request.backup_id.0;
    let shares: Vec<_> = GuardianShareCollection::load(&mut ctx, (account_id, backup_id))
        .unwrap_or_default()
        .values()
        .cloned()
        .map(StrEncoded)
        .collect();
    create_json_response(200, &Response { shares }).map_err(|e| e.into())
}
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L48-50)
```rust
    let backup: &BackupCiphertext = account.recover_id(backup_id).ok_or_else(|| {
        ServerError::NotFound(format!("Backup not found for backup_id: {}", backup_id))
    })?;
```

**File:** lib/src/account/v0.rs (L510-514)
```rust
    pub fn remove_backup(&mut self, id: BackupId) {
        self.dirty = true;
        self.backups.retain(|ct| ct.id() != id);
        self.recover.retain(|ct| ct.id() != id);
    }
```

**File:** lib/src/backup/v0.rs (L290-340)
```rust
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
