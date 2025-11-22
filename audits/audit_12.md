# Audit Report

## Title
Non-Atomic Guardian Share Storage Leads to Lost Updates and Backup Reconstruction Denial-of-Service

## Summary
The guardian share upload handler in `contracts/src/http/endpoints/reconstruction/upload_share.rs` performs commitment verification (share verification) and storage in a non-atomic manner, implementing a vulnerable read-modify-write pattern. When multiple guardians upload shares concurrently for the same backup, the last write wins and earlier shares are silently lost, potentially preventing backup reconstruction despite sufficient guardian approvals. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** `contracts/src/http/endpoints/reconstruction/upload_share.rs`, lines 64-67, within the `handler` function.

**Intended Logic:** The system should accept and store guardian shares such that when the required threshold of guardians approve a backup reconstruction request, all uploaded shares are available for the reconstruction process. The invariant from the README states: "Recovery of a backup only occurs when more than the specified threshold of Guardians has approved the request." [2](#0-1) 

**Actual Logic:** The handler implements a non-atomic read-modify-write pattern:
1. Load existing shares from storage (line 65)
2. Insert the new share into an in-memory copy (line 66)
3. Store the modified copy back to storage (line 67)

Between these operations, no lock or atomic operation prevents concurrent requests from interfering with each other. When two or more guardians upload shares simultaneously, their operations interleave, causing the classic "lost update" problem where the last store operation overwrites all previous changes.

**Exploit Scenario:**
1. User initiates backup reconstruction for `(account_id=A, backup_id=B)` with threshold `t=3` (requiring 3 out of 5 guardians)
2. Five guardians approve and begin uploading their shares concurrently via the `/reconstruction/upload-share` endpoint
3. Share verification passes for all guardians (line 53-55)
4. Concurrent execution interleaving:
   - Guardian 0: `load()` → returns `{}` (empty map)
   - Guardian 1: `load()` → returns `{}` (empty map)
   - Guardian 0: `insert(share_id=0, share_0)` into local copy
   - Guardian 1: `insert(share_id=1, share_1)` into local copy
   - Guardian 0: `store({0: share_0})`
   - Guardian 1: `store({1: share_1})` ← **Overwrites Guardian 0's store, losing share_0**
   - Guardian 2-4: Similar race conditions occur
5. Final storage state: Only 2 shares remain (e.g., `{2: share_2, 4: share_4}`)
6. User calls `/reconstruction/get-shares` and receives only 2 shares
7. Reconstruction fails because 2 < threshold of 3 [3](#0-2) 

**Security Failure:** This violates the backup reconstruction invariant. Despite having sufficient guardian approvals (5 guardians approved, exceeding the threshold of 3), the user cannot reconstruct their backup because the non-atomic storage operation lost guardian shares. The system enters a state where guardians believe they have successfully uploaded shares (they received HTTP 200 responses), but those shares are missing from storage. [4](#0-3) 

## Impact Explanation

**Affected Assets:** Backup secrets encrypted in `BackupCiphertext` that users are attempting to reconstruct. These could contain critical data such as master secret keys, signing keys, or other sensitive information that users need to recover their accounts. [5](#0-4) 

**Severity of Damage:** 
- **Temporary Denial-of-Service:** Users cannot reconstruct their backups even though enough guardians have approved, because shares are silently lost during concurrent uploads
- **User Experience Impact:** Users and guardians have no indication that shares were lost—the upload succeeds with HTTP 200, but the share doesn't persist
- **Recovery Requirement:** Guardians must manually retry uploads, but they have no way of knowing this is necessary. The system provides no notification that their previous upload was overwritten
- **Potential for Permanent Loss:** If guardians believe their upload succeeded and are no longer available to retry (e.g., offline, unresponsive), and enough shares are lost that the remaining count falls below the threshold, the backup becomes permanently unrecoverable

**System Impact:** This directly undermines the reliability of the backup reconstruction system, which is a core security feature for account recovery. According to the in-scope impacts, this qualifies as "Temporary freezing of transactions or recovery operations" (Medium severity).

## Likelihood Explanation

**Who Can Trigger:** Any set of guardians legitimately attempting to fulfill their duty to upload shares for an approved backup reconstruction request. No adversarial intent is required—this is a normal operational race condition.

**Conditions Required:** 
- Multiple guardians uploading shares for the same `(account_id, backup_id)` pair within a short time window (milliseconds to seconds)
- Concurrent request processing by the off-chain node's HTTP handler
- This is the **expected normal behavior** when guardians respond promptly to a reconstruction request

**Frequency:** 
- **High likelihood in production:** When a user requests backup reconstruction, guardians are typically notified simultaneously through out-of-band channels (per README, users communicate with guardians). Well-behaved, responsive guardians will upload their shares quickly, leading to concurrent requests.
- **Scales with guardian count:** The more guardians in the system, the higher the probability of concurrent uploads
- **No warning or retry mechanism:** The code comment acknowledges retry scenarios but only considers "buggy client library" retries, not concurrent upload failures. Guardians receive success responses even when their shares are silently overwritten. [6](#0-5) 

## Recommendation

Implement atomic read-modify-write semantics using one of these approaches:

**Option 1: Optimistic Concurrency Control**
Add a version counter or timestamp to the storage value and retry on conflict:
```rust
loop {
    let storage_key = (account_id, backup_id);
    let mut shares = GuardianShareCollection::load(&mut ctx, storage_key).unwrap_or_default();
    let old_len = shares.len();
    shares.insert(share_id, request.share.0);
    
    // Only store if no concurrent modification occurred
    // This requires storage backend support for conditional updates
    if GuardianShareCollection::compare_and_swap(&mut ctx, storage_key, old_len, shares) {
        break;
    }
    // Retry on conflict
}
```

**Option 2: Individual Share Storage**
Store each share independently with a composite key `(account_id, backup_id, share_id)` instead of storing all shares in a map. This eliminates the read-modify-write pattern:
```rust
let storage_key = (account_id, backup_id, share_id);
IndividualGuardianShare::store(&mut ctx, storage_key, request.share.0);
```

**Option 3: Application-Level Locking**
Implement per-backup locking to serialize access to share storage for each `(account_id, backup_id)` pair. This requires adding a locking mechanism to the contract state.

**Recommended Solution:** Option 2 is simplest and most robust, as it eliminates the concurrency issue entirely by avoiding shared mutable state. The `get_shares` handler would need to be updated to iterate over all possible share_ids or use a secondary index.

## Proof of Concept

**File:** Add a new test file `contracts/tests/test_concurrent_share_upload.rs` or add to an existing contract test file.

**Test Function Name:** `test_concurrent_guardian_share_upload_race_condition`

**Setup:**
1. Initialize contract state with a test account that has a backup registered
2. Create the backup ciphertext with threshold `t=3` and `n=5` guardians
3. Have each of the 5 guardians prepare their shares by decrypting from the backup
4. Verify each guardian share individually to ensure they're all valid

**Trigger:**
1. Simulate concurrent execution by spawning multiple threads or async tasks
2. Have each guardian (0-4) simultaneously call the `/reconstruction/upload-share` endpoint with their respective shares for the same `(account_id, backup_id)` pair
3. All requests should complete successfully (HTTP 200)

**Observation:**
1. Call `/reconstruction/get-shares` for the `(account_id, backup_id)` pair
2. Count the number of shares returned
3. **Expected (without fix):** Fewer than 5 shares are returned (typically 1-3 shares due to lost updates)
4. **Expected (with fix):** All 5 shares are returned
5. The test should assert that `shares.len() == 5`, which will fail on the vulnerable code, confirming that concurrent uploads cause share loss

The test demonstrates that despite all 5 guardians successfully uploading (receiving HTTP 200 responses) and despite all shares being individually valid, the final storage contains fewer shares than uploaded due to the race condition. This proves the backup reconstruction would fail even though the required threshold of guardians approved the request.

### Citations

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L53-67)
```rust
    let share_id = backup
        .verify(&request.share.0)
        .map_err(|_| ServerError::InvalidParameter("Invalid guardian share".to_string()))?;

    // Update the share mapping for this backup
    // usually, the share will not already exist in this map:
    // we allow overwriting in case of a buggy client library and to
    // simplify a client which fails during the upload process: it can simply retry all uploads.
    //
    // Potentially different multiple versions of the same share are all equivalent.
    // Hence no replay protection is required here.
    let storage_key = (account_id, backup_id);
    let mut shares = GuardianShareCollection::load(&mut ctx, storage_key).unwrap_or_default();
    shares.insert(share_id, request.share.0);
    GuardianShareCollection::store(&mut ctx, storage_key, shares);
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L69-72)
```rust
    let response = Response {
        success: true,
        message: "Share uploaded successfully".to_string(),
    };
```

**File:** README.md (L140-140)
```markdown
- Recovery of a backup only occurs when more than the specified threshold of Guardians has approved the request.
```

**File:** contracts/src/http/endpoints/reconstruction/get_shares.rs (L28-33)
```rust
    let shares: Vec<_> = GuardianShareCollection::load(&mut ctx, (account_id, backup_id))
        .unwrap_or_default()
        .values()
        .cloned()
        .map(StrEncoded)
        .collect();
```

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
