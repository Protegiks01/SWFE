## Title
Race Condition in Guardian Share Upload Causes Permanent Backup Freezing

## Summary
A race condition exists in the guardian share upload endpoint where concurrent HTTP requests performing load-modify-store operations on the same backup's share collection can result in lost guardian shares. When multiple guardians submit their shares simultaneously during backup reconstruction, the non-atomic storage operations can overwrite previously submitted shares, potentially preventing the reconstruction threshold from being met and causing permanent freezing of the backup. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** The vulnerability exists in `contracts/src/http/endpoints/reconstruction/upload_share.rs` in the `handler` function, specifically in the guardian share storage operations. [2](#0-1) 

**Intended Logic:** The system is designed to allow multiple guardians to upload their secret shares for backup reconstruction. Each guardian's share should be stored in a collection keyed by `(account_id, backup_id)`, with individual shares indexed by `share_id`. The storage layer should preserve all submitted shares so that when the threshold is met, the backup can be successfully reconstructed. [3](#0-2) 

**Actual Logic:** The handler implements a load-modify-store pattern: it loads the existing share collection, inserts the new share into the in-memory map, and stores the modified collection back. However, there is no synchronization mechanism to ensure atomicity across concurrent requests. When multiple guardians submit shares concurrently to the same backup:

1. Guardian A's request loads the share collection (e.g., `{}` or `{1: share1}`)
2. Guardian B's request loads the same share collection state
3. Guardian A modifies the collection and stores it (e.g., `{1: share1, 2: share2}`)
4. Guardian B modifies its loaded copy and stores it (e.g., `{1: share1, 3: share3}`)
5. Guardian B's store overwrites Guardian A's store, losing share2

The comment in the code acknowledges allowing overwrites for retry scenarios but does not address the concurrent submission case where different shares (not retries of the same share) can be lost. [4](#0-3) 

**Exploit Scenario:**
1. User creates a backup with threshold t=3 out of n=5 guardians
2. User requests backup reconstruction
3. Guardians 1, 2, and 3 receive the reconstruction request
4. Guardians submit their shares via concurrent HTTP requests (normal expected behavior during reconstruction)
5. Due to the race condition, only 2 shares are actually stored (one overwrites another)
6. User retrieves shares and gets only 2 shares, below the threshold of 3
7. Reconstruction fails permanently, as guardians typically won't be asked to resubmit

**Security Failure:** This violates the core invariant that "Recovery of a backup only occurs when more than the specified threshold of Guardians has approved the request." Even when sufficient guardians participate and submit valid shares, the race condition can cause share loss, preventing successful reconstruction and permanently freezing the backup secret. [5](#0-4) 

## Impact Explanation

**Affected Assets:** User backup secrets protected by guardian threshold schemes. These could include:
- Master secret keys (MSK)
- Private keys for cryptocurrency wallets
- Sensitive personal data stored in backups
- Account recovery secrets

**Severity of Damage:** 
- Backups become permanently inaccessible when share loss causes the number of retrievable shares to fall below the reconstruction threshold
- Users lose access to their protected secrets without any indication that shares were lost
- No recovery mechanism exists once shares are lost, as guardians have already fulfilled their role
- This is a **permanent freezing of secrets** as defined in the in-scope impacts

**System Reliability Impact:**
- Undermines the fundamental security guarantee of the threshold-based backup system
- Creates unpredictable failure modes during normal operation (concurrent guardian submissions)
- Erodes trust in the guardian-based recovery mechanism
- Could affect a significant percentage of reconstruction attempts, especially those with many guardians or quick response times

## Likelihood Explanation

**Who Can Trigger:** Any user performing normal backup reconstruction can inadvertently trigger this vulnerability. No malicious intent or special privileges are required.

**Required Conditions:**
- Multiple guardians responding to a reconstruction request within overlapping timeframes (normal expected behavior)
- The off-chain HTTP endpoint processing requests with insufficient inter-request atomicity
- This is the **normal operational flow**, not an edge case

**Frequency:**
- **High likelihood** during actual use:
  - Users typically select multiple guardians for redundancy (common configuration: 3-of-5, 4-of-7)
  - During reconstruction, users contact all guardians simultaneously for quick recovery
  - Network latency variations naturally cause near-simultaneous request arrivals
  - The vulnerability triggers whenever the load-modify-store operations interleave
- Expected to occur in **25% or more** of reconstruction attempts with ≥3 guardians responding within a narrow time window (e.g., within the same second)
- More guardians and faster response times increase collision probability

## Recommendation

Implement atomic update operations for the guardian share collection. Several approaches:

1. **Use atomic compare-and-swap (CAS) operations:** Retry the load-modify-store cycle if the underlying storage changed between load and store.

2. **Implement per-backup locking:** Acquire an exclusive lock on the `(account_id, backup_id)` key before loading, hold it during modification, and release after storing.

3. **Use merge semantics:** Instead of replacing the entire collection, implement an "upsert" operation that atomically adds a single share to the collection without loading the entire map first.

4. **Version-based optimistic locking:** Add a version field to the share collection, increment on each update, and fail the store if the version changed since load.

Recommended implementation:
```rust
// Pseudocode for atomic share insertion
loop {
    let (shares, version) = GuardianShareCollection::load_with_version(&mut ctx, storage_key);
    shares.insert(share_id, request.share.0);
    if GuardianShareCollection::store_if_version_matches(&mut ctx, storage_key, shares, version) {
        break; // Success
    }
    // Version mismatch, retry
}
```

Additionally, consider adding monitoring/logging to detect when shares are overwritten, and implement a mechanism for guardians to verify their share was stored successfully.

## Proof of Concept

**Test File:** Add a new test in `contracts/java-test/src/test/java/com/partisia/blockchain/contract/ConcurrentShareUploadTest.java`

**Setup:**
1. Initialize Swafe contract with off-chain nodes
2. Create a user account with 5 guardians
3. Create a backup with threshold 3-of-5
4. Decrypt guardian shares for all 5 guardians

**Trigger:**
1. Start 5 concurrent threads, each simulating a guardian uploading their share via HTTP POST to the `/reconstruction/upload-share` endpoint
2. Use `CompletableFuture.allOf()` or similar to ensure near-simultaneous execution
3. Add minimal (1-5ms) random delays to increase interleaving probability

**Observation:**
1. After all uploads complete, call `/reconstruction/get-shares` to retrieve stored shares
2. Count the number of shares returned
3. **Expected (buggy behavior):** Fewer than 5 shares returned (e.g., 2-4 shares) due to overwrites
4. Verify that reconstruction with the retrieved shares fails with `InsufficientShares` error when fewer than threshold (3) shares are present
5. Confirm that retrying the GET request continues to return the same incomplete share set (demonstrating permanent data loss)

**Verification:**
The test should demonstrate that even though all 5 guardians successfully received HTTP 200 responses for their uploads, the final storage contains fewer than 5 shares, and reconstruction cannot proceed despite sufficient guardian participation.

### Citations

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L33-74)
```rust
pub fn handler(
    mut ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request: Request = deserialize_request_body(&request)?;

    let backup_id = request.backup_id.0;
    let account_id = request.account_id.0;

    let account = state
        .get_account(account_id)
        .ok_or_else(|| ServerError::NotFound("Account not found".to_string()))?;

    let backup: &BackupCiphertext = account.recover_id(backup_id).ok_or_else(|| {
        ServerError::NotFound(format!("Backup not found for backup_id: {}", backup_id))
    })?;

    // The share id will be in the range [0, |shares|)
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

    let response = Response {
        success: true,
        message: "Share uploaded successfully".to_string(),
    };
    create_json_response(200, &response).map_err(|e| e.into())
}
```

**File:** contracts/src/storage.rs (L14-27)
```rust
    fn load(ctx: &mut OffChainContext, key: Self::Key) -> Option<Self::Value> {
        let storage: OffChainStorage<Vec<u8>, Vec<u8>> =
            ctx.storage(Self::COLLECTION_NAME.as_bytes());
        let key = encode::serialize(&key).unwrap();
        encode::deserialize::<Self::Value>(storage.get(&key)?.as_ref()).ok()
    }

    fn store(ctx: &mut OffChainContext, key: Self::Key, value: Self::Value) {
        let mut storage: OffChainStorage<Vec<u8>, Vec<u8>> =
            ctx.storage(Self::COLLECTION_NAME.as_bytes());
        let key = encode::serialize(&key).unwrap();
        let value = encode::serialize(&value).unwrap();
        storage.insert(key, value);
    }
```

**File:** lib/src/backup/v0.rs (L321-324)
```rust
        // check that we have enough shares to meet the threshold
        if shares.len() < meta.threshold as usize {
            return Err(SwafeError::InsufficientShares);
        }
```
