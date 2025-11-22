# Audit Report

## Title
Race Condition in Concurrent Guardian Share Uploads Causes Lost Shares and Permanent Backup Freezing

## Summary
The `/reconstruction/upload-share` endpoint in the Swafe contract contains a read-modify-write race condition that can cause guardian shares to be permanently lost when multiple guardians upload shares concurrently. This occurs due to the absence of proper idempotency tokens, request IDs, or transaction isolation mechanisms, leading to potential permanent freezing of user backups when insufficient shares remain to meet the recovery threshold. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
The vulnerability exists in `contracts/src/http/endpoints/reconstruction/upload_share.rs` in the `handler` function, specifically in the share storage logic. [2](#0-1) 

**Intended Logic:**
The system is designed to allow guardians to upload their decrypted shares for backup reconstruction. The code intentionally allows overwrites to support retry scenarios where a guardian's upload fails and they need to resubmit. [3](#0-2) 

**Actual Logic:**
The handler implements a classic read-modify-write pattern without any concurrency control:
1. Load the current `BTreeMap` of shares from storage
2. Insert the new share into the local copy of the map
3. Store the modified map back to storage

When multiple guardians upload shares concurrently, each handler loads the same initial state, modifies their local copy with different share IDs, and stores back. The last write wins, causing earlier submissions to be lost entirely.

**Exploit Scenario:**
1. User initiates backup reconstruction requiring threshold `t` shares from `n` guardians
2. Multiple guardians (e.g., Guardian A and Guardian B) receive the request and begin processing
3. Guardian A uploads their share (share_id=0) via HTTP POST to `/reconstruction/upload-share`
4. Guardian B uploads their share (share_id=1) concurrently
5. Both handlers execute simultaneously:
   - Handler A loads shares: `{}`
   - Handler B loads shares: `{}`
   - Handler A inserts: `{0: share_A}` and stores
   - Handler B inserts: `{1: share_B}` and stores (overwrites A's write)
6. Final storage state: `{1: share_B}` - Guardian A's share is permanently lost
7. Both guardians receive 200 OK responses, believing their uploads succeeded
8. User attempts to retrieve shares for reconstruction but only receives 1 share
9. If `t=2`, reconstruction fails permanently due to insufficient shares

**Security Failure:**
This violates the recovery liveness guarantee - even though `t` honest guardians submitted valid shares, the user cannot recover their backup due to lost shares from the race condition. The backup becomes permanently frozen.

## Impact Explanation

**Affected Assets:**
- User's backup ciphertexts containing encrypted secrets, master keys, or sensitive data
- The ability to reconstruct backups and recover accounts

**Severity of Damage:**
- **Permanent Freezing of Secrets**: If the race condition causes enough shares to be lost such that the remaining shares are below the threshold, the backup becomes permanently inaccessible. This requires manual intervention or guardians to retry their uploads (but they received successful responses and won't know to retry).
- **Loss of Recovery Capability**: Users who lose access to their accounts cannot recover if their backup reconstruction fails due to insufficient shares.
- **Silent Failure**: Guardians receive 200 OK responses even though their shares may be overwritten later, providing false confidence that the upload succeeded.

**System Reliability:**
This directly undermines one of Swafe's main invariants: "Recovery of a backup only occurs when more than the specified threshold of Guardians has approved the request." While the guardians technically approved and submitted shares, the system's race condition prevents the shares from being properly stored, breaking the recovery guarantee.

## Likelihood Explanation

**Who Can Trigger:**
This occurs during normal operation - no malicious actor is required. Any backup reconstruction scenario where multiple guardians respond to a recovery request at approximately the same time will trigger the race condition.

**Conditions Required:**
- Multiple guardians uploading shares concurrently for the same backup
- No transaction isolation in the underlying Partisia off-chain storage layer
- Timing overlap in the HTTP request processing

**Frequency:**
**High likelihood** in production:
- In a real distributed system with multiple guardians operating independently, concurrent submissions are the expected behavior during recovery operations
- Guardians typically all receive the recovery request simultaneously and begin processing immediately
- The HTTP handlers execute asynchronously without explicit serialization
- The vulnerability manifests whenever handler execution timing overlaps, which is highly probable with network latency variations
- Each recovery operation with multiple guardians has a significant probability of losing at least one share

## Recommendation

Implement proper concurrency control for guardian share uploads using one of these approaches:

**Option 1: Optimistic Locking with Versioning**
```
1. Add a version field to GuardianShareCollection
2. Load current shares with version number
3. Insert new share into local copy
4. Store with compare-and-swap: only succeed if version unchanged
5. If version mismatch, retry the load-modify-store cycle
```

**Option 2: Request-Level Idempotency Tokens**
```
1. Require guardians to include a unique request_id in upload requests
2. Store a mapping of (account_id, backup_id, share_id, request_id) -> GuardianShare
3. Before processing, check if request_id already processed for this share_id
4. Return cached response for duplicate request_ids
5. This prevents both retries and concurrent submissions from causing lost updates
```

**Option 3: Per-Share Storage**
```
1. Change storage key from (account_id, backup_id) to (account_id, backup_id, share_id)
2. Store each guardian share individually instead of in a BTreeMap
3. This eliminates the read-modify-write pattern entirely
4. Share retrieval becomes a range query over share_ids
```

Option 3 is the simplest and most robust solution as it eliminates the race condition entirely by removing the need for read-modify-write operations.

## Proof of Concept

**Test File:** `contracts/java-test/src/test/java/com/partisia/blockchain/contract/BackupWorkflow.java`

**Test Function:** Add new method `testConcurrentGuardianShareUpload()`

**Setup:**
1. Initialize 3 guardian accounts and 1 owner account
2. Create a backup with threshold=2 requiring 2 out of 3 guardians
3. Upload the backup to the contract
4. Have each guardian decrypt their share locally (share_id 0, 1, 2)
5. Convert decrypted shares to GuardianShare objects for upload

**Trigger:**
1. Create 3 threads, one for each guardian
2. Each thread simultaneously calls `uploadGuardianShareToContract()` with their respective share
3. All threads submit to the same `/reconstruction/upload-share` endpoint at approximately the same time
4. All threads complete and verify they received 200 OK responses

**Observation:**
1. Call `/reconstruction/get-shares` to retrieve all stored shares
2. Verify that the response contains fewer than 3 shares (typically only 1-2 shares will be present)
3. Assert that at least one guardian's share was lost despite receiving a successful upload response
4. Attempt backup reconstruction with the retrieved shares
5. Observe that reconstruction fails with `InsufficientShares` error even though 3 guardians submitted valid shares

The test demonstrates that concurrent uploads result in lost shares, violating the recovery guarantee and causing permanent freezing of the backup when insufficient shares remain below the threshold.

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
