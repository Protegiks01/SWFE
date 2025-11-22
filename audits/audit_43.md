## Title
Race Condition in Guardian Share Upload Leads to Permanent Loss of Backup Recovery Shares

## Summary
The `/reconstruction/upload-share` endpoint in the Partisia smart contract contains a race condition vulnerability when multiple guardians upload their shares concurrently for the same backup. Without read-after-write consistency guarantees from Partisia's `OffChainStorage`, concurrent uploads can overwrite each other, resulting in permanently lost guardian shares and the inability to reconstruct backups when the threshold cannot be met. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** The vulnerability exists in the `upload_share` handler function in the reconstruction endpoint. [2](#0-1) 

**Intended Logic:** The endpoint is designed to allow guardians to upload their decrypted shares for a backup reconstruction. Each guardian's share should be stored in a `BTreeMap` indexed by `share_id`, and all shares for a given `(account_id, backup_id)` pair should be preserved so that when the threshold number of shares is collected, the owner can reconstruct their backup.

**Actual Logic:** The code implements a non-atomic read-modify-write pattern:
1. Load the current map of all shares from storage
2. Insert the new share into the in-memory map
3. Store the entire map back to storage [3](#0-2) 

If Partisia's `OffChainStorage` does not guarantee read-after-write consistency (as the security question probes), concurrent HTTP requests from multiple guardians can read stale data before previous writes are visible, leading to a classic lost update problem.

**Exploit Scenario:**
1. User creates a backup with a 2-of-3 guardian threshold
2. Guardian A and Guardian B both decide to upload their shares simultaneously to help the user recover
3. Request A arrives at time T0, loads the shares map (gets empty `{}` or current state)
4. Request B arrives at time T1 (shortly after), loads the shares map (gets the same stale state due to lack of read-after-write consistency)
5. Request A inserts `share_id=0` and stores `{0: share_A}` at time T2
6. Request B inserts `share_id=1` and stores `{1: share_B}` at time T3, completely overwriting A's write
7. Only Guardian B's share is preserved; Guardian A's share is permanently lost [4](#0-3) 

**Security Failure:** The protocol violates the recovery invariant that states "Recovery of a backup only occurs when more than the specified threshold of Guardians has approved the request." If enough shares are lost due to this race condition such that fewer than the threshold number of shares remain, the backup becomes permanently unrecoverable, leading to permanent freezing of secrets. [5](#0-4) 

## Impact Explanation

**Affected Assets:** User backup data encrypted in `BackupCiphertext` structures, including potentially sensitive information such as master secret keys, wallet private keys, or other critical secrets that users have entrusted to the social recovery mechanism.

**Severity of Damage:** When guardian shares are lost due to concurrent uploads:
- If the number of successfully stored shares drops below the recovery threshold, the backup becomes permanently unrecoverable
- Users lose access to their backed-up secrets forever, with no remediation path
- This constitutes "Permanent freezing of secrets" - explicitly listed as a High-severity in-scope impact [6](#0-5) 

**System Reliability Impact:** This vulnerability undermines the core value proposition of the social recovery system. Users trust that if they configure a proper threshold (e.g., 2-of-3), they can recover their secrets as long as the required number of guardians participate. The race condition breaks this guarantee without any indication to the user or guardians that shares were lost.

## Likelihood Explanation

**Who Can Trigger:** Any set of guardians participating in a legitimate backup reconstruction. No special privileges or malicious intent required - this occurs during normal protocol operation.

**Required Conditions:** 
- Multiple guardians attempting to upload shares for the same backup within a short time window
- Lack of read-after-write consistency in Partisia's off-chain storage (which the security question implies is not guaranteed)
- No special timing requirements - guardians naturally upload concurrently when helping a user recover

**Frequency:** This can occur whenever multiple guardians respond to a recovery request simultaneously, which is the expected behavior in a well-functioning social recovery system. The vulnerability is more likely to manifest when:
- Guardians are automated systems that respond quickly
- Multiple guardians are online and active
- Network latency causes overlapping request processing

The code comment explicitly acknowledges overwrite semantics but fails to account for concurrent different shares being lost: [7](#0-6) 

## Recommendation

Implement one of the following solutions:

**Option 1 - Per-Share Storage:** Instead of storing all shares in a single `BTreeMap`, store each guardian share as a separate key-value pair in the off-chain storage. This eliminates the read-modify-write pattern entirely:
```
Key: (account_id, backup_id, share_id)
Value: GuardianShare
```

**Option 2 - Optimistic Locking:** Implement version tracking for the share collection. On write, verify that the version hasn't changed since the read. If it has, reload and retry the operation.

**Option 3 - Append-Only Log:** Use an append-only storage pattern where each share upload writes to a unique key, and the retrieval endpoint aggregates all shares for the backup.

**Recommended:** Option 1 is the most robust solution as it completely eliminates the concurrency issue and works regardless of Partisia's consistency guarantees.

## Proof of Concept

**Test File:** `contracts/java-test/src/test/java/com/partisia/blockchain/contract/ConcurrentShareUploadTest.java`

**Setup:**
1. Deploy the Swafe contract with multiple test execution engines
2. Create an owner account and 3 guardian accounts on-chain
3. Owner creates a backup with 2-of-3 threshold and uploads it to the contract
4. Each guardian decrypts their share locally and prepares upload requests

**Trigger:**
1. Create 3 threads, each representing a different guardian
2. Each thread simultaneously sends an HTTP POST request to `/reconstruction/upload-share` for the same `(account_id, backup_id)` with their respective shares
3. All requests should arrive within a narrow time window (e.g., within 100ms of each other) to maximize the chance of concurrent processing

**Observation:**
1. After all requests complete successfully (all return 200 status)
2. Query `/reconstruction/get-shares` to retrieve all stored shares
3. Expected: 3 shares should be stored (one from each guardian)
4. Actual (with race condition): Fewer than 3 shares are stored due to overwrites
5. If only 1 share is stored, backup reconstruction will fail as it requires threshold=2
6. The test should assert that the number of retrieved shares equals the number of uploaded shares, and this assertion will fail on vulnerable code

This PoC demonstrates that legitimate concurrent guardian share uploads can result in permanent data loss, preventing backup reconstruction and violating the core recovery invariant of the protocol.

### Citations

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L33-73)
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
```

**File:** README.md (L138-138)
```markdown
- Only the owner of an email should be able to request the recovery of an account.
```

**File:** README.md (L140-140)
```markdown
- Recovery of a backup only occurs when more than the specified threshold of Guardians has approved the request.
```
