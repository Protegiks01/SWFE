# Audit Report

## Title
Race Condition in Concurrent Guardian Share Uploads Causes Loss of Valid Shares and Recovery Failure

## Summary
The `upload_share` contract handler performs a non-atomic read-modify-write operation on the guardian share storage, allowing concurrent uploads from different guardians to overwrite each other's shares. This causes valid shares to be lost, resulting in backup/account recovery failures even when sufficient guardians have submitted their shares.

## Impact
**Medium**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The handler should accumulate all guardian shares in the `GuardianShareCollection` mapping such that when `threshold` number of guardians upload their shares, the backup can be successfully reconstructed. Each guardian's share should be preserved in storage after a successful upload.

**Actual Logic:** The handler performs a non-atomic read-modify-write sequence:
1. Loads the current `BTreeMap<u32, GuardianShare>` from storage
2. Inserts the new share into the local map copy
3. Stores the entire modified map back to storage

When multiple guardians upload shares concurrently for the same `(account_id, backup_id)` key, both requests load the same initial state, modify their local copies independently, and then both call `store()`. The last `store()` operation overwrites the previous one, causing all shares from earlier concurrent uploads to be lost.

**Exploit Scenario:**
1. Account owner initiates recovery with a backup requiring threshold=2 out of 3 guardians
2. Guardian 0 and Guardian 1 both receive recovery requests and upload their shares nearly simultaneously
3. Both upload requests execute concurrently in the contract:
   - Request A (Guardian 0): loads empty `{}`, inserts share_id 0 → `{0: share_0}`, stores it
   - Request B (Guardian 1): loads empty `{}`, inserts share_id 1 → `{1: share_1}`, stores it (overwrites Request A)
4. Final storage state: `{1: share_1}` (share 0 is lost)
5. Both guardians receive `"success": true` responses and believe their upload succeeded
6. Account owner attempts reconstruction but only 1 share is available
7. Recovery fails with `InsufficientShares` error [2](#0-1) 

**Security Failure:** The system fails to preserve valid guardian shares during concurrent uploads, breaking the invariant that successful share uploads should be persisted. This prevents legitimate backup/account recovery operations from completing.

## Impact Explanation

**Affected Assets:** Master secret keys (MSK), backup secrets, account access during recovery operations.

**Severity of Damage:**
- Users attempting recovery are **temporarily locked out** of their accounts/backups even though sufficient guardians submitted shares
- Guardians receive success responses but their shares are silently lost, making the issue hard to diagnose
- Recovery remains blocked until guardians are manually contacted to re-upload shares
- If guardians don't retain their decrypted shares or become unavailable, the lockout becomes **permanent**, requiring intervention or rendering the account unrecoverable

**System Impact:** This violates the core security invariant that "Recovery of an account only occurs when more than the specified threshold of Guardians has approved the request" - not because guardians didn't approve, but because the system lost their approvals due to race conditions. [3](#0-2) 

## Likelihood Explanation

**Trigger Conditions:**
- Any network participant (account owner requesting recovery) can inadvertently trigger this
- Requires normal concurrent operation - guardians naturally upload shares around the same time after receiving recovery requests
- No malicious intent or special privileges needed

**Frequency:**
- **High likelihood** during normal recovery operations where multiple guardians respond promptly
- The race window is substantial since guardians typically upload shares in parallel for faster recovery
- Off-chain HTTP endpoints [4](#0-3)  are designed to handle concurrent requests, making this scenario common in production

**Realistic Scenario:** In a 2-of-3 or 3-of-5 guardian setup, if 2+ guardians respond within seconds of each other (expected behavior for responsive guardians), the race condition is likely to occur.

## Recommendation

Implement atomic updates to prevent the lost update problem. Options include:

1. **Use compare-and-swap semantics:** Before storing, verify the loaded state hasn't changed. If changed, retry the operation.

2. **Implement per-share_id storage:** Instead of storing the entire `BTreeMap`, store each share individually using keys like `(account_id, backup_id, share_id)`. This makes each guardian's upload independent.

3. **Add transaction sequencing:** Include a version/sequence number in the storage and reject updates with stale versions.

**Recommended fix (Option 2):**
```rust
// In GuardianShareCollection, change to:
type Key = (AccountId, BackupId, u32);  // Include share_id
type Value = GuardianShare;  // Single share, not BTreeMap

// In handler, directly store without loading:
let storage_key = (account_id, backup_id, share_id);
GuardianShareCollection::store(&mut ctx, storage_key, request.share.0);
```

This eliminates the read-modify-write pattern entirely.

## Proof of Concept

**Test File:** `contracts/src/http/endpoints/reconstruction/upload_share.rs` (add integration test) or create new file `contracts/src/http/endpoints/reconstruction/tests.rs`

**Test Function:** `test_concurrent_guardian_share_upload_race_condition`

**Setup:**
1. Initialize a contract with an account containing a backup requiring threshold=2
2. Register 3 guardians (share_ids: 0, 1, 2) for the backup
3. Each guardian decrypts their share from the backup

**Trigger:**
1. Simulate concurrent execution by:
   - Creating two separate `OffChainContext` instances representing two concurrent requests
   - Guardian 0 uploads share_id 0 using context A
   - Guardian 1 uploads share_id 1 using context B
   - Both load empty storage state before either completes storing
   - Both complete their storage operations
2. Query the final storage state using `GuardianShareCollection::load()`

**Observation:**
1. Expected: Storage contains `{0: share_0, 1: share_1}` (both shares preserved)
2. Actual: Storage contains only `{1: share_1}` or `{0: share_0}` (one share lost)
3. Call `BackupCiphertextV0::recover()` [5](#0-4)  with the stored shares
4. Expected: Successful recovery with threshold=2
5. Actual: Fails with `SwafeError::InsufficientShares` because only 1 share is available

**Note:** The actual implementation of this PoC requires understanding the Partisia blockchain's off-chain execution model to properly simulate concurrent contexts. The vulnerability is demonstrated by the non-atomic pattern in the handler code itself [6](#0-5)  combined with the lack of any synchronization primitives in the `Mapping` trait [7](#0-6) .

### Citations

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L64-67)
```rust
    let storage_key = (account_id, backup_id);
    let mut shares = GuardianShareCollection::load(&mut ctx, storage_key).unwrap_or_default();
    shares.insert(share_id, request.share.0);
    GuardianShareCollection::store(&mut ctx, storage_key, shares);
```

**File:** lib/src/backup/v0.rs (L290-296)
```rust
    pub fn recover<M: Tagged + DeserializeOwned, A: Tagged>(
        &self,
        dke: &pke::DecryptionKey,
        sym: &sym::Key,
        aad: &A,
        shares: &[GuardianShare],
    ) -> Result<M, SwafeError> {
```

**File:** lib/src/backup/v0.rs (L322-324)
```rust
        if shares.len() < meta.threshold as usize {
            return Err(SwafeError::InsufficientShares);
        }
```

**File:** README.md (L139-139)
```markdown
- Recovery of an account only occurs when more than the specified threshold of Guardians has approved the request.
```

**File:** contracts/src/http/mod.rs (L158-172)
```rust
/// Main HTTP dispatch function for the contract
#[off_chain_on_http_request]
pub fn http_dispatch(
    ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
) -> HttpResponseData {
    let mut router: HttpRouter = HttpRouter::new();

    // Register all routes
    register_routes(&mut router);

    let result = router.dispatch(ctx, state, request);
    result.unwrap_or_else(|err| err)
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
