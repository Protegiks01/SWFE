## Audit Report

## Title
Race Condition in MskRecord Upload Causes Permanent Account Lockout Due to Inconsistent Cross-Node State

## Summary
The MskRecord upload endpoint allows unconditional overwrites without checking for consistency with existing records or coordinating across nodes. When users upload MskRecord updates, network failures or partial update scenarios can cause different nodes to store MskRecords with different cryptographic material (different `fixed` fields). During reconstruction, the majority vote mechanism filters out minority records, potentially leaving fewer than threshold shares available, permanently locking users out of their accounts.

## Impact
**High**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The system should ensure that all nodes storing MskRecords for a given email maintain consistent cryptographic material to enable reliable threshold-based reconstruction during account recovery.

**Actual Logic:** 
The upload endpoint unconditionally stores incoming MskRecords without checking if a record already exists or validating consistency with existing records. The storage operation directly overwrites any previous value: [2](#0-1) 

When multiple MskRecords with different cryptographic commitments exist across nodes, the reconstruction process uses majority voting to determine which "version" is valid: [3](#0-2) 

Records not matching the majority are filtered out, and if the remaining count falls below the threshold, reconstruction fails permanently.

**Exploit Scenario:**
1. User sets up account with threshold=3 requiring shares from 3 nodes
2. User uploads MskRecord version A to all 3 nodes successfully
3. User later updates account (e.g., rotating keys) and creates MskRecord version B with new random values
4. User begins uploading version B to all nodes, but network issues cause partial success:
   - Node 1: Upload succeeds, version B stored (overwrites A)
   - Node 2: Upload succeeds, version B stored (overwrites A)
   - Node 3: Upload fails due to network timeout/partition, version A remains
5. During recovery, user retrieves records from all 3 nodes:
   - Nodes 1 & 2 return version B (fixed_B)
   - Node 3 returns version A (fixed_A)
6. Majority vote selects fixed_B (2 out of 3 votes)
7. Node 3's record is filtered out as it doesn't match majority
8. Only 2 shares remain, but threshold requires 3
9. Reconstruction fails with `NotEnoughSharesForReconstruction` error [4](#0-3) 

**Security Failure:** 
The system violates the invariant that legitimate account owners should always be able to recover their accounts given the correct threshold of guardian approvals or email certificates. The race condition between concurrent or sequential upload operations creates inconsistent cross-node state that makes account recovery impossible.

## Impact Explanation

**Affected Assets:**
- User's Master Secret Key (MSK) and associated account secrets
- Recovery Initiation Key (RIK) encrypted data stored in MskRecords
- User's ability to access their Swafe-protected accounts

**Severity:**
- Users become **permanently locked out** of their accounts with no recovery path
- The cryptographic material remains stored but becomes unusable due to insufficient consistent shares
- This requires manual intervention or hard fork to resolve, as the system has no built-in mechanism to detect or repair inconsistent state
- Multiple users can be affected simultaneously if network issues occur during system-wide updates or maintenance windows

**System-Wide Implications:**
This matters critically because Swafe is a social recovery system where users depend on being able to reconstruct their secrets. Permanent account lockout defeats the entire purpose of the protocol and could result in complete loss of access to user assets protected by Swafe.

## Likelihood Explanation

**Who Can Trigger:**
Any legitimate user performing normal account operations (initial setup, key rotation, guardian changes) can accidentally trigger this condition. No attacker privileges required.

**Required Conditions:**
- Network instability or partial node availability during MskRecord uploads
- User software crashes/restarts between upload attempts generating new random values
- Concurrent update attempts from multiple user devices
- Load balancing or retry logic that doesn't maintain consistency

**Frequency:**
- **High likelihood** in production environments with:
  - Geographically distributed nodes (network latency/partitions)
  - Mobile clients with unstable connections
  - High user concurrency during peak usage
  - Automated key rotation policies

The reconstruction logic's comment explicitly acknowledges similar concerns for guardian shares: [5](#0-4) 

However, guardian shares are verified against a fixed `BackupCiphertext` ensuring consistency, whereas MskRecords have no such protection.

## Recommendation

**Immediate Fix:**
Implement consistency checks in the upload_msk handler:

1. **Add version/nonce tracking:** Include a monotonically increasing version number in MskRecordFixed that nodes can check before accepting overwrites
2. **Check before overwrite:** Load existing MskRecord and reject uploads that would create inconsistency:
   - If a record exists with different `fixed` fields, reject the new upload
   - Require explicit "force overwrite" parameter for legitimate updates
3. **Atomic multi-node upload:** Implement two-phase commit or similar coordination:
   - Phase 1: All nodes validate and prepare the new MskRecord
   - Phase 2: Only commit if all nodes confirm success
   - Rollback if any node fails

**Alternative Mitigation:**
Add consistency verification during retrieval:
- When `get_secret_share` is called, verify that retrieved records across multiple nodes have consistent `fixed` fields
- Reject reconstruction attempts if inconsistency is detected
- Return detailed error indicating which nodes have mismatched state for user debugging

## Proof of Concept

**Test File:** `lib/src/association/v0.rs` (add to existing tests module)

**Test Function:** `test_race_condition_inconsistent_mskrecord_lockout`

**Setup:**
```
1. Create Association with threshold=3
2. Generate MskRecords for 3 different nodes from same EncapsulatedMsk (version A)
3. Simulate storing version A on all nodes
4. Generate NEW EncapsulatedMsk with fresh randomness (version B)
5. Generate MskRecords for version B
6. Simulate partial update: nodes 1 & 2 get version B, node 3 retains version A
```

**Trigger:**
```
7. Call Association::reconstruct_rik_data() with the 3 mismatched MskRecords:
   - (node1, MskRecord_B1)
   - (node2, MskRecord_B2)  
   - (node3, MskRecord_A3)
8. Provide the RIK from version A (user's original RIK)
```

**Expected Observation:**
The test should demonstrate that reconstruction fails with `SwafeError::NotEnoughSharesForReconstruction` even though the user has valid shares from all 3 nodes and a valid RIK. The majority vote eliminates node 3's record, leaving only 2 shares when 3 are required. This confirms permanent account lockout from an accidental race condition during legitimate updates.

### Citations

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L60-64)
```rust
    MskRecordCollection::store(
        &mut ctx,
        email_tag,
        request.association.0.verify(user_pk, &node_id)?,
    );
```

**File:** contracts/src/storage.rs (L21-27)
```rust
    fn store(ctx: &mut OffChainContext, key: Self::Key, value: Self::Value) {
        let mut storage: OffChainStorage<Vec<u8>, Vec<u8>> =
            ctx.storage(Self::COLLECTION_NAME.as_bytes());
        let key = encode::serialize(&key).unwrap();
        let value = encode::serialize(&value).unwrap();
        storage.insert(key, value);
    }
```

**File:** lib/src/association/v0.rs (L467-491)
```rust
        // Do a threshold vote on the fixed fields
        let mut votes = HashMap::new();
        for (_, record) in &v0_records {
            *votes.entry(record.fixed.clone()).or_insert(0) += 1;
        }

        let majority_threshold = v0_records.len().div_ceil(2);
        let majority_fixed = votes
            .into_iter()
            .find(|(_, count)| *count >= majority_threshold)
            .map(|(fixed, _)| fixed)
            .ok_or_else(|| {
                SwafeError::InvalidInput(
                    "No majority consensus on fixed fields among MSK records".to_string(),
                )
            })?;

        let v0_records: Vec<_> = v0_records
            .into_iter()
            .filter(|(_, record)| record.fixed == majority_fixed)
            .collect();

        if v0_records.len() < majority_fixed.threshold() {
            return Err(SwafeError::NotEnoughSharesForReconstruction);
        }
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L58-63)
```rust
    // usually, the share will not already exist in this map:
    // we allow overwriting in case of a buggy client library and to
    // simplify a client which fails during the upload process: it can simply retry all uploads.
    //
    // Potentially different multiple versions of the same share are all equivalent.
    // Hence no replay protection is required here.
```
