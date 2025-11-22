## Title
Off-by-One Vulnerability in Share Index Bounds Check Enables Processing Node Crash

## Summary
The `BackupCiphertextV0::verify()` function contains an off-by-one error in its bounds checking logic that allows an attacker to trigger an out-of-bounds array access by providing `share.idx` equal to `self.comms.len()`. This causes a panic that crashes Partisia processing nodes when handling guardian share uploads. [1](#0-0) 

## Impact
**Severity: Medium**

## Finding Description

**Location:** The vulnerability exists in `lib/src/backup/v0.rs` at lines 343-346, within the `BackupCiphertextV0::verify()` function.

**Intended Logic:** The `verify()` function should validate that a guardian share's index (`share.idx`) is within valid bounds before accessing the corresponding commitment in the `self.comms` vector. Valid indices for a vector of length `n` are `0` to `n-1` (inclusive).

**Actual Logic:** The bounds check incorrectly uses the greater-than operator (`>`) instead of greater-than-or-equal (`>=`): [2](#0-1) 

This allows `share.idx == self.comms.len()` to pass the check (since `len > len` evaluates to `false`), but then the subsequent array access at line 346 attempts to read `self.comms[share.idx as usize]`, which is out of bounds and causes a Rust panic. [3](#0-2) 

**Exploit Scenario:** 
1. An attacker obtains the backup ciphertext for any account (this is public on-chain data)
2. The attacker determines `n = backup.comms.len()` by inspecting the backup structure
3. The attacker crafts a malicious `GuardianShare` JSON payload with `idx` field set to `n`
4. The attacker sends this to the `/reconstruction/upload-share` endpoint
5. The contract handler deserializes the request and calls `backup.verify(&request.share.0)`
6. The verify function's bounds check passes (`n > n` is false)
7. The array access `self.comms[n]` triggers a Rust panic
8. The panic crashes the processing node or aborts transaction processing [4](#0-3) 

The `GuardianShareV0` structure is deserializable, allowing an attacker to set arbitrary values for the `idx` field: [5](#0-4) 

**Security Failure:** This vulnerability breaks the availability guarantees of the Swafe protocol by enabling denial-of-service attacks against processing nodes. The panic bypasses normal error handling mechanisms and directly crashes the node.

## Impact Explanation

**Assets Affected:** Partisia blockchain processing nodes running the Swafe contract.

**Severity of Damage:** An attacker can repeatedly crash processing nodes by sending malicious share upload requests. Each request with `share.idx = comms.len()` will cause a panic that:
- Terminates the HTTP endpoint handler
- Potentially crashes the entire processing node
- Prevents legitimate guardians from uploading valid shares during recovery operations
- Blocks account recovery flows for users whose backups are being targeted

**System Impact:** This vulnerability allows an unprivileged attacker to disrupt critical recovery operations and potentially take down multiple processing nodes without brute force. According to the in-scope impact criteria, shutting down ≥10% but <30% of processing nodes qualifies as a Medium severity issue, and ≥30% qualifies as High severity.

The comment in the code explicitly acknowledges the valid range should be `[0, |shares|)`, confirming indices must be strictly less than `comms.len()`: [6](#0-5) 

## Likelihood Explanation

**Who Can Trigger:** Any unauthenticated user or attacker with network access to the Partisia blockchain can trigger this vulnerability. No special privileges or credentials are required.

**Conditions Required:** 
- The attacker needs to know a valid account ID and backup ID (both are public on-chain data)
- The attacker must craft a JSON request with the malicious `idx` value
- Normal network operation - no special timing or race conditions needed

**Frequency:** This can be triggered repeatedly and reliably. An attacker can target multiple accounts and send batches of malicious requests to crash multiple nodes simultaneously. The attack requires minimal resources and can be automated.

## Recommendation

**Fix:** Change the bounds check operator from `>` to `>=` to properly reject indices equal to or greater than the vector length:

```rust
if share.idx >= self.comms.len() as u32 {
    return Err(SwafeError::InvalidShare);
}
```

This ensures that only valid indices in the range `[0, comms.len())` are accepted, preventing out-of-bounds access.

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** Add the following test to demonstrate the vulnerability:

```rust
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_verify_with_out_of_bounds_index() {
    let mut rng = OsRng;
    
    // Create accounts
    let owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian = AccountSecrets::gen(&mut rng).unwrap();
    let guardian_state = guardian.state(&mut rng).unwrap();
    
    // Create backup with 1 guardian (so comms.len() = 1, valid idx = 0)
    let test_data = TestData {
        value: "test".to_string(),
    };
    let backup = owner
        .backup(
            &mut rng,
            &test_data,
            Metadata::new("Test".to_string(), "Test".to_string()),
            &[guardian_state.clone()],
            1,
        )
        .unwrap();
    
    // Get the backup ciphertext
    let BackupCiphertext::V0(backup_v0) = &backup;
    
    // Craft a malicious share with idx = comms.len() (which is 1)
    // This should be rejected but passes the bounds check due to off-by-one
    let malicious_share = GuardianShareV0 {
        ct: guardian_state.encryption_key().encrypt(&mut rng, &[0u8; 32], &EmptyInfo),
        idx: backup_v0.comms.len() as u32,  // Off-by-one: equals length, not < length
        sig: sig::SigningKey::gen(&mut rng).sign(&mut rng, &"dummy"),
    };
    
    // This will panic with "index out of bounds" instead of returning InvalidShare error
    let _ = backup_v0.verify(&malicious_share);
}
```

**Setup:** The test creates a simple backup with one guardian, resulting in `comms.len() = 1`.

**Trigger:** A malicious `GuardianShareV0` is crafted with `idx = 1` (equal to `comms.len()`). This passes the buggy bounds check but causes an out-of-bounds access.

**Observation:** The test expects a panic with "index out of bounds" message. On the vulnerable code, the bounds check passes (`1 > 1` is false), then `self.comms[1]` panics. After the fix (changing to `>=`), the function would return `Err(SwafeError::InvalidShare)` instead, and the test would need to be updated to verify proper error handling.

### Citations

**File:** lib/src/backup/v0.rs (L43-48)
```rust
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct GuardianShareV0 {
    ct: pke::Ciphertext,
    idx: u32,
    sig: sig::Signature,
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

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L52-55)
```rust
    // The share id will be in the range [0, |shares|)
    let share_id = backup
        .verify(&request.share.0)
        .map_err(|_| ServerError::InvalidParameter("Invalid guardian share".to_string()))?;
```
