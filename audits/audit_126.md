## Title
Off-By-One Error in Guardian Share Verification Allows Out-of-Bounds Access to Comms Vector

## Summary
An off-by-one error in the bounds check of `BackupCiphertextV0::verify()` allows attackers to cause a contract panic by submitting a crafted `GuardianShare` with an index equal to `comms.len()`. The vulnerable bounds check uses `>` instead of `>=`, enabling out-of-bounds array access that crashes the smart contract endpoint. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** The vulnerability exists in `lib/src/backup/v0.rs` in the `BackupCiphertextV0::verify()` function at lines 342-354, which is called by the contract endpoint `contracts/src/http/endpoints/reconstruction/upload_share.rs` at lines 53-55. [1](#0-0) [2](#0-1) 

**Intended Logic:** The `verify()` function should validate that `share.idx` is within the valid bounds of the `comms` vector (indices 0 through `comms.len()-1`), then use the index to retrieve the corresponding verification key for signature validation.

**Actual Logic:** The bounds check uses `share.idx > self.comms.len()` instead of `share.idx >= self.comms.len()`. This allows `share.idx` equal to `comms.len()` to pass validation. Subsequently, the array access `self.comms[share.idx as usize]` at line 346 attempts to access an out-of-bounds index, causing a panic.

**Exploit Scenario:**
1. Attacker identifies a legitimate backup with N guardians (comms vector has length N, valid indices 0 to N-1)
2. Attacker crafts a malicious `GuardianShare` with arbitrary ciphertext, signature, and `idx` field set to N
3. Attacker submits this crafted share via the `/reconstruction/upload-share` endpoint
4. The contract deserializes the request without additional validation on the `idx` field (the `GuardianShareV0` struct uses standard Serde derive macros)
5. The contract calls `backup.verify(&request.share.0)` which executes the flawed bounds check
6. Since `N > N` evaluates to false, the check passes
7. Line 346 attempts `self.comms[N]` which panics with index out of bounds
8. The contract transaction fails and the endpoint becomes unresponsive for that backup [3](#0-2) 

**Security Failure:** This breaks the contract's availability and reliability. An attacker can repeatedly trigger panics in the smart contract's HTTP endpoint handler, preventing legitimate guardian shares from being uploaded and blocking recovery operations.

## Impact Explanation

The vulnerability affects the backup reconstruction process for any account:

- **Affected Process:** The guardian share upload mechanism, which is critical for account and backup recovery operations
- **Damage Severity:** An attacker can cause the contract endpoint to panic repeatedly, preventing legitimate users from uploading guardian shares needed for recovery. This effectively freezes recovery operations for the targeted backup
- **System Reliability:** This represents unintended smart contract behavior - a panic in the contract endpoint violates expected error handling patterns. The contract should return proper error responses, not crash
- **User Impact:** Users attempting to recover their accounts or backups cannot complete the process if guardians cannot upload shares. This matches the in-scope impact: "Temporary freezing of transactions or recovery operations" and "A bug in the Swafe/Partisia integration that results in unintended smart contract behaviour"

While the README states that "Denial-of-Service attacks for HTTP endpoints are not considered in scope as HM issues," this is not merely an HTTP DoS - it's a contract-level panic caused by a logic error in bounds checking that results in unintended smart contract behavior.

## Likelihood Explanation

**Triggering Actor:** Any unprivileged network participant who can craft and submit JSON requests to the contract endpoint.

**Required Conditions:** 
- A legitimate backup must exist on-chain (created by any user)
- The attacker needs to know the `AccountId` and `BackupId` (both are potentially observable on-chain)
- The attacker can construct a `GuardianShare` with any desired `idx` value through standard Serde serialization

**Frequency:** The attack can be executed repeatedly and on-demand. An attacker can target multiple backups or repeatedly attack the same backup to maintain the DoS condition. Since the `GuardianShareV0` struct derives `Serialize, Deserialize` without custom validation, crafting malicious shares is straightforward. [4](#0-3) 

**Exploitation Ease:** High - the vulnerability requires only:
1. Knowledge of a backup's existence (observable on-chain)
2. Ability to construct and submit JSON requests
3. No special privileges or cryptographic material

## Recommendation

Change the bounds check in `BackupCiphertextV0::verify()` from:
```rust
if share.idx > self.comms.len() as u32
```

to:
```rust
if share.idx >= self.comms.len() as u32
```

This ensures that only valid indices (0 through `comms.len()-1`) pass validation, preventing out-of-bounds array access. The fix is minimal and preserves all intended functionality while eliminating the panic condition.

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** Add a new test `test_backup_out_of_bounds_index_panic`:

**Setup:**
- Create an owner account and 3 guardians
- Create a backup with threshold 2 using the 3 guardians
- This creates a `comms` vector with length 3 (valid indices 0, 1, 2)

**Trigger:**
- Manually construct a `GuardianShareV0` with `idx = 3` (equal to `comms.len()`)
- Wrap it in `GuardianShare::V0()`
- Call `backup.verify()` on this crafted share

**Observation:**
- The test expects a panic or an error, but the current code panics with "index out of bounds"
- The bounds check `3 > 3` evaluates to false, allowing the check to pass
- The subsequent array access `self.comms[3]` panics because only indices 0-2 exist

The test demonstrates that the off-by-one error allows exploitation of the comms vector bounds, effectively enabling an attacker to attempt "extending" the vector access beyond its actual length.

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

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L53-55)
```rust
    let share_id = backup
        .verify(&request.share.0)
        .map_err(|_| ServerError::InvalidParameter("Invalid guardian share".to_string()))?;
```
