## Title
Off-By-One Error in Guardian Share Verification Allows Out-of-Bounds Array Access and Contract Panic

## Summary
The `BackupCiphertextV0::verify()` function contains an off-by-one error in its bounds check at line 343, allowing `share.idx` to equal `self.comms.len()` instead of being strictly less than it. This enables an attacker to trigger a panic by submitting a crafted guardian share with an out-of-bounds index via the `/reconstruction/upload-share` HTTP endpoint, causing unintended smart contract behavior. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** The vulnerability exists in `BackupCiphertextV0::verify()` in `lib/src/backup/v0.rs` at line 343, and is exploitable through the contract's HTTP endpoint at `contracts/src/http/endpoints/reconstruction/upload_share.rs` at lines 53-54. [1](#0-0) [2](#0-1) 

**Intended Logic:** The function should validate that `share.idx` is a valid index into the `self.comms` array before attempting to access it. For an array of length N, valid indices are 0 to N-1.

**Actual Logic:** The bounds check at line 343 uses the wrong comparison operator:
- Current: `if share.idx > self.comms.len() as u32`
- This allows `share.idx == self.comms.len()`, which is out of bounds
- When `share.idx` equals the array length, line 346 attempts to access `self.comms[share.idx as usize]`, causing a Rust panic due to out-of-bounds array access

**Exploit Scenario:**
1. An attacker identifies a backup with N guardians (e.g., 3 guardians with indices 0, 1, 2)
2. The backup has `comms.len() == 3`, so valid indices are only 0, 1, 2
3. The attacker crafts a malicious `GuardianShareV0` structure with:
   - `idx` set to 3 (equal to `comms.len()`)
   - Arbitrary `ct` (PKE ciphertext)
   - Arbitrary `sig` (signature)
4. The attacker serializes this into a `GuardianShare` and sends it to the `/reconstruction/upload-share` endpoint
5. The contract calls `backup.verify(&request.share.0)` which triggers the vulnerability
6. The bounds check at line 343 evaluates `3 > 3` as false, so no error is returned
7. Line 346 attempts to access `self.comms[3]`, causing a panic with an "index out of bounds" error [3](#0-2) 

**Security Failure:** This violates the robustness invariant that the contract should gracefully handle invalid inputs without panicking. The panic causes unintended smart contract behavior, preventing proper error handling and potentially causing service disruption.

## Impact Explanation

**Affected Processes:**
- The guardian share upload mechanism becomes vulnerable to malicious inputs
- The backup recovery process could be disrupted if exploited during the `recover()` function call at line 303
- Contract request handlers crash instead of returning proper error responses [4](#0-3) 

**Severity of Damage:**
- The panic causes the contract's HTTP request handler to fail abruptly
- Repeated exploitation could lead to resource exhaustion on processing nodes
- This qualifies as "A bug in the Swafe/Partisia integration that results in unintended smart contract behaviour" per the in-scope impacts
- While not directly compromising secrets or funds, it disrupts the legitimate operation of the backup/recovery system

**System Reliability Impact:**
The vulnerability undermines the reliability guarantees of the Swafe protocol by allowing unprivileged users to trigger crashes in contract code that should handle all inputs gracefully. This could prevent legitimate users from uploading valid guardian shares during critical recovery operations.

## Likelihood Explanation

**Who Can Trigger:** Any network participant with access to the `/reconstruction/upload-share` HTTP endpoint can exploit this vulnerability. No special privileges or authentication beyond basic API access are required.

**Required Conditions:** 
- The attacker needs to know the `account_id` and `backup_id` of an existing backup
- The attacker must craft a `GuardianShare` with `idx` equal to the number of guardians in the target backup
- This can be done during normal operation without any special timing requirements

**Exploitation Frequency:** 
- The vulnerability can be triggered repeatedly and reliably
- Each malformed request causes a panic
- An attacker could automate this attack to repeatedly disrupt the contract's operation
- The issue will manifest every time a share with `idx == comms.len()` is submitted

## Recommendation

Change the bounds check operator from `>` to `>=` at line 343:

```rust
if share.idx >= self.comms.len() as u32 {
    return Err(SwafeError::InvalidShare);
}
```

This ensures that only indices strictly less than the array length are accepted, preventing out-of-bounds access. The fix is minimal, maintains backward compatibility for valid shares, and eliminates the panic condition.

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** `test_verify_guardian_share_out_of_bounds`

**Setup:**
1. Create an owner account and 3 guardian accounts
2. Generate their public states
3. Create a backup with threshold 2 and the 3 guardians
4. This results in a backup with `comms.len() == 3` (valid indices: 0, 1, 2)

**Trigger:**
1. Create a malicious `GuardianShareV0` with:
   - `idx` set to 3 (equal to `comms.len()`)
   - Valid `ct` obtained from encrypting arbitrary data
   - Valid `sig` signed with an arbitrary signing key
2. Wrap it in `GuardianShare::V0`
3. Call `backup.verify(&malicious_share)`

**Observation:**
- The test should panic with an "index out of bounds" error
- Without the fix, the bounds check at line 343 fails to catch the invalid index
- Line 346 attempts `self.comms[3]` on an array of length 3, causing a panic
- With the recommended fix (`>=` instead of `>`), the function returns `Err(SwafeError::InvalidShare)` gracefully

The panic demonstrates that the vulnerability allows triggering undefined behavior (out-of-bounds array access) through user-controlled input, confirming the exploitability of the bug.

### Citations

**File:** lib/src/backup/v0.rs (L299-313)
```rust
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

**File:** api/src/reconstruction/upload_share.rs (L8-13)
```rust
#[derive(Serialize, Deserialize)]
pub struct Request {
    pub account_id: StrEncoded<AccountId>,
    pub backup_id: StrEncoded<BackupId>,
    pub share: StrEncoded<GuardianShare>,
}
```
