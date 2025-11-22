## Title
Off-By-One Error in Guardian Share Index Validation Causes Panic During Recovery

## Summary
The `verify()` function in `BackupCiphertextV0` contains an off-by-one error in its index bounds check, allowing guardian shares with `idx == comms.len()` to pass validation. This causes a panic due to out-of-bounds array access during the recovery process, enabling attackers to crash recovery operations and prevent legitimate account recovery or backup reconstruction. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** The vulnerability exists in the `verify()` method of `BackupCiphertextV0` at line 343, which is invoked during the `recover()` process. [1](#0-0) 

**Intended Logic:** The function should validate that the guardian share's index is within valid bounds (0 to `comms.len() - 1`) before accessing the commitments array. Only shares with valid indices that correspond to actual guardian positions should be accepted.

**Actual Logic:** The bounds check uses `share.idx > self.comms.len() as u32`, which incorrectly allows `share.idx == self.comms.len()` to pass. When this occurs, line 346 attempts to access `self.comms[share.idx as usize]`, which is `self.comms[comms.len()]` - an out-of-bounds access that causes a panic.

**Exploit Scenario:**
1. An attacker observes a legitimate backup ciphertext with `N` guardians (hence `N` commitments)
2. The attacker crafts a malicious `GuardianShare` with `idx = N` (equal to `comms.len()`)
3. The attacker submits this share via the `/reconstruction/upload-share` endpoint or includes it in recovery operations
4. When `verify()` is called (either directly via the endpoint or indirectly through `recover()`), the invalid index passes the bounds check
5. The subsequent array access at line 346 panics, crashing the recovery operation [2](#0-1) [3](#0-2) 

**Security Failure:** This breaks the availability guarantee of the recovery system. An unprivileged attacker can repeatedly crash recovery attempts, effectively preventing legitimate users from recovering their accounts or backups, constituting a denial-of-service attack on critical recovery operations.

## Impact Explanation

This vulnerability affects the core recovery mechanism of the Swafe protocol:

- **Affected Process:** Account recovery and backup reconstruction operations are completely disrupted when the malicious share is processed
- **Severity of Damage:** Legitimate users are locked out from recovering their master secret keys and backed-up data. Since recovery is a critical safety mechanism, users who lose access to their primary credentials cannot regain access to their accounts
- **System-Wide Impact:** An attacker can target multiple users simultaneously by submitting malicious shares for their recovery requests, potentially preventing ≥25% of users from completing recovery operations

This matters because:
1. Recovery is the last line of defense when users lose their primary access keys
2. Without functioning recovery, users suffer permanent loss of access to their accounts and secrets
3. The attack requires no special privileges and can be executed by any network participant
4. The panic crashes the processing endpoint/contract, affecting all recovery operations being processed

## Likelihood Explanation

**Who can trigger it:** Any unprivileged network participant who can submit guardian shares (either via the REST API endpoint or by including shares in on-chain transactions).

**Required conditions:** 
- Normal operation - no special circumstances needed
- Attacker only needs to know the backup ID and account ID (which are publicly visible)
- No authentication or guardian privileges required to submit the malicious share

**Frequency:** This can be exploited continuously:
- Attacker can submit malicious shares as fast as the network accepts requests
- Each malicious share causes a panic, requiring recovery operation restart
- Can target multiple users' recovery attempts simultaneously
- No rate limiting or validation prevents repeated exploitation

The attack is highly practical and can be executed immediately upon deployment.

## Recommendation

Change the bounds check in the `verify()` function from greater-than to greater-than-or-equal:

```rust
if share.idx >= self.comms.len() as u32 {
    return Err(SwafeError::InvalidShare);
}
```

This ensures that only valid indices in the range `[0, comms.len() - 1]` are accepted, preventing out-of-bounds array access.

## Proof of Concept

**Test File:** `lib/src/backup/tests.rs`

**Test Function:** Add a new test called `test_verify_out_of_bounds_index`

**Setup:**
1. Create an owner account and three guardian accounts
2. Generate a backup ciphertext with threshold 2 and the three guardians
3. Have one guardian decrypt their legitimate share
4. Extract the encrypted share structure

**Trigger:**
1. Create a malicious `GuardianShareV0` by copying the legitimate share but setting `idx = comms.len()` (which equals 3 for three guardians)
2. Wrap it in `GuardianShare::V0`
3. Call `backup.verify()` on the malicious share

**Observation:**
The test will panic with an index out-of-bounds error when trying to access `self.comms[3]` where only indices 0-2 exist. This confirms the vulnerability - the bounds check fails to prevent the invalid index, causing a panic instead of returning an error.

The test demonstrates that an attacker can crash the verification process by submitting a share with an index equal to the number of commitments, which should be rejected but instead causes a panic.

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
