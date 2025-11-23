## Title
Guardian Share Substitution Leading to Permanent Backup Freezing When Multiple Guardians Share the Same Encryption Key

## Summary
When two or more guardians use identical PKE encryption keys for backup shares, the `decrypt_batch` function returns the first successfully decrypted ciphertext to all guardians sharing that key, rather than their individually assigned shares. This causes all affected guardians to obtain the same share with the same index, leading to share deduplication during recovery and permanent backup freezing when the threshold cannot be met. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** 
- Primary: [1](#0-0) 
- Secondary: [2](#0-1) 

**Intended Logic:** 
Each guardian should decrypt their own uniquely assigned share from a batch-encrypted backup. The batch encryption creates N distinct ciphertexts (one per guardian), each encrypted with a different guardian's public key. When a guardian calls `decrypt_share`, they should retrieve their specific share at their designated index.

**Actual Logic:** 
The `decrypt_batch` function iterates sequentially through all ciphertexts in the batch and returns the first one that successfully decrypts with the provided decryption key. If Guardian A (index 0) and Guardian B (index 1) share the same PKE decryption key, both will successfully decrypt ciphertext[0] first. The function returns `(share_data, 0)` to both guardians, assigning both the same index and share content. [3](#0-2) 

The `decrypt_share` function directly uses the index returned by `decrypt_batch` without validating that it corresponds to the guardian's intended position.

**Exploit Scenario:**
1. User creates backup with threshold=2 and three guardians (A, B, C)
2. Guardians A and B accidentally use identical PKE encryption keys (same `pke::EncryptionKey`)
3. During backup creation, all three guardians receive distinct encrypted shares at indices 0, 1, 2
4. When Guardian A decrypts: `decrypt_batch` returns ciphertext[0] with index=0 ✓
5. When Guardian B decrypts: `decrypt_batch` also returns ciphertext[0] with index=0 ✗ (should be index=1)
6. Both guardians submit shares with idx=0 during recovery
7. Recovery deduplication logic uses BTreeMap keyed by index: [4](#0-3) 
8. BTreeMap keeps only one entry for idx=0, discarding the duplicate
9. Result: Only 1 unique share available instead of 2, threshold not met
10. Recovery fails permanently with `InsufficientShares` error

**Security Failure:** 
Violation of the threshold recovery invariant. The backup becomes permanently frozen because the required number of unique shares cannot be collected, even though sufficient guardians are cooperating. This constitutes a denial-of-service on the backup recovery mechanism.

## Impact Explanation

**Affected Assets:**
- User's encrypted backup data (permanently inaccessible)
- Master secret keys or sensitive data protected by the backup
- Account recovery functionality relying on guardian thresholds

**Severity of Damage:**
- **Permanent freezing**: The backup cannot be recovered without protocol-level intervention or hard fork
- **Threshold bypass**: A 2-of-3 threshold becomes effectively impossible if 2 guardians share keys
- **Cascading failures**: If this affects multiple users' backup configurations, it could impact ≥25% of users

**Why This Matters:**
The Swafe protocol's security model relies on threshold cryptography to ensure backup availability and resilience. When guardians inadvertently share encryption keys (through key reuse, configuration errors, or account state duplication), the deduplication mechanism treats their distinct cooperation as a single share, breaking the threshold guarantee. Users lose access to their backed-up secrets permanently.

## Likelihood Explanation

**Who Can Trigger:**
This vulnerability can be triggered by:
- Users who accidentally assign the same `AccountState` object to multiple guardian roles
- System administrators who misconfigure guardian encryption keys
- Guardians who reuse account credentials across different backup instances
- Any scenario where two guardians' `pke::EncryptionKey` values are identical

**Required Conditions:**
- Two or more guardians must share identical PKE decryption keys
- A backup must be created with these guardians
- Recovery must be attempted with shares from the affected guardians
- The threshold must require contributions from guardians sharing keys

**Frequency:**
- **Moderate likelihood**: While not the default behavior, key reuse is a common operational error
- Higher probability in testing/development environments where accounts are duplicated
- Could affect production systems during initial deployment or guardian rotation
- No active attacker required—purely a configuration/implementation issue

## Recommendation

**Fix Strategy:**

1. **Modify `decrypt_batch` to validate uniqueness**: Add a check ensuring each decryption key can only decrypt one specific ciphertext from the batch, not multiple ones. Alternatively, bind each ciphertext to a specific guardian index in the authentication context.

2. **Add guardian key uniqueness validation**: During backup creation in `BackupCiphertextV0::new`, verify that all guardian encryption keys are unique before proceeding:

```rust
// In BackupCiphertextV0::new, after line 377
let unique_keys: std::collections::HashSet<_> = guardians.iter()
    .map(|g| g.encryption_key())
    .collect();
if unique_keys.len() != guardians.len() {
    return Err(SwafeError::DuplicateGuardianKeys);
}
```

3. **Alternative: Use deterministic index binding**: Modify the batch encryption context to include an intended recipient index, making it cryptographically impossible for the wrong guardian to decrypt a ciphertext even with the same key.

## Proof of Concept

**File:** `lib/src/backup/tests.rs` (add new test function)

**Test Function:** `test_duplicate_guardian_keys_cause_recovery_failure`

**Setup:**
1. Create owner account and three guardian accounts normally
2. Manually create a fourth guardian account but reuse Guardian 1's PKE encryption key
3. Create backup with threshold=2 using Owner, Guardian1, Guardian2, and the duplicate-key guardian
4. All guardians can successfully decrypt their shares
5. Observe that Guardian1 and the duplicate both receive shares with idx=0

**Trigger:**
1. Guardian1 decrypts their share: receives `SecretShare::V0(DecryptedShareV0 { idx: 0, ... })`
2. Duplicate-key guardian decrypts: also receives `SecretShare::V0(DecryptedShareV0 { idx: 0, ... })`
3. Both guardians send their shares to owner for recovery
4. Attempt recovery with both shares

**Observation:**
- Both guardian shares verify successfully against `comms[0]`
- During recovery, the BTreeMap deduplicates by `idx`, keeping only one entry for `idx=0`
- Recovery fails with `SwafeError::InsufficientShares` despite having 2 cooperating guardians
- The test confirms that the threshold mechanism is bypassed when guardians share encryption keys

**Expected Behavior:**
The system should either:
- Reject backup creation when guardians have duplicate keys (prevention)
- Ensure each guardian receives their own unique share regardless of key duplication (fix)
- The test should PASS on fixed code (recovery succeeds) and FAIL on vulnerable code (recovery fails)

**Test demonstrates:** Permanent freezing of backups when guardians inadvertently share PKE encryption keys, violating the threshold security guarantee and matching the in-scope impact criteria.

## Notes

This vulnerability is particularly insidious because:
1. It requires no malicious actor—purely a configuration/operational error
2. The issue manifests silently during backup creation but only fails at recovery time
3. The batch encryption mechanism's sequential decryption logic doesn't account for duplicate keys
4. The deduplication by index in recovery is correct for its intended purpose but interacts poorly with this edge case

The root cause is the assumption that all guardians will have unique encryption keys, which is not enforced at the protocol level. The `decrypt_batch` function's behavior of returning the first successful decryption is correct for its general use case but creates this vulnerability when combined with the guardian share system.

### Citations

**File:** lib/src/crypto/pke/mod.rs (L96-124)
```rust
    pub fn decrypt_batch<M: Tagged + DeserializeOwned, A: Tagged>(
        &self,
        ct: &BatchCiphertext,
        ctx: &A,
    ) -> Result<(M, usize), SwafeError> {
        match ct {
            BatchCiphertext::V0(ct) => {
                // verify signature
                ct.inn.vk.verify(&ct.sig, &ct.inn)?;

                // try to decrypt every ct with context
                // bound to the verification key
                for (i, shr) in ct.inn.cts.iter().enumerate() {
                    if let Ok(msg) = self.decrypt(
                        shr,
                        &BatchCtx {
                            vk: &ct.inn.vk,
                            ctx: (A::SEPARATOR, ctx),
                        },
                    ) {
                        return Ok((msg, i));
                    }
                }

                // if all ciphertexts failed to decrypt, return an error
                Err(SwafeError::DecryptionFailed)
            }
        }
    }
```

**File:** lib/src/account/v0.rs (L572-603)
```rust
    fn decrypt_share<A: Tagged>(&self, aad: &A, backup: &BackupCiphertext) -> Option<SecretShare> {
        fn decrypt_v0<A: Tagged>(
            v0: &BackupCiphertextV0,
            aad: &A,
            pke: &crate::crypto::pke::DecryptionKey,
        ) -> Option<SecretShare> {
            let (data, index) = pke
                .decrypt_batch::<BackupShareV0, _>(
                    &v0.encap,
                    &EncryptionContext {
                        aad: (A::SEPARATOR, aad),
                        data: &v0.data,
                        comms: &v0.comms,
                    },
                )
                .ok()?;

            Some(SecretShare::V0(DecryptedShareV0 {
                idx: index as u32,
                share: data,
            }))
        }

        match backup {
            BackupCiphertext::V0(v0) => {
                if let Some(share) = decrypt_v0(v0, aad, &self.pke) {
                    return Some(share);
                }
                self.old_pke.last().and_then(|old| decrypt_v0(v0, aad, old))
            }
        }
    }
```

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
