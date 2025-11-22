## Title
Guardian Key Rotation Breaks Backup Recovery Due to Incomplete Old Key Fallback

## Summary
The `decrypt_share()` method in `lib/src/account/v0.rs` only attempts decryption with the current PKE key and the most recent old key (`old_pke.last()`), but not all historical keys stored in the `old_pke` vector. When a guardian rotates their PKE key multiple times after a backup is created, they cannot decrypt their share from that backup, permanently breaking the threshold recovery mechanism.

## Impact
**High**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
When guardians decrypt their shares from a backup ciphertext, the system should try all available decryption keys to ensure backward compatibility with backups created before key rotations. The `old_pke` vector stores historical PKE keys specifically to enable decryption of data encrypted with previous keys.

**Actual Logic:** 
The `decrypt_share()` method only attempts decryption with two keys:
1. The current PKE key (`self.pke`)
2. The most recent old key (`self.old_pke.last()`)

If a guardian has rotated their key multiple times, older keys beyond the most recent one are never tried. For example, with `old_pke = [key_1, key_2, key_3]` and `current = key_4`, a backup encrypted with `key_1` will fail to decrypt because the method only tries `key_4` and `key_3`.

**Exploit Scenario:**
1. Alice creates a backup with guardians Bob and Charlie using a 2-of-2 threshold
2. Bob's backup share is encrypted with his current PKE key (`bob_key_1`)
3. Bob rotates his PKE key twice: `bob_key_1 → bob_key_2 → bob_key_3`
4. Bob's state now has: `old_pke = [bob_key_1, bob_key_2]`, `current = bob_key_3`
5. Alice initiates backup recovery and requests guardian shares
6. Bob calls `decrypt_share_backupy()` to decrypt his share
7. The method tries `bob_key_3` (fails), then `bob_key_2` via `old_pke.last()` (fails)
8. `bob_key_1` is in the `old_pke` vector but is never tried
9. Bob cannot provide his share, threshold cannot be met, backup recovery fails permanently

**Security Failure:** 
This violates the backup recoverability invariant. Backups become permanently unrecoverable not due to loss of keys or threshold violations, but due to a logic error in key fallback. This affects both regular backup recovery [2](#0-1)  and account recovery flows [3](#0-2) .

## Impact Explanation

**Assets Affected:**
- All backup ciphertexts created before a guardian's second key rotation become permanently unrecoverable
- Account recovery operations that depend on guardian participation fail permanently
- Master secret keys and sensitive data stored in affected backups are frozen

**Severity:**
- This is a **permanent freezing of secrets** - one of the explicitly in-scope high-severity impacts
- Unlike temporary DoS, the data cannot be recovered without external intervention or hard fork
- The issue compounds over time as guardians naturally rotate keys for security best practices
- Users lose access to critical backup data and cannot complete account recovery operations

**System Reliability:**
The core value proposition of the Swafe protocol - social recovery through guardians - is fundamentally broken. Users who diligently rotate their keys for security actually make the system less reliable.

## Likelihood Explanation

**Triggering Conditions:**
- Any guardian who rotates their PKE key 2+ times after backup creation
- No malicious behavior required - this occurs during normal operation
- Key rotation is encouraged for security, making this highly likely in production

**Frequency:**
- Occurs whenever: (guardian key rotations > 1) AND (backup age > rotation period)
- High probability in long-lived deployments where security-conscious guardians regularly rotate keys
- Impact accumulates: older backups become increasingly likely to be affected

**Exploitation:**
- Not an "attack" - this is an operational failure triggered by legitimate user actions
- Users discover the issue only when attempting backup recovery, at which point it's too late
- No warning or error prevention mechanism exists

## Recommendation

Modify the `decrypt_share()` method to iterate through all keys in `old_pke`, not just the most recent one:

```rust
fn decrypt_share<A: Tagged>(&self, aad: &A, backup: &BackupCiphertext) -> Option<SecretShare> {
    match backup {
        BackupCiphertext::V0(v0) => {
            // Try current key first
            if let Some(share) = decrypt_v0(v0, aad, &self.pke) {
                return Some(share);
            }
            
            // Try all old keys in reverse order (most recent first)
            for old_key in self.old_pke.iter().rev() {
                if let Some(share) = decrypt_v0(v0, aad, old_key) {
                    return Some(share);
                }
            }
            
            None
        }
    }
}
```

This ensures backward compatibility with all historical backups regardless of how many times a guardian has rotated their keys.

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** `test_guardian_multiple_key_rotations_breaks_recovery`

```rust
#[test]
fn test_guardian_multiple_key_rotations_breaks_recovery() {
    let mut rng = OsRng;

    // Setup: Create owner and guardian
    let owner = AccountSecrets::gen(&mut rng).unwrap();
    let mut guardian = AccountSecrets::gen(&mut rng).unwrap();
    let guardian_state_1 = guardian.state(&mut rng).unwrap();

    // Create backup with guardian's initial key
    let test_data = TestData {
        value: "critical backup data".to_string(),
    };
    let backup = owner
        .backup(
            &mut rng,
            &test_data,
            Metadata::new("Critical Backup".to_string(), "Important data".to_string()),
            &[guardian_state_1],
            1,
        )
        .unwrap();

    // Trigger: Guardian rotates key twice
    guardian.new_pke(&mut rng);  // First rotation: key_1 -> old_pke, current = key_2
    guardian.new_pke(&mut rng);  // Second rotation: old_pke = [key_1, key_2], current = key_3

    // Observation: Guardian cannot decrypt their share anymore
    let share_result = guardian.decrypt_share_backupy(*owner.acc(), &backup);
    
    // This assertion FAILS on the vulnerable code - share_result is None
    // because decrypt_share only tries current key (key_3) and old_pke.last() (key_2),
    // but the backup was encrypted with key_1
    assert!(
        share_result.is_some(),
        "Guardian should be able to decrypt share encrypted with old key after multiple rotations"
    );
    
    // Further verification: Even if we could decrypt, recovery should succeed
    if let Some(share) = share_result {
        let owner_st = owner.state(&mut rng).unwrap();
        let gs = share.send(&mut rng, &owner_st).unwrap();
        let recovered: TestData = owner.recover(&backup, &[gs]).unwrap();
        assert_eq!(recovered, test_data);
    }
}
```

**Expected Behavior:** Test should pass - guardian can decrypt their share regardless of key rotations.

**Actual Behavior:** Test fails at the assertion because `decrypt_share_backupy()` returns `None`, confirming the vulnerability. The guardian cannot decrypt the backup share encrypted with `key_1` because `decrypt_share()` only tries `key_3` (current) and `key_2` (`old_pke.last()`), never trying `key_1`.

### Citations

**File:** lib/src/account/v0.rs (L556-562)
```rust
    pub fn decrypt_share_backupy(
        &self,
        acc: AccountId,
        backup: &BackupCiphertext,
    ) -> Option<SecretShare> {
        self.decrypt_share(&AADBackup { acc }, backup)
    }
```

**File:** lib/src/account/v0.rs (L564-570)
```rust
    pub fn decrypt_share_recovery(
        &self,
        acc: AccountId,
        backup: &BackupCiphertext,
    ) -> Option<SecretShare> {
        self.decrypt_share(&AADRecovery { acc }, backup)
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
