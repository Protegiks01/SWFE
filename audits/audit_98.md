## Audit Report

## Title
Permanent Loss of Backup Data After MSK Rotation Due to Missing Old MSK Preservation

## Summary
The `AccountSecrets::recover()` function does not verify that the provided backup belongs to the account via BackupId matching, and critically, it only uses the current Master Secret Key (MSK) for decryption without attempting old MSKs. When users rotate their MSK via `new_msk()`, the old MSK is not preserved in the `old_msk` vector, causing all backups created before the rotation to become permanently unrecoverable.

## Impact
**High** - This vulnerability leads to permanent freezing of backed-up secrets after MSK rotation, which is an in-scope high-impact issue.

## Finding Description

**Location:** 
- Primary issue in `lib/src/backup/v0.rs` in the `AccountSecrets::recover()` function [1](#0-0) 

- MSK rotation function in `lib/src/account/v0.rs` [2](#0-1) 

**Intended Logic:** 
The system should allow users to recover their backed-up data even after rotating cryptographic keys. Similar to how PKE (Public Key Encryption) rotation preserves old keys for backward compatibility, MSK rotation should also preserve old MSKs to allow recovery of backups created with previous MSKs.

**Actual Logic:** 
1. When `new_msk()` is called, it simply replaces the current MSK without saving the old one: [2](#0-1) 

2. In contrast, when PKE is rotated via `new_pke()`, the old key IS properly preserved: [3](#0-2) 

3. The `recover()` function uses only the current MSK to derive the decryption key: [1](#0-0) 

4. The backup encryption key is derived from the MSK at backup creation time: [4](#0-3) 

5. During recovery, the same derivation is performed, but with the current MSK only: [5](#0-4) 

**Exploit Scenario:**
1. User creates `AccountSecrets` with MSK_1
2. User creates backup B1 using `AccountSecrets::backup()` - data is encrypted with a key derived from MSK_1
3. User calls `new_msk()` which rotates to MSK_2 (old MSK_1 is lost)
4. User attempts to recover backup B1 using `AccountSecrets::recover()`
5. Recovery fails because it tries to decrypt with MSK_2, but B1 was encrypted with MSK_1
6. Backup B1 is now permanently unrecoverable

**Security Failure:** 
The system violates the availability invariant - legitimate backups become permanently inaccessible after a routine key rotation operation. The `old_msk` field exists in the `AccountSecrets` structure but is never populated: [6](#0-5) 

## Impact Explanation

**Assets Affected:**
- All backed-up data created before MSK rotation becomes permanently inaccessible
- This includes user secrets, private keys, credentials, or any data users chose to back up

**Severity:**
- **Permanent data loss:** Unlike temporary unavailability, this is irreversible without external backup of the old MSK
- **Silent failure:** Users may not realize backups are broken until they need them after rotation
- **Breaks key rotation best practices:** Security hygiene requires periodic key rotation, but this makes rotation dangerous

**System-wide Impact:**
This directly causes "permanent freezing of secrets" which is explicitly listed as an in-scope high-impact vulnerability. Once a user rotates their MSK:
- All pre-rotation backups become worthless
- Guardian shares collected for those backups cannot reconstruct the data
- No on-chain or off-chain mechanism can recover the lost backups

## Likelihood Explanation

**Who Can Trigger:**
Any account owner who performs the normal, legitimate operation of MSK rotation via `new_msk()`.

**Conditions Required:**
1. User creates one or more backups with initial MSK
2. User calls `new_msk()` for any reason (security hygiene, suspected compromise, regular rotation)
3. User later attempts to recover any backup created before the rotation

**Frequency:**
- **High likelihood:** MSK rotation is a security best practice that users will naturally perform
- **Immediate impact:** All pre-rotation backups are instantly broken
- **Multiple backups affected:** A single rotation breaks all historical backups at once

The vulnerability is not exploited by an attacker but rather is triggered by normal user operations, making it even more dangerous as users unknowingly destroy their own backup recovery capability.

## Recommendation

Modify `new_msk()` to preserve the old MSK before rotation, matching the behavior of `new_pke()`:

```rust
pub fn new_msk<R: Rng + CryptoRng>(&mut self, rng: &mut R) {
    self.dirty = true;
    self.old_msk.push(self.msk.clone()); // Add this line
    self.msk = MasterSecretKey::new(rng.gen())
}
```

Then update `AccountSecrets::recover()` to attempt decryption with old MSKs if the current MSK fails, similar to how `decrypt_share()` handles old PKE keys: [7](#0-6) 

The recovery logic should iterate through `old_msk` when current MSK decryption fails, ensuring backward compatibility with all historical backups.

## Proof of Concept

**Test File:** `lib/src/backup/tests.rs`

**Test Function:** `test_backup_recovery_after_msk_rotation`

**Setup:**
1. Create an account using `AccountSecrets::gen()`
2. Create guardian accounts
3. Create a backup using the initial MSK
4. Guardians decrypt and send their shares

**Trigger:**
1. Call `account.new_msk()` to rotate the MSK
2. Attempt to recover the backup created with the old MSK

**Observation:**
The recovery will fail with a decryption error, even though:
- The backup was legitimately created by the account
- All guardian shares are valid
- The threshold is met
- The only issue is MSK rotation

```rust
#[test]
fn test_backup_recovery_after_msk_rotation() {
    let mut rng = OsRng;
    
    // Create account and guardians
    let mut owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
    
    let guardian1_state = guardian1.state(&mut rng).unwrap();
    let guardian2_state = guardian2.state(&mut rng).unwrap();
    
    // Create test data and backup with original MSK
    let test_data = TestData {
        value: "secret before rotation".to_string(),
    };
    
    let backup = owner.backup(
        &mut rng,
        &test_data,
        Metadata::new("Test".to_string(), "Test backup".to_string()),
        &[guardian1_state.clone(), guardian2_state.clone()],
        2,
    ).unwrap();
    
    // Get guardian shares
    let share1 = guardian1.decrypt_share_backupy(*owner.acc(), &backup).unwrap();
    let share2 = guardian2.decrypt_share_backupy(*owner.acc(), &backup).unwrap();
    let owner_st = owner.state(&mut rng).unwrap();
    let gs1 = share1.send(&mut rng, &owner_st).unwrap();
    let gs2 = share2.send(&mut rng, &owner_st).unwrap();
    
    // Rotate MSK
    owner.new_msk(&mut rng);
    
    // Try to recover - THIS WILL FAIL
    let result: Result<TestData, _> = owner.recover(&backup, &[gs1, gs2]);
    
    // This assertion demonstrates the bug - recovery fails after MSK rotation
    assert!(result.is_err(), "Backup recovery should fail after MSK rotation (demonstrates the vulnerability)");
}
```

This test demonstrates that backup recovery fails after MSK rotation, confirming the permanent freezing of backed-up secrets.

### Citations

**File:** lib/src/backup/v0.rs (L276-286)
```rust
    pub fn recover<M: Tagged + DeserializeOwned>(
        &self,
        backup: &BackupCiphertext,
        shares: &[GuardianShare],
    ) -> Result<M, SwafeError> {
        match backup {
            BackupCiphertext::V0(v0) => {
                v0.recover(self.pke(), self.msk().as_bytes(), &EmptyInfo, shares)
            }
        }
    }
```

**File:** lib/src/backup/v0.rs (L336-337)
```rust
        let key_data: sym::Key = kdfn(&BackupKDFInput { key: sym, secret }, &EmptyInfo);

```

**File:** lib/src/backup/v0.rs (L406-415)
```rust
        // Derive the data encryption key from:
        // - The msk
        // - The threshold shared secret
        let key_data: [u8; sym::SIZE_KEY] = kdfn(
            &BackupKDFInput {
                key: sym_key,
                secret,
            },
            &EmptyInfo,
        );
```

**File:** lib/src/account/v0.rs (L48-61)
```rust
pub struct AccountSecrets {
    dirty: bool,
    acc: AccountId,
    cnt: u32,
    msk: MasterSecretKey,
    backups: Vec<BackupCiphertext>,
    recover: Vec<BackupCiphertext>,
    sig: sig::SigningKey,
    pke: pke::DecryptionKey,
    old_sig: sig::SigningKey,
    old_msk: Vec<MasterSecretKey>,
    old_pke: Vec<pke::DecryptionKey>,
    recovery: AccountSecretsV0Recovery,
}
```

**File:** lib/src/account/v0.rs (L480-483)
```rust
    pub fn new_msk<R: Rng + CryptoRng>(&mut self, rng: &mut R) {
        self.dirty = true;
        self.msk = MasterSecretKey::new(rng.gen())
    }
```

**File:** lib/src/account/v0.rs (L492-496)
```rust
    pub fn new_pke<R: Rng + CryptoRng>(&mut self, rng: &mut R) {
        self.dirty = true;
        self.old_pke.push(self.pke.clone());
        self.pke = pke::DecryptionKey::gen(rng);
    }
```

**File:** lib/src/account/v0.rs (L595-602)
```rust
        match backup {
            BackupCiphertext::V0(v0) => {
                if let Some(share) = decrypt_v0(v0, aad, &self.pke) {
                    return Some(share);
                }
                self.old_pke.last().and_then(|old| decrypt_v0(v0, aad, old))
            }
        }
```
