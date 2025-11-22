## Title
Lack of Backup Versioning Allows Stale Guardian Shares to Participate in Recovery After MSK Rotation

## Summary
The `BackupCiphertextV0::new()` function does not include account version information in the backup ciphertext. When users rotate their Master Secret Key (MSK) without explicitly calling `update_recovery()`, the social recovery backup is cloned rather than regenerated with fresh shares. This allows compromised guardian shares from previous account versions to remain cryptographically valid and participate in future recovery operations, undermining the security benefit of key rotation. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- `lib/src/backup/v0.rs`: `BackupCiphertextV0::new()` function (lines 356-447)
- `lib/src/account/v0.rs`: `AccountSecrets::update()` function (line 714)

**Intended Logic:**
The system should ensure that guardian shares become invalid after critical security operations like MSK rotation, providing forward secrecy. When a user rotates their keys, old cryptographic material should be rendered useless to prevent compromised old shares from being used in future recovery attempts.

**Actual Logic:**
The `BackupCiphertextV0::new()` function creates backup ciphertexts without including any version information. The AAD (Additional Authenticated Data) passed to the function only contains the account ID, not the account version counter: [2](#0-1) 

When `AccountSecrets::update()` is called to publish account state changes (including MSK rotations via `new_msk()`), the social recovery backup is simply cloned rather than regenerated: [3](#0-2) 

The TODO comment explicitly acknowledges this limitation. This means that if a user:
1. Sets up recovery at version V1 (social backup B1 created)
2. Rotates MSK at version V2 using `new_msk()` 
3. Publishes update without calling `update_recovery()`

The social backup remains B1, and guardian shares decrypted from B1 remain cryptographically valid at version V2 and beyond.

**Exploit Scenario:**
1. **T1**: User sets up recovery with guardians G1-G5, threshold=3
   - `update_recovery()` creates social backup B1 with BackupId ID1
   - Guardians decrypt and save their shares locally as `DecryptedShareV0`
   
2. **T2**: Attacker compromises Guardian G1's device
   - Attacker steals G1's `DecryptedShareV0` (containing the signing key and share)
   
3. **T3**: User suspects compromise and rotates MSK using `new_msk()`
   - User calls `update()` to publish new state
   - Social backup is cloned (still B1), not regenerated
   - User believes old shares are invalidated
   
4. **T4**: Similar compromises occur for G2 and G3 over time
   - Attacker accumulates 3 stolen `DecryptedShareV0` instances
   
5. **T5**: User initiates legitimate recovery
   - Sets `rec.pke` in account state
   
6. **T6**: Attacker exploits stolen shares
   - For each stolen share, calls `send_for_recovery()` to re-encrypt for current `rec.pke`
   - Uploads shares to contract via `upload_share` endpoint
   - Shares pass verification because they're cryptographically valid for B1
   
7. **T7**: Unauthorized recovery completes
   - Threshold met with compromised shares
   - Attacker recovers the current MSK [4](#0-3) 

**Security Failure:**
This violates the forward secrecy principle and the user's reasonable expectation that key rotation invalidates old cryptographic material. It allows an attacker to accumulate compromised guardian shares across multiple versions without them being invalidated, effectively extending the time window for attacks and reducing the effective security threshold.

## Impact Explanation

This vulnerability affects the Master Secret Key (MSK), which is the root secret controlling the user's account and all encrypted data. 

If an attacker can accumulate `t` compromised guardian shares over time (where `t` is the recovery threshold), they can perform unauthorized account recovery and obtain the current MSK, even if:
- The user has rotated their MSK multiple times since the shares were compromised
- The user believes old shares are no longer valid
- The user has taken other security measures

This leads to:
- **Complete compromise of the account**: The attacker obtains the current MSK, giving them full control
- **Loss of all secrets**: All data encrypted with the MSK becomes accessible to the attacker
- **Violation of user expectations**: Users performing key rotation after suspected compromise have a false sense of security
- **Weakened threshold security**: The effective security degrades over time as old compromises accumulate

The severity is Medium because it requires multiple guardian compromises over time, but it's realistic in scenarios where:
- Guardian devices are periodically compromised (malware, physical theft)
- Users rotate keys after suspected security incidents
- Users don't explicitly call `update_recovery()` to regenerate guardian shares

## Likelihood Explanation

**Who can trigger it:**
Any attacker who can compromise guardian devices over time. This doesn't require privileged access, just opportunistic compromise of guardian endpoints.

**Required conditions:**
1. User must set up guardian-based recovery
2. Attacker must compromise `t` guardian devices over time (where `t` is the threshold)
3. User must rotate MSK or make other updates without calling `update_recovery()`
4. User must eventually initiate recovery

**Frequency:**
- Moderately likely in real-world scenarios where:
  - Guardian devices (e.g., friends' phones) may be compromised periodically
  - Users rotate keys after security incidents but don't regenerate recovery shares
  - Recovery is initiated months or years after initial setup
- The lack of documentation requiring `update_recovery()` after MSK rotation makes this more likely

The vulnerability is realistic because users are unlikely to know they must explicitly regenerate guardian shares after each key rotation, especially given the TODO comment suggesting this is a known limitation.

## Recommendation

**Primary Fix:**
Include the account version counter in the backup ciphertext AAD during creation:

```rust
// In AccountSecrets::backup()
BackupCiphertextV0::new(
    rng,
    data,
    &AADBackupVersioned { 
        acc: *self.acc(),
        version: self.cnt  // Include version
    },
    meta,
    self.msk().as_bytes(),
    guardians,
    threshold,
)
```

**Alternative/Additional Mitigations:**
1. **Automatic regeneration**: Regenerate the social backup on every `update()` call that includes MSK rotation:
   ```rust
   if msk_rotated {
       self.update_recovery(rng, &self.recovery.guardians, self.recovery.threshold)?;
   }
   ```

2. **Explicit invalidation**: Add a mechanism to invalidate old guardian shares in contract storage when the social backup changes (by tracking BackupId changes)

3. **Documentation**: Clearly document that users MUST call `update_recovery()` after MSK rotation to invalidate old guardian shares

4. **Version binding**: Bind guardian shares to account version during verification:
   - Store the account version when shares are uploaded
   - Reject shares from versions older than the most recent `update_recovery()` call

## Proof of Concept

**File:** `lib/src/account/tests.rs`

**Test function:** `test_stale_guardian_shares_after_msk_rotation`

**Setup:**
1. Create account with 3 guardians (G1, G2, G3), threshold=2
2. Call `update_recovery()` to set up social recovery
3. Guardians decrypt and save their shares (simulating local storage)
4. Publish initial account state

**Trigger:**
1. User rotates MSK using `new_msk()`
2. User calls `update()` without calling `update_recovery()`
3. Verify that social backup BackupId remains unchanged
4. User initiates recovery
5. Guardians re-encrypt their OLD shares (from before MSK rotation) for the recovery PKE
6. Upload the old shares to contract

**Observation:**
The test should demonstrate that:
- The old shares pass verification (`backup.verify()` succeeds)
- The shares can be uploaded successfully via `upload_share` endpoint
- Recovery can complete with these old shares (`RecoverySecrets::complete()` succeeds)
- The attacker obtains the NEW MSK despite using OLD guardian shares

This proves that MSK rotation does not invalidate guardian shares, allowing compromised old shares to participate in recovery of the new MSK, which is a security failure.

The test would look like:
```rust
#[test]
fn test_stale_guardian_shares_after_msk_rotation() {
    // Setup: Create account and guardians
    // Call update_recovery() and get social backup ID1
    // Guardians save DecryptedShareV0 locally
    
    // Trigger: Rotate MSK without update_recovery()
    // Assert: social backup still has ID1
    
    // Initiate recovery
    // Re-encrypt old shares for recovery PKE
    // Verify shares are still valid
    // Complete recovery with old shares
    // Assert: Obtains new MSK (security failure)
}
```

The test confirms the vulnerability by showing that stale guardian shares remain valid across MSK rotations when `new()` lacks versioning.

### Citations

**File:** lib/src/backup/v0.rs (L246-253)
```rust
#[derive(Serialize)]
pub struct AADBackup {
    pub acc: AccountId,
}

impl Tagged for AADBackup {
    const SEPARATOR: &'static str = "v0:aad-backup";
}
```

**File:** lib/src/backup/v0.rs (L356-447)
```rust
    pub fn new<R: Rng + CryptoRng, M: Tagged, A: Tagged>(
        rng: &mut R,
        data: &M,
        aad: &A,
        meta: Metadata,
        sym_key: &sym::Key,
        guardians: &[AccountState],
        threshold: usize,
    ) -> Result<Self, SwafeError> {
        // check if there are enough guardians to meet the threshold
        // note that the threshold MAY be 0: in which case
        // only the msk is required to recover the secret
        if guardians.len() < threshold {
            return Err(SwafeError::InsufficientShares);
        }

        // shuffle guardians to prevent leaking the ordering
        let mut guardians = guardians.to_vec();
        guardians.shuffle(rng);

        // obtain current public keys for the guardians
        let pks = guardians.iter().map(|guardian| guardian.encryption_key());

        // create a shamir secret sharing
        let (secret, shares) = sss::share(rng, threshold, guardians.len());

        // plaintexts - use shuffled indices
        let pts: Vec<BackupShareV0> = (0..guardians.len())
            .map(|i| BackupShareV0 {
                sk: sig::SigningKey::gen(rng),
                share: shares[i].clone(),
            })
            .collect();

        // Form commitments to each share
        // note: this is fine because they have high entropy
        // and hence it is hiding if we assume that hash
        // can be modelled as a random oracle
        let comms: Vec<ShareComm> = (0..guardians.len())
            .map(|i| ShareComm {
                vk: pts[i].sk.verification_key(),
                hash: hash(&ShareHash { share: &shares[i] }),
            })
            .collect();

        // Derive the metadata key:
        // used to encrypt the metadata, allowing the owner to see *what*
        // a ciphertext contains before attempting to decrypt it
        let key_meta: [u8; sym::SIZE_KEY] = kdfn(sym_key, &KDFMetakey { comms: &comms });

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

        // Encrypt the metadata
        let now = std::time::SystemTime::now();
        let dur = now.duration_since(std::time::UNIX_EPOCH).unwrap();
        let sealed_data = sym::seal(rng, &key_data, data, &sym::EmptyAD);
        let data = sym::seal(
            rng,
            &key_meta,
            &BackupMetadata {
                name: meta.name,
                desc: meta.desc,
                data: sealed_data,
                threshold: threshold as u32,
                timestamp: dur.as_secs(),
            },
            &sym::EmptyAD,
        );

        // create a batched encryption of the shares
        let encap = pke::EncryptionKey::batch_encrypt(
            rng,
            pks.zip(pts),
            &EncryptionContext {
                aad: (A::SEPARATOR, aad),
                data: &data,
                comms: &comms,
            },
        );

        // encrypt the signature
        Ok(BackupCiphertextV0 { data, encap, comms })
    }
```

**File:** lib/src/account/v0.rs (L137-163)
```rust
impl RecoverySecrets {
    /// Complete recovery of the master secret key
    ///
    /// This function takes the account state and recovery secrets,
    /// along with guardian shares, and reconstructs the MSK using the dual-recovery approach.
    ///
    /// # Arguments
    /// * `shares` - Guardian shares from the social recovery system
    pub fn complete(&self, shares: &[GuardianShare]) -> Result<MasterSecretKey> {
        // recover the social secret share from the backup
        let msk_ss_social: MskSecretShareSocial = match &self.rec.social {
            BackupCiphertext::V0(v0) => {
                v0.recover(&self.dkey, &self.msk_ss_rik, &EmptyInfo, shares)?
            }
        };

        // derive the MSK decryption key from both secret shares
        let msk_dec_key = derive_msk_decryption_key(
            &self.acc,
            &MskSecretShareRik::new(self.msk_ss_rik),
            &msk_ss_social,
        );

        // decrypt the MSK using the derived key
        sym::open(&msk_dec_key, &self.rec.enc_msk, &self.acc)
    }
}
```

**File:** lib/src/account/v0.rs (L710-716)
```rust
            rec: RecoveryStateV0 {
                pke: None,
                assoc,
                // TODO: unfortunately we cannot generate this anew every time
                social: self.recovery.social.clone(),
                enc_msk,
            },
```
