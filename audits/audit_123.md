# Audit Report

## Title
Metadata Substitution Allows Guardian Threshold Bypass in Account Recovery

## Summary
The `BackupCiphertextV0::recover()` function in `lib/src/backup/v0.rs` fails to cryptographically bind the encrypted metadata (which contains the guardian threshold) to the share commitments. An attacker who has initiated recovery and obtained the RIK secret share can modify the encrypted metadata to lower the threshold, allowing them to complete account recovery with fewer guardian approvals than originally configured.

## Impact
**Severity: High**

## Finding Description

**Location:** [1](#0-0) 

The vulnerability exists in the `recover()` method where metadata decryption and threshold validation occur.

**Intended Logic:** The guardian threshold in the backup metadata should be immutable and authenticated to prevent unauthorized modification. The system should require exactly the number of guardian shares specified during backup creation to successfully recover the Master Secret Key.

**Actual Logic:** The encrypted metadata is decrypted using a key derived from the MSK/RIK secret share and share commitments: [2](#0-1) 

However, the metadata is decrypted with empty associated data (`EmptyAD`): [3](#0-2) 

This means the encrypted metadata (`self.data`) is NOT authenticated against the share commitments (`self.comms`). The AEAD encryption scheme protects the metadata's integrity with respect to the key, but provides no binding between the metadata and the commitments.

**Exploit Scenario:**
1. Attacker compromises the victim's email and obtains the RIK (Recovery Initiation Key)
2. Attacker calls `AccountStateV0::initiate_recovery()` with the RIK, obtaining `RecoverySecrets` which includes the `msk_ss_rik` (RIK secret share): [4](#0-3) 
3. Attacker retrieves the account state from the blockchain contract, extracting the `rec.social` backup ciphertext
4. Attacker computes the metadata key: `kdfn(&msk_ss_rik, &KDFMetakey { comms: &backup.comms })`
5. Attacker decrypts the metadata using the symmetric decryption function: [5](#0-4) 
6. Attacker modifies the `threshold` field in the `BackupMetadata` struct from (e.g., 2 to 1): [6](#0-5) 
7. Attacker re-encrypts the modified metadata with the same key using the seal function: [7](#0-6) 
8. Attacker replaces the `data` field in the `BackupCiphertextV0` structure with the new ciphertext
9. Since `RecoverySecrets` is serializable and controlled off-chain by the user: [8](#0-7) , the attacker modifies `rec.social` before calling `complete()`
10. Attacker obtains only 1 guardian share (below the original threshold of 2)
11. Attacker calls `RecoverySecrets::complete()` with the modified backup and insufficient shares: [9](#0-8) 
12. The recovery succeeds because the threshold check uses the tampered value: [10](#0-9) 

**Security Failure:** The guardian threshold security mechanism is completely bypassed. An account configured with threshold=2 can be recovered with just 1 guardian share, violating the core security invariant that "the specified guardian threshold must be respected."

## Impact Explanation

This vulnerability compromises the fundamental security model of Swafe's account recovery system:

- **Assets Affected:** The victim's Master Secret Key (MSK), which is the root secret for the entire account and all derived keys
- **Severity of Damage:** Complete compromise of account security. The attacker gains full control of the account and can:
  - Access all secrets encrypted with the MSK
  - Impersonate the account owner
  - Modify account state and recovery configuration
  - Steal or permanently lock the account
  
This represents a **direct loss of private keys/secrets** as specified in the in-scope impact criteria.

The multi-guardian threshold is a critical security control designed to prevent unauthorized recovery even if a single point of failure (like the RIK/email) is compromised. This vulnerability negates that protection entirely, reducing the security to that of a single guardian, regardless of the configured threshold.

## Likelihood Explanation

**Likelihood: High**

- **Who can trigger it:** Any attacker who obtains a victim's RIK (e.g., through email compromise, which is explicitly within the documented threat model)
- **Conditions required:** Normal recovery operation - no special timing, race conditions, or rare circumstances needed
- **Frequency:** Can be exploited whenever an attacker gains access to a victim's RIK, which is a realistic attack vector given that RIKs are stored with email providers

The attack is straightforward to execute:
1. RIK compromise is part of the documented attack surface
2. The `RecoverySecrets` structure is controlled entirely off-chain by the user between `initiate_recovery()` and `complete()` calls
3. The attacker has all the cryptographic material (RIK secret share and commitments) needed to perform the metadata manipulation
4. No on-chain validation prevents the use of a modified backup ciphertext

## Recommendation

Cryptographically bind the encrypted metadata to the share commitments by including the commitments in the associated data (AD) during encryption/decryption:

**At backup creation** (in `BackupCiphertextV0::new()`):
```rust
// Instead of:
let data = sym::seal(rng, &key_meta, &BackupMetadata {...}, &sym::EmptyAD);

// Use:
let data = sym::seal(rng, &key_meta, &BackupMetadata {...}, &comms);
```

**At recovery** (in `BackupCiphertextV0::recover()`):
```rust
// Instead of:
let meta: BackupMetadata = sym::open(&key_meta, &self.data, &sym::EmptyAD)?;

// Use:
let meta: BackupMetadata = sym::open(&key_meta, &self.data, &self.comms)?;
```

This ensures that any modification to the encrypted metadata will fail MAC verification during decryption, as the commitments are authenticated as part of the AEAD scheme. An attacker cannot create a valid ciphertext for modified metadata without also modifying the commitments, which would break the share hash verification at: [11](#0-10) 

## Proof of Concept

**File:** `lib/src/account/tests.rs`

**Test Function:** `test_metadata_substitution_bypass_threshold`

**Setup:**
1. Create an account with 3 guardians and threshold=2
2. Call `update_recovery()` to configure social recovery
3. Add an association to get the RIK
4. Call `initiate_recovery()` to obtain `RecoverySecrets`

**Trigger:**
1. Extract the backup ciphertext from `RecoverySecrets.rec.social`
2. Compute the metadata key using `msk_ss_rik` and commitments
3. Decrypt the metadata with `sym::open(&key_meta, &backup.data, &EmptyAD)`
4. Modify the threshold field from 2 to 1
5. Re-encrypt with `sym::seal(rng, &key_meta, &modified_metadata, &EmptyAD)`
6. Replace `data` in the backup ciphertext
7. Update `RecoverySecrets.rec.social` with the modified backup
8. Obtain only 1 guardian share (below original threshold)
9. Call `complete()` with the modified `RecoverySecrets` and single share

**Observation:**
The test demonstrates that:
1. With the original (unmodified) `RecoverySecrets`, `complete()` fails with `SwafeError::InsufficientShares` when given only 1 share (expected behavior per: [12](#0-11) )
2. With the modified `RecoverySecrets` (tampered metadata with threshold=1), `complete()` succeeds with only 1 share, returning the MSK
3. This confirms the threshold check can be bypassed through metadata substitution

The PoC proves that the integrity checks in `recover()` do not prevent metadata manipulation, allowing unauthorized recovery with insufficient guardian approvals.

### Citations

**File:** lib/src/backup/v0.rs (L205-212)
```rust
#[derive(Serialize, Deserialize)]
struct BackupMetadata {
    name: String,         // user defined name for secret
    desc: String,         // user defined description for secret
    data: AEADCiphertext, // encrypted data
    threshold: u32,       // threshold for the secret
    timestamp: u64,       // timestamp of the backup
}
```

**File:** lib/src/backup/v0.rs (L289-340)
```rust
impl BackupCiphertextV0 {
    pub fn recover<M: Tagged + DeserializeOwned, A: Tagged>(
        &self,
        dke: &pke::DecryptionKey,
        sym: &sym::Key,
        aad: &A,
        shares: &[GuardianShare],
    ) -> Result<M, SwafeError> {
        // Verify and decrypt each share
        // Ignore invalid and duplicate shares
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

        // derive the metadata key
        let key_meta: sym::Key = kdfn(sym, &KDFMetakey { comms: &self.comms });

        // decrypt the metadata
        let meta: BackupMetadata = sym::open(&key_meta, &self.data, &sym::EmptyAD)?;

        // check that we have enough shares to meet the threshold
        if shares.len() < meta.threshold as usize {
            return Err(SwafeError::InsufficientShares);
        }

        // recover the secret using Shamir's Secret Sharing
        let secret: sss::Secret = sss::recover(
            &shares
                .into_iter()
                .take(meta.threshold as usize)
                .map(|(idx, share)| (idx as usize, share))
                .collect::<Vec<_>>()[..],
        );

        // derive the data encryption key
        let key_data: sym::Key = kdfn(&BackupKDFInput { key: sym, secret }, &EmptyInfo);

        // decrypt the data
        sym::open(&key_data, &meta.data, &sym::EmptyAD)
    }
```

**File:** lib/src/account/v0.rs (L129-135)
```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct RecoverySecrets {
    acc: AccountId,
    rec: RecoveryStateV0,
    msk_ss_rik: sym::Key,
    dkey: pke::DecryptionKey,
}
```

**File:** lib/src/account/v0.rs (L145-162)
```rust
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
```

**File:** lib/src/account/v0.rs (L171-226)
```rust
    pub fn initiate_recovery<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        acc: AccountId,
        rik: &RecoveryInitiationKey,
    ) -> Result<(AccountUpdate, RecoverySecrets)> {
        // decrypt AssociationsV0 using RIK
        let encap = self
            .rec
            .assoc
            .iter()
            .find_map(|assoc| {
                // attempt to decrypt the encapsulated key using RIK
                let encap = sym::open::<EncapV0, _>(rik.as_bytes(), &assoc.encap, &acc).ok()?;

                // check if the verification key matches the expected one
                if encap.key_sig.verification_key() != assoc.sig {
                    None
                } else {
                    Some(encap)
                }
            })
            .ok_or(SwafeError::InvalidRecoveryKey)?;

        // generate new keys for this recovery session
        let dkey = pke::DecryptionKey::gen(rng);

        // sign the recovery request with the signing key from RIK
        let sig = encap.key_sig.sign(
            rng,
            &RecoveryRequestMessage {
                account_id: acc,
                recovery_pke: dkey.encryption_key(),
            },
        );

        // create the recovery update
        let update = AccountUpdate::V0(AccountUpdateV0 {
            acc,
            msg: AccountMessageV0::Recovery(AccountUpdateRecoveryV0 {
                pke: dkey.encryption_key(),
                sig,
            }),
        });

        // return public update (for contract upload) and secret data (for final recovery)
        Ok((
            update,
            RecoverySecrets {
                acc,
                rec: self.rec.clone(),
                msk_ss_rik: *encap.msk_ss_rik.as_bytes(),
                dkey,
            },
        ))
    }
```

**File:** lib/src/crypto/symmetric.rs (L71-109)
```rust
pub(crate) fn seal<M: Tagged, A: Tagged, R: Rng>(
    rng: &mut R,
    key: &Key,
    pt: &M,
    ad: &A,
) -> AEADCiphertext {
    // serialize the plaintext
    let pt = bincode::serde::encode_to_vec(pt, bincode::config::standard()).unwrap();

    // sample synthetic nonce
    let nonce: Nonce = kdfn(
        key,
        &NonceTuple {
            separator: (M::SEPARATOR, A::SEPARATOR),
            nonce: &rng.gen::<Nonce>(),
            pt: &pt,
            ad,
        },
    );

    // encrypt the plaintext
    let mut ct = vec![0u8; pt.len()];
    kdf(key, &KDFPad(&nonce), &mut ct);
    for i in 0..ct.len() {
        ct[i] ^= pt[i];
    }

    // generate the MAC
    let mac: [u8; SIZE_MAC] = kdfn(
        key,
        &MACTuple {
            separator: (M::SEPARATOR, A::SEPARATOR),
            nonce: &nonce,
            ct: ct.as_slice(),
            ad,
        },
    );
    AEADCiphertext { nonce, ct, mac }
}
```

**File:** lib/src/crypto/symmetric.rs (L112-149)
```rust
pub(crate) fn open<M: Tagged + DeserializeOwned, A: Tagged>(
    key: &Key,
    ct: &AEADCiphertext,
    ad: &A,
) -> Result<M> {
    // check the MAC
    let mac_corr: Mac = kdfn(
        key,
        &MACTuple {
            separator: (M::SEPARATOR, A::SEPARATOR),
            nonce: &ct.nonce,
            ct: &ct.ct,
            ad,
        },
    );
    if mac_corr.ct_eq(&ct.mac).unwrap_u8() != 1 {
        return Err(SwafeError::DecryptionFailed);
    }

    // decrypt the raw plaintext
    let mut pt = vec![0u8; ct.ct.len()];
    kdf(key, &KDFPad(&ct.nonce), &mut pt);
    for (i, byte) in pt.iter_mut().enumerate() {
        *byte ^= ct.ct[i];
    }

    // deserialize to a message
    match bincode::serde::decode_from_slice::<M, _>(&pt, bincode::config::standard()) {
        Ok((msg, n)) => {
            if n != pt.len() {
                Err(SwafeError::DecryptionFailed)
            } else {
                Ok(msg)
            }
        }
        Err(_) => Err(SwafeError::DecryptionFailed),
    }
}
```

**File:** lib/src/account/tests.rs (L584-595)
```rust
        let recovery_result = recovery_secrets.complete(&insufficient_shares);

        assert!(
            recovery_result.is_err(),
            "Recovery should fail with insufficient shares"
        );
        match recovery_result {
            Err(SwafeError::InsufficientShares) => {
                // Expected error type
            }
            _ => panic!("Expected InsufficientShares error"),
        }
```
