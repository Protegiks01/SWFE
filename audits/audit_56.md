## Audit Report

## Title
Guardian Key Rotation Does Not Re-Encrypt Historical Backups, Enabling Retroactive Decryption After Old Key Compromise

## Summary
When guardians rotate their PKE encryption keys, existing backup ciphertexts stored in user accounts remain encrypted to the old guardian public keys. If a guardian's old private key is later compromised (through device theft, insecure storage, or software vulnerability), an attacker can query on-chain account state and decrypt that guardian's share from all backups created before the key rotation. With threshold number of compromised old keys, attackers can reconstruct users' master secret keys retroactively. [1](#0-0) [2](#0-1) 

## Impact
**High**

## Finding Description

**Location:** 
- Key rotation logic: `lib/src/account/v0.rs`, `AccountSecrets::new_pke()` function (lines 491-496)
- Backup creation: `lib/src/backup/v0.rs`, `BackupCiphertextV0::new()` function (lines 356-447)
- Guardian share decryption: `lib/src/account/v0.rs`, `AccountSecrets::decrypt_share()` function (lines 572-603)
- On-chain storage: `contracts/src/lib.rs`, account state storage (lines 29-45) [3](#0-2) 

**Intended Logic:** 
When a guardian rotates their encryption key for forward secrecy, existing encrypted data should either be re-encrypted to the new key or become inaccessible with old keys. The system should provide forward secrecy such that compromise of an old key does not compromise historical encrypted data.

**Actual Logic:** 
When `new_pke()` is called, it only updates the guardian's own account state by storing the old key in an `old_pke` vector and generating a new key. However, backup ciphertexts stored in other users' account states remain encrypted to the old public key indefinitely. These backups are never automatically re-encrypted or invalidated. [4](#0-3) 

The account state structure stores backups as persistent vectors that are not automatically updated when guardian keys change.

**Exploit Scenario:**

1. **T0 - Backup Creation:** Alice creates a backup with guardians Bob, Charlie, and Dave (threshold 2/3). Each guardian's share is encrypted to their current PKE (Bob's is PKE_B0). [5](#0-4) 

2. **T1 - Key Rotation:** Bob rotates his encryption key (PKE_B0 → PKE_B1) for security best practice after upgrading devices. His old key PKE_B0 is stored in `old_pke` vector.

3. **T2 - Old Key Compromise:** Bob's old device is stolen/sold, or his old key backup is compromised. Attacker obtains Bob's old private key sk_B0.

4. **Attack Execution:**
   - Attacker queries Alice's account state from the blockchain contract
   - Retrieves backup ciphertext from Alice's `backups` field
   - Uses sk_B0 to decrypt Bob's share from the BatchCiphertext [6](#0-5) 

5. **Threshold Breach:** If attacker compromises one more guardian's old key (Charlie or Dave), they meet the 2/3 threshold and can reconstruct Alice's master secret key using Shamir's Secret Sharing. [7](#0-6) 

**Security Failure:** 
The system violates forward secrecy. Key rotation should protect historical data from future key compromise, but here old keys retain their decryption capability indefinitely for all backups created during their lifetime. The amplification occurs because one compromised old key affects all historical backups, not just data at the time of compromise.

## Impact Explanation

**Affected Assets:** Master secret keys (MSK) of all users who created backups with compromised guardians before their key rotation.

**Severity of Damage:**
- Attackers can reconstruct users' master secret keys by collecting threshold number of guardian shares
- MSK compromise allows decryption of all user secrets and account takeover
- The attack is retroactive - affects ALL historical backups created before guardian key rotations
- Impact scales with time: the longer guardians use keys before rotation, the more backups become vulnerable
- Multiple users are affected simultaneously if they share common guardians

**Why This Matters:**
This violates users' reasonable expectation that guardians rotating their keys (security best practice) would invalidate old encrypted data. Users cannot protect themselves by asking guardians to rotate keys, because the protocol doesn't implement forward secrecy. The vulnerability creates a long-term, accumulating risk where old compromised devices/backups from years ago can decrypt current secrets. [8](#0-7) 

## Likelihood Explanation

**Who Can Trigger:** Any external attacker who obtains guardian's old private keys through device theft, insecure key storage, software vulnerabilities, or social engineering.

**Required Conditions:**
- Guardian must have rotated keys at least once (common security practice)
- Attacker must compromise threshold number of guardians' old keys
- This is realistic because: guardians upgrade devices, old devices are sold/stolen, old backups may be insecurely stored, and software vulnerabilities may expose old keys

**Frequency:**
- Likelihood increases over time as more key rotations occur
- Likelihood increases with number of guardians (more potential compromise targets)
- Old devices and backups accumulate as e-waste, increasing long-term risk
- Can affect multiple users simultaneously who share guardians

## Recommendation

Implement one of the following mitigation strategies:

1. **Automatic Re-encryption:** When guardians update their encryption keys via `new_pke()`, broadcast this change so account owners can re-encrypt affected backups. Add a mechanism to iterate through backups and re-encrypt shares to new guardian keys.

2. **Backup Versioning with Key Binding:** Bind each backup to specific guardian key versions. Mark backups as "stale" when any guardian rotates keys, requiring explicit user action to either re-encrypt or accept the risk.

3. **Time-Limited Backups:** Implement automatic backup expiration, requiring periodic re-creation with current guardian keys to maintain forward secrecy.

4. **Key Rotation Protocol:** Modify the `update_recovery()` function to not only update the social recovery backup but also trigger re-encryption of all user backups when guardian states change.

The most comprehensive fix would be option 1, adding automatic re-encryption logic to the key rotation flow.

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** `test_old_key_compromise_retroactive_decryption`

**Setup:**
1. Create account owner Alice with MSK
2. Create three guardian accounts (Bob, Charlie, Dave)  
3. Alice creates backup with guardians (threshold 2/3)
4. Store Bob's current PKE state (PKE_B0 and corresponding sk_B0)

**Trigger:**
1. Bob rotates his encryption key via `new_pke()`
2. Bob updates his account on-chain with new key
3. Simulate attacker obtaining Bob's old private key sk_B0
4. Similarly compromise Charlie's old key sk_C0
5. Query Alice's account state from contract (contains backup with old key encryption)
6. Attacker decrypts Bob's share using sk_B0
7. Attacker decrypts Charlie's share using sk_C0
8. Attacker reconstructs Alice's MSK using two shares (meeting 2/3 threshold)

**Observation:**
The test demonstrates that the attacker successfully reconstructs Alice's master secret key using only the old compromised guardian keys, despite those keys having been rotated. This proves the lack of forward secrecy - old key compromise enables retroactive decryption of all historical backups. The test should demonstrate that `recover()` succeeds with shares decrypted using old keys, returning Alice's original MSK.

## Notes

This vulnerability stems from the fundamental protocol design where backup ciphertexts are immutable once created and stored on-chain. The `old_pke` fallback mechanism is intended for legitimate guardians to decrypt their own old shares, but it inadvertently enables attackers with compromised old keys to decrypt historical data. The system assumes guardian corruption is within the threat model (per trust assumptions in README), but the protocol design amplifies the impact of such compromise beyond the expected scope.

### Citations

**File:** lib/src/account/v0.rs (L230-238)
```rust
pub(crate) struct AccountStateV0 {
    cnt: u32, // current count of operations
    act: AccountCiphertext,
    pub(crate) rec: RecoveryStateV0,
    sig: sig::VerificationKey,
    pke: pke::EncryptionKey,
    backups: Vec<BackupCiphertext>, // backups to store
    recover: Vec<BackupCiphertext>, // backups to recover
}
```

**File:** lib/src/account/v0.rs (L491-496)
```rust
    /// Update the encryption key (for rotation)
    pub fn new_pke<R: Rng + CryptoRng>(&mut self, rng: &mut R) {
        self.dirty = true;
        self.old_pke.push(self.pke.clone());
        self.pke = pke::DecryptionKey::gen(rng);
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

**File:** lib/src/backup/v0.rs (L326-333)
```rust
        // recover the secret using Shamir's Secret Sharing
        let secret: sss::Secret = sss::recover(
            &shares
                .into_iter()
                .take(meta.threshold as usize)
                .map(|(idx, share)| (idx as usize, share))
                .collect::<Vec<_>>()[..],
        );
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

**File:** contracts/src/lib.rs (L33-45)
```rust
impl ContractState {
    fn get_account(&self, id: AccountId) -> Option<AccountState> {
        self.accounts
            .get(id.as_ref())
            .map(|data| encode::deserialize(&data).expect("failed to deserialize account"))
    }

    fn set_account(&mut self, id: AccountId, account: AccountState) {
        self.accounts.insert(
            *id.as_ref(),
            encode::serialize(&account).expect("failed to serialize account"),
        );
    }
```
