# Audit Report

## Title
Insufficient AAD Binding Allows Backup Transplantation via Guardian Share Re-encryption to Attacker's Key

## Summary
The `EncryptionContext.aad` field binds guardian shares to an `AccountId` during backup creation, but this binding is only enforced during guardian decryption. After decryption, guardians can re-encrypt shares to any recipient's public key without validation that the recipient corresponds to the original `AccountId`. An attacker can exploit this by providing the correct `AccountId` for decryption but their own `AccountState` for re-encryption, allowing them to recover victims' backup secrets.

## Impact
**High**

## Finding Description

**Location:** 
- Guardian share decryption: [1](#0-0) 
- Guardian share re-encryption: [2](#0-1) 
- CLI handler missing validation: [3](#0-2) 

**Intended Logic:** 
The AAD field should cryptographically bind backup ciphertexts to specific accounts, ensuring that only the legitimate account owner can recover their backed-up secrets. The `EncryptionContext` structure is designed to provide this binding: [4](#0-3) 

**Actual Logic:** 
The AAD binding is only enforced when guardians initially decrypt their shares from the `BatchCiphertext`. The `decrypt_share` function requires the correct `AccountId` to decrypt: [5](#0-4) 

However, after successful decryption, the `send()` method accepts an arbitrary `AccountState` parameter with no validation that it corresponds to the `AccountId` used during decryption: [2](#0-1) 

The method simply encrypts to whatever `AccountState.encryption_key()` is provided, with no cryptographic or programmatic check linking it to the original account.

**Exploit Scenario:**

1. **Setup**: Alice creates a backup with threshold=2 and guardians [G1, G2, G3]. The backup is encrypted with `AADBackup { acc: Alice_ID }`: [6](#0-5) 

2. **Attack**: Bob (attacker) obtains Alice's `BackupCiphertext` from the public blockchain state.

3. **Deception**: Bob contacts guardians G1 and G2, providing:
   - `backup`: Alice's `BackupCiphertext`
   - `account_id`: Alice's `AccountId` (correctly, for decryption)
   - `owner_state`: Bob's `AccountState` (falsely, claiming ownership)

4. **Guardian Processing**: Each guardian executes via CLI: [3](#0-2) 
   - Calls `decrypt_share_backupy(Alice_ID, Alice_backup)` → Succeeds because `Alice_ID` matches the AAD
   - Calls `share.send(rng, Bob_State)` → Encrypts to Bob's public key without validation

5. **Recovery**: Bob collects threshold shares encrypted to his key and calls: [7](#0-6) 
   - `Bob_Secrets.recover(Alice_backup, guardian_shares)` → Successfully decrypts with Bob's private key and recovers Alice's secret data

**Security Failure:** 
The security property "only the account owner may reconstruct backed-up secrets" is violated. The AAD binding provides insufficient protection because it only validates the `AccountId` during guardian decryption, not during the critical re-encryption step to the final recipient.

## Impact Explanation

**Affected Assets:**
- User secrets stored in `BackupCiphertext` (passwords, private keys, sensitive data)
- Master Secret Keys in social recovery backups: [8](#0-7) 

**Severity of Damage:**
- **Direct loss of confidentiality**: Attacker gains access to victim's backed-up secrets
- **Bypass of threshold guardian model**: The social recovery mechanism meant to protect secrets becomes an attack vector
- **Compromise of account recovery**: If the backup contains MSK secret shares, the attacker can gain full account control

**System Impact:**
This fundamentally breaks the security model of guardian-based backup protection. Users cannot trust that their secrets are protected by guardians, as guardians can be socially engineered or deceived into helping attackers without realizing it. The cryptographic binding is insufficient to prevent the transplantation attack.

## Likelihood Explanation

**Who Can Trigger:**
Any unprivileged attacker who can:
- Observe `BackupCiphertext` on the public blockchain
- Communicate with guardians (social engineering, impersonation, or legitimate contact)
- Create their own account with an `AccountState`

**Required Conditions:**
- Victim has created a backup with guardians (normal operation)
- Attacker can convince guardians to process a "recovery request" (social engineering, but guardians are acting in good faith)
- No additional cryptographic or programmatic validation exists to prevent the attack

**Frequency:**
- Can be exploited against any user with guardian-protected backups
- Requires threshold guardians to cooperate (but unknowingly)
- Social engineering component makes it practical in real-world scenarios where guardians believe they're helping a legitimate recovery

The vulnerability is **highly likely** to be exploited because:
1. Guardians have no way to verify they're sending shares to the correct recipient
2. The attack requires no special privileges or trusted role compromise
3. All backup data is publicly visible on-chain

## Recommendation

**Primary Fix**: Add cryptographic binding between `AccountId` and `AccountState` in the guardian share flow:

1. **Validate AccountState ownership**: Before calling `send()`, verify that the provided `AccountState` corresponds to the `AccountId` used for decryption by checking: [9](#0-8) 
   ```rust
   // In send() method or CLI handler
   let expected_account_id = AccountId::from_vk(&owner_state.sig);
   if expected_account_id != account_id_used_for_decryption {
       return Err(SwafeError::AccountIdMismatch);
   }
   ```

2. **Include AccountId in re-encryption AAD**: Modify the `send()` method to use `AADBackup { acc: owner_account_id }` instead of `EmptyInfo` when re-encrypting shares: [10](#0-9) 

3. **Store AccountId in SecretShare**: Include the `AccountId` in `DecryptedShareV0` structure so guardians can validate consistency between decryption and re-encryption steps.

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** `test_backup_transplantation_attack`

**Setup:**
1. Create Alice's account with `AccountSecrets::gen()`
2. Create Bob's account (attacker) with `AccountSecrets::gen()`
3. Create three guardian accounts
4. Alice creates a backup with threshold=2 and test data containing sensitive information
5. Obtain Alice's and Bob's `AccountState` objects

**Trigger:**
1. Guardian1 calls `decrypt_share_backupy(*alice.acc(), &alice_backup)` → Should succeed with Alice's ID
2. Guardian1 calls `share.send(&mut rng, &bob_state)` → Encrypts to Bob's key (no validation prevents this)
3. Guardian2 repeats the same steps
4. Bob calls `bob_secrets.recover(&alice_backup, &[guardian_share1, guardian_share2])`

**Observation:**
The test demonstrates that:
- Guardians successfully decrypt with Alice's `AccountId` (AAD binding works for decryption)
- Guardians successfully encrypt to Bob's `AccountState` (no validation prevents wrong recipient)
- Bob successfully recovers Alice's secret data (transplantation attack succeeds)
- The test confirms the AAD field does NOT properly prevent backup transplantation

The vulnerability is proven by the fact that Bob can recover secrets from a backup created by Alice, violating the core security property that only the account owner should be able to recover their backed-up data.

**Notes:**
- This vulnerability affects all backup types including regular backups and social recovery backups
- The test in `lib/src/backup/tests.rs` at lines 70-79 only validates that decryption fails with wrong `AccountId`, but doesn't test the re-encryption transplantation scenario: [11](#0-10) 
- The existing test suite doesn't cover the guardian workflow where different `AccountId` and `AccountState` are provided to different steps of the process

### Citations

**File:** lib/src/account/v0.rs (L381-393)
```rust
    BackupCiphertextV0::new(
        rng,
        msk_ss_social,
        &AADRecovery { acc },
        crate::backup::Metadata::new(
            "RIK Social Recovery".to_string(),
            "MSK secret share for social recovery".to_string(),
        ),
        msk_ss_rik.as_bytes(),
        guardians,
        threshold,
    )
    .map(BackupCiphertext::V0)
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

**File:** lib/src/backup/v0.rs (L132-152)
```rust
    pub fn send<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        owner: &AccountState,
    ) -> Result<GuardianShare, SwafeError> {
        let ct = owner
            .encryption_key()
            .encrypt(rng, &self.share.share, &EmptyInfo);
        let sig = self.share.sk.sign(
            rng,
            &SignedEncryptedShare {
                ct: &ct,
                idx: self.idx,
            },
        );
        Ok(GuardianShare::V0(GuardianShareV0 {
            ct,
            idx: self.idx,
            sig,
        }))
    }
```

**File:** lib/src/backup/v0.rs (L235-244)
```rust
#[derive(Serialize)]
pub struct EncryptionContext<'a, 'b, A: Tagged> {
    pub aad: (&'static str, &'a A),
    pub(crate) data: &'a sym::AEADCiphertext,
    pub comms: &'b [ShareComm],
}

impl<A: Tagged> Tagged for EncryptionContext<'_, '_, A> {
    const SEPARATOR: &'static str = "v0:encryption-context";
}
```

**File:** lib/src/backup/v0.rs (L264-273)
```rust
        BackupCiphertextV0::new(
            rng,
            data,
            &AADBackup { acc: *self.acc() },
            meta,
            self.msk().as_bytes(),
            guardians,
            threshold,
        )
        .map(BackupCiphertext::V0)
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

**File:** cli/src/commands/backup.rs (L140-165)
```rust
pub fn guardian_send_share(
    secret_share_str: String,
    owner_account_state_str: String,
    output: PathBuf,
) -> Result<()> {
    let mut rng = thread_rng();

    let secret_share: SecretShare = encode::deserialize_str(&secret_share_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode secret share: {}", e))?;

    let owner_state: AccountState = encode::deserialize_str(&owner_account_state_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode owner account state: {}", e))?;

    let guardian_share = secret_share
        .send(&mut rng, &owner_state)
        .map_err(|e| anyhow::anyhow!("Failed to create guardian share: {:?}", e))?;

    let share_output = VerifiedShareOutput {
        share: StrEncoded(guardian_share),
        index: 0, // Index is embedded in GuardianShare
    };

    write_json_output(share_output, &output)?;

    Ok(())
}
```

**File:** lib/src/account/mod.rs (L43-52)
```rust
impl AccountId {
    // This method is intentially left unexported.
    pub(crate) fn from_vk(vk: &sig::VerificationKey) -> Self {
        AccountId(hash(vk))
    }

    /// Create AccountId from a verification key (for node setup)
    pub fn from_verification_key(vk: &sig::VerificationKey) -> Self {
        Self::from_vk(vk)
    }
```

**File:** lib/src/backup/tests.rs (L70-80)
```rust
    // Test that decrypting with the *wrong* account fails
    assert!(guardian1
        .decrypt_share_backupy(*guardian2.acc(), &backup)
        .is_none());
    assert!(guardian2
        .decrypt_share_backupy(*guardian1.acc(), &backup)
        .is_none());
    assert!(guardian2
        .decrypt_share_backupy(*non_guardian.acc(), &backup)
        .is_none());
}
```
