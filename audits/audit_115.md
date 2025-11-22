## Title
Guardian Public Key Validation Missing: Identity Point Allows Predictable Share Decryption

## Summary
Guardian PKE (Public Key Encryption) keys are not validated before use in the backup encryption process. A malicious guardian can register an AccountState with their PKE public key set to the elliptic curve identity point (point at infinity), making shares encrypted for them predictably decryptable by anyone without requiring the corresponding private key. This breaks the threshold security guarantee of the backup system.

## Impact
**High**

## Finding Description

**Location:** 
- Primary vulnerability: [1](#0-0) 
- Encryption usage: [2](#0-1) 
- Missing validation in verification: [3](#0-2) 

**Intended Logic:** 
Guardian public keys should be valid, non-identity elliptic curve points to ensure shares encrypted for guardians can only be decrypted by holders of the corresponding private keys. The threshold secret sharing scheme depends on this property to maintain its security guarantees.

**Actual Logic:** 
The code extracts guardian PKE public keys and uses them directly in batch encryption without validating that they are non-identity points. When a guardian's public key is the identity element (point at infinity):

1. In `BackupCiphertextV0::new()`, guardian encryption keys are extracted via `guardian.encryption_key()` without validation
2. In `EncryptionKey::encrypt()`, the Diffie-Hellman shared secret is computed as `(self.0 * ts)` where `self.0` is the guardian's public key
3. For identity point: `identity * ts = identity` for any scalar `ts`
4. The shared secret becomes a fixed, predictable value (serialization of the identity point)
5. The derived encryption key is therefore predictable and constant
6. Anyone knowing the guardian uses an identity key can decrypt that share without the private key

**Exploit Scenario:**

1. Malicious guardian generates normal AccountSecrets via `AccountSecrets::gen()`
2. Guardian creates an AccountUpdate with the `pke` field manually set to the identity point
3. Guardian signs the update with their valid signing key
4. The contract's `update_account` accepts this because verification only checks signatures and version increments, not PKE key validity
5. When an owner creates a backup including this malicious guardian, one share is encrypted using the identity point
6. The malicious guardian (or any observer) can decrypt this share with predictable keys
7. This reduces the effective threshold by 1, breaking the security model

**Security Failure:** 
The threshold security invariant is violated. A backup with threshold `t` and one malicious guardian with an identity key has effective security of threshold `t-1`, since that guardian's share is publicly decryptable.

## Impact Explanation

**Assets Affected:**
- Master secret keys (MSK) stored in backups
- Recovery secret shares (MSK components)
- Any sensitive data protected by the backup system

**Severity:**
- **Direct compromise of secrets:** Backup shares become decryptable without authorization
- **Threshold security broken:** A 2-of-3 backup becomes effectively 1-of-2 if one guardian is malicious
- **Irrevocable damage:** Once a backup is created with a malicious guardian, those shares are permanently compromised
- **Loss of funds/keys:** Recovering backups means reconstructing MSKs, which control user assets

**System Impact:**
The backup system is a core security primitive. Users trust that threshold guardians collectively protect their secrets. Breaking this trust means users can lose control of their master keys and associated assets.

## Likelihood Explanation

**Who can trigger:** 
Any user who can register as a guardian (by creating and uploading an AccountState with a malicious PKE key).

**Conditions required:**
- Attacker must be chosen as a guardian by at least one user
- The affected user must create a backup including the malicious guardian
- No special timing or race conditions needed

**Frequency:**
- Can be exploited repeatedly for every backup that includes the malicious guardian
- Permanent impact on all affected backups
- Easy to execute: only requires crafting a malicious AccountState

**Realistic scenario:**
A sophisticated attacker posing as a legitimate guardian service could deploy this attack against multiple users, gradually compromising backup secrets across the network.

## Recommendation

Add validation to ensure guardian PKE public keys are not the identity point before using them in backup encryption:

1. **In `BackupCiphertextV0::new()`** (before line 377): Validate each guardian's encryption key is not identity:
   - Check that `guardian.encryption_key()` is not the curve identity element
   - Reject backup creation if any guardian has an invalid key

2. **In `AccountUpdate::verify_update()`** (after signature verification): Add validation for the new AccountState's PKE key:
   - Verify the `pke` field is not the identity point
   - This prevents malicious AccountStates from being accepted on-chain

3. **In `EncryptionKey::encrypt()`**: Add defensive check that `self.0` (the public key) is not identity before computing shared secret

Example validation (to be added):
```rust
// Check that PKE key is not the identity point
if guardian_pke.0.is_identity() {
    return Err(SwafeError::InvalidPublicKey);
}
```

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** `test_identity_guardian_key_vulnerability`

**Setup:**
1. Create a legitimate owner account using `AccountSecrets::gen()`
2. Create a malicious guardian account with valid signing key but identity PKE key
3. The malicious AccountState should have `pke` field manually set to `G1Affine::identity()`
4. Create test data to be backed up

**Trigger:**
1. Owner creates a backup with threshold 1, including the malicious guardian: `owner.backup(..., &[malicious_guardian_state], 1)`
2. The backup is created successfully (vulnerability: no validation)
3. Attempt to decrypt the share using a predictable key derived from identity point

**Observation:**
- The backup creation succeeds without error (should fail)
- The share encrypted for the malicious guardian can be decrypted without the guardian's private key
- The decryption uses only public information: the identity point as the "shared secret"
- Test confirms that `(identity * random_scalar).serialize() == identity.serialize()` always holds
- Anyone can compute the same encryption key and decrypt the share

The test demonstrates that the threshold security is broken: a share that should only be decryptable by the guardian's private key is instead publicly decryptable.

### Citations

**File:** lib/src/backup/v0.rs (L377-377)
```rust
        let pks = guardians.iter().map(|guardian| guardian.encryption_key());
```

**File:** lib/src/crypto/pke/v0.rs (L99-131)
```rust
    pub fn encrypt<M: Tagged, A: Tagged, R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        msg: &M,
        ctx: &A,
    ) -> Ciphertext {
        // generate diffie-hellman key
        let ts: curve::Fr = rng.gen();
        let tp: curve::GAffine = (curve::GAffine::generator() * ts).into();

        // compute shared secret
        let mut ikm = vec![];
        (self.0 * ts)
            .into_affine()
            .serialize_compressed(&mut ikm)
            .unwrap();

        // encrypt with symmetric encryption
        let ct = sym::seal(
            rng,
            &kdfn(
                &ikm,
                &DiffieHellmanCtx {
                    tp, //
                    pk: self.0,
                },
            ),
            msg,
            ctx,
        );

        Ciphertext { tp, ct }
    }
```

**File:** lib/src/account/v0.rs (L786-834)
```rust
    /// Verify an update to the account returns the new state of the account
    pub(super) fn verify_update(self, old: &AccountStateV0) -> Result<AccountStateV0> {
        match self.msg {
            AccountMessageV0::Update(auth) => {
                let st = auth.state;
                // version must increase by exactly one
                if Some(st.cnt) != old.cnt.checked_add(1) {
                    return Err(SwafeError::InvalidAccountStateVersion);
                }

                // verify signature using old verification key
                old.sig.verify(&auth.sig, &st)?;

                // Return the new state as provided in the update
                Ok(st)
            }
            AccountMessageV0::Recovery(recovery) => {
                // Handle recovery update: set the recovery pke field in the account state
                let mut new_state = old.clone();

                {
                    let rec = &mut new_state.rec;
                    // Verify the recovery request signature
                    let recovery_msg = RecoveryRequestMessage {
                        account_id: self.acc,
                        recovery_pke: recovery.pke.clone(),
                    };

                    // Find the matching association and verify signature
                    let mut verified = false;
                    for assoc in &rec.assoc {
                        // Verify signature using the recovery signing key from associations
                        if assoc.sig.verify(&recovery.sig, &recovery_msg).is_ok() {
                            verified = true;
                            break;
                        }
                    }

                    if !verified {
                        return Err(SwafeError::InvalidSignature);
                    }

                    // Set the recovery PKE to indicate recovery has been initiated
                    rec.pke = Some(recovery.pke);
                }
                Ok(new_state)
            }
        }
    }
```
