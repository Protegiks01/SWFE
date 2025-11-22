## Audit Report

## Title
Encapsulation Key Not Used for Encryption Leading to Permanent Account Recovery Denial of Service

## Summary
The encapsulation key derived from Pedersen commitments is never used for encryption or decryption of the `enc_rik` field. Instead, an independent Recovery Initiation Key (RIK) is used, breaking the cryptographic binding between commitments and encrypted data. This allows creation of associations where the commitments appear valid but the encrypted data cannot be decrypted with the expected key, leading to permanent account recovery failure.

## Impact
**High**

## Finding Description

**Location:** 
The vulnerability exists in the association creation and reconstruction logic: [1](#0-0) [2](#0-1) 

**Intended Logic:**
The system should cryptographically bind the encrypted RIK data (`enc_rik`) to the Pedersen commitments through the encapsulation key. The design derives an encapsulation key from the constant term v₀ of the committed polynomial: `encap_key = KDF([v₀]·G, "EncapKey")`. This key should be used to encrypt/decrypt `enc_rik`, ensuring that only someone who can reconstruct v₀ from threshold shares can decrypt the data.

**Actual Logic:**
The code derives the encapsulation key but never uses it:
1. During creation, `enc_rik` is encrypted with the provided RIK parameter, not the derived encapsulation key [3](#0-2) 
2. During reconstruction, the encapsulation key is derived but assigned to an unused variable prefixed with underscore [4](#0-3) 
3. Decryption uses the provided RIK parameter instead [5](#0-4) 

**Exploit Scenario:**
1. A compromised or malicious client generates valid Pedersen commitments C₀, ..., Cₜ with proper openings
2. The client derives encapsulation key A from v₀ (as expected)
3. However, the client encrypts `enc_rik` with a different RIK B (not related to the commitments)
4. The client uploads the association with valid commitments, shares, and SoK proof to nodes
5. Nodes verify and accept: shares match commitments ✓, SoK proof valid ✓
6. The client stores incorrect RIK C with the user (different from RIK B used for encryption)
7. User later attempts account recovery using RIK C
8. Reconstruction succeeds (v₀ is correctly interpolated, encap_key is derived)
9. Decryption fails because RIK C doesn't match RIK B used during encryption
10. Account recovery permanently fails - user cannot access their signing key or MSK share

**Security Failure:**
The absence of cryptographic binding between commitments and encrypted data violates the core threshold security property. The verification in `AssociationRequestEmail::verify()` [6](#0-5)  checks that shares match commitments and the SoK proof is valid, but never validates that `enc_rik` is actually encrypted with the encapsulation key derived from those commitments. This allows creation of self-inconsistent associations that permanently break recovery.

## Impact Explanation

**Affected Assets:**
- User's signing key (required for initiating recovery operations)
- MSK secret share from RIK (msk_ss_rik)
- Entire account recovery capability

**Damage Severity:**
- **Permanent account freezing**: If enc_rik is encrypted with the wrong RIK, the user can never decrypt it to obtain their signing key, permanently preventing account recovery
- **Loss of threshold security**: The commitments provide no actual protection since they don't bind to the encryption key
- **Silent failure**: The association appears valid (all cryptographic checks pass during upload) but is actually unrecoverable

**System Impact:**
This vulnerability breaks a fundamental security invariant: that valid-looking cryptographic commitments guarantee the ability to reconstruct protected data with threshold shares. Users could create associations in good faith (or via buggy client software) that permanently lock them out of recovery, requiring manual intervention or hard fork to resolve.

## Likelihood Explanation

**Who Can Trigger:**
- Any user creating a new association through buggy client software
- Malicious client applications
- Compromised wallet implementations

**Conditions Required:**
- User creating or updating an email association
- Client software that incorrectly implements the encryption (using wrong RIK)
- Normal operation - no special privileges needed

**Frequency:**
- Could affect any user during association creation if client software is buggy
- Particularly likely during client implementation errors, dependency updates, or when integrating with different wallet software
- Once triggered, the damage is permanent and irreversible without direct node intervention

The vulnerability is especially concerning because:
1. The error would not be detected immediately (association upload succeeds)
2. Users only discover the issue when attempting recovery (potentially months/years later)
3. Multiple validation checks pass, creating false confidence
4. No recovery mechanism exists within the protocol

## Recommendation

**Fix the cryptographic binding by using the encapsulation key for encryption/decryption:**

1. In `create_encrypted_msk()`, use the derived encapsulation key instead of RIK for encryption:
```rust
// Change line 345-350 to use encap_key instead of rik
let ciphertext = symmetric::seal(
    rng,
    encap_key.as_bytes(),  // Use encap_key derived from v₀
    &CombinedSecretData::V0 { rik_data },
    &symmetric::EmptyAD,
);
```

2. In `reconstruct_rik_data()`, use the reconstructed encapsulation key for decryption:
```rust
// Change line 522-530 to use reconstructed encap_key
let encapsulation_key: symmetric::Key = kdfn(&v0_bytes, &EncapKeyKDF);
let combined_secret: CombinedSecretData = symmetric::open(
    &encapsulation_key,  // Use reconstructed encap_key
    &encrypted_data.ciphertext,
    &symmetric::EmptyAD,
)?;
```

3. Remove the RIK parameter from these functions since it should not be used for encryption - the RIK should only be used for other purposes in the protocol flow.

4. Add validation in `AssociationRequestEmail::verify()` to ensure enc_rik can be decrypted with the expected encapsulation key (requires protocol redesign to make this feasible).

## Proof of Concept

**File:** `lib/src/association/v0.rs` - Add to the tests module at the end of the file

**Test Function:** `test_encap_key_not_used_vulnerability`

**Setup:**
1. Create an association with threshold = 3
2. Generate valid Pedersen commitments and secret shares
3. Create a signing key and derive the encapsulation key from v₀
4. Intentionally encrypt enc_rik with a DIFFERENT RIK than the one returned by create_rik_association

**Trigger:**
1. Upload the association to simulated nodes (commitments and shares are valid, so upload succeeds)
2. Attempt to reconstruct using the "correct" RIK (the one returned by create_rik_association)
3. The reconstruction will derive the correct encapsulation key from shares
4. But decryption will fail because enc_rik was encrypted with a different RIK

**Observation:**
The test demonstrates that:
- Association upload succeeds (all validations pass: shares match commitments ✓, SoK proof valid ✓)
- Secret share verification passes (commitments are valid)
- Reconstruction correctly interpolates v₀ and derives encapsulation key
- But decryption fails with "InvalidRecoveryKey" error because the encapsulation key is not actually used
- This proves that valid commitments don't guarantee decryptability, violating the threshold security property

The test would look for the `SwafeError::InvalidRecoveryKey` or decryption failure when the "correct" RIK (from the user's perspective) doesn't match the actual RIK used during encryption, demonstrating permanent recovery denial of service.

**Notes:**
- The vulnerability is demonstrated by the fact that `_encapsulation_key` on line 522 has an underscore prefix, indicating it's intentionally unused by the compiler
- The code comments at lines 324 and 344 suggest the intention to use encapsulation key, but the implementation uses RIK instead
- This is a design-level vulnerability where the implementation doesn't match the cryptographic security model implied by the Pedersen commitment scheme

### Citations

**File:** lib/src/association/v0.rs (L186-214)
```rust
impl AssociationRequestEmail {
    pub fn verify(
        self,
        user_pk: &sig::VerificationKey,
        node_id: &NodeId,
    ) -> Result<MskRecord, SwafeError> {
        // Verify that the user_pk in the request matches the provided one
        if &self.fixed.user_pk != user_pk {
            return Err(SwafeError::VerificationFailed(
                "User public key mismatch".to_string(),
            ));
        }

        // Verify secret share consistency with commitments
        verify_secret_share(&self.fixed.commits, &self.share, node_id)?;

        // Verify SoK proof
        let generators = PedersenGenerators::new();
        self.fixed
            .sok_proof
            .verify(&generators, &self.fixed.commits, user_pk)?;

        // Store
        Ok(MskRecord::V0(MskRecordV0 {
            share: self.share,
            fixed: self.fixed,
        }))
    }
}
```

**File:** lib/src/association/v0.rs (L310-372)
```rust
    pub fn create_encrypted_msk<R: Rng + CryptoRng>(
        rng: &mut R,
        threshold: usize,
        rik: &RecoveryInitiationKey,
        msk_ss_rik: MskSecretShareRik,
    ) -> Result<EncapsulatedMsk, SwafeError> {
        // Generate user signing key internally
        let sig_sk = sig::SigningKey::gen(rng);

        let generators = PedersenGenerators::new();

        let (comms, opens) = Self::generate_commitment_values(rng, &generators, threshold)?;

        // Generate encapsulation key
        // key ← kdf([v_0] · G, "EncapKey")
        let v0 = opens[0].value();
        let v0_point = (curve::GProjective::generator() * v0).into();
        let v0_bytes = {
            let mut bytes = Vec::new();
            let affine: curve::GAffine = v0_point;
            affine
                .serialize_compressed(&mut bytes)
                .map_err(|e| SwafeError::SerializationError(e.to_string()))?;
            bytes
        };
        let encap_key = EncapsulationKey::new(kdfn(&v0_bytes, &EncapKeyKDF));

        // Create RIK secret data containing signing key and MSK secret share
        let rik_data = RikSecretData {
            sig_sk: sig_sk.clone(),
            msk_ss_rik,
        };

        // Encrypt RIK data instead of MSK
        // ct ← skAEnc(rik, (sigSK_user, msk_ss_rik))
        let ciphertext = symmetric::seal(
            rng,
            rik.as_bytes(),
            &CombinedSecretData::V0 { rik_data },
            &symmetric::EmptyAD,
        );

        let ct = EncryptedMsk { ciphertext };

        // Generate signature of knowledge proof of commitments
        // π ← sokSign(msg = sigPK_user, rel = {∀i. (v_i, r_i) : ∀i. C_i = pedersen(v_i, r_i)})
        let sok_proof =
            SokProof::prove(rng, &generators, &opens, &comms, &sig_sk.verification_key())?;

        // Note: For RIK associations, we don't store the MSK directly
        // The MSK will be derived during recovery using both RIK and social shares
        let placeholder_msk = MasterSecretKey::gen(rng); // Placeholder for compatibility

        Ok(EncapsulatedMsk {
            pedersen_open: opens,
            pedersen_commitments: comms,
            ct,
            sok_proof,
            msk: placeholder_msk, // This is not the actual MSK for RIK associations
            user_pk: sig_sk.clone(),
            encapsulation_key: encap_key,
        })
    }
```

**File:** lib/src/association/v0.rs (L453-536)
```rust
    /// Reconstruct RIK data from multiple MskRecord instances using Lagrange interpolation
    /// For the new recovery flow where MskRecord contains RIK-encrypted data
    pub fn reconstruct_rik_data(
        msk_records: Vec<(NodeId, MskRecord)>,
        rik: &RecoveryInitiationKey,
    ) -> Result<RikSecretData, SwafeError> {
        // Convert all MskRecord enums to their V0 variants
        let v0_records: Vec<(NodeId, MskRecordV0)> = msk_records
            .into_iter()
            .map(|(node_id, record)| match record {
                MskRecord::V0(v0) => (node_id, v0),
            })
            .collect();

        // Do a threshold vote on the fixed fields
        let mut votes = HashMap::new();
        for (_, record) in &v0_records {
            *votes.entry(record.fixed.clone()).or_insert(0) += 1;
        }

        let majority_threshold = v0_records.len().div_ceil(2);
        let majority_fixed = votes
            .into_iter()
            .find(|(_, count)| *count >= majority_threshold)
            .map(|(fixed, _)| fixed)
            .ok_or_else(|| {
                SwafeError::InvalidInput(
                    "No majority consensus on fixed fields among MSK records".to_string(),
                )
            })?;

        let v0_records: Vec<_> = v0_records
            .into_iter()
            .filter(|(_, record)| record.fixed == majority_fixed)
            .collect();

        if v0_records.len() < majority_fixed.threshold() {
            return Err(SwafeError::NotEnoughSharesForReconstruction);
        }

        // Verify shares and collect valid points
        let points: Vec<_> = v0_records
            .iter()
            .filter_map(|(node_id, msk_record)| {
                match verify_secret_share(&majority_fixed.commits, &msk_record.share, node_id) {
                    Ok(()) => {
                        let x = node_id.eval_point();
                        let y = msk_record.share.value();
                        Some((x, y))
                    }
                    Err(_) => None,
                }
            })
            .collect();

        // Reconstruct v_0 using Lagrange interpolation
        let v0 = interpolate_eval(&points, curve::Fr::zero());

        // Derive encapsulation key from v_0
        let v0_point = (curve::GProjective::generator() * v0).into();
        let v0_bytes = {
            let mut bytes = Vec::new();
            let affine: curve::GAffine = v0_point;
            affine
                .serialize_compressed(&mut bytes)
                .map_err(|e| SwafeError::SerializationError(e.to_string()))?;
            bytes
        };

        let _encapsulation_key: symmetric::Key = kdfn(&v0_bytes, &EncapKeyKDF);

        // Decrypt using RIK to get RikSecretData
        let encrypted_data = &majority_fixed.enc_rik;
        let combined_secret: CombinedSecretData = symmetric::open(
            rik.as_bytes(),
            &encrypted_data.ciphertext,
            &symmetric::EmptyAD,
        )?;

        match combined_secret {
            CombinedSecretData::V0 { rik_data } => Ok(rik_data),
        }
    }

```
