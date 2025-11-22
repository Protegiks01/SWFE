## Title
Missing User Signature on MskRecordFixed Enables Association Substitution Attack Leading to Permanent Secret Freezing

## Summary
The `MskRecordFixed` structure containing Pedersen commitments, encrypted RIK data, and SoK proof lacks user signature protection. While SoK proofs serialize `delta` and `alpha` fields and prove knowledge of commitment openings, they do not authenticate that the proof was created by the legitimate user. An attacker can intercept association upload requests and substitute the entire `MskRecordFixed` with their own malicious data, causing permanent freezing of the victim's secrets.

## Impact
High

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended Logic:** 
The system should ensure that association data (commitments, encrypted secrets, and SoK proofs) uploaded for a user's email can only be created by that user. The SoK proof is intended to prove knowledge of commitment openings and bind them to the user's public key.

**Actual Logic:** 
The SoK proof verification only checks that someone knows the openings to the commitments with `user_pk` as the message in the challenge computation: [3](#0-2) 

The `user_pk` in the proof message does not require the prover to possess the corresponding private key. The verification in `AssociationRequestEmail::verify` only checks:
1. That `fixed.user_pk` matches the email certificate's `user_pk`
2. That the SoK proof is valid for the commitments
3. That secret shares are consistent with commitments [4](#0-3) 

None of these checks authenticate that the `MskRecordFixed` was actually created by the legitimate user.

**Exploit Scenario:**

1. **Victim creates legitimate association:** User generates `AssociationRequestEmail` with their commitments C_0...C_{t-1}, RIK-encrypted data, and SoK proof
2. **Attacker intercepts request:** MitM on the network path to the off-chain node
3. **Attacker creates malicious data:**
   - Generates their own commitments C'_0...C'_{t-1} (knows the openings)
   - Creates their own encrypted data using attacker's RIK (not victim's RIK)
   - Generates valid SoK proof for their commitments with message = victim's `user_pk`
   - Computes consistent secret shares for their commitments
4. **Attacker substitutes the association:**
   - Keeps original email cert token (unchanged)
   - Replaces `association.fixed.commits` with C'_0...C'_{t-1}
   - Replaces `association.fixed.enc_rik` with attacker's encrypted data
   - Replaces `association.fixed.sok_proof` with attacker's proof
   - Replaces `association.share` with attacker's share
   - Keeps `association.fixed.user_pk` = victim's public key
5. **All verifications pass:**
   - Email certificate authenticates victim owns the email
   - `user_pk` check passes (line 193-196 in v0.rs)
   - SoK proof verification passes (attacker knows openings to their commitments)
   - Secret share consistency passes (attacker's shares match their commitments)
6. **Attacker's data gets stored** under victim's email
7. **Recovery fails permanently:** When victim tries to recover, they get attacker's `enc_rik` which cannot be decrypted with victim's RIK [5](#0-4) 

**Security Failure:** 
The association binding invariant is broken: the uploaded association data is not authenticated as belonging to the user who owns the email. This allows unauthorized replacement of association data, causing permanent denial of recovery service.

## Impact Explanation

**Affected Assets:**
- Victim's master secret key recovery capability
- Victim's encrypted RIK data 
- Victim's backup reconstruction ability

**Damage Severity:**
- **Permanent freezing of secrets:** The victim's backup is permanently frozen. During recovery, they receive encrypted data (`enc_rik`) that was encrypted with the attacker's RIK, not their own RIK. Decryption fails, making recovery impossible.
- **Loss of account access:** The victim cannot recover their account through the social recovery mechanism, effectively losing access to any secrets or funds protected by that account.
- **Unrecoverable state:** Since the malicious data wins the majority vote during reconstruction (if attacker MitM'd requests to all nodes), there is no way to recover the legitimate association data without protocol-level intervention.

**System Impact:**
This breaks the core security guarantee that only the legitimate account owner can store association data for their email. It enables a network-level attacker to permanently deny users their recovery capability, which is the primary security feature of the Swafe protocol.

## Likelihood Explanation

**Who can trigger it:**
Any network-level attacker capable of intercepting HTTP requests between the user and off-chain nodes (man-in-the-middle attacker).

**Required conditions:**
- User is uploading an association (normal operation during account setup)
- Attacker has network position to intercept and modify requests
- Attacker intercepts requests to a majority of nodes (to win the majority vote during reconstruction)

**Frequency:**
- Can occur during any association upload operation
- Every user setting up social recovery is potentially vulnerable
- In networks with compromised routers, ISPs, or malicious proxies, this could affect a significant percentage of users
- The attack is undetectable to the victim until they attempt recovery and it fails

The attack is practical and exploitable during normal protocol operation. Network-level MitM attacks are realistic threat vectors, especially for web applications where users may connect through untrusted networks.

## Recommendation

Add user signature protection to `MskRecordFixed`:

1. **Extend `MskRecordFixed` structure** to include a user signature field:
   ```rust
   pub(crate) struct MskRecordFixed {
       pub(super) user_pk: VerificationKey,
       pub(super) enc_rik: EncryptedMsk,
       pub(super) commits: Vec<PedersenCommitment>,
       pub(super) sok_proof: SokProof,
       pub(super) user_sig: sig::Signature,  // NEW: User's signature over the entire structure
   }
   ```

2. **During association creation**, the user signs the hash of `(user_pk, enc_rik, commits, sok_proof)` using their private key.

3. **During verification** in `AssociationRequestEmail::verify()`, add signature verification:
   ```rust
   // Create a structure to sign
   #[derive(Serialize)]
   struct SignedData {
       user_pk: VerificationKey,
       enc_rik: EncryptedMsk,
       commits: Vec<PedersenCommitment>,
       sok_proof: SokProof,
   }
   
   // Verify user's signature on the fixed data
   let signed_data = SignedData {
       user_pk: self.fixed.user_pk.clone(),
       enc_rik: self.fixed.enc_rik.clone(),
       commits: self.fixed.commits.clone(),
       sok_proof: self.fixed.sok_proof.clone(),
   };
   user_pk.verify(&self.fixed.user_sig, &signed_data)?;
   ```

This ensures that only the user possessing the private key can create valid `MskRecordFixed` structures, preventing substitution attacks.

## Proof of Concept

**File:** `lib/src/association/v0.rs`  
**Test function:** Add new test `test_association_substitution_attack`

**Setup:**
1. Create legitimate user with signing keypair
2. Create attacker with their own signing keypair and RIK
3. User creates legitimate `EncapsulatedMsk` for threshold=3
4. Attacker creates their own malicious `EncapsulatedMsk` with same threshold
5. Create email certificate for the legitimate user

**Trigger:**
1. User generates legitimate `AssociationRequestEmail` for node:1
2. Attacker intercepts and creates substituted request:
   - Keeps same `user_pk` from legitimate user
   - Replaces all other fields (commits, enc_rik, sok_proof, share) with attacker's data
3. Submit the substituted request to verification

**Observation:**
- The substituted request **passes verification** (demonstrates the vulnerability)
- When victim attempts recovery using their RIK, decryption **fails** because `enc_rik` was encrypted with attacker's RIK
- This confirms permanent freezing of the victim's secrets

**Test Code Structure:**
```rust
#[test]
fn test_association_substitution_attack() {
    let mut rng = thread_rng();
    
    // 1. Setup: Legitimate user
    let user_sk = sig::SigningKey::gen(&mut rng);
    let user_pk = user_sk.verification_key();
    let (user_msk, user_rik) = Association::create_association(&mut rng, 3).unwrap();
    
    // 2. Setup: Attacker creates malicious data
    let attacker_sk = sig::SigningKey::gen(&mut rng);
    let (attacker_msk, attacker_rik) = Association::create_association(&mut rng, 3).unwrap();
    
    let node_id: NodeId = "node:1".parse().unwrap();
    
    // 3. Attacker creates substituted request with victim's user_pk
    let attacker_share = attacker_msk.compute_secret_shares(&node_id);
    let substituted_request = AssociationRequestEmail {
        fixed: MskRecordFixed {
            user_pk: user_pk.clone(),  // Keep victim's public key
            enc_rik: attacker_msk.ct.clone(),  // Attacker's encrypted data
            commits: attacker_msk.pedersen_commitments.clone(),  // Attacker's commitments
            sok_proof: attacker_msk.sok_proof.clone(),  // Attacker's proof
        },
        share: attacker_share,  // Attacker's share
    };
    
    // 4. Verification passes (demonstrates vulnerability)
    let verified_record = substituted_request.verify(&user_pk, &node_id);
    assert!(verified_record.is_ok(), "Substituted request should pass verification");
    
    // 5. Victim's recovery fails (permanent freezing)
    let stored_records = vec![(node_id.clone(), verified_record.unwrap())];
    let recovery_result = Association::reconstruct_rik_data(stored_records, &user_rik);
    assert!(recovery_result.is_err(), "Recovery should fail with victim's RIK");
    
    // The vulnerability is confirmed: attacker can substitute association data
    // and victim's recovery is permanently frozen
}
```

### Citations

**File:** lib/src/association/v0.rs (L139-149)
```rust
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct MskRecordFixed {
    /// User's signature public key
    pub(super) user_pk: VerificationKey,
    /// Encrypted RIK data (contains signing key and MSK secret share from RIK)
    pub(super) enc_rik: EncryptedMsk,
    /// Pedersen commitments (C_0, ..., C_{threshold-1})
    pub(super) commits: Vec<PedersenCommitment>,
    /// Signature of Knowledge proof
    pub(super) sok_proof: SokProof,
}
```

**File:** lib/src/association/v0.rs (L186-213)
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
```

**File:** lib/src/association/v0.rs (L524-534)
```rust
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
```

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L60-64)
```rust
    MskRecordCollection::store(
        &mut ctx,
        email_tag,
        request.association.0.verify(user_pk, &node_id)?,
    );
```

**File:** lib/src/crypto/commitments.rs (L202-237)
```rust
    /// Verify a SoK proof for multiple Pedersen commitments
    /// Implements the verification procedure as specified in notation.md
    pub fn verify<T: Tagged>(
        &self,
        gens: &PedersenGenerators,
        coms: &[PedersenCommitment],
        msg: &T,
    ) -> Result<(), SwafeError> {
        if coms.is_empty() {
            return Err(SwafeError::InvalidInput("Empty commitment set".to_string()));
        }

        // 1. Recompute challenge alpha = H("SchnorrSoK", msg, Delta, C_0, ..., C_{n-1})
        let alpha = pp::hash_to_fr(&SokMessage {
            msg: hash(msg),
            delta: self.delta.clone(),
            commitments: coms,
        });

        // 2. Compute C_alpha = Delta + [alpha] * (sum_i [alpha^i] * C_i)
        let mut alpha_power = pp::Fr::ONE;
        let mut combine = PedersenCommitment::zero();
        for com in coms {
            combine = combine + com.clone() * alpha_power;
            alpha_power *= alpha;
        }

        // 3. Check C_alpha = pedersen(v_alpha, r_alpha)
        if self.delta.clone() + combine * alpha == gens.commit(&self.alpha) {
            Ok(())
        } else {
            Err(SwafeError::VerificationFailed(
                "Pedersen SoK Failure".to_string(),
            ))
        }
    }
```
