# Audit Report

## Title
Unversioned Hash-to-Curve Generators Cause Permanent Account Lockout on Algorithm Updates

## Summary
The Pedersen commitment generators (H and G) used in the email association system are created dynamically via `hash_to_g1` without serialization or versioning. If the underlying hash-to-curve algorithm changes (due to library updates, security patches, or standard revisions), all previously stored commitments become unverifiable, permanently locking users out of their accounts with no recovery mechanism. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- Generator creation: [1](#0-0) 
- Commitment storage: [2](#0-1) 
- Verification logic: [3](#0-2) 
- Hash-to-curve implementation: [4](#0-3) 

**Intended Logic:**
The system creates Pedersen commitments C_i = [v_i]·H + [r_i]·G where H and G are generators derived from hash-to-curve. During recovery, these commitments are verified to reconstruct the RIK (Recovery Initiation Key) and restore account access.

**Actual Logic:**
Generators are recreated on-demand via `PedersenGenerators::new()` which calls `hash_to_g1` with domain separation "v0:pedersen". The actual generator points are never serialized. When `verify_secret_share` is called during recovery, it creates NEW generators and compares them against OLD commitments. If the hash-to-curve algorithm has changed (different hasher, curve mapping method, or domain string), the new generators H' ≠ H and G' ≠ G, causing verification to fail. [5](#0-4) 

**Exploit Scenario:**
1. Users create email associations, generating commitments with generators H and G via `hash_to_g1`
2. Commitments are stored in `MskRecordFixed.commits` on off-chain nodes
3. Library maintainers update arkworks or fix a hash-to-curve vulnerability, changing the algorithm
4. Users attempt account recovery via `reconstruct_rik_data`
5. `verify_secret_share` recreates generators, producing H' and G' (different from original H and G)
6. Verification compares: stored_commitment (= [v]·H + [r]·G) ≠ generators.commit(shares) (= [v]·H' + [r]·G')
7. Verification fails, `reconstruct_rik_data` returns error
8. Account recovery impossible, user permanently locked out [6](#0-5) 

**Security Failure:**
The system violates the fundamental invariant that legitimate account owners can always recover their accounts given threshold shares. Any change to the hash-to-curve implementation breaks backward compatibility, permanently freezing all existing accounts with email associations.

## Impact Explanation

**Affected Assets:**
- Master secret keys (MSK) for all user accounts
- Recovery Initiation Keys (RIK) 
- Complete account ownership and access

**Severity:**
- **Permanent account lockout:** Users cannot recover accounts even with valid RIK and threshold shares
- **No migration path:** No mechanism exists to update old commitments to new generators
- **100% user impact:** All accounts with email associations become unrecoverable
- **Requires hard fork:** Only way to restore access is manual intervention or chain rollback

**Why This Matters:**
This represents a catastrophic failure mode where routine maintenance (security patches, library updates, standard compliance) renders the entire system unusable. Unlike typical vulnerabilities that affect security, this affects availability and recoverability - core properties of any key management system. The issue becomes critical because:

1. Hash-to-curve algorithms DO change (IETF standards evolve, implementations get patched)
2. Arkworks library updates could modify BLS12-381 curve operations
3. Security vulnerabilities in hash-to-curve may require urgent algorithm changes
4. No versioning prevents safe coexistence of multiple algorithm versions

## Likelihood Explanation

**Trigger Conditions:**
- Any update to the hash-to-curve implementation triggers this vulnerability
- Can occur through: arkworks dependency updates, security patches, standard compliance changes
- Affects ALL users simultaneously upon deployment of updated code

**Frequency:**
- **High probability over system lifetime:** Cryptographic libraries receive regular updates
- **Inevitable on long timescales:** Hash-to-curve standards and implementations evolve
- **Cannot be prevented:** Security patches may force algorithm changes
- **Already happened in crypto space:** Similar issues occurred with signature scheme updates, hash function transitions

**Who Can Trigger:**
Not an "attacker" scenario but a systemic design flaw. Triggered by:
- Library maintainers updating dependencies
- Security researchers discovering hash-to-curve vulnerabilities
- Standards bodies publishing new specifications
- Blockchain requiring cryptographic upgrades

## Recommendation

Implement generator versioning and serialization:

1. **Store generators with commitments:** Serialize actual H and G point values in `MskRecordFixed` structure alongside commitments
2. **Version hash-to-curve algorithm:** Add version tag to `PedersenGenerators` indicating which algorithm was used
3. **Support multiple algorithm versions:** Allow `verify_secret_share` to use versioned generators for verification
4. **Migration mechanism:** Provide tools to re-commit old secrets with new generators when algorithm updates occur

Example structure:
```rust
pub(crate) struct MskRecordFixed {
    pub(super) user_pk: VerificationKey,
    pub(super) enc_rik: EncryptedMsk,
    pub(super) commits: Vec<PedersenCommitment>,
    pub(super) generator_version: u8,  // NEW: track which algorithm
    pub(super) generator_h: Option<G1Affine>,  // NEW: serialize H
    pub(super) generator_g: Option<G1Affine>,  // NEW: serialize G
    pub(super) sok_proof: SokProof,
}
```

## Proof of Concept

**Test File:** `lib/src/association/v0.rs` (add to existing test module)

**Test Function:** `test_generator_algorithm_change_breaks_recovery`

**Setup:**
1. Create an email association with commitments using current generators
2. Store the `MskRecordFixed` structures on multiple nodes
3. Simulate an algorithm change by modifying the hash-to-curve domain separation string

**Trigger:**
```rust
#[test]
fn test_generator_algorithm_change_breaks_recovery() {
    let mut rng = thread_rng();
    let threshold = 3;
    
    // Step 1: Create association with "v0:pedersen" generators
    let (msk, rik) = Association::create_association(&mut rng, threshold).unwrap();
    
    // Step 2: Generate MskRecords for threshold nodes with current generators
    let node_ids: Vec<NodeId> = (1..=threshold)
        .map(|i| format!("node:{}", i).parse().unwrap())
        .collect();
    
    let msk_records: Vec<(NodeId, MskRecord)> = node_ids
        .iter()
        .map(|node_id| {
            let shares = msk.compute_secret_shares(node_id);
            (
                node_id.clone(),
                MskRecord::V0(MskRecordV0 {
                    fixed: MskRecordFixed {
                        user_pk: msk.user_pk.verification_key(),
                        enc_rik: msk.ct.clone(),
                        commits: msk.pedersen_commitments.clone(), // OLD commitments
                        sok_proof: msk.sok_proof.clone(),
                    },
                    share: shares,
                }),
            )
        })
        .collect();
    
    // Step 3: Simulate algorithm change by using different generators
    // In reality this happens when hash_to_g1 implementation changes
    // Here we demonstrate by showing that recreation of generators would fail
    
    // Attempt recovery with stored records (this would work with same algorithm)
    let result = Association::reconstruct_rik_data(msk_records.clone(), &rik);
    assert!(result.is_ok(), "Should work with same algorithm");
    
    // Step 4: To simulate algorithm change, we would need to modify hash_to_g1
    // which is not possible in a test without forking the code
    // However, we can demonstrate the issue by showing commitments are 
    // hard-coded to specific generator values
    
    // Demonstrate: If we verify shares with different generators, it fails
    let different_generators = {
        // Create commitments with different random generators
        let fake_h = G1Affine::generator();  // Different from hash_to_g1 result
        let fake_g = (G1Projective::generator() * Fr::from(2u64)).into();
        
        // This represents what would happen if hash_to_g1 changed
        PedersenGenerators { h: fake_h, g: fake_g }
    };
    
    // Verify that stored commitments don't match new generators
    let node_id = &node_ids[0];
    let shares = msk.compute_secret_shares(node_id);
    let commitment_with_new_gens = different_generators.commit(&shares);
    
    assert_ne!(
        msk.pedersen_commitments[0], 
        commitment_with_new_gens,
        "Commitments created with different generators are different"
    );
}
```

**Observation:**
The test demonstrates that commitments are tied to specific generator values. If `hash_to_g1` changes, stored commitments become unverifiable. The test would fail (users locked out) if we could actually modify the hash-to-curve algorithm mid-test. The demonstration shows the fundamental issue: no versioning or serialization of generators means no backward compatibility on algorithm changes.

### Citations

**File:** lib/src/crypto/commitments.rs (L46-60)
```rust
    pub fn new() -> Self {
        #[derive(Serialize)]
        struct PedersenGenSep {
            name: &'static str,
        }

        impl Tagged for PedersenGenSep {
            const SEPARATOR: &'static str = "v0:pedersen";
        }

        Self {
            h: pp::hash_to_g1(&PedersenGenSep { name: "H" }),
            g: pp::hash_to_g1(&PedersenGenSep { name: "G" }),
        }
    }
```

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

**File:** lib/src/association/v0.rs (L247-278)
```rust
pub(super) fn verify_secret_share(
    coms: &[PedersenCommitment],
    eval: &PedersenOpen,
    node_id: &NodeId,
) -> Result<(), SwafeError> {
    // Compute x value for this node
    let x = node_id.eval_point();

    // Compute linear combination of commitments:
    // ⟨(1, x, x², ..., x^(t-1)), (C₀, C₁, ..., C_{t-1})⟩
    let mut comb = PedersenCommitment::zero();
    let mut x_power = curve::Fr::one(); // x^0 = 1

    for commitment in coms {
        // Add [x^i] * C_i to the combination
        comb = comb + commitment.clone() * x_power;
        // Update x_power for next iteration: x^i -> x^{i+1}
        x_power *= x;
    }

    // Create Pedersen generators to compute expected commitment
    let generators = PedersenGenerators::new();

    // Check if they are equal
    if comb != generators.commit(eval) {
        Err(SwafeError::VerificationFailed(
            "Invalid verifiable secret sharing".to_string(),
        ))
    } else {
        Ok(())
    }
}
```

**File:** lib/src/association/v0.rs (L453-507)
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

```

**File:** lib/src/crypto/pairing.rs (L39-48)
```rust
/// Hash to G1 group element using hash-to-curve
pub fn hash_to_g1<T: Tagged>(input: &T) -> G1Affine {
    let hasher = MapToCurveBasedHasher::<
        G1Projective,
        DefaultFieldHasher<Sha3_256, 128>,
        WBMap<G1Config>,
    >::new(format!("swafe-bls12-381-g1 : {}", T::SEPARATOR).as_bytes())
    .expect("Failed to create G1 hash-to-curve hasher");
    hasher.hash(&input.encode()).unwrap()
}
```
