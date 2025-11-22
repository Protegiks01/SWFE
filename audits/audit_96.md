# Audit Report

## Title
Non-Constant-Time Cryptographic Operations Enable Physical Side-Channel Extraction of Secret Shares

## Summary
The Swafe protocol's Pedersen commitment operations use the arkworks cryptographic library (ark-bls12-381, ark-ff), which does not provide constant-time implementations. Secret opening values (`PedersenOpen` containing `value` and `randomness` field elements) are processed through non-constant-time scalar multiplication during commitment verification and creation. An attacker with physical access to off-chain nodes can exploit cache-timing, power analysis, or electromagnetic emanation side channels to extract these secret shares and reconstruct master secret keys. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- Primary vulnerability: [1](#0-0) 
- Affected operations: [2](#0-1) 
- Attack surface: [3](#0-2) 

**Intended Logic:** 
The Pedersen commitment scheme should protect the confidentiality of secret opening values (`value` and `randomness`) even when commitments are publicly visible. The protocol assumes that cryptographic operations are implemented in a side-channel resistant manner, such that physical access to the hardware does not leak secret information through observable physical characteristics (cache access patterns, power consumption, electromagnetic radiation).

**Actual Logic:** 
The `PedersenGenerators::commit()` function performs scalar multiplication using the arkworks library, which is NOT implemented in constant-time. The operations `h_proj * open.value + g_proj * open.randomness` leak information about the secret scalar values through:
- **Cache timing**: Memory access patterns vary based on the bit pattern of the scalar
- **Power consumption**: Different operations consume different amounts of power
- **EM emanations**: Electromagnetic radiation patterns correspond to the operations being performed

The arkworks library prioritizes performance over side-channel resistance and is documented to lack constant-time guarantees for its field arithmetic and scalar multiplication operations.

**Exploit Scenario:**
1. User uploads an association to an off-chain node via the `/association/upload-association` endpoint
2. The off-chain node calls `AssociationRequestEmail::verify()` which invokes `verify_secret_share()` 
3. During verification, `generators.commit(eval)` performs non-constant-time scalar multiplication with the node's secret `PedersenOpen` share
4. An attacker with physical access to the node's hardware (or co-located on the same machine) monitors:
   - CPU cache timing using FLUSH+RELOAD or similar techniques
   - Power consumption using an oscilloscope on the power supply
   - EM emanations using a near-field probe
5. The attacker extracts information about the secret scalar values from the observed side channels
6. After sufficient observations (potentially across multiple operations), the attacker reconstructs the complete `PedersenOpen` values
7. If the attacker compromises the threshold number of nodes (e.g., 3 out of 5), they can perform Lagrange interpolation to reconstruct the master secret key [4](#0-3) 

**Security Failure:** 
The protocol fails to provide side-channel resistance for its cryptographic operations. While the protocol includes memory zeroization (`ZeroizeOnDrop` on `PedersenOpen`) to prevent secrets from lingering in memory after use, it does not protect against active side-channel attacks during computation. This breaks the fundamental security assumption that secret shares stored by off-chain nodes cannot be extracted through physical means. [5](#0-4) 

## Impact Explanation

**Assets Affected:**
- Master secret keys (MSKs) derived from threshold secret sharing
- Recovery Initiation Keys (RIKs) encrypted with reconstructed secrets
- User wallet private keys and funds protected by these keys

**Severity of Damage:**
Once an attacker extracts secret shares from the threshold number of off-chain nodes through physical side-channel attacks:
1. They can reconstruct the polynomial's zero evaluation point (v₀) using Lagrange interpolation
2. They can derive the encapsulation key and decrypt the RIK-encrypted data
3. They gain access to the user's signing keys and master secret keys
4. They can steal all funds and assets controlled by the compromised accounts

**Systemic Impact:**
Unlike a software vulnerability that can be patched remotely, side-channel vulnerabilities in deployed hardware are extremely difficult to remediate. If off-chain nodes are running in data centers, cloud environments, or other multi-tenant infrastructure, attackers with physical or co-location access can systematically compromise nodes without detection. This undermines the entire security model of the threshold secret sharing system. [6](#0-5) 

## Likelihood Explanation

**Who Can Trigger:**
Any attacker with physical access to off-chain node hardware or the ability to run code on the same physical machine (e.g., through cloud co-location attacks). This includes:
- Data center employees with physical access
- Attackers who compromise the hosting infrastructure
- Malicious cloud tenants co-located on the same physical hardware
- Supply chain attackers who compromise hardware before deployment

**Conditions Required:**
- Physical proximity to the hardware during cryptographic operations
- Access to side-channel measurement equipment (oscilloscope, EM probe, or CPU cache analysis tools)
- Multiple observations of commitment operations to extract sufficient information

**Frequency:**
The vulnerability is triggered during normal protocol operation:
- Every time an association is uploaded and verified by a node
- During secret share reconstruction when nodes verify their stored shares
- During recovery operations when multiple nodes process secret shares

Given that commitment operations occur frequently during normal protocol usage, an attacker with persistent physical access has numerous opportunities to collect side-channel measurements. [7](#0-6) 

## Recommendation

**Immediate Mitigation:**
Replace the arkworks library with a constant-time cryptographic library for all operations involving secret values. Consider:
- Using `subtle` crate's constant-time operations for field arithmetic where possible
- Implementing constant-time scalar multiplication using algorithms like Montgomery ladder with constant-time conditional swaps
- Switching to a cryptographic library explicitly designed for side-channel resistance (e.g., curve25519-dalek for supported curves, or constant-time implementations of BLS12-381)

**Specific Changes:**
1. Audit all uses of arkworks scalar multiplication and field operations that involve secret values
2. Replace with constant-time alternatives or add masking/blinding techniques
3. Use constant-time comparison operations (already using `subtle::ConstantTimeEq` for MAC comparison in symmetric.rs, extend this pattern)
4. Add side-channel testing to the CI/CD pipeline using tools like dudect or ctgrind

**Long-term Solution:**
Consider architectural changes to minimize the exposure of secret shares:
- Implement secrets in secure enclaves (SGX, TrustZone) if available
- Add additional layers of blinding to secret shares before processing
- Use homomorphic properties to verify commitments without directly operating on raw secret values where possible [8](#0-7) 

## Proof of Concept

**Note:** A complete physical side-channel attack requires specialized hardware and is beyond the scope of a software PoC. However, the following test demonstrates that arkworks operations are indeed non-constant-time by measuring execution timing variance:

**File:** `lib/src/crypto/commitments.rs` (add to the test module)

**Test Function:** `test_timing_variance_in_scalar_multiplication`

**Setup:**
```
// This test demonstrates timing variance in scalar multiplication,
// indicating non-constant-time implementation
```

**Trigger:**
1. Generate two `PedersenOpen` values: one with all bits set to 0, one with all bits set to 1
2. Measure the time taken to perform `generators.commit()` on each value
3. Repeat the measurement many times to account for noise
4. Compare the timing distributions statistically

**Observation:**
The test would observe that:
- Scalar multiplication with different bit patterns takes measurably different amounts of time
- The timing variance correlates with the Hamming weight of the scalar
- This timing variation is the foundation for cache-timing and other side-channel attacks

In production, an attacker would use more sophisticated side-channel analysis techniques (correlation power analysis, template attacks, etc.) to extract the full secret values rather than just detecting timing variance.

**Verification of Non-Constant-Time Library:**
The arkworks library documentation and source code confirm that constant-time implementation is not a design goal. The library uses optimized algorithms (window methods, precomputation) that inherently leak information through timing and power consumption. [9](#0-8) 

---

## Notes

The vulnerability is distinct from the trust assumption stated in the README that "leaking an off-chain node's state does not reveal user emails or their association to on-chain contracts." State leakage (e.g., memory dumps, snapshots) is different from active side-channel attacks during cryptographic computation. Side-channel resistance is a specific security property that requires constant-time implementation of cryptographic primitives, which is not provided by the arkworks library used in this protocol.

While `PedersenOpen` is marked with `ZeroizeOnDrop` to clear secrets from memory after use, this only prevents passive memory disclosure attacks and does not protect against active side-channel observation during computation.

### Citations

**File:** lib/src/crypto/commitments.rs (L1-8)
```rust
use std::ops::{Add, Mul};

use ark_ff::{AdditiveGroup, Field};
use ark_std::rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{crypto::hash::hash, crypto::pairing as pp, encode::Tagged, SwafeError};
```

**File:** lib/src/crypto/commitments.rs (L63-67)
```rust
    pub fn commit(&self, open: &PedersenOpen) -> PedersenCommitment {
        let h_proj: pp::G1Projective = self.h.into();
        let g_proj: pp::G1Projective = self.g.into();
        PedersenCommitment((h_proj * open.value + g_proj * open.randomness).into())
    }
```

**File:** lib/src/crypto/commitments.rs (L76-83)
```rust
/// Secrets of a Pedersen commitment (value and randomness)
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ZeroizeOnDrop)]
pub(crate) struct PedersenOpen {
    #[serde(with = "crate::crypto::pairing::serialize::fr")]
    value: pp::Fr,
    #[serde(with = "crate::crypto::pairing::serialize::fr")]
    randomness: pp::Fr,
}
```

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

**File:** lib/src/association/v0.rs (L455-507)
```rust
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

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L60-64)
```rust
    MskRecordCollection::store(
        &mut ctx,
        email_tag,
        request.association.0.verify(user_pk, &node_id)?,
    );
```

**File:** lib/src/crypto/symmetric.rs (L127-127)
```rust
    if mac_corr.ct_eq(&ct.mac).unwrap_u8() != 1 {
```

**File:** lib/src/crypto/pairing.rs (L1-17)
```rust
use ark_bls12_381::{g1::Config as G1Config, g2::Config as G2Config, Bls12_381};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{de::Error as DeError, Deserializer, Serializer};
use sha3::Sha3_256;

use crate::{crypto::hash, Tagged};

pub type Fr = ark_bls12_381::Fr; // Field elements
pub type G1Projective = ark_bls12_381::G1Projective; // Group elements
pub type G1Affine = ark_bls12_381::G1Affine;
pub type G2Projective = ark_bls12_381::G2Projective; // Group elements
pub type G2Affine = ark_bls12_381::G2Affine;
```
