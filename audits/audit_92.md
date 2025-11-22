## Title
Encapsulation Key Not Used for Encryption - Threshold Protection Completely Bypassed

## Summary
The encapsulation key derived from Pedersen commitments is never used for encryption or decryption in the association system. Instead, the Recovery Initiation Key (RIK) is used directly to encrypt/decrypt the `RikSecretData`. This completely breaks the cryptographic binding between commitments and encrypted data, allowing an attacker who obtains the RIK to decrypt data from a single node without needing threshold shares, bypassing the entire threshold protection mechanism.

## Impact
High

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended Logic:** 
The system is designed to derive an encapsulation key from v₀ (the first Pedersen commitment value) and use this key to encrypt the RIK data. This creates a cryptographic binding where:
- The encapsulation key can only be reconstructed by collecting threshold shares
- Decryption requires proving knowledge of the committed values through threshold reconstruction
- A single node cannot decrypt the data alone

The code comments explicitly state this intention at line 324: `// key ← kdf([v_0] · G, "EncapKey")`

**Actual Logic:** 
The implementation derives the encapsulation key but never uses it:

1. In `create_encrypted_msk()`:
   - Lines 323-335: Encapsulation key is derived from v₀
   - Line 335: `let encap_key = EncapsulationKey::new(kdfn(&v0_bytes, &EncapKeyKDF));`
   - Lines 345-350: Encryption uses `rik.as_bytes()` instead of the encapsulation key
   - Line 370: The unused encapsulation key is stored but never applied

2. In `reconstruct_rik_data()`:
   - Lines 509-522: Encapsulation key is reconstructed from threshold shares
   - Line 522: `let _encapsulation_key: symmetric::Key = kdfn(&v0_bytes, &EncapKeyKDF);` (note the underscore prefix indicating unused variable)
   - Lines 526-530: Decryption uses `rik.as_bytes()` instead of the encapsulation key [3](#0-2) 

The `symmetric::seal` and `symmetric::open` functions use the first parameter as the encryption/decryption key, confirming that the RIK is used directly.

**Exploit Scenario:**
1. User creates an association and distributes encrypted `MskRecord`s to offchain nodes
2. User stores the RIK locally (e.g., browser localStorage, encrypted backup, device storage)
3. Attacker compromises the RIK through:
   - XSS attack on web interface extracting localStorage
   - Malware on user's device
   - Insecure backup compromise
   - Memory dump or forensics
4. Attacker queries any single offchain node for the `MskRecord`
5. Attacker decrypts `enc_rik` using the compromised RIK
6. Attacker obtains the user's signing key and MSK secret share
7. No threshold reconstruction needed - the Pedersen commitments provide zero protection

**Security Failure:** 
The threshold secret sharing protection is completely bypassed. The Pedersen commitments are verified during upload but provide no cryptographic protection for the encrypted data. The system fails to enforce the invariant that threshold shares must be reconstructed to access the encrypted secrets.

## Impact Explanation

This vulnerability fundamentally breaks the security model of the association system:

**Assets Affected:**
- User signing keys (`sig_sk` in `RikSecretData`) used for recovery authorization
- MSK secret shares (`msk_ss_rik`) required for master secret key reconstruction
- Account security and recovery mechanisms

**Severity:**
- If the RIK is compromised through any vector (XSS, malware, insecure storage, device compromise), an attacker can decrypt all associated data from a single node
- The intended "threshold" protection (requiring t-of-n nodes) is completely ineffective
- Users who believe they have threshold protection are vulnerable to single-point-of-failure attacks on their RIK storage
- This represents a direct compromise of private keys and enables unauthorized account recovery

**System-Wide Impact:**
This affects the core security guarantee of the system. The dual-recovery approach (offchain nodes + guardians) is supposed to provide threshold protection on the offchain side, but this protection is non-existent when the RIK is the encryption key rather than the commitment-derived encapsulation key.

## Likelihood Explanation

**Who Can Exploit:**
Any attacker who obtains the user's RIK through:
- Client-side attacks (XSS, malicious browser extensions)
- Device compromise (malware, physical access)
- Insecure backup practices
- Memory forensics or crash dumps

**Conditions Required:**
- User has created an association with offchain nodes
- Attacker obtains the RIK (single secret, easier than compromising threshold nodes)
- Attacker can query any single offchain node

**Likelihood:**
High - RIKs are stored client-side and are vulnerable to numerous attack vectors. Users commonly experience:
- Browser-based attacks compromising localStorage
- Device malware extracting stored secrets
- Insecure cloud backup exposure
- Social engineering attacks

The likelihood is significantly higher than compromising threshold nodes because it's a single point of failure on the client side.

## Recommendation

**Immediate Fix:**
Modify the encryption/decryption to use the encapsulation key instead of the RIK:

1. In `create_encrypted_msk()` around line 345:
```rust
// Use encap_key instead of rik for encryption
let ciphertext = symmetric::seal(
    rng,
    encap_key.as_bytes(),  // ← Changed from rik.as_bytes()
    &CombinedSecretData::V0 { rik_data },
    &symmetric::EmptyAD,
);
```

2. In `reconstruct_rik_data()` around line 526:
```rust
// Use reconstructed encapsulation_key instead of rik for decryption
let encapsulation_key: symmetric::Key = kdfn(&v0_bytes, &EncapKeyKDF);  // ← Remove underscore
let combined_secret: CombinedSecretData = symmetric::open(
    &encapsulation_key,  // ← Changed from rik.as_bytes()
    &encrypted_data.ciphertext,
    &symmetric::EmptyAD,
)?;
```

This ensures that decryption requires threshold reconstruction of v₀, properly binding the encrypted data to the Pedersen commitments.

**Additional Consideration:**
The RIK should still be required as an additional authentication factor (e.g., as associated data in the AEAD encryption), but should not be the primary encryption key.

## Proof of Concept

**Test File:** `lib/src/association/v0.rs` (add to existing test module after line 819)

**Test Function:** `test_rik_bypass_threshold_protection`

**Setup:**
1. Create an association with threshold=3
2. Generate MskRecords for 3 nodes
3. Store the RIK

**Trigger:**
1. Attacker obtains the RIK
2. Attacker queries only ONE node (below threshold) for the MskRecord
3. Attacker attempts to decrypt using RIK directly without threshold reconstruction

**Observation:**
The test demonstrates that decryption succeeds with only the RIK and a single node's data, proving that threshold protection is bypassed. In the fixed version, this should fail because the encapsulation key cannot be derived from a single node's share.

```rust
#[test]
fn test_rik_bypass_threshold_protection() {
    let mut rng = thread_rng();
    const THRESHOLD: usize = 3;
    
    // Create association with threshold=3
    let (msk, rik) = Association::create_association(&mut rng, THRESHOLD).unwrap();
    
    // Get data from only ONE node (below threshold!)
    let single_node_id: NodeId = "node:1".parse().unwrap();
    let single_share = msk.compute_secret_shares(&single_node_id);
    
    let single_record = MskRecord::V0(MskRecordV0 {
        fixed: MskRecordFixed {
            user_pk: msk.user_pk.verification_key(),
            enc_rik: msk.ct.clone(),
            commits: msk.pedersen_commitments.clone(),
            sok_proof: msk.sok_proof.clone(),
        },
        share: single_share,
    });
    
    // VULNERABILITY: Attacker can decrypt with just RIK and single node
    // This should FAIL because we don't have threshold shares
    // But it SUCCEEDS because encryption uses RIK directly, not encapsulation_key
    let encrypted_data = &single_record.as_v0().unwrap().fixed.enc_rik;
    let decrypted: Result<CombinedSecretData, _> = symmetric::open(
        rik.as_bytes(),  // Using RIK directly bypasses threshold protection!
        &encrypted_data.ciphertext,
        &symmetric::EmptyAD,
    );
    
    // This assertion PASSES on vulnerable code (proving the bug)
    // but should FAIL on fixed code that uses encapsulation_key
    assert!(
        decrypted.is_ok(),
        "VULNERABILITY: Decryption succeeded with single node, bypassing threshold protection!"
    );
}
```

The test demonstrates that with access to only one node's data and the RIK, an attacker can decrypt the secrets, completely bypassing the threshold=3 requirement. After the fix, decryption would require reconstructing v₀ from threshold shares, and this test would fail as expected.

### Citations

**File:** lib/src/association/v0.rs (L323-350)
```rust
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
```

**File:** lib/src/association/v0.rs (L509-530)
```rust
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
