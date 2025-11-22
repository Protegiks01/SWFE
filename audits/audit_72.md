## Title
Email Case Sensitivity in VDRF Evaluation Causes Permanent Loss of Backup Access

## Summary
The email association system does not normalize email addresses before VDRF evaluation and storage key derivation. Different casings of the same email address (e.g., "user@example.com" vs "User@Example.com") produce different VDRF evaluations and therefore different EmailKey storage keys, causing users to permanently lose access to their encrypted master secret key backups if they don't use the exact same casing during recovery.

## Impact
**High**

## Finding Description

**Location:** 
The vulnerability exists across multiple components:
- Email input parsing without normalization: [1](#0-0) 
- Email certificate storing raw email string: [2](#0-1) 
- VDRF evaluation using case-sensitive hash: [3](#0-2) 
- EmailKey derivation from VDRF: [4](#0-3) 
- Storage mapping using EmailKey: [5](#0-4) 

**Intended Logic:**
The system should allow users to recover their encrypted master secret keys using their email address, regardless of how they capitalize it. Email addresses are generally treated as case-insensitive in practice by email providers.

**Actual Logic:**
The email string is stored and processed without any normalization. When the email is serialized for hashing via the Tagged trait [6](#0-5) , bincode preserves the exact casing. The hash function [7](#0-6)  produces different outputs for different casings, leading to different VDRF evaluations and different EmailKey values.

**Exploit Scenario:**
1. Alice sets up backup association with email "alice@example.com"
2. Swafe operator issues EmailCertificate with email "alice@example.com"
3. VDRF evaluation computes: hash("v0:email-input", {"alice@example.com"}) → EmailKey K1
4. MskRecord is stored at key K1 in the contract storage [8](#0-7) 
5. Later, Alice requests recovery using "Alice@Example.com" (different casing)
6. Swafe operator issues EmailCertificate with email "Alice@Example.com"
7. VDRF evaluation computes: hash("v0:email-input", {"Alice@Example.com"}) → EmailKey K2 (where K1 ≠ K2)
8. Secret share retrieval attempts to look up with key K2 [9](#0-8) 
9. Lookup fails because the MskRecord is stored under K1, not K2
10. Alice permanently loses access to her backup

**Security Failure:**
The fundamental invariant that "a user's email uniquely identifies their backup" is broken. The system creates multiple separate identities for the same email address based solely on casing differences, violating user expectations and causing permanent loss of access to encrypted secrets.

## Impact Explanation

**Affected Assets:**
- User's encrypted master secret keys (MskRecord) stored in the association system
- Recovery Initiation Key (RIK) data encrypted within the MskRecord
- User's ability to recover their account and access their funds/secrets

**Severity of Damage:**
Users who create backups with one casing but later attempt recovery with different casing will experience permanent loss of access. The encrypted MskRecord remains stored on-chain but becomes permanently unretrievable because:
- The VDRF evaluation produces a different EmailKey
- There is no mechanism to search for MskRecords by user public key or alternative email casings
- The user cannot modify the stored record without the original EmailKey

This constitutes **permanent freezing of secrets** as defined in the in-scope impacts, requiring operator intervention or hard fork to recover.

**System Reliability Impact:**
This fundamentally breaks the usability of the email-based recovery system, as users cannot reasonably be expected to remember the exact casing they used months or years earlier during backup creation. Email providers treat addresses as case-insensitive, so users have no expectation that "user@example.com" and "User@Example.com" would be different identities.

## Likelihood Explanation

**Who Can Trigger:**
Any regular user during normal operation. No privileged access or malicious behavior required.

**Required Conditions:**
This occurs in normal usage when:
- A user creates a backup with one email casing
- The same user later attempts recovery but types their email with different casing
- The Swafe operator issues certificates with the casing provided by the user (as it should)

**Frequency:**
This is highly likely to occur because:
- Users commonly type emails with inconsistent capitalization (e.g., starting with capital letter, all lowercase, etc.)
- Email clients and browsers may auto-capitalize emails differently
- Users don't expect case sensitivity in email addresses
- The issue may not be discovered until months/years later during actual recovery attempts
- Each affected user experiences permanent, irrecoverable loss

## Recommendation

Implement email normalization before any cryptographic operations. Specifically:

1. **In EmailInput::from_str**: Add normalization to convert email to lowercase:
   ```rust
   fn from_str(s: &str) -> Result<Self, Self::Err> {
       Ok(EmailInput {
           email: s.to_lowercase(),
       })
   }
   ```

2. **In EmailCert::issue**: Normalize the email parameter before creating the certificate to ensure consistency across all certificates for the same user.

3. **Add validation**: Ensure all email processing paths apply the same normalization consistently.

4. **Migration consideration**: For already-deployed systems, implement a backward-compatible lookup that tries both the provided casing and the normalized (lowercase) version.

## Proof of Concept

**Test File:** `lib/src/association/v0.rs` (add to existing test module)

**Test Function:** `test_email_case_sensitivity_breaks_recovery`

**Setup:**
1. Create a VDRF setup with threshold = 3 and multiple nodes
2. Generate user signing keypair
3. Create Swafe operator keypair for issuing certificates
4. Create email certificate with lowercase email "alice@example.com"
5. Create association and upload to simulated storage with lowercase email

**Trigger:**
1. Create a second email certificate with mixed-case email "Alice@Example.com"
2. Attempt VDRF evaluation with the mixed-case email
3. Compute EmailKey from the mixed-case VDRF evaluation
4. Attempt to retrieve MskRecord using the mixed-case EmailKey

**Observation:**
The test demonstrates that:
- EmailKey derived from "alice@example.com" ≠ EmailKey derived from "Alice@Example.com"
- Storage lookup with the different-casing EmailKey returns None (not found)
- The user cannot retrieve their MskRecord despite having valid credentials
- This confirms permanent loss of access due to casing difference

The test should show that hash("v0:email-input", {"alice@example.com"}) produces a different 32-byte output than hash("v0:email-input", {"Alice@Example.com"}), resulting in different VDRF evaluations and ultimately different storage keys, proving the vulnerability.

### Citations

**File:** lib/src/association/v0.rs (L36-44)
```rust
impl FromStr for EmailInput {
    type Err = SwafeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(EmailInput {
            email: s.to_string(),
        })
    }
}
```

**File:** lib/src/association/v0.rs (L176-184)
```rust
impl EmailKey {
    pub fn new(
        vdrf_pk: &VdrfPublicKey,
        email: &EmailInput,
        eval: VdrfEvaluation,
    ) -> Result<Self, SwafeError> {
        Vdrf::verify(vdrf_pk, email, eval).map(EmailKey)
    }
}
```

**File:** lib/src/crypto/email_cert.rs (L29-34)
```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct EmailCertificateMessage {
    user_pk: sig::VerificationKey,
    email: String,
    timestamp: u64,
}
```

**File:** lib/src/crypto/vdrf.rs (L139-142)
```rust
        let pnt = pp::G2Projective::from(pp::hash_to_g2(&VdrfKPoint {
            c0: public_key.c0,
            input: hash(input),
        }));
```

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L26-31)
```rust
impl Mapping for MskRecordCollection {
    type Key = EmailKey;
    type Value = MskRecord;

    const COLLECTION_NAME: &'static str = "map:associations";
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

**File:** lib/src/encode.rs (L20-37)
```rust
    fn encode(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        #[derive(Serialize)]
        struct DomainTuple<'a, T: Tagged + ?Sized> {
            sep: &'a str,
            val: &'a T,
        }
        bincode::serde::encode_to_vec(
            &DomainTuple {
                sep: Self::SEPARATOR,
                val: self,
            },
            BINCODE_CONFIG,
        )
        .unwrap()
    }
```

**File:** lib/src/crypto/hash.rs (L22-27)
```rust
pub fn hash<T: Tagged>(val: &T) -> [u8; SIZE_HASH] {
    let mut hsh = Sha3_256::new();
    let encoded_data = val.encode();
    hsh.update(&encoded_data);
    hsh.finalize().into()
}
```

**File:** contracts/src/http/endpoints/association/get_secret_share.rs (L48-49)
```rust
    let msk_record = MskRecordCollection::load(&mut ctx, email_tag)
        .ok_or_else(|| ServerError::InvalidParameter("MSK record not found".to_string()))?;
```
