## Title
Email Case Sensitivity Bypass Allows Multiple Associations for Same Email Address

## Summary
The Swafe protocol lacks email address normalization before VDRF evaluation and EmailKey generation, allowing the same semantic email address to create multiple distinct associations. This directly violates the stated invariant "An email should be associated to at most one account at a time" from the README.

## Impact
**Medium**

## Finding Description

**Location:** 
- `lib/src/association/v0.rs` lines 36-43 (EmailInput::from_str) [1](#0-0) 

- `lib/src/crypto/email_cert.rs` line 32 (email field in EmailCertificateMessage) [2](#0-1) 

- `lib/src/crypto/hash.rs` lines 22-27 (hash function that serializes without normalization) [3](#0-2) 

**Intended Logic:** 
The system should enforce the invariant stated in README.md: "An email should be associated to at most one account at a time." [4](#0-3) 

The EmailKey derived from VDRF evaluation should uniquely identify an email address, ensuring one-to-one mapping between emails and accounts.

**Actual Logic:** 
The `EmailInput::from_str()` implementation performs no normalization, simply wrapping the raw string. When this email is used for VDRF evaluation, it gets hashed via `hash()` which serializes using bincode. Since bincode is byte-exact and case-sensitive, different character encodings of the same semantic email produce different hashes and thus different EmailKeys.

For example:
- "user@example.com" produces EmailKey A
- "User@example.com" produces EmailKey B (different)
- "USER@example.com" produces EmailKey C (different)

All three would be accepted as distinct associations, even though they represent the same email address.

**Exploit Scenario:**
1. User Alice owns the email "user@example.com"
2. Alice requests an EmailCertificate from Swafe-io for "user@example.com" (proves ownership via magic link) [5](#0-4) 

3. Alice creates an association for account A with certificate for "user@example.com"
4. Alice requests another EmailCertificate for "User@example.com" (same mailbox, different case)
5. Since email providers typically treat local parts case-insensitively, Alice receives this certificate too
6. Alice creates a second association for account B with certificate for "User@example.com"
7. Both associations exist in the system with different EmailKeys, stored separately [6](#0-5) 

**Security Failure:** 
The email uniqueness invariant is violated. The system allows multiple accounts to be associated with semantically identical email addresses, breaking the one-to-one email-to-account mapping guarantee.

## Impact Explanation

**Affected Assets:**
- Email-to-account association mappings
- Account recovery integrity
- System invariants

**Severity of Damage:**
1. **Recovery Ambiguity**: When a user attempts account recovery using their email, the system cannot deterministically identify which account to recover if multiple associations exist for case variants of the same email.

2. **Invariant Violation**: The core security model assumes email uniqueness (README line 142). Breaking this assumption undermines the recovery mechanism's design.

3. **Account Conflicts**: Users could inadvertently create multiple associations for their single email by using different capitalizations across different devices/sessions, leading to confusion about which account contains their actual secrets.

**System Impact:**
While this doesn't directly lead to immediate key compromise, it creates a fundamental protocol inconsistency that could:
- Cause legitimate users to be unable to recover the correct account
- Lead to permanent loss of access if the wrong account is recovered
- Violate user expectations about email uniqueness

## Likelihood Explanation

**Who can trigger it:**
Any legitimate user with an email address can trigger this vulnerability without malicious intent. Email certificate issuance by Swafe-io doesn't normalize the email before signing. [7](#0-6) 

**Conditions required:**
- User requests email certificates with different case variations (e.g., "user@example.com" then "User@example.com")
- Since most email providers deliver to the same mailbox regardless of case, users can easily obtain multiple valid certificates
- Normal operation - no special timing or race conditions needed

**Frequency:**
- Can occur unintentionally whenever users are inconsistent with email capitalization
- Could be exploited deliberately by users to create multiple associations
- Affects all users as the VDRF evaluation lacks normalization [8](#0-7) 

## Recommendation

Implement email normalization before VDRF evaluation:

1. **Normalize email addresses** in `EmailInput::from_str()`:
   - Convert the entire email to lowercase (both local and domain parts)
   - Apply Unicode normalization (e.g., NFC form) to handle Unicode homoglyphs
   - Trim whitespace

2. **Apply normalization** in `EmailCert::issue()` before storing in certificate:
   - Normalize the email string before creating EmailCertificateMessage
   - Ensures certificates are only issued for normalized forms

3. **Validate at API boundaries**: Add normalization in all HTTP endpoints that parse emails:
   - `contracts/src/http/endpoints/association/vdrf/eval.rs`
   - `contracts/src/http/endpoints/association/upload_msk.rs`
   - `contracts/src/http/endpoints/association/get_secret_share.rs`

Example implementation for `EmailInput::from_str()`:
```rust
fn from_str(s: &str) -> Result<Self, Self::Err> {
    // Normalize: lowercase + Unicode NFC + trim
    let normalized = s.trim().to_lowercase();
    // Could add additional validation (e.g., basic email format check)
    Ok(EmailInput { email: normalized })
}
```

## Proof of Concept

**Test File:** Add to `lib/src/association/v0.rs` in the existing tests module (after line 896)

**Test Function Name:** `test_email_case_sensitivity_creates_different_keys`

**Setup:**
1. Create a VDRF public key and node ID
2. Generate two EmailInput instances with the same email but different cases
3. Create valid VDRF evaluations for both inputs

**Trigger:**
1. Parse "user@example.com" as EmailInput
2. Parse "User@example.com" as EmailInput
3. Generate EmailKeys from both using valid VDRF evaluations
4. Compare the resulting EmailKeys

**Observation:**
The test will demonstrate that the two EmailKeys are different, proving the vulnerability. The test should assert inequality to show the bug exists:

```rust
#[test]
fn test_email_case_sensitivity_creates_different_keys() {
    let mut rng = thread_rng();
    
    // Setup VDRF
    let vdrf_sk = VdrfSecretKey::gen(&mut rng, 3);
    let vdrf_pk = vdrf_sk.public_key();
    let node_id: NodeId = "node:1".parse().unwrap();
    let secret_share = vdrf_sk.deal(&node_id).unwrap();
    
    // Two email variants (same semantic email, different case)
    let email1: EmailInput = "user@example.com".parse().unwrap();
    let email2: EmailInput = "User@example.com".parse().unwrap();
    
    // Generate VDRF evaluations
    let eval_share1 = Vdrf::partial_eval(&vdrf_pk, &secret_share, &email1).unwrap();
    let eval1 = Vdrf::combine::<_, 32>(&vdrf_pk, &email1, &[(node_id.clone(), eval_share1)]).unwrap();
    
    let eval_share2 = Vdrf::partial_eval(&vdrf_pk, &secret_share, &email2).unwrap();
    let eval2 = Vdrf::combine::<_, 32>(&vdrf_pk, &email2, &[(node_id, eval_share2)]).unwrap();
    
    // Create EmailKeys
    let key1 = EmailKey::new(&vdrf_pk, &email1, eval1).unwrap();
    let key2 = EmailKey::new(&vdrf_pk, &email2, eval2).unwrap();
    
    // BUG: These should be equal but are different due to lack of normalization
    assert_ne!(key1, key2, "Email keys differ for case variants - invariant violated!");
}
```

The test confirms that semantically identical emails produce different EmailKeys, violating the uniqueness invariant and allowing multiple associations for the same email address.

### Citations

**File:** lib/src/association/v0.rs (L36-43)
```rust
impl FromStr for EmailInput {
    type Err = SwafeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(EmailInput {
            email: s.to_string(),
        })
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

**File:** lib/src/crypto/email_cert.rs (L44-66)
```rust
    /// Issue an email possession certificate
    /// This is called by Swafe after verifying email ownership via magic link
    pub fn issue<R: Rng + CryptoRng>(
        rng: &mut R,
        swafe_keypair: &sig::SigningKey,
        user_pk: &sig::VerificationKey,
        email: String,
    ) -> EmailCertificate {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let msg = EmailCertificateMessage {
            user_pk: user_pk.clone(),
            email,
            timestamp,
        };

        let sig = swafe_keypair.sign(rng, &msg);

        EmailCertificate { msg, sig }
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

**File:** README.md (L142-142)
```markdown
- An email should be associated to at most one account at a time.
```

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L57-64)
```rust
    let email: EmailInput = email.parse()?;
    let email_tag: EmailKey = EmailKey::new(&vdrf_pk, &email, request.vdrf_eval.0)?;

    MskRecordCollection::store(
        &mut ctx,
        email_tag,
        request.association.0.verify(user_pk, &node_id)?,
    );
```

**File:** lib/src/crypto/vdrf.rs (L133-146)
```rust
    pub fn partial_eval<T: Tagged>(
        public_key: &VdrfPublicKey,
        secret_share: &VdrfSecretKeyShare,
        input: &T,
    ) -> Result<VdrfEvaluationShare, SwafeError> {
        // hash to point
        let pnt = pp::G2Projective::from(pp::hash_to_g2(&VdrfKPoint {
            c0: public_key.c0,
            input: hash(input),
        }));

        // return [secret_share] * png
        Ok(VdrfEvaluationShare((pnt * secret_share.0).into()))
    }
```
