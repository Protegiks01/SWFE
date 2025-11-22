# Audit Report

## Title
Email Case Sensitivity Allows Multiple Associations for One Logical Email Address

## Summary
The Swafe protocol does not normalize email addresses to a canonical case before hashing them into `EmailKey` storage identifiers. This allows different case variations of the same logical email address (e.g., "user@example.com" vs "User@Example.com") to create distinct storage keys, enabling multiple associations for a single logical email address and violating a core protocol invariant.

## Impact
**Medium**

## Finding Description

### Location
- **Core vulnerability:** [1](#0-0) 
- **EmailKey creation:** [2](#0-1) 
- **Hash function:** [3](#0-2) 
- **Storage operations:** [4](#0-3) 

### Intended Logic
According to the protocol's main invariants, "An email should be associated to at most one account at a time." [5](#0-4)  The system should treat email addresses in a case-insensitive manner, as email addresses are logically case-insensitive in practice (domain part per RFC 1035, local part typically treated as case-insensitive by providers).

### Actual Logic
The `EmailInput` structure stores email addresses as raw `String` values without any case normalization. When an `EmailKey` is derived from an `EmailInput`, the email is serialized and hashed directly using bincode serialization [6](#0-5) , which preserves the exact case of the string. This means:
- "user@example.com" hashes to one `EmailKey`
- "User@Example.com" hashes to a different `EmailKey`
- Both can coexist in storage as separate associations

### Exploit Scenario
1. User proves ownership of "user@example.com" and Swafe-io issues an email certificate
2. User completes VDRF evaluation for "user@example.com" and uploads association to storage
3. Later, user attempts recovery but types "User@Example.com" (common user behavior)
4. Swafe-io issues a certificate for "User@Example.com" (user still legitimately owns the email)
5. VDRF evaluation produces a different result for "User@Example.com"
6. User either cannot find their original association or creates a new one
7. Two distinct associations now exist for the same logical email address

### Security Failure
This breaks the protocol invariant that one email should map to at most one association at any given time. The system allows multiple storage entries for case variations of the same email, creating confusion about which association is authoritative and potentially allowing account recovery ambiguity.

## Impact Explanation

The vulnerability affects the integrity of the email-to-account association system:

- **Invariant Violation:** The core invariant stating one email maps to one account is violated, creating ambiguity in the protocol's fundamental identity mechanism
- **Recovery Confusion:** Users may be unable to recover their original association if they type their email with different casing, or may inadvertently create duplicate associations
- **Storage Pollution:** Multiple associations for the same logical email consume unnecessary storage space and complicate account management
- **Security Ambiguity:** In recovery scenarios, it becomes unclear which association is the "correct" one, potentially allowing disputes about account ownership

While this does not directly lead to theft of keys or funds, it creates a critical state inconsistency that violates the protocol's design assumptions and could lead to users being unable to recover their accounts reliably.

## Likelihood Explanation

**Likelihood: High**

- **Trigger:** Any user who types their email with different casing across different sessions can trigger this
- **Frequency:** Very common - users often type emails inconsistently (e.g., "john@gmail.com" vs "John@Gmail.com")
- **Prerequisites:** Only requires normal user behavior and Swafe-io following standard procedures (issuing certificates after email verification)
- **No malicious intent needed:** This occurs through normal protocol operation without requiring Swafe-io to behave maliciously

The vulnerability is highly likely to occur in practice because:
1. Users naturally vary email casing when typing
2. Different email clients and forms may auto-capitalize emails differently
3. Swafe-io has no reason to reject legitimate ownership verification just because the casing changed
4. The protocol provides no defense against this at the cryptographic/storage layer

## Recommendation

**Implement email normalization before VDRF evaluation and storage:**

1. **In `EmailInput::from_str`:** Convert email addresses to lowercase before storing:
   ```rust
   fn from_str(s: &str) -> Result<Self, Self::Err> {
       Ok(EmailInput {
           email: s.to_lowercase(), // Normalize to lowercase
       })
   }
   ```

2. **In `EmailCert::issue`:** Normalize the email parameter before creating the certificate:
   ```rust
   pub fn issue<R: Rng + CryptoRng>(
       rng: &mut R,
       swafe_keypair: &sig::SigningKey,
       user_pk: &sig::VerificationKey,
       email: String,
   ) -> EmailCertificate {
       // Normalize email to lowercase
       let email = email.to_lowercase();
       // ... rest of function
   }
   ```

3. **Add validation:** Consider rejecting emails with mixed case at the API/contract endpoints to enforce consistency.

This ensures all email addresses are canonicalized to lowercase before any cryptographic operations, making "user@example.com" and "User@Example.com" produce identical `EmailKey` values.

## Proof of Concept

**Test file:** `lib/src/association/tests.rs` (new file in the association module's tests)

**Test function:** `test_email_case_sensitivity_multiple_associations`

**Setup:**
1. Initialize a VDRF key pair for email hashing
2. Create two `EmailInput` instances: one with "user@example.com" and one with "User@Example.com"
3. Perform VDRF evaluation on both inputs using the same VDRF public key

**Trigger:**
1. Create `EmailKey` from each `EmailInput` with its respective VDRF evaluation
2. Compare the resulting `EmailKey` values

**Observation:**
The test will observe that:
- Two different `EmailKey` values are produced for the same logical email address
- These keys would map to different storage locations in `MskRecordCollection`
- This violates the invariant that one email should map to one association

**Expected test behavior:**
The test should demonstrate that different case variations produce different keys, confirming the vulnerability exists. With the recommended fix applied, both email variations should produce identical `EmailKey` values.

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

**File:** lib/src/crypto/hash.rs (L22-27)
```rust
pub fn hash<T: Tagged>(val: &T) -> [u8; SIZE_HASH] {
    let mut hsh = Sha3_256::new();
    let encoded_data = val.encode();
    hsh.update(&encoded_data);
    hsh.finalize().into()
}
```

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L54-64)
```rust
    let (email, user_pk) =
        EmailCert::verify(&swafe_pk, &node_id, &request.token.0, ctx.current_time())?;

    let email: EmailInput = email.parse()?;
    let email_tag: EmailKey = EmailKey::new(&vdrf_pk, &email, request.vdrf_eval.0)?;

    MskRecordCollection::store(
        &mut ctx,
        email_tag,
        request.association.0.verify(user_pk, &node_id)?,
    );
```

**File:** README.md (L142-142)
```markdown
- An email should be associated to at most one account at a time.
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
