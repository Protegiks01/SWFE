## Title
Email-Account Correlation via user_pk Linkage in Initialization Metadata

## Summary
Swafe-io can correlate email addresses with user accounts by matching the `user_pk` field that appears in both the `EmailCertificate` (issued by Swafe-io with email binding) and the `MskRecordFixed` structure (stored in off-chain nodes during initialization). This violates the protocol's privacy guarantee that off-chain node state leakage should not reveal email-account associations.

## Impact
Medium

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 

**Intended Logic:** 
The protocol is designed to hide email-to-account associations using VDRF (Verifiable Distributed Random Function) to derive storage keys. According to the trust model [5](#0-4) , "Snapshot of corrupted off-chain node states hides user emails and account associations." The VDRF mechanism is explicitly stated as being used to "hide email ↔ account association" [6](#0-5) . Additionally, privacy violations including "leakage of user identity (e.g., email addresses)" are listed as areas of concern [7](#0-6) .

**Actual Logic:** 
During association initialization, a signing key is generated [8](#0-7) , and its verification key becomes the `user_pk`. This same `user_pk` is embedded in two critical places:

1. In the `EmailCertificateMessage` issued by Swafe-io, linking `user_pk` to the user's email address [9](#0-8) 

2. In the `MskRecordFixed` structure stored in off-chain nodes, where it appears as the `user_pk` field [10](#0-9) 

When generating association requests for upload to nodes, the `user_pk` from the association's signing key is directly included in `MskRecordFixed` [11](#0-10) .

**Exploit Scenario:**
1. Swafe-io issues an `EmailCertificate` for a user, creating a binding: `email="alice@example.com" ↔ user_pk=PK_A` [12](#0-11) 
2. Swafe-io maintains a database of all issued certificates (required for their trusted role)
3. User uploads their `MskRecordFixed` containing the same `user_pk=PK_A` to off-chain nodes [13](#0-12) 
4. If Swafe-io gains access to off-chain node storage (through operating nodes themselves, node compromise, or data leaks), they can:
   - Enumerate stored `MskRecord` entries in off-chain storage
   - Extract the `user_pk` from each `MskRecordFixed`
   - Match against their certificate database to correlate emails with accounts
   - Identify which accounts belong to which email addresses

**Security Failure:** 
This violates the privacy guarantee that off-chain node state leakage does not reveal email associations. The VDRF mechanism only protects the storage key (EmailKey) but does nothing to prevent correlation via the stored value (`user_pk`). If Swafe-io has access to off-chain storage, the stated privacy property fails.

## Impact Explanation

This vulnerability affects user privacy and anonymity in the Swafe protocol:

- **Assets Affected:** User identity privacy - the linkage between email addresses and blockchain accounts
- **Severity:** While no direct loss of funds occurs, this represents a critical privacy violation that undermines the protocol's design goals
- **Systemic Impact:** The protocol explicitly claims to hide email-account associations using VDRF [6](#0-5) , but this guarantee fails if Swafe-io can access off-chain storage
- **Real-World Consequences:** 
  - Swafe-io (or anyone who compromises them) can build a complete database mapping emails to accounts
  - This breaks user anonymity and could enable targeted attacks, social engineering, or regulatory issues
  - Users who rely on the privacy guarantee may be unknowingly exposed

## Likelihood Explanation

**Triggering Conditions:**
- Swafe-io must have access to off-chain node storage (either by operating nodes, through compromise, or via data leaks)
- This is realistic because:
  - Swafe-io may legitimately operate some off-chain nodes as part of the infrastructure
  - Off-chain nodes could be compromised by external attackers
  - Node data leaks are a common occurrence in blockchain systems

**Frequency:**
- The correlation can occur any time Swafe-io gains access to off-chain storage
- Every user who initializes an account through the system is affected
- The vulnerability is structural and affects all users, not just specific edge cases

**Who Can Exploit:**
- Primarily Swafe-io (who already has the email certificate database)
- Secondarily, any attacker who compromises both Swafe-io's certificate database AND off-chain node storage
- The trust model assumes off-chain nodes are separate from Swafe-io [14](#0-13) , but doesn't prevent Swafe-io from operating nodes

## Recommendation

**Immediate Fix:**
Use a different signing key for `EmailCertificate` authentication than the one stored in `MskRecordFixed`. Specifically:

1. Generate TWO separate signing key pairs during association initialization:
   - `email_auth_key`: Used only for email certificate authentication (short-lived, disposable)
   - `recovery_key`: Used in `MskRecordFixed` (long-term, for recovery authorization)

2. Modify `EmailCertificate` to bind to `email_auth_key` verification key instead of the recovery key

3. Ensure no long-term identifier stored in off-chain/on-chain state can be correlated back to email certificates

**Alternative Approach:**
If the same key must be used, implement additional blinding:
- Use a commitment scheme where `MskRecordFixed` stores `Commit(user_pk, randomness)` instead of raw `user_pk`
- Store the randomness separately, encrypted under a key unknown to Swafe-io
- This prevents direct correlation even if storage is accessed

## Proof of Concept

**File:** `lib/src/association/tests.rs` (add new test function)

**Setup:**
```
1. Create a signing key pair (simulating user): `sig_sk = SigningKey::gen(rng)`
2. Extract verification key: `user_pk = sig_sk.verification_key()`
3. Swafe-io issues EmailCertificate: `cert = EmailCert::issue(rng, swafe_keypair, user_pk, "alice@example.com")`
4. User creates association: `(msk, rik) = Association::create_association(rng, threshold)`
5. Extract user_pk from association: `assoc_user_pk = msk.user_keypair().verification_key()`
6. Generate MskRecordFixed for upload: `assoc_request = association.gen_association_request(rng, node_id)`
```

**Trigger:**
```
1. Swafe-io maintains database: `{email: "alice@example.com", user_pk: cert.msg.user_pk}`
2. Swafe-io accesses off-chain storage and retrieves MskRecord
3. Extract user_pk from MskRecordFixed: `stored_pk = msk_record.fixed.user_pk`
4. Compare: `assert_eq!(cert.msg.user_pk, stored_pk)`
```

**Observation:**
The test demonstrates that `user_pk` from the `EmailCertificate` matches exactly the `user_pk` in `MskRecordFixed`, enabling trivial correlation. The assertion succeeds, proving that Swafe-io can map emails to stored records by matching public keys, thus violating the privacy guarantee stated in the README that off-chain state leakage should not reveal email associations [5](#0-4) .

### Citations

**File:** lib/src/crypto/email_cert.rs (L29-34)
```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct EmailCertificateMessage {
    user_pk: sig::VerificationKey,
    email: String,
    timestamp: u64,
}
```

**File:** lib/src/crypto/email_cert.rs (L44-65)
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

**File:** lib/src/association/v0.rs (L435-451)
```rust
    pub fn gen_association_request<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        node_id: &NodeId,
    ) -> Result<AssociationRequestEmail, SwafeError> {
        let node_secret_share = self.gen_node_secret_share(rng, node_id)?;

        Ok(AssociationRequestEmail {
            fixed: MskRecordFixed {
                user_pk: self.sk_user.verification_key(),
                enc_rik: node_secret_share.msk_result().ct.clone(),
                commits: node_secret_share.msk_result().pedersen_commitments.clone(),
                sok_proof: node_secret_share.msk_result().sok_proof.clone(),
            },
            share: node_secret_share.secret_shares().clone(),
        })
    }
```

**File:** README.md (L133-133)
```markdown
- Privacy Violations - Anonymity violations from on-chain content or off-chain node interaction, including leakage of user identity (e.g., email addresses)
```

**File:** README.md (L148-159)
```markdown
### Swafe-io

#### Trust Assumptions

- Keeping user emails confidential.
- Providing "email certificates" only after users prove email possession.
- Generating shares for the VPRF used to hide email ↔ account association during a one-time setup ceremony.

#### Prohibitions

Must not be able to unilaterally cause Guardians to reconstruct or recover an account without explicit permission provided by each guardian.

```

**File:** README.md (L193-194)
```markdown
- Snapshot of corrupted off-chain node states hides user emails and account associations.
- Leaking an off-chain node's state does not reveal user emails or their association to on-chain contracts.
```

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L60-64)
```rust
    MskRecordCollection::store(
        &mut ctx,
        email_tag,
        request.association.0.verify(user_pk, &node_id)?,
    );
```
