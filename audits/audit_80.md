## Title
Email Association Hijacking via MskRecord Overwrite Without Audit Trail or Ownership Verification

## Summary
The Swafe protocol stores email-to-account associations as MskRecords indexed by email-derived keys (EmailKey) in off-chain storage. When a user uploads a new MskRecord for an email, it unconditionally overwrites any existing record without verifying that the new record belongs to the same account owner. Combined with the complete absence of an audit trail, this enables attackers who temporarily gain access to a victim's email to permanently hijack the email→account association, violating the protocol invariant and causing permanent loss of account recovery capability.

## Impact
**High**

## Finding Description

**Location:** 
The vulnerability exists in the MskRecord storage mechanism: [1](#0-0) [2](#0-1) 

**Intended Logic:** 
According to the protocol's main invariants, "An email should be associated to at most one account at a time." The email certificate system is designed to verify email ownership before allowing MskRecord uploads. The intended behavior is that each email should maintain a persistent association with a single account, enabling the legitimate owner to recover their account. [3](#0-2) 

**Actual Logic:** 
The system has three critical flaws:

1. **No Ownership Verification**: When verifying an AssociationRequestEmail, the system only checks that the user_pk in the request matches the certificate, but does NOT check if an existing MskRecord already exists for this email with a different user_pk: [4](#0-3) 

2. **Unconditional Overwrite**: The storage layer unconditionally overwrites existing values without any history or versioning: [2](#0-1) 

3. **No Audit Trail**: There are no events, logs, or on-chain records of certificate issuance or MskRecord modifications. Certificates are ephemeral (5-minute validity) and never stored: [5](#0-4) [6](#0-5) 

**Exploit Scenario:**

1. Alice associates her email `alice@example.com` with Account A:
   - Creates MskRecord_A with user_pk_Alice and enc_rik_A containing Account A's recovery signing key
   - Uploads to nodes at EmailKey(alice@example.com)

2. Attacker gains temporary access to `alice@example.com` (via phishing, email compromise, social engineering, or password reuse)

3. Attacker requests an email certificate from Swafe-io:
   - Swafe-io correctly verifies the attacker has email access (by magic link or other verification)
   - Issues a valid EmailCertificate with user_pk_Attacker

4. Attacker creates MskRecord_B for their own Account B:
   - Contains user_pk_Attacker and enc_rik_B (encrypted with attacker's RIK)
   - Creates valid SoK proof binding commitments to user_pk_Attacker

5. Attacker uploads MskRecord_B using the certificate:
   - Passes all verification checks (certificate valid, SoK proof valid, user_pk matches)
   - MskRecord_B OVERWRITES MskRecord_A at EmailKey(alice@example.com)

6. Result:
   - Alice can no longer recover Account A using her email
   - When Alice retrieves the MskRecord, she gets MskRecord_B (attacker's record)
   - The reconstructed RIK cannot decrypt Account A's AssociationsV0 (wrong encryption key)
   - Account A recovery permanently fails
   - Without audit trail, Alice cannot prove the hijack occurred or identify when/by whom

**Security Failure:** 
This violates the protocol's stated invariant: "An email should be associated to at most one account at a time." The lack of audit trail specifically HIDES the abuse—there is no record of the previous association, no way to detect the overwrite, and no mechanism to rollback or prove ownership.

## Impact Explanation

**Affected Assets:**
- Victim's account recovery capability permanently lost
- Master secret keys (MSK) become permanently inaccessible if this was the only recovery email
- All funds and assets controlled by the account are permanently frozen

**Severity of Damage:**
- **Direct loss of funds/secrets**: If the victim loses access to their account and this email was their primary or only recovery method, their account and all associated assets are permanently lost
- **Permanent freezing**: The account cannot be recovered through the hijacked email, and if no alternative recovery methods exist, the account is permanently frozen
- **Undetectable**: Without an audit trail, victims cannot prove the hijack occurred, cannot determine when it happened, and have no recourse for recovery

**System Impact:**
This vulnerability fundamentally breaks the account recovery system's security guarantee. The trust model assumes email ownership verification is sufficient, but temporary email compromise (a common real-world threat) can cause permanent, irreversible damage. The lack of audit trail makes post-incident investigation impossible and prevents detection of systemic abuse.

## Likelihood Explanation

**Who Can Trigger:**
Any attacker who gains temporary access to a victim's email account. This does NOT require:
- Compromising Swafe-io, guardians, or off-chain nodes (trusted roles)
- Breaking cryptographic primitives
- Network-level attacks
- Long-term persistent access

**Required Conditions:**
- Temporary email access (achievable through common attack vectors: phishing, credential stuffing, password reuse, compromised email providers)
- Ability to receive and verify the magic link from Swafe-io (standard email certificate issuance process)

**Frequency:**
- Email compromises are a common, well-documented threat vector in Web3
- Phishing campaigns targeting crypto users are widespread
- Once exploited, the damage is permanent and irreversible
- Multiple users can be targeted simultaneously
- The attack leaves no forensic evidence due to lack of audit trail

**Realistic Probability:** HIGH - Email account compromise is one of the most common attack vectors in the Web3 ecosystem. The attack requires no special technical skills beyond standard phishing techniques.

## Recommendation

Implement a multi-layered protection mechanism:

1. **Add Ownership Verification**: Before allowing MskRecord overwrite, verify that the new user_pk matches the existing MskRecord's user_pk (if one exists):
```rust
// In upload_msk handler, before storing:
if let Some(existing_record) = MskRecordCollection::load(&mut ctx, email_tag) {
    let existing_user_pk = match existing_record {
        MskRecord::V0(v0) => &v0.fixed.user_pk,
    };
    if existing_user_pk != user_pk {
        return Err(ServerError::EmailAssociationConflict.into());
    }
}
```

2. **Implement Audit Trail**: Store certificate issuance and MskRecord modification events on-chain:
   - Log certificate issuances with (email_hash, user_pk, timestamp)
   - Log MskRecord uploads with (email_hash, user_pk, timestamp, operation_type)
   - Enable querying of association history

3. **Add Re-verification Window**: Require a waiting period and email re-verification before allowing MskRecord overwrites with a different user_pk

4. **Version MskRecords**: Instead of overwriting, maintain versioned history with tombstone records, allowing rollback in case of detected compromise

## Proof of Concept

**Test File:** `lib/src/association/tests.rs` (add new test to existing test module)

**Test Function:** `test_email_association_hijacking`

**Setup:**
1. Initialize two users: Alice with keypair (sk_alice, pk_alice) and Attacker with keypair (sk_attacker, pk_attacker)
2. Alice creates Association_A for her Account A and uploads MskRecord_A to a test node for email "victim@example.com"
3. Simulate the attacker obtaining a valid email certificate for "victim@example.com" with pk_attacker (issued by Swafe-io after attacker proves email access)

**Trigger:**
1. Attacker creates Association_B for their Account B with pk_attacker
2. Attacker uploads MskRecord_B to the same node for "victim@example.com"
3. The storage layer accepts and overwrites MskRecord_A with MskRecord_B (no error, no check)

**Observation:**
1. Query the node for MskRecord at EmailKey("victim@example.com")
2. Assert that retrieved record has user_pk == pk_attacker (not pk_alice)
3. Attempt to use the retrieved MskRecord to recover Alice's Account A
4. Assert that recovery FAILS because the RIK in MskRecord_B cannot decrypt Account A's AssociationsV0
5. Assert that no audit trail or history exists showing the previous association with pk_alice

**Expected Test Result:** The test demonstrates that:
- MskRecord_B successfully overwrites MskRecord_A
- Alice's recovery capability is permanently lost
- The attacker's account association is now stored under Alice's email
- No audit trail exists to detect or prove the hijack

This test should be run against the existing codebase to confirm the vulnerability exists, then run again after implementing the fix to verify the issue is resolved (should reject the attacker's upload attempt with ownership mismatch error).

### Citations

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L60-64)
```rust
    MskRecordCollection::store(
        &mut ctx,
        email_tag,
        request.association.0.verify(user_pk, &node_id)?,
    );
```

**File:** contracts/src/storage.rs (L21-27)
```rust
    fn store(ctx: &mut OffChainContext, key: Self::Key, value: Self::Value) {
        let mut storage: OffChainStorage<Vec<u8>, Vec<u8>> =
            ctx.storage(Self::COLLECTION_NAME.as_bytes());
        let key = encode::serialize(&key).unwrap();
        let value = encode::serialize(&value).unwrap();
        storage.insert(key, value);
    }
```

**File:** lib/src/crypto/email_cert.rs (L7-7)
```rust
const VALIDITY_PERIOD: Duration = Duration::from_secs(5 * 60);
```

**File:** lib/src/crypto/email_cert.rs (L82-116)
```rust
    /// Verify the email certificate and token.
    /// On Execution Engine, the system time should be passed from the EE context.
    pub fn verify<'a>(
        swafe_pk: &sig::VerificationKey,
        node_id: &NodeId,
        token: &'a EmailCertToken,
        now: SystemTime,
    ) -> Result<(&'a str, &'a sig::VerificationKey), SwafeError> {
        // Verify Swafe signature on certificate
        swafe_pk.verify(&token.cert.sig, &token.cert.msg)?;

        // Verify user signature on node_id
        token.cert.msg.user_pk.verify(&token.user_sig, node_id)?;

        // convert UNIX timestamp (u64) to SystemTime
        let ts = UNIX_EPOCH
            .checked_add(Duration::from_secs(token.cert.msg.timestamp))
            .ok_or(SwafeError::CertificateExpired)?;

        // Check if certificate is from the future
        if ts > now {
            return Err(SwafeError::CertificateFromFuture);
        }

        // Check if certificate is expired
        if now
            .duration_since(ts)
            .map_err(|_| SwafeError::CertificateExpired)?
            > VALIDITY_PERIOD
        {
            return Err(SwafeError::CertificateExpired);
        }

        Ok((&token.cert.msg.email, &token.cert.msg.user_pk))
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

**File:** contracts/src/lib.rs (L20-31)
```rust
/// State of the contract
#[state]
struct ContractState {
    /// Offchain node configurations mapped by node_id
    nodes: AvlTreeMap<String, OffchainNodeState>,
    /// Swafe public key for EmailCert verification
    swafe_public_key: Vec<u8>,
    /// VDRF public key for VDRF operations
    vdrf_public_key: Vec<u8>,
    /// Map account id to serialized account object
    accounts: AvlTreeMap<[u8; 32], Vec<u8>>,
}
```
