## Title
Email Association Key Substitution Attack via Association Overwrite Without Ownership Verification

## Summary
The `upload_msk` endpoint allows any user with a valid email certificate to overwrite existing email associations without verifying they are the original creator. This enables an attacker who compromises an email account to substitute the legitimate user's public key with their own, permanently destroying the original user's recovery capability and violating the system's security invariants. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
The vulnerability exists in the `upload_msk` handler in the smart contract HTTP endpoints. [2](#0-1) 

**Intended Logic:**
The system should prevent unauthorized modification of email associations. According to the protocol invariants, "An email should be associated to at most one account at a time" and only the original account owner should be able to modify or replace their association.

**Actual Logic:**
The `upload_msk` handler verifies that the requester has a valid email certificate for the email address, but it does NOT check whether an association already exists for that email or whether the requester's public key matches the existing association's public key. The handler unconditionally stores the new association via `MskRecordCollection::store()`, which performs a standard map insertion that overwrites any existing value. [3](#0-2) 

The storage layer's `insert` operation (line 26) replaces any existing MskRecord for that email_tag without any authorization check.

**Exploit Scenario:**
1. Victim Alice creates an association for email "alice@example.com" with her public key PK_Alice
2. Alice uploads this association to all off-chain nodes via the `upload_msk` endpoint
3. Attacker Bob compromises Alice's email account through phishing, credential theft, or other means
4. Bob generates his own keypair (SK_Bob, PK_Bob)
5. Bob requests an email certificate from Swafe.io for "alice@example.com" with PK_Bob (Swafe.io legitimately issues this since Bob now controls the email)
6. Bob creates his own `AssociationRequestEmail` containing:
   - `user_pk = PK_Bob` (Bob's public key)
   - New Pedersen commitments and SoK proof tied to PK_Bob
   - New encrypted RIK data encrypted with Bob's keys
7. Bob calls the `upload_msk` endpoint on each node with:
   - Valid email certificate token proving he controls "alice@example.com"
   - Valid VDRF evaluation for the email
   - His own association request
8. Each node's `upload_msk` handler:
   - Verifies Bob's email certificate (passes - Bob controls the email)
   - Verifies Bob's VDRF evaluation (passes - correct for the email)
   - Verifies Bob's association request (passes - internally consistent with PK_Bob)
   - Stores Bob's MskRecord, **overwriting Alice's original MskRecord**
9. Alice's original association is permanently lost across all nodes

**Security Failure:**
This breaks multiple security properties:
- **Key Substitution**: Bob successfully substitutes Alice's public key with his own
- **Association Integrity**: The original owner's association is destroyed without authorization
- **Recovery Denial of Service**: Alice can no longer use this email for account recovery since her association is gone
- **Invariant Violation**: While the system maintains "one email, one account at a time," it fails to protect the original account owner's exclusive control over their association

## Impact Explanation

**Affected Assets:**
- User's email-to-account associations (MskRecord containing user_pk, encrypted RIK, Pedersen commitments)
- Account recovery capability tied to the compromised email
- Potentially the master secret keys if the attacker gains additional recovery components

**Severity of Damage:**
- **Permanent Loss**: Alice's original MskRecord is irretrievably overwritten with no backup mechanism
- **Recovery Lockout**: If Alice relied on this email as one of her recovery methods, that path is now permanently blocked
- **Cascading Failure**: If Alice had multiple accounts using this email association, all are affected
- **No Remediation**: The system provides no way to detect or reverse this unauthorized overwrite

**System Security Impact:**
This vulnerability fundamentally undermines the email-based recovery mechanism, which is a core security feature of Swafe. Users cannot trust that their recovery associations remain under their control if their email accounts are compromised. The attack requires no exploitation of cryptographic primitives or trusted roles - it exploits a missing authorization check in the association management logic.

## Likelihood Explanation

**Who Can Trigger It:**
Any attacker who gains control of a user's email account can execute this attack. Email compromise is a common attack vector through:
- Phishing attacks targeting email credentials
- Credential stuffing from leaked password databases  
- Social engineering of email providers
- Compromise of email provider infrastructure

**Conditions Required:**
- Target user must have created an email association (normal operation)
- Attacker must compromise the target's email account (common threat)
- Attacker must know to exploit this specific vulnerability (requires knowledge of the protocol)

**Frequency:**
- Email account compromises occur regularly in practice
- Once an email is compromised, this attack is trivially executable
- The attack is permanent - one successful execution destroys the victim's association forever
- Multiple users could be targeted simultaneously if an attacker gains access to an email provider or multiple compromised accounts

Given the prevalence of email compromise and the severe, permanent impact, this vulnerability poses a significant practical threat.

## Recommendation

Add an ownership verification check before allowing association overwrites. Specifically, modify the `upload_msk` handler to:

1. **Check for existing association**: Before storing a new MskRecord, check if one already exists for the email_tag
2. **Verify ownership**: If an association exists, verify that the user_pk from the email certificate matches the user_pk in the existing MskRecord
3. **Reject unauthorized overwrites**: Return an error if the public keys don't match, preventing the overwrite
4. **Allow legitimate updates**: Only permit overwrites when the public keys match (same user updating their association)

Suggested implementation changes in `upload_msk.rs`:

```rust
// After line 58, before storing:
if let Some(existing_record) = MskRecordCollection::load(&mut ctx, email_tag) {
    // Extract user_pk from existing record
    let existing_user_pk = match existing_record {
        MskRecord::V0(v0) => &v0.fixed.user_pk,
    };
    
    // Verify the certificate's user_pk matches the existing one
    if existing_user_pk != user_pk {
        return Err(ServerError::Unauthorized(
            "Cannot overwrite association: public key mismatch. Email association already exists for a different user.".to_string()
        ).into());
    }
}

// Then proceed with store as normal
MskRecordCollection::store(&mut ctx, email_tag, request.association.0.verify(user_pk, &node_id)?);
```

Additionally, consider adding similar verification to the `get_secret_share` endpoint to ensure users can only retrieve associations they originally created, though this is less critical since the attacker cannot decrypt the RIK without additional information.

## Proof of Concept

**Test File:** `contracts/java-test/src/test/java/com/partisia/blockchain/contract/KeySubstitutionAttackTest.java`

**Setup:**
1. Initialize a Swafe contract with VDRF nodes configured
2. Create two users: Alice (victim) and Bob (attacker)
3. Generate email certificate for Alice with her public key PK_Alice for email "alice@example.com"
4. Have Alice create an association with threshold=3 and upload it to all nodes via the normal workflow
5. Verify Alice's association is stored correctly on all nodes

**Trigger:**
1. Generate a new email certificate for Bob with his public key PK_Bob for the SAME email "alice@example.com" (simulating email account takeover where Swafe.io legitimately issues a new certificate to the new email owner)
2. Have Bob create his own association with his keypair for the same email
3. Have Bob upload his association to all nodes via `upload_msk` endpoint with his valid certificate
4. Each node should accept Bob's upload request (current vulnerable behavior)

**Observation:**
1. Query each node's `/association/secret_share` endpoint for the email using both Alice's and Bob's certificates
2. With Alice's certificate: The request should either fail (association not found) OR return Bob's MskRecord containing PK_Bob instead of PK_Alice
3. With Bob's certificate: The request succeeds and returns Bob's MskRecord containing PK_Bob
4. Verify that Alice's original MskRecord (containing PK_Alice, her Pedersen commitments, her SoK proof) is permanently gone - there is no way to retrieve it
5. Attempt account recovery using Alice's original RIK - it should fail because the nodes no longer have Alice's association data

The test demonstrates that Bob successfully performed a key substitution attack by overwriting Alice's association, permanently locking Alice out of email-based recovery while establishing his own control over the email association.

### Citations

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L33-74)
```rust
pub fn handler(
    mut ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request: Request = deserialize_request_body(&request)?;

    let swafe_pk = encode::deserialize(&state.swafe_public_key).map_err(|_| {
        ServerError::SerializationError("Failed to deserialize Swafe public key".to_owned())
    })?;

    let stored_secret =
        OffchainSecrets::load(&mut ctx, ()).ok_or(ServerError::VdrfNodeNotInitialized)?;

    let vdrf_pk = encode::deserialize(&state.vdrf_public_key).map_err(|_| {
        ServerError::SerializationError("Failed to deserialize VDRF public key".to_owned())
    })?;

    let node_id: swafe_lib::NodeId = stored_secret.node_id.0;

    let (email, user_pk) =
        EmailCert::verify(&swafe_pk, &node_id, &request.token.0, ctx.current_time())?;

    let email: EmailInput = email.parse()?;
    let email_tag: EmailKey = EmailKey::new(&vdrf_pk, &email, request.vdrf_eval.0)?;

    MskRecordCollection::store(
        &mut ctx,
        email_tag,
        request.association.0.verify(user_pk, &node_id)?,
    );

    create_json_response(
        200,
        &Response {
            success: true,
            message: "Association uploaded successfully".to_string(),
        },
    )
    .map_err(|e| e.into())
}
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
