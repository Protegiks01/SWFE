# Audit Report

## Title
Missing Off-Chain Storage Revocation Allows Compromised Email Certificates to Remain Usable After On-Chain Association Revocation

## Summary
When a user revokes an email association on-chain using `revoke_association()`, the corresponding `MskRecord` remains accessible in off-chain storage indefinitely. A compromised email certificate can still be used to retrieve and overwrite the legitimate `MskRecord` data, even after the association has been revoked on-chain. This violates the expected security guarantee that revoked associations should be fully unusable and creates a denial-of-service vector against the user's recovery mechanism.

## Impact
**Medium**

## Finding Description

**Location:**
- Primary: [1](#0-0) 
- Related: [2](#0-1) 
- Related: [3](#0-2) 

**Intended Logic:**
When a user revokes an email association via the `revoke_association()` method, they expect all data related to that association to become unusable and inaccessible. The revocation should prevent both on-chain recovery operations and off-chain data access associated with the revoked email.

**Actual Logic:**
The `revoke_association()` function only removes the RIK from the on-chain account state. However, the `MskRecord` stored in off-chain nodes remains accessible indefinitely. The `get_secret_share` handler verifies only the email certificate validity and VDRF evaluation, but does not check whether the association is currently active in the on-chain account state. Similarly, the `upload_msk` handler allows unrestricted overwrites without checking for existing records or verifying the association's on-chain status.

**Exploit Scenario:**
1. User creates an email association with email A, generates RIK1, and uploads MskRecord1 to off-chain nodes
2. User's email account is compromised by an attacker
3. User notices the compromise and calls `revoke_association(&rik1)` to revoke the association on-chain
4. The on-chain association is removed from `rec.assoc`, preventing on-chain recovery initiation
5. However, MskRecord1 remains in off-chain storage at the `EmailKey` derived from VDRF(email A)
6. Attacker requests a new email certificate from Swafe-io (within 5-minute validity or at any later time)
7. Attacker can still retrieve MskRecord1 from off-chain nodes using the valid email certificate
8. Attacker can overwrite MskRecord1 with a malicious MskRecord2 (encrypted with attacker's own RIK)
9. If the user later re-uses email A for a new association and attempts recovery, they will retrieve the corrupted MskRecord2
10. The user cannot decrypt MskRecord2 with their legitimate RIK, causing recovery to fail

**Security Failure:**
This vulnerability breaks the security invariant that revoked associations should be fully deactivated. It violates the principle of revocation semantics where users expect that revoking an association makes all related data inaccessible. Additionally, it enables an integrity violation where an attacker can corrupt the association data, causing denial-of-service on the recovery mechanism.

## Impact Explanation

**Affected Assets:**
- User's recovery mechanism via email associations
- MskRecord data containing encrypted RIK secrets
- User's ability to recover their account using specific email addresses

**Severity:**
The damage manifests in two ways:

1. **Information Disclosure:** After revocation, an attacker with a compromised email certificate can still retrieve the encrypted MskRecord. While the encryption protects the RIK data, the continued accessibility violates user expectations and revocation semantics.

2. **Denial-of-Service on Recovery:** An attacker can upload a malicious MskRecord to overwrite the legitimate one. When the user later attempts recovery using the same email (with a new association), they will retrieve corrupted data that cannot be decrypted with their legitimate RIK, permanently breaking recovery via that email address.

**System Impact:**
This undermines the security model where users can revoke compromised associations to protect their accounts. Users may believe they have secured their account through revocation, but the off-chain data remains exploitable. This can lead to permanent loss of recovery capability for specific email addresses, forcing users to rely on alternative recovery methods or guardians.

## Likelihood Explanation

**Trigger Conditions:**
- Any user with a compromised email account
- User performs on-chain revocation expecting full deactivation
- Attacker has access to the compromised email to request new certificates from Swafe-io

**Frequency:**
This vulnerability can be exploited during normal operation whenever:
1. A user revokes an association due to suspected compromise
2. The attacker maintains access to the email account
3. The user later attempts to re-use the same email for recovery

The attack window is indefinite because:
- Email certificates can be re-issued at any time by Swafe-io
- MskRecords persist indefinitely in off-chain storage
- No cleanup mechanism exists for revoked associations

This is highly likely to occur in practice because email compromise is a common threat vector, and users naturally revoke associations when they detect suspicious activity.

## Recommendation

Implement proper synchronization between on-chain revocation and off-chain storage:

1. **Add deletion endpoint:** Create a new API endpoint `/association/delete-association` that removes MskRecords from off-chain storage when called with a valid email certificate.

2. **Automatic cleanup on revocation:** Modify the `revoke_association()` flow to trigger deletion of the corresponding MskRecord from all off-chain nodes. This could be implemented by:
   - Emitting an event when associations are revoked on-chain
   - Having off-chain nodes listen for these events and delete corresponding MskRecords
   - Or requiring users to explicitly call the deletion endpoint after revocation

3. **Prevent overwrites:** Modify the `upload_msk` handler to check if a MskRecord already exists and return an error if attempting to overwrite, or require explicit user authorization for overwrites with verification of the current on-chain association state.

4. **Add on-chain verification:** Modify `get_secret_share` and `upload_msk` handlers to verify that an active association exists in the on-chain account state before allowing retrieval or upload operations.

## Proof of Concept

**File:** `lib/src/account/tests.rs`

**Test Function:** `test_revoked_association_msk_record_persistence`

**Setup:**
1. Create an account with guardians
2. Generate an email certificate for email "user@example.com"
3. Create an association with RIK1 and upload MskRecord1 to a simulated off-chain node
4. Verify MskRecord1 can be retrieved with the email certificate

**Trigger:**
1. Revoke the association using `revoke_association(&rik1)`
2. Publish the updated account state on-chain
3. Verify on-chain that the association is no longer in `rec.assoc` list
4. Simulate attacker with compromised email requesting new certificate
5. Attempt to retrieve MskRecord1 from off-chain storage using the new certificate
6. Attempt to upload a malicious MskRecord2 (encrypted with attacker's RIK2)

**Observation:**
The test demonstrates that:
- MskRecord1 can still be retrieved after revocation (information disclosure)
- MskRecord1 can be overwritten with MskRecord2 (integrity violation)
- On-chain recovery with RIK1 correctly fails (as expected)
- But off-chain data operations succeed despite revocation (unexpected vulnerability)

The test confirms that the revocation only affects on-chain recovery initiation but does not prevent off-chain data access and manipulation through valid email certificates. This violates the expected behavior where revocation should make the association and all its data fully unusable.

### Citations

**File:** contracts/src/http/endpoints/association/get_secret_share.rs (L23-58)
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

    let vdrf_pk: VdrfPublicKey = encode::deserialize(&state.vdrf_public_key).map_err(|_| {
        ServerError::SerializationError("Failed to deserialize VDRF public key".to_owned())
    })?;

    let node_id: swafe_lib::NodeId = stored_secret.node_id.0;
    let (email, _) = EmailCert::verify(&swafe_pk, &node_id, &request.token.0, ctx.current_time())?;

    let email: EmailInput = email.parse()?;
    let email_tag: EmailKey = EmailKey::new(&vdrf_pk, &email, request.vdrf_eval.0)?;

    let msk_record = MskRecordCollection::load(&mut ctx, email_tag)
        .ok_or_else(|| ServerError::InvalidParameter("MSK record not found".to_string()))?;

    create_json_response(
        200,
        &Response {
            entry: encode::StrEncoded(msk_record),
        },
    )
    .map_err(|e| e.into())
}
```

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

**File:** lib/src/account/v0.rs (L621-632)
```rust
    /// Revoke a specific association by its RIK
    pub fn revoke_association(&mut self, rik: &RecoveryInitiationKey) -> Result<()> {
        let original_len = self.recovery.assoc.len();
        self.recovery.assoc.retain(|assoc| &assoc.rik != rik);

        if self.recovery.assoc.len() == original_len {
            return Err(SwafeError::InvalidRecoveryKey);
        }

        self.dirty = true;
        Ok(())
    }
```
