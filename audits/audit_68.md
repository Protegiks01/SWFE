## Title
Revoked Associations Can Still Retrieve MskRecords via Email Certificate Validation

## Summary
The `get_secret_share` endpoint validates email certificates and serves MskRecords from off-chain storage without checking whether the associated RIK (Recovery Initiation Key) has been revoked on-chain. This allows revoked associations to continue accessing encrypted secret data despite being removed from the account state, violating the revocation security invariant. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** The vulnerability exists in the `get_secret_share` handler function at: [1](#0-0) 

**Intended Logic:** When a user revokes an association using `revoke_association()`, the RIK should be completely disabled and unable to access any associated data. The revocation mechanism is implemented to remove associations from the account state: [2](#0-1) 

This prevents revoked RIKs from initiating recovery operations on-chain, as verified by tests: [3](#0-2) 

**Actual Logic:** The `get_secret_share` endpoint only validates the email certificate's cryptographic properties (signatures and timestamp) but does not check whether the association has been revoked: [4](#0-3) 

The endpoint retrieves and returns the MskRecord from off-chain storage without cross-referencing the on-chain account state to verify the association's revocation status. The handler has access to `ContractState` which could be used to check revocation status, but this check is not performed.

**Exploit Scenario:**
1. User creates an association linking email alice@example.com to their account with RIK_A
2. User uploads MskRecord to off-chain nodes containing encrypted RIK data
3. User later suspects email compromise and calls `revoke_association(&RIK_A)`
4. The association is removed from on-chain account state; `initiate_recovery()` with RIK_A now fails with `InvalidRecoveryKey`
5. Attacker who compromised the email can:
   - Request a fresh email certificate from Swafe.io operator (valid for 5 minutes)
   - Call `get_secret_share` with the valid email certificate and VDRF evaluation
   - Successfully retrieve the MskRecord despite the revocation
   - MskRecord contains `enc_rik` with encrypted signing key and MSK secret share

**Security Failure:** The revocation security invariant is violated. The system fails to enforce access control consistently across on-chain (recovery initiation blocked) and off-chain (secret share retrieval allowed) layers. While the encrypted data in MskRecord requires the RIK to decrypt, the system should not serve any data associated with revoked associations as a defense-in-depth measure.

## Impact Explanation

**Affected Assets:**
- MskRecord containing encrypted signing keys and MSK secret shares
- User privacy and revocation security guarantees
- Information about threshold, Pedersen commitments, and user public keys

**Severity:**
The vulnerability compromises the revocation mechanism's effectiveness. While the encrypted data (`enc_rik`) requires the RIK to decrypt, the failure to enforce revocation at the off-chain layer creates several risks:

1. **Defense-in-depth violation**: If an attacker compromises both the email AND somehow obtains the RIK (through social engineering, backup theft, or other means), they can access the data despite explicit revocation
2. **Information leakage**: The MskRecord reveals metadata including user public key, threshold parameters, and cryptographic commitments that should be inaccessible after revocation
3. **Incomplete security model**: Users reasonably expect that revoking an association completely disables it, but the off-chain layer continues serving data

This matters because revocation is a critical security feature intended to mitigate compromised credentials. The incomplete enforcement undermines user trust and the protocol's security guarantees.

## Likelihood Explanation

**Trigger Conditions:**
- Any user can revoke an association
- An attacker needs to compromise the associated email account
- The attacker must request a fresh email certificate (requires email access)
- The attacker can then immediately exploit this vulnerability

**Frequency:**
This vulnerability is exploitable whenever:
1. A user revokes an association due to suspected email compromise (common security practice)
2. The email account is actually compromised at the time of or after revocation
3. The attacker acts within the email certificate's 5-minute validity window

The vulnerability is readily exploitable by anyone with access to a compromised email account associated with a revoked RIK, making it a realistic attack vector that could occur frequently in practice.

## Recommendation

Add revocation status checking to the `get_secret_share` endpoint:

1. **Retrieve account state**: Use the existing `ContractState` parameter to query the account associated with the MskRecord's user public key
2. **Verify association validity**: Cross-reference the account's current associations against the requesting user's credentials
3. **Reject revoked associations**: Return an error if the association has been revoked

Implementation approach:
```
In get_secret_share handler:
1. After verifying EmailCert (line 43)
2. Retrieve the MskRecord to get user_pk (line 48)
3. Query account state using the user_pk to find the associated AccountId
4. Verify that the account state still contains an active association for this user_pk
5. Only return the MskRecord if verification succeeds
```

Note: This requires establishing a mapping between user public keys and account IDs, or modifying MskRecord to include the account ID for verification purposes.

## Proof of Concept

**Test File:** `lib/src/account/tests.rs` (add new test function)

**Setup:**
1. Create an account with recovery setup
2. Create guardians and add an association with RIK
3. Upload MskRecord to off-chain storage (simulated)
4. Verify association works initially
5. Revoke the association via `revoke_association()`
6. Publish updated account state

**Trigger:**
1. Obtain a fresh email certificate for the revoked association
2. Call the equivalent of `get_secret_share` with the email certificate
3. Observe that the endpoint still returns the MskRecord

**Observation:**
The test should detect that despite revocation:
- `initiate_recovery()` correctly fails with `InvalidRecoveryKey`
- BUT the off-chain node would still serve the MskRecord if queried with a valid email certificate
- This demonstrates the incomplete revocation enforcement

The test confirms the vulnerability by showing that revocation only blocks on-chain recovery initiation but not off-chain secret share retrieval, violating the expected security invariant that revoked associations should be completely disabled.

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

**File:** lib/src/account/tests.rs (L960-1018)
```rust
    #[test]
    fn test_revoked_association_cannot_initiate_recovery() {
        let mut rng = OsRng;

        // Create account
        let account_secrets = AccountSecrets::gen(&mut rng).unwrap();

        // Create and verify initial state
        let update = account_secrets.update(&mut rng).unwrap();
        let account_state = update.verify(None).unwrap();

        // Decrypt to continue
        let mut account_secrets = account_state
            .decrypt(account_secrets.msk(), *account_secrets.acc())
            .unwrap();

        // Create guardians
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardians = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
        ];

        // Setup recovery
        account_secrets
            .update_recovery(&mut rng, &guardians, 2)
            .unwrap();

        // Add a second association
        let second_rik = account_secrets.add_association(&mut rng).unwrap();

        // Publish state with recovery
        let update = account_secrets.update(&mut rng).unwrap();
        let account_state = update.verify(Some(&account_state)).unwrap();

        // Verify second_rik works initially
        let AccountState::V0(ref state_v0) = account_state;
        let (_recovery_update, _recovery_secrets) = state_v0
            .initiate_recovery(&mut rng, *account_secrets.acc(), &second_rik)
            .expect("Second RIK should work before revocation");

        // Decrypt to continue making changes
        let mut account_secrets = account_state
            .decrypt(account_secrets.msk(), *account_secrets.acc())
            .unwrap();

        // Now revoke second_rik
        account_secrets.revoke_association(&second_rik).unwrap();

        // Publish updated state
        let update2 = account_secrets.update(&mut rng).unwrap();
        let account_state2 = update2.verify(Some(&account_state)).unwrap();

        // Verify second_rik NO LONGER works
        let AccountState::V0(ref state_v0_2) = account_state2;
        let result = state_v0_2.initiate_recovery(&mut rng, *account_secrets.acc(), &second_rik);
        assert!(matches!(result, Err(SwafeError::InvalidRecoveryKey)));
    }
```

**File:** lib/src/crypto/email_cert.rs (L84-116)
```rust
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
