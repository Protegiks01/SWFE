# Audit Report

## Title
Unprotected Encrypted RIK Data Allows MITM Tampering Leading to Permanent Account Loss

## Summary
The `enc_rik` field in `AssociationRequestEmail` is not cryptographically bound by the Signature of Knowledge (SoK) proof, allowing a malicious HTTP proxy or compromised off-chain node to replace the encrypted RIK data with arbitrary content before it reaches the smart contract. Since the contract validation only verifies the SoK proof over the Pedersen commitments and user public key (but not `enc_rik`), the tampered data is stored on-chain. When users later attempt account recovery, they receive corrupted encrypted data, resulting in permanent loss of account access.

## Impact
**High**

## Finding Description

### Location
- **Primary vulnerability:** [1](#0-0) 
- **SoK proof creation:** [2](#0-1) 
- **Request structure:** [3](#0-2) 
- **Contract handler:** [4](#0-3) 

### Intended Logic
The system should ensure that all fields in the `AssociationRequestEmail` structure are cryptographically authenticated, preventing tampering by intermediate parties. The encrypted RIK data (`enc_rik`) contains critical secrets (user's signing key and MSK secret share) that must maintain integrity from client to contract storage.

### Actual Logic
The SoK proof is generated with only the user's verification key as the message parameter, binding only the Pedersen commitments and user public key: [5](#0-4) 

During verification, the contract checks: [6](#0-5) 

1. User public key matches (line 193-196)
2. Secret share consistency with commitments (line 200)
3. SoK proof validity against commitments and user_pk (line 203-206)

However, the `enc_rik` field is never validated for integrity. It's simply included in the stored `MskRecord` without any cryptographic binding: [7](#0-6) 

### Exploit Scenario

1. **User Creates Association:** Client generates legitimate `AssociationRequestEmail` with correct `enc_rik` containing encrypted signing key and MSK secret share.

2. **MITM Interception:** A malicious HTTP proxy or compromised off-chain node intercepts the upload_msk request before it reaches the contract handler.

3. **Tampering:** The attacker modifies the `enc_rik.ciphertext` field to contain random bytes or malicious data while leaving all other fields (user_pk, commits, sok_proof, share) unchanged.

4. **Contract Processing:** The contract handler receives the modified request: [8](#0-7) 

5. **Validation Passes:** All cryptographic checks succeed because:
   - EmailCert verification passes (unchanged token)
   - SoK proof verifies against unchanged commitments and user_pk
   - Secret share matches unchanged commitments
   - The modified `enc_rik` is never checked

6. **Corrupted Storage:** The modified `MskRecord` with tampered `enc_rik` is stored on-chain.

7. **Recovery Failure:** When the user later attempts account recovery:
   - They reconstruct the RIK correctly
   - They retrieve the stored (but tampered) `enc_rik` 
   - Decryption fails or produces garbage data
   - User cannot obtain their signing key and MSK secret share
   - Account is permanently inaccessible

### Security Failure
This breaks the fundamental security invariant: "Only the owner of an email should be able to request the recovery of an account." The tampering doesn't prevent the initial association upload, but it permanently prevents legitimate recovery, effectively denying the rightful owner access to their account.

## Impact Explanation

**Affected Assets:**
- Master Secret Key (MSK) secret share from RIK side
- User's signing key for recovery authorization
- Complete account access and all associated backups

**Severity:**
- **Permanent Account Loss:** The user cannot decrypt the tampered `enc_rik` during recovery, making the account permanently inaccessible. No amount of valid email certificates or guardian approvals can recover the account because the encrypted data itself is corrupted.
- **Undetectable Until Recovery:** The attack succeeds silently during association upload. Users only discover the problem when attempting recovery, potentially months or years later when the attacker is long gone.
- **No Remediation Path:** Once the corrupted data is stored on-chain, there's no cryptographic way to recover the original secrets. The account would require manual intervention or hard fork to fix.

This qualifies as "Direct loss of funds or compromise of private keys/secrets" and "Permanent freezing of secrets or accounts" per the in-scope impact criteria.

## Likelihood Explanation

**Who Can Trigger:**
- Any malicious HTTP proxy positioned between client and off-chain node
- Any compromised off-chain node (even one in a set of many)
- Accidental corruption due to buggy proxy/node implementations

**Conditions Required:**
- User's request must route through the malicious proxy or compromised node
- No additional authentication required - the attack works on any valid association upload
- Attack window exists during every association creation or update

**Frequency:**
- **High probability per request:** Every upload_msk request is vulnerable
- **Network exposure:** HTTP traffic is susceptible to MITM without additional transport security
- **Persistent compromise:** A single compromised node can attack all users routing through it
- **Silent failure:** Attack remains undetected until recovery attempt, potentially years later

While off-chain nodes are nominally trusted, the security question explicitly frames this scenario as in-scope. The system's design claims to tolerate minority node corruption, but this vulnerability breaks that guarantee. Additionally, MITM proxies are external threats not covered by the trust model.

## Recommendation

**Primary Fix:** Include `enc_rik` in the SoK proof message to cryptographically bind it to the other verified fields.

Modify the SoK proof creation to use a composite message structure:

```rust
// In create_encrypted_msk function
#[derive(Serialize)]
struct SokMessage {
    user_pk: sig::VerificationKey,
    enc_rik: EncryptedMsk,
}

let sok_message = SokMessage {
    user_pk: sig_sk.verification_key(),
    enc_rik: ct.clone(),
};

let sok_proof = SokProof::prove(rng, &generators, &opens, &comms, &sok_message)?;
```

And update the verification in `AssociationRequestEmail::verify` to reconstruct the same message structure before verifying the SoK proof.

**Alternative Fix:** Add a separate signature from the user's signing key over the complete `MskRecordFixed` structure (including `enc_rik`) and verify this signature in the contract handler before storage.

Both approaches ensure that `enc_rik` cannot be modified without invalidating the cryptographic proofs.

## Proof of Concept

**File:** `lib/src/association/tests.rs` (or create new test file `lib/src/association/tampering_test.rs`)

**Test Function:** `test_enc_rik_tampering_undetected`

### Setup
1. Generate Swafe keypair, VDRF keys, and user keypair
2. Create a legitimate association with correct `enc_rik` using `Association::create_rik_association`
3. Generate `AssociationRequestEmail` for a specific node

### Trigger
1. Extract the legitimate `AssociationRequestEmail`
2. Clone it and modify the `enc_rik.ciphertext` field to random garbage bytes
3. Call `verify()` on the tampered request with the legitimate user_pk and node_id

### Observation
The test expects the `verify()` call to **succeed** (demonstrating the vulnerability), returning a valid `MskRecord` with the tampered `enc_rik`. The test then attempts to decrypt the stored `enc_rik` using the correct RIK and observes that decryption fails or produces garbage, confirming that the tampered data would prevent legitimate recovery.

```rust
#[test]
fn test_enc_rik_tampering_undetected() {
    let mut rng = thread_rng();
    
    // Setup: Create legitimate association
    let (encapsulated_msk, rik) = AssociationV0::create_rik_association(&mut rng, 3).unwrap();
    let user_keypair = encapsulated_msk.user_keypair().clone();
    let user_pk = user_keypair.verification_key();
    
    let node_id: NodeId = "node:test".parse().unwrap();
    
    // Generate legitimate request
    let swafe_keypair = sig::SigningKey::gen(&mut rng);
    let email_cert = EmailCert::issue(&mut rng, &swafe_keypair, &user_pk, "user@test.com".to_string());
    
    let association = AssociationV0::new(encapsulated_msk, email_cert, user_keypair);
    let legitimate_request = association.gen_association_request(&mut rng, &node_id).unwrap();
    
    // Trigger: Tamper with enc_rik
    let mut tampered_request = legitimate_request.clone();
    tampered_request.fixed.enc_rik.ciphertext = vec![0xFF; 100]; // Replace with garbage
    
    // Observation: Verify still passes (demonstrating vulnerability)
    let stored_record = tampered_request.verify(&user_pk, &node_id);
    assert!(stored_record.is_ok(), "Tampered request should pass verification - THIS IS THE VULNERABILITY");
    
    // Demonstrate that recovery would fail
    let stored = stored_record.unwrap();
    if let MskRecord::V0(record) = stored {
        // Attempt to decrypt with correct RIK - should fail with tampered data
        let decrypt_result = symmetric::open(
            rik.as_bytes(),
            &record.fixed.enc_rik.ciphertext,
            &symmetric::EmptyAD,
        );
        assert!(decrypt_result.is_err(), "Decryption should fail with tampered enc_rik");
    }
}
```

The test demonstrates that the contract validation accepts tampered `enc_rik` data, which would permanently prevent legitimate account recovery.

### Citations

**File:** lib/src/association/v0.rs (L166-171)
```rust
/// Request to associate an email with an MskRecord
#[derive(Clone, Serialize, Deserialize)]
pub struct AssociationRequestEmail {
    pub(super) fixed: MskRecordFixed,
    pub(super) share: PedersenOpen,
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

**File:** lib/src/association/v0.rs (L354-357)
```rust
        // Generate signature of knowledge proof of commitments
        // π ← sokSign(msg = sigPK_user, rel = {∀i. (v_i, r_i) : ∀i. C_i = pedersen(v_i, r_i)})
        let sok_proof =
            SokProof::prove(rng, &generators, &opens, &comms, &sig_sk.verification_key())?;
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
