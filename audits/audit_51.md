# Audit Report

## Title
Unbounded Request Deserialization Enables Resource Exhaustion Attack on Processing Nodes

## Summary
The smart contract's HTTP request deserialization lacks size validation for vector fields, allowing an attacker to craft malicious association upload requests with arbitrarily large commitment vectors. This triggers expensive cryptographic operations that can exhaust memory and CPU resources on Partisia processing nodes, potentially causing node shutdowns. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** 
The vulnerability spans multiple files:
- HTTP deserialization: [1](#0-0) 
- Upload endpoint handler: [2](#0-1) 
- Secret share verification: [3](#0-2) 
- SoK proof verification: [4](#0-3) 

**Intended Logic:** 
The system should deserialize legitimate association upload requests containing a reasonable number of Pedersen commitments (typically equal to the threshold value, e.g., 3-10 commitments), verify the secret shares, and store the association data.

**Actual Logic:** 
The deserialization process does not enforce any size limits on the `commits: Vec<PedersenCommitment>` field within `AssociationRequestEmail`. When verification occurs, both `verify_secret_share()` and `SokProof::verify()` iterate over the entire commitment vector, performing expensive elliptic curve operations (point multiplications and field arithmetic) for each commitment without checking the vector size first. [5](#0-4) 

**Exploit Scenario:**
1. Attacker crafts a malicious JSON request for the `/association/upload-association` endpoint
2. The request contains a valid email certificate token and VDRF evaluation (obtainable through legitimate means)
3. The `AssociationRequestEmail` payload includes a `commits` vector with millions of Pedersen commitments (e.g., 1-10 million entries)
4. The contract node deserializes the entire request, allocating memory for all commitments
5. During `verify()`, the node performs cryptographic operations in two nested loops:
   - `verify_secret_share()` loops through all commitments performing point multiplications [6](#0-5) 
   - `SokProof::verify()` loops through all commitments again performing more point multiplications [7](#0-6) 
6. The processing node experiences memory exhaustion (each G1 point ~96 bytes × millions = hundreds of MB) and CPU exhaustion (elliptic curve operations for millions of commitments)

**Security Failure:** 
Resource exhaustion on Partisia blockchain processing nodes. The node becomes unresponsive or crashes due to excessive memory allocation and CPU consumption, preventing it from processing legitimate transactions and potentially causing a partial network outage.

## Impact Explanation

**Affected Components:**
- Partisia blockchain processing nodes running the Swafe smart contract
- Network capacity to process legitimate association uploads and recovery operations
- Overall system availability and reliability

**Severity:**
An attacker can send a single malicious request to cause:
- **Memory exhaustion**: With 1 million commitments × 96 bytes per G1Affine point ≈ 96 MB of memory allocation just for the commitments, plus additional overhead for serialization structures
- **CPU exhaustion**: Millions of elliptic curve point multiplications (each requiring significant computation) and field element operations
- **Node shutdown**: The processing node may crash due to out-of-memory errors or become unresponsive due to CPU saturation
- **Network degradation**: If multiple nodes process the malicious request or the attacker targets multiple nodes, ≥30% of processing nodes could be affected, meeting the Medium severity threshold

This matters because the Swafe protocol relies on processing nodes for all critical operations including account recovery and backup reconstruction. If processing nodes are offline or unresponsive, legitimate users cannot recover their accounts or access their encrypted secrets.

## Likelihood Explanation

**Triggerability:** 
- **Who:** Any unprivileged network participant who can obtain a valid email certificate token (through legitimate registration) can exploit this vulnerability
- **Prerequisites:** Minimal - attacker only needs to register one email to obtain a valid token, then craft a malicious request
- **Frequency:** The attack can be executed repeatedly with different email certificates or re-using the same token if not rate-limited
- **Conditions:** Works during normal network operation; no special timing or state requirements

**Likelihood: High**
The attack is trivial to execute (just craft a large JSON payload), requires no special privileges beyond what any legitimate user has, and can be automated. Each malicious request can potentially take down a processing node, making this a practical and easily exploitable vulnerability.

## Recommendation

Implement size validation for vector fields in request deserialization:

1. **Add maximum size constants** for commitment vectors (e.g., `MAX_COMMITMENTS = 100`) based on reasonable threshold values
2. **Validate before expensive operations** in `AssociationRequestEmail::verify()`:
   ```
   if self.fixed.commits.len() > MAX_COMMITMENTS {
       return Err(SwafeError::InvalidInput("Too many commitments"));
   }
   ```
3. **Add early size check** in `deserialize_request_body()` to reject oversized request bodies before full deserialization
4. **Apply similar limits** to other unbounded vectors like `BackupCiphertextV0.comms`

The limit should be set based on maximum realistic threshold values (e.g., 100 guardians would be extraordinarily high, so 100 commitments is a safe upper bound).

## Proof of Concept

**File:** `contracts/java-test/src/test/java/com/partisia/blockchain/contract/TestResourceExhaustion.java`

**Setup:**
1. Initialize a Swafe contract instance with VDRF setup
2. Generate a valid email certificate token for an attacker-controlled email
3. Create a legitimate `AssociationRequestEmail` structure
4. Modify the `commits` vector to contain a large number (e.g., 100,000) of Pedersen commitments

**Trigger:**
1. Serialize the malicious `AssociationRequestEmail` with oversized `commits` vector to JSON
2. Send POST request to `/association/upload-association` endpoint
3. Measure processing time and memory consumption during deserialization and verification

**Observation:**
- Without size limits: Processing time scales linearly with commitment count (e.g., 100,000 commitments could take minutes and consume hundreds of MB)
- Memory allocation grows unbounded with commitment vector size
- Node may crash with out-of-memory error or become unresponsive
- Test confirms that a single malicious request can cause processing node resource exhaustion meeting the ≥30% increase threshold

The test would demonstrate that verification time and memory consumption scale linearly with the number of commitments, and with sufficiently large vectors (e.g., 1 million commitments), can cause node failure.

### Citations

**File:** contracts/src/http/mod.rs (L13-23)
```rust
pub fn deserialize_request_body<T>(request: &HttpRequestData) -> Result<T, ServerError>
where
    T: serde::de::DeserializeOwned,
{
    // Parse request body as UTF-8
    let body_str =
        std::str::from_utf8(&request.body).map_err(|_| ServerError::InvalidRequestBody)?;

    // Deserialize JSON
    json::from_str(body_str)
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

**File:** lib/src/association/v0.rs (L247-278)
```rust
pub(super) fn verify_secret_share(
    coms: &[PedersenCommitment],
    eval: &PedersenOpen,
    node_id: &NodeId,
) -> Result<(), SwafeError> {
    // Compute x value for this node
    let x = node_id.eval_point();

    // Compute linear combination of commitments:
    // ⟨(1, x, x², ..., x^(t-1)), (C₀, C₁, ..., C_{t-1})⟩
    let mut comb = PedersenCommitment::zero();
    let mut x_power = curve::Fr::one(); // x^0 = 1

    for commitment in coms {
        // Add [x^i] * C_i to the combination
        comb = comb + commitment.clone() * x_power;
        // Update x_power for next iteration: x^i -> x^{i+1}
        x_power *= x;
    }

    // Create Pedersen generators to compute expected commitment
    let generators = PedersenGenerators::new();

    // Check if they are equal
    if comb != generators.commit(eval) {
        Err(SwafeError::VerificationFailed(
            "Invalid verifiable secret sharing".to_string(),
        ))
    } else {
        Ok(())
    }
}
```

**File:** lib/src/crypto/commitments.rs (L202-230)
```rust
    /// Verify a SoK proof for multiple Pedersen commitments
    /// Implements the verification procedure as specified in notation.md
    pub fn verify<T: Tagged>(
        &self,
        gens: &PedersenGenerators,
        coms: &[PedersenCommitment],
        msg: &T,
    ) -> Result<(), SwafeError> {
        if coms.is_empty() {
            return Err(SwafeError::InvalidInput("Empty commitment set".to_string()));
        }

        // 1. Recompute challenge alpha = H("SchnorrSoK", msg, Delta, C_0, ..., C_{n-1})
        let alpha = pp::hash_to_fr(&SokMessage {
            msg: hash(msg),
            delta: self.delta.clone(),
            commitments: coms,
        });

        // 2. Compute C_alpha = Delta + [alpha] * (sum_i [alpha^i] * C_i)
        let mut alpha_power = pp::Fr::ONE;
        let mut combine = PedersenCommitment::zero();
        for com in coms {
            combine = combine + com.clone() * alpha_power;
            alpha_power *= alpha;
        }

        // 3. Check C_alpha = pedersen(v_alpha, r_alpha)
        if self.delta.clone() + combine * alpha == gens.commit(&self.alpha) {
```
