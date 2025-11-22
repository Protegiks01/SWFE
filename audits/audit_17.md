## Title
Missing VdrfPublicKey Consistency Validation in Node Initialization Causes Permanent VDRF Operation Failure

## Summary
The node initialization endpoint in `contracts/src/http/endpoints/init.rs` fails to verify that the `VdrfPublicKey` embedded in the provided `OffchainSecret` matches the `vdrf_public_key` stored in the contract state. This allows nodes to be initialized with mismatched cryptographic parameters, leading to permanent denial of service on all VDRF-dependent operations (email associations, account recovery) when an honest setup operator makes a configuration error.

## Impact
**High**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The initialization endpoint should ensure that nodes are configured with cryptographically consistent parameters. Specifically, the `VdrfPublicKey` in the `OffchainSecret` (which corresponds to the node's `secret_share`) must match the global `vdrf_public_key` stored in the contract state, as both are derived from the same VDRF master secret key during the setup ceremony.

**Actual Logic:** 
The handler only verifies that `hash(&secret) == node_config.comm` to check commitment integrity, but performs no validation that `secret.public_key` equals `state.vdrf_public_key`. The `OffchainSecret` structure contains its own `public_key` field [2](#0-1) , which is stored but never validated against the contract's global VDRF public key.

**Exploit Scenario:**
1. During contract initialization, Swafe-io provides a `vdrf_public_key` parameter [3](#0-2) 
2. Due to an honest mistake (copy-paste error, using an old key from a previous setup, mixing multiple VDRF configurations), Swafe-io initializes the contract with `vdrf_public_key = PK2`
3. But the `OffchainSecret` instances (and their pre-computed commitments) were generated from a different setup where `public_key = PK1` and `secret_share` was derived for PK1
4. During node initialization, the commitment check passes (commitments were computed correctly for PK1-based secrets) [1](#0-0) 
5. The mismatched secret is stored successfully
6. When VDRF evaluation is requested, the handler loads `secret_share` (derived for PK1) but uses `state.vdrf_public_key` (PK2) [4](#0-3) 
7. The partial evaluation `Vdrf::partial_eval(&PK2, &share_for_PK1, &input)` produces cryptographically invalid output
8. During combination, the pairing check `e(G1, eval_i) * e(-E_i, K) = 1` fails [5](#0-4) 
9. All shares from this node are rejected, and threshold cannot be met
10. All VDRF operations fail permanently

**Security Failure:** 
Complete and permanent denial of service on all VDRF-dependent functionality. The system fails to enforce the cryptographic consistency invariant that all nodes must use matching VDRF public keys with their corresponding secret shares.

## Impact Explanation

**Affected Components:**
- All email-to-account association operations (users cannot register or associate emails)
- All account recovery operations (users cannot recover accounts via email)
- All VDRF evaluation requests fail at the pairing verification stage
- Entire distributed VDRF protocol becomes non-functional

**Severity:**
This vulnerability causes **permanent freezing** of critical protocol functionality affecting **100% of users**. Unlike temporary outages, this cannot be fixed without:
- Redeploying the smart contract with corrected parameters
- Re-running the entire VDRF setup ceremony
- Re-initializing all nodes with new secrets

The error is undetectable during initialization and only manifests when users attempt VDRF operations, at which point the system is already in an unrecoverable state.

**Why This Matters:**
VDRF is fundamental to Swafe's privacy-preserving email association system. Without functioning VDRF operations, the entire protocol's core functionality (email-based account recovery) is permanently disabled. This represents a critical failure mode that requires manual intervention and contract redeployment to resolve.

## Likelihood Explanation

**Trigger Conditions:**
- Any honest operator performing the setup ceremony can trigger this through configuration errors
- Requires no malicious intent, only human error in parameter management
- Common scenarios: copy-pasting wrong public key string, using backup/test configurations, mixing development and production parameters

**Timing:**
- Occurs during the one-time setup phase
- Not detectable until first VDRF evaluation is attempted
- Once triggered, affects all subsequent operations permanently

**Frequency:**
While this is a one-time setup issue, the likelihood of occurrence is **moderate to high** because:
1. Setup involves manually coordinating multiple cryptographic parameters across contract initialization and secret distribution
2. No validation exists to catch the mismatch early
3. The error is silent (initialization succeeds) until actual use
4. Human error in complex cryptographic setup is common

## Recommendation

Add explicit validation in the initialization handler to verify VdrfPublicKey consistency:

```rust
// After line 57 in contracts/src/http/endpoints/init.rs
let vdrf_pk_state: VdrfPublicKey = encode::deserialize(&state.vdrf_public_key)
    .map_err(|_| ServerError::SerializationError("Failed to deserialize VDRF public key".to_owned()))?;

// Verify the public keys match
if encode::serialize(&secret.public_key).unwrap() != encode::serialize(&vdrf_pk_state).unwrap() {
    return Err(ServerError::InvalidParameter(
        "VdrfPublicKey mismatch - OffchainSecret public_key does not match contract vdrf_public_key".to_string()
    ).into());
}
```

This ensures cryptographic consistency is enforced at initialization time, catching configuration errors before they cause permanent protocol failure.

## Proof of Concept

**Test File:** Add to `contracts/src/http/endpoints/init.rs` test module (or create integration test)

**Setup:**
1. Initialize contract with `vdrf_public_key` set to PK1 (from first VDRF setup)
2. Generate a second, different VDRF setup producing PK2 and corresponding secret shares
3. Compute commitment for OffchainSecret containing PK2 and share_for_PK2
4. Use this commitment in the contract's node configuration
5. Create initialization request with OffchainSecret containing PK2 and share_for_PK2

**Trigger:**
1. Call the `/init` endpoint with the mismatched secret
2. Observe that initialization succeeds (commitment check passes)
3. Attempt VDRF evaluation using stored secret
4. Call `Vdrf::partial_eval` with `state.vdrf_public_key` (PK1) and `stored_secret.secret_share` (share_for_PK2)
5. Attempt to combine partial evaluations

**Observation:**
The test should demonstrate:
- Initialization succeeds despite VdrfPublicKey mismatch
- VDRF partial evaluation produces invalid output
- Pairing verification fails during `Vdrf::combine`
- Error: `NotEnoughSharesForReconstruction` even with sufficient nodes
- System is permanently unable to complete VDRF operations

This confirms the vulnerability: missing validation allows cryptographically inconsistent initialization that permanently breaks VDRF functionality.

### Citations

**File:** contracts/src/http/endpoints/init.rs (L56-64)
```rust
    // Verify that the computed hash matches the stored commitment
    let secret = request.secret.0;
    if hash(&secret) != node_config.comm {
        return Err(ServerError::InvalidParameter(
            "Secret commitment mismatch - provided secret does not match on-chain commitment"
                .to_string(),
        )
        .into());
    }
```

**File:** api/src/init.rs (L8-13)
```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct OffchainSecret {
    pub public_key: VdrfPublicKey,
    pub secret_share: VdrfSecretKeyShare,
    pub randomizer: [u8; 32],
}
```

**File:** contracts/src/lib.rs (L79-97)
```rust
#[init]
fn initialize(
    _ctx: ContractContext,
    nodes: Vec<OffchainNodeSetup>,
    swafe_public_key: String,
    vdrf_public_key: String,
) -> ContractState {
    // Insert nodes into the map using their node_id as the key
    let mut node_map = AvlTreeMap::new();
    for node in nodes.into_iter() {
        let node_id: NodeId = node.node_id.parse().expect("Failed to parse node ID");
        node_map.insert(node_id.to_string(), node.state);
    }

    let swafe_public_key: sig::VerificationKey = encode::deserialize_str(swafe_public_key.as_str())
        .expect("Failed to deserialize swafe public key");

    let vdrf_public_key: VdrfPublicKey = encode::deserialize_str(vdrf_public_key.as_str())
        .expect("Failed to deserialize vdrf public key");
```

**File:** contracts/src/http/endpoints/association/vdrf/eval.rs (L47-50)
```rust
    let secret_share = &stored_secret.secret.secret_share;
    let vdrf_public_key: VdrfPublicKey = encode::deserialize(&state.vdrf_public_key)?;
    let email_input: EmailInput = email.parse()?;
    let evaluation_result = Vdrf::partial_eval(&vdrf_public_key, secret_share, &email_input)?;
```

**File:** lib/src/crypto/vdrf.rs (L169-181)
```rust
            // optimized: e(G1, eval_i) * e(-E_i, K) = 1
            if pp::check_pairing(
                &[
                    pp::G1Affine::generator(),
                    Self::compute_commitment_at_point(public_key, xi),
                ],
                &[evl.0, -pnt],
            ) {
                uniq_shares.insert(xi, evl);
                if uniq_shares.len() == public_key.threshold() {
                    break;
                }
            }
```
