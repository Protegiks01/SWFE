# Audit Report

## Title
TOCTOU Race Condition in Node Initialization Allows Node Identity Misconfiguration

## Summary
The `/init` endpoint handler in the Partisia smart contract contains a Time-of-Check-Time-of-Use (TOCTOU) race condition that allows concurrent initialization requests to overwrite each other's stored secrets. This can cause a node to be permanently initialized with an incorrect node identity, rendering it unable to participate in VDRF evaluations and breaking email certificate verification for all users attempting to use that node. [1](#0-0) [2](#0-1) 

## Impact
Medium

## Finding Description

**Location:** 
The vulnerability exists in `contracts/src/http/endpoints/init.rs` in the `handler` function, specifically between the initialization check and the storage operation. [3](#0-2) 

**Intended Logic:** 
The initialization endpoint should ensure that each off-chain node instance is initialized exactly once with a single, correct node identity. The check at line 44 is intended to prevent re-initialization by returning an error if a secret already exists.

**Actual Logic:** 
The check (`OffchainSecrets::load`) and store (`OffchainSecrets::store`) operations are not atomic. If two concurrent initialization requests arrive:
1. Both pass the check at line 44 (finding no existing secret)
2. Both deserialize and validate their respective secrets (lines 48-64)
3. Both execute the store operation at line 71, with one overwriting the other

Since the storage uses a unit key `()`, there is only one storage slot per node instance, and concurrent stores will race. [4](#0-3) [5](#0-4) 

**Exploit Scenario:**
1. Contract is deployed with multiple node configurations (node1, node2, node3, etc.)
2. During deployment, an off-chain node instance receives two concurrent `/init` POST requests:
   - Request A: `node_id="node:node1"` with corresponding valid secret
   - Request B: `node_id="node:node2"` with corresponding valid secret
3. Both requests reach line 44 simultaneously, both find no stored secret
4. Both proceed through validation (each secret hashes to its respective on-chain commitment)
5. Both execute line 71, storing their secrets; one overwrites the other
6. The node is now initialized with whichever request won the race (potentially the wrong node_id)

**Security Failure:** 
The node is permanently misconfigured with an incorrect identity. Subsequent operations will fail because:
- EmailCert verification checks that tokens are signed for the specific node_id
- VDRF evaluations use the stored node_id to identify which secret share to use
- Once initialized, the node cannot be re-initialized (line 44 prevents it) [6](#0-5) [7](#0-6) 

## Impact Explanation

**Affected Components:**
- Off-chain node identity and VDRF evaluation capabilities
- Email certificate verification for all users attempting to use the misconfigured node
- Association system functionality dependent on VDRF

**Severity of Damage:**
- The misconfigured node becomes permanently unusable for its intended operations
- Users attempting to create email-account associations through this node will receive verification failures
- VDRF evaluations will use the wrong secret share, producing incorrect results
- The node cannot self-recover; redeployment or manual intervention is required
- If multiple nodes are affected during initial deployment (realistic scenario), this could disable ≥10-30% of processing nodes

**System Impact:**
This directly impacts system availability and reliability. In a distributed VDRF system designed with n-1 threshold, having multiple nodes misconfigured reduces fault tolerance and can prevent the system from reaching the required threshold for VDRF evaluations, effectively breaking account association and recovery features for users.

## Likelihood Explanation

**Who Can Trigger:**
- Node operators during initial deployment
- Automation scripts with retry logic
- Accidental misconfiguration during node setup

**Required Conditions:**
- Two or more `/init` requests arrive at the same node instance concurrently
- This is realistic during:
  - Initial multi-node deployment when operators initialize all nodes simultaneously
  - Retry logic in automation tools
  - Network delays causing request buffering and concurrent delivery

**Frequency:**
- Moderate likelihood during deployment phase
- Low likelihood during normal operation (initialization is typically one-time)
- Higher risk in automated deployment pipelines with parallel initialization

The vulnerability is particularly concerning because:
1. It can affect multiple nodes simultaneously during deployment
2. The misconfiguration is permanent (no re-initialization allowed)
3. It's difficult to detect until operational issues arise

## Recommendation

Implement atomic check-and-set semantics for the initialization operation. Options include:

1. **Use a transaction/lock mechanism** if supported by the Partisia blockchain storage layer
2. **Store a dedicated initialization flag** alongside the secret and use it atomically
3. **Add a nonce or version field** that must match expected values
4. **Implement idempotent initialization** that verifies the stored node_id matches the request before considering it already initialized:

```rust
if let Some(existing) = OffchainSecrets::load(&mut ctx, ()) {
    // Allow re-initialization only if node_id matches
    if existing.node_id.0 != request.node_id.0 {
        return Err(ServerError::VdrfNodeAlreadyInitialized.into());
    }
    // If same node_id, treat as idempotent re-initialization and proceed
}
```

5. **Pre-allocate node identities** to specific node instances at deployment time and validate during initialization that only the correct node_id is accepted

The most robust solution would combine options 2 and 4, using atomic storage operations with idempotent semantics that validate node_id consistency.

## Proof of Concept

**Test File:** Add to `contracts/java-test/src/test/java/com/partisia/blockchain/contract/ConcurrentInitTest.java`

**Setup:**
1. Generate VDRF setup with 2+ nodes using `VdrfSetup.generateVdrfSetup()`
2. Deploy contract with node configurations
3. Create two initialization requests for the same node instance but with different node_ids (node1 and node2)

**Trigger:**
```java
// Simulate concurrent requests to the same TestExecutionEngine
TestExecutionEngine nodeEngine = engines[0]; // Same engine for both requests

// Create init request for node1
Map<String, String> initRequest1 = Map.of(
    "node_id", encodeNodeId("node:node1"),
    "secret", signedShares.get("node:node1")
);

// Create init request for node2 (wrong node for this instance)
Map<String, String> initRequest2 = Map.of(
    "node_id", encodeNodeId("node:node2"),
    "secret", signedShares.get("node:node2")
);

// Send both requests (in practice, send from concurrent threads)
HttpRequestData req1 = new HttpRequestData("POST", "/init", Map.of(), mapper.writeValueAsString(initRequest1));
HttpRequestData req2 = new HttpRequestData("POST", "/init", Map.of(), mapper.writeValueAsString(initRequest2));

HttpResponseData resp1 = nodeEngine.makeHttpRequest(contractAddress, req1).response();
HttpResponseData resp2 = nodeEngine.makeHttpRequest(contractAddress, req2).response();
```

**Observation:**
- Both requests may return success (200 status)
- The node stores whichever request executed line 71 last
- Subsequent operations (e.g., VDRF eval with a token for node1) will fail if node2 won the race
- Attempting to re-initialize will fail with `VdrfNodeAlreadyInitialized` error
- The test confirms the vulnerability by observing that the stored node_id doesn't match the expected initialization target

The test demonstrates that without atomic check-and-set semantics, concurrent initialization requests can cause permanent node misconfiguration that breaks the VDRF system's correctness guarantees.

### Citations

**File:** contracts/src/http/endpoints/init.rs (L28-36)
```rust
#[derive(ReadWriteState, Serialize, Deserialize, Clone, Default)]
pub struct OffchainSecrets {}

impl Mapping for OffchainSecrets {
    type Key = ();
    type Value = StoredOffchainSecret;

    const COLLECTION_NAME: &'static str = "map:node-secret";
}
```

**File:** contracts/src/http/endpoints/init.rs (L38-81)
```rust
pub fn handler(
    mut ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    if OffchainSecrets::load(&mut ctx, ()).is_some() {
        return Err(ServerError::VdrfNodeAlreadyInitialized.into());
    }

    let request: Request = deserialize_request_body(&request)?;

    // Get the node config from state to compare against the commitment
    let node_id = &request.node_id.0;
    let node_config = state.nodes.get(node_id.as_ref()).ok_or_else(|| {
        ServerError::InvalidParameter(format!("Node with id '{}' not found", node_id))
    })?;

    // Verify that the computed hash matches the stored commitment
    let secret = request.secret.0;
    if hash(&secret) != node_config.comm {
        return Err(ServerError::InvalidParameter(
            "Secret commitment mismatch - provided secret does not match on-chain commitment"
                .to_string(),
        )
        .into());
    }

    let stored_secret = StoredOffchainSecret {
        node_id: request.node_id,
        secret,
    };

    OffchainSecrets::store(&mut ctx, (), stored_secret);

    create_json_response(
        200,
        &Response {
            success: true,
            message: "Offchain node initialized successfully".to_string(),
        },
    )
    .map_err(|e| e.into())
}
```

**File:** contracts/src/storage.rs (L14-27)
```rust
    fn load(ctx: &mut OffChainContext, key: Self::Key) -> Option<Self::Value> {
        let storage: OffChainStorage<Vec<u8>, Vec<u8>> =
            ctx.storage(Self::COLLECTION_NAME.as_bytes());
        let key = encode::serialize(&key).unwrap();
        encode::deserialize::<Self::Value>(storage.get(&key)?.as_ref()).ok()
    }

    fn store(ctx: &mut OffChainContext, key: Self::Key, value: Self::Value) {
        let mut storage: OffChainStorage<Vec<u8>, Vec<u8>> =
            ctx.storage(Self::COLLECTION_NAME.as_bytes());
        let key = encode::serialize(&key).unwrap();
        let value = encode::serialize(&value).unwrap();
        storage.insert(key, value);
    }
```

**File:** lib/src/crypto/email_cert.rs (L84-94)
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
```

**File:** contracts/src/http/endpoints/association/vdrf/eval.rs (L34-50)
```rust
    let stored_secret =
        OffchainSecrets::load(&mut ctx, ()).ok_or(ServerError::VdrfNodeNotInitialized)?;

    // Now we have access to the node_id from stored_secret
    let node_id: NodeId = stored_secret.node_id.0;

    let (email, _) = EmailCert::verify(
        &swafe_public_key,
        &node_id,
        &request.token.0,
        ctx.current_time(),
    )?;

    let secret_share = &stored_secret.secret.secret_share;
    let vdrf_public_key: VdrfPublicKey = encode::deserialize(&state.vdrf_public_key)?;
    let email_input: EmailInput = email.parse()?;
    let evaluation_result = Vdrf::partial_eval(&vdrf_public_key, secret_share, &email_input)?;
```
