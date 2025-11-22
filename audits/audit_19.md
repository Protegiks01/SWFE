## Title
Missing Node Identity Verification Allows Cross-Node Identity Assumption During Initialization

## Summary
The `/init` endpoint in the Swafe contract accepts any valid `node_id` and corresponding secret without verifying that the node_id matches the intended identity of the receiving node. This allows an operator with access to multiple node secrets to initialize their physical node infrastructure with arbitrary node identities, breaking the distributed trust model that assumes independent node operation. [1](#0-0) 

## Impact
**Severity: Medium**

## Finding Description

**Location:** The vulnerability exists in `contracts/src/http/endpoints/init.rs`, specifically in the `handler` function (lines 38-81).

**Intended Logic:** Each physical off-chain node should initialize with its own pre-determined identity. The distributed VDRF system assumes that each logical node (identified by `node_id`) corresponds to an independently operated physical node. The threshold security model (t-of-n) relies on at least `t` nodes being independently controlled.

**Actual Logic:** The init handler accepts any `node_id` from the request body and only validates:
1. The node hasn't been initialized before (line 44-46)
2. The provided `node_id` exists in on-chain state (lines 52-54)
3. The provided secret's hash matches the on-chain commitment for that `node_id` (lines 58-63)

There is no verification that the `node_id` in the request matches the intended identity of the receiving node. [2](#0-1) 

**Exploit Scenario:**
1. During VDRF setup, secrets for nodes A, B, and C are generated with commitments stored on-chain
2. An operator who has access to multiple node secrets (e.g., the setup administrator, or through secret leakage) controls physical nodes M1 and M2
3. The operator sends POST request to M1's `/init` endpoint with `node_id="node:A"` and secret_A
4. The operator sends POST request to M2's `/init` endpoint with `node_id="node:B"` and secret_B  
5. Both M1 and M2 successfully initialize, with M1 storing node:A's identity and M2 storing node:B's identity
6. One operator now controls two logical nodes in the VDRF system [3](#0-2) 

**Security Failure:** The system fails to enforce the invariant that each logical node identity corresponds to an independently operated physical node. This breaks the distributed trust assumption underlying the VDRF threshold cryptography, where the security model requires that at most (t-1) out of n nodes are controlled by the same entity.

## Impact Explanation

This vulnerability affects the core security properties of the VDRF system:

1. **Privacy Compromise**: The VDRF system hides email-to-account associations by requiring threshold participation. If one operator controls multiple nodes, they can perform VDRF evaluations with fewer independent parties, potentially compromising user email privacy. [4](#0-3) 

2. **Threshold Security Degradation**: With a 2-of-3 threshold, if one operator controls 2 nodes, they effectively have complete control over VDRF evaluations, negating the security benefit of distribution. The trust model assumes "Minority of Off-Chain Nodes Corrupted" for security, but one operator controlling multiple nodes violates this assumption.

3. **System Integrity**: The on-chain configuration maps each `node_id` to specific addresses and URLs, expecting independent operation. Multiple physical nodes claiming the same identity creates operational confusion and potential routing issues.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability can be triggered whenever:
- An operator has access to multiple node secrets (high probability during initial setup phase when all secrets are generated centrally)
- Node HTTP endpoints are accessible for initialization (required for normal operation)

During the VDRF setup ceremony, all node secrets are generated in a single location before distribution. The entity performing setup (typically a system administrator or Swafe-io) has temporary access to all secrets. [5](#0-4) 

Additionally, if node secrets are ever leaked, stored insecurely, or transmitted through insecure channels during deployment, an attacker could exploit this vulnerability to consolidate control over multiple node identities.

## Recommendation

Implement a pre-configured node identity mechanism:

1. **Add Node Configuration**: Introduce a configuration parameter (e.g., environment variable `EXPECTED_NODE_ID` or config file) that each physical node must set before deployment, specifying its intended identity.

2. **Verify Identity Match**: Modify the `/init` handler to verify that the provided `node_id` matches the pre-configured expected identity:

```rust
// Pseudo-code for the fix:
let expected_node_id = load_expected_node_id_from_config();
if request.node_id.0 != expected_node_id {
    return Err(ServerError::InvalidParameter(
        format!("Node identity mismatch: expected '{}', got '{}'", 
                expected_node_id, request.node_id.0)
    ));
}
```

3. **Deployment Documentation**: Update deployment procedures to require node operators to configure their expected identity before initialization, ensuring each physical node knows its intended role in the VDRF system.

## Proof of Concept

**Test File**: `contracts/java-test/src/test/java/com/partisia/blockchain/contract/TestCrossNodeInit.java`

**Setup**:
1. Initialize Swafe contract with 3 pre-configured nodes (node:A, node:B, node:C) with their respective commitments
2. Create 3 test execution engines simulating 3 physical nodes
3. Generate VDRF setup with secrets for all 3 nodes

**Trigger**:
1. Extract node:A and node:B secrets from the setup
2. Send POST to engine[0]'s `/init` endpoint with `node_id="node:A"` and node:A's secret → Success
3. Send POST to engine[1]'s `/init` endpoint with `node_id="node:B"` and node:B's secret → Success  
4. Verify both engines successfully initialized with different identities
5. Send VDRF evaluation requests to both engines → Both respond successfully

**Observation**:
- Both physical nodes (engine[0] and engine[1]) initialize successfully with different identities
- No error is raised despite potentially being controlled by the same operator
- Both nodes can perform VDRF operations using their respective identities
- This demonstrates that one operator can control multiple logical nodes by initializing separate physical nodes with different valid credentials

The test confirms that there is no mechanism preventing one operator from assuming multiple node identities, violating the independent operation assumption of the VDRF threshold system.

### Citations

**File:** contracts/src/http/endpoints/init.rs (L48-64)
```rust
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
```

**File:** contracts/src/http/endpoints/init.rs (L66-71)
```rust
    let stored_secret = StoredOffchainSecret {
        node_id: request.node_id,
        secret,
    };

    OffchainSecrets::store(&mut ctx, (), stored_secret);
```

**File:** contracts/src/http/endpoints/association/vdrf/eval.rs (L23-50)
```rust
pub fn handler(
    mut ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request = deserialize_request_body::<Request>(&request)?;
    let swafe_public_key = encode::deserialize(&state.swafe_public_key).map_err(|_| {
        ServerError::SerializationError("Failed to deserialize Swafe public key".to_owned())
    })?;

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

**File:** contracts/java-test/src/test/java/com/partisia/blockchain/contract/VdrfSetup.java (L68-136)
```java
  public static java.util.List<SwafeContract.OffchainNodeSetup> generateVdrfSetup(
      String[] nodeIds, TestExecutionEngine[] testEngines, BlockchainAddress[] nodeAddresses)
      throws IOException, InterruptedException {
    logger.debug("Setup VDRF...");

    int numNodes = nodeIds.length;

    if (testEngines.length != numNodes) {
      throw new IllegalArgumentException(
          "Number of execution engines ("
              + testEngines.length
              + ") must match number of nodes ("
              + numNodes
              + ")");
    }

    Path outputPath = Path.of("src/test/resources/vdrf_test_setup.json");

    List<String> command =
        CliHelper.buildCommand(
            "generate-vdrf-test-setup",
            "--num-nodes",
            String.valueOf(numNodes),
            "--threshold",
            String.valueOf(numNodes - 1), // Use n-1 threshold for fault tolerance
            "--output",
            outputPath.toAbsolutePath().toString());

    if (nodeIds != null && nodeIds.length > 0) {
      command.add("--node-ids");
      command.add(String.join(",", nodeIds));
    }

    CliHelper.runCommand(command, "Generating VDRF test setup");

    String jsonContent = Files.readString(outputPath);
    ObjectMapper mapper = new ObjectMapper();
    JsonNode data = mapper.readTree(jsonContent);

    JsonNode sharesNode = data.get("signed_shares");
    Map<String, String> signedShares =
        mapper.convertValue(
            sharesNode,
            mapper.getTypeFactory().constructMapType(Map.class, String.class, String.class));

    JsonNode configsNode = data.get("node_configs");
    List<NodeConfig> nodeConfigs = new ArrayList<>();
    for (JsonNode configNode : configsNode) {
      nodeConfigs.add(
          new NodeConfig(
              configNode.get("node_id").asText(), configNode.get("public_key_str").asText()));
    }

    VdrfSetupData result =
        new VdrfSetupData(
            data.get("vdrf_public_key").asText(),
            signedShares,
            nodeConfigs,
            data.get("num_nodes").asInt());

    setupData = result;

    nodeEngineMap = new java.util.HashMap<>();
    for (int i = 0; i < nodeConfigs.size(); i++) {
      nodeEngineMap.put(nodeConfigs.get(i).nodeId, testEngines[i]);
    }

    return createVdrfNodeConfigsFromSetup(nodeAddresses);
  }
```
