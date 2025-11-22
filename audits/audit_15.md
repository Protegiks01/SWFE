## Title
Missing Authentication Allows Unauthorized Node Initialization via Secret Knowledge Alone

## Summary
The POST /init endpoint for initializing off-chain execution nodes lacks proper authentication. It only verifies that the provided secret matches an on-chain commitment hash, without requiring cryptographic proof of the node operator's identity via signature verification. This allows any party with knowledge of the `OffchainSecret` to initialize a node, preventing the legitimate operator from doing so. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
The initialization endpoint should authenticate that the request comes from the legitimate node operator who was assigned the node during setup. The system generates signing key pairs for each node during VDRF setup, with the public key stored in `OffchainNodeState` specifically for "signature verification": [2](#0-1) [3](#0-2) 

**Actual Logic:**
The init handler performs only knowledge-based authentication:
1. Checks if the node is already initialized (line 44-46)
2. Verifies the node_id exists in contract state (line 51-54)  
3. Verifies `hash(&secret) == node_config.comm` (line 58-64)

There is **no signature verification** despite the node having a signing key pair. The handler accepts any request providing the correct `node_id` and `OffchainSecret` that matches the commitment, regardless of who sends it. [4](#0-3) 

**Exploit Scenario:**
1. During VDRF setup, `OffchainSecret` values are generated and distributed to node operators
2. An attacker obtains an `OffchainSecret` through:
   - Network interception during distribution
   - Compromised temporary storage where secrets are kept before initialization
   - Leaked backup files or configuration
   - Insider threat or social engineering
3. The attacker sends POST /init with the stolen `node_id` and secret before the legitimate operator initializes
4. The handler accepts it (hash verification passes, no signature check)
5. The node is marked as initialized
6. The legitimate operator's later initialization attempt is rejected (line 44-46 prevents re-initialization) [5](#0-4) 

**Security Failure:**
Authorization is based solely on secret knowledge rather than cryptographic proof of identity. The node's signing key exists for "signature verification" but is never used, creating a single point of failure: if the secret is compromised during distribution, there is no additional authentication layer.

## Impact Explanation

**Affected Components:**
- Off-chain execution nodes that become permanently locked to unauthorized initialization
- VDRF evaluation system if multiple nodes are affected
- System availability and reliability

**Severity:**
- **Denial of Service**: Once a node is initialized by an attacker, the legitimate operator cannot re-initialize it. The node becomes unavailable for legitimate VDRF operations.
- **System Degradation**: If multiple nodes are compromised, the VDRF threshold-based system may fail to meet its availability requirements
- **Operational Impact**: Requires manual intervention to recover (redeployment or contract reset)

**Why This Matters:**
The Swafe system relies on a distributed VDRF scheme where multiple off-chain nodes collectively hide email-to-account associations. Each node must be properly initialized and operated by legitimate parties. If attackers can initialize nodes, they can:
1. Deny service to legitimate operators
2. Potentially operate nodes maliciously (depending on what secrets they possess)
3. Degrade system availability if enough nodes are affected [6](#0-5) 

## Likelihood Explanation

**Who Can Trigger:**
Any party who obtains the `OffchainSecret` for a target node. While this requires access to confidential material, realistic scenarios include:
- Network-level attackers intercepting secrets during distribution
- Compromised storage or configuration management systems
- Insider threats with access to setup materials

**Conditions Required:**
1. The attacker must obtain the `OffchainSecret` before legitimate initialization
2. The attacker must have network access to the execution engine's HTTP endpoint
3. The attacker must act before the legitimate operator initializes

**Frequency:**
The vulnerability window exists between secret generation/distribution and legitimate initialization. In production deployments with:
- Multiple nodes being set up simultaneously
- Secrets transmitted over networks
- Temporary storage of setup materials
- Multiple personnel involved in deployment

The attack surface is non-trivial, especially during initial system deployment or when adding new nodes.

## Recommendation

Implement signature-based authentication for the init endpoint:

1. **Generate and securely distribute signing key pairs**: Modify the VDRF setup process to generate signing key pairs and distribute the private keys securely to node operators (separate from the `OffchainSecret` distribution if possible)

2. **Require signed initialization requests**: Modify the init endpoint to accept a signature over the request data:
   - The request should include a signature from the node operator's private key
   - The handler should verify the signature against the public key stored in `OffchainNodeState`
   - Only accept initialization if both the secret matches the commitment AND the signature is valid

3. **Defense in depth**: This ensures that even if the `OffchainSecret` is intercepted, an attacker cannot initialize the node without the signing private key. The two factors (knowledge of secret + possession of signing key) should be distributed through different channels.

Example fix for the handler:
```rust
// Add signature parameter to Request structure
// In handler, after line 58-64:
let node_public_key: sig::VerificationKey = 
    encode::deserialize(&node_config.public_key)?;
    
// Verify signature over (node_id, secret) using node_public_key
node_public_key.verify(&request.signature, &(node_id, &secret))?;
```

## Proof of Concept

**Test File:** `contracts/java-test/src/test/java/com/partisia/blockchain/contract/TestNodeInitAuth.java`

**Setup:**
1. Deploy Swafe contract with VDRF node configurations (including commitment hashes)
2. Create multiple execution engine instances for different nodes
3. Generate valid `OffchainSecret` values for each node (as done in normal setup)

**Trigger:**
1. As an attacker, obtain Node1's `OffchainSecret` (simulate interception)
2. Send POST /init request to Node1's execution engine with the stolen secret
3. Observe that initialization succeeds without any signature verification
4. Attempt to initialize Node1 again as the legitimate operator
5. Observe that the second initialization is rejected with "VdrfNodeAlreadyInitialized" error

**Observation:**
The test demonstrates that:
- Any party with knowledge of the `OffchainSecret` can initialize a node
- No signature or proof of node operator identity is required
- Once initialized (even by an unauthorized party), legitimate initialization is permanently blocked
- This violates the principle of defense-in-depth: secret knowledge alone should not be sufficient for authorization

The test should verify that initialization without proper authentication succeeds (demonstrating the vulnerability), and that the legitimate operator is subsequently locked out, causing denial of service.

### Citations

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

**File:** contracts/src/lib.rs (L48-59)
```rust
#[derive(Clone, ReadWriteState, CreateTypeSpec, ReadWriteRPC)]
struct OffchainNodeState {
    /// Node's Partisia address
    pub address: Address,
    /// Node's public key for signature verification
    pub public_key: Vec<u8>,
    /// Node off-chain url (must be HTTPS),
    /// e.g. https://node.example.com/node_url/
    pub url: String,
    /// Commitment to the node's offchain secret (hash of OffchainSecret)
    pub comm: [u8; 32],
}
```

**File:** cli/src/commands/vdrf.rs (L133-142)
```rust
        use swafe_lib::crypto::sig::SigningKey;
        let node_signing_key = SigningKey::gen(&mut rng);
        let node_public_key = node_signing_key.verification_key();

        let node_id: NodeId = format!("node:{}", label).parse().unwrap();

        let config = NodeTestConfig {
            node_id: node_id.to_string(),
            public_key_str: StrEncoded(node_public_key),
        };
```

**File:** README.md (L185-196)
```markdown
Off-chain nodes are full nodes capable of running off-chain computation and holding secret state. Security guarantees vary based on the corruption model:

#### No Corrupted Off-Chain Nodes

- User emails remain hidden even at registration/recovery time.

#### Minority of Off-Chain Nodes Corrupted

- Snapshot of corrupted off-chain node states hides user emails and account associations.
- Leaking an off-chain node's state does not reveal user emails or their association to on-chain contracts.
- Secrets without specified guardians remain decryptable without a valid "email certificate" from Swafe.
- The system remains available even if a minority subset of off-chain nodes are offline or unresponsive.
```
