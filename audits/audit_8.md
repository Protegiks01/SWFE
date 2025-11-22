## Title
Lack of Version Prefix in OffchainSecret Causes Permanent VDRF Freezing on Schema Upgrades

## Summary
The `OffchainSecret` structure lacks version tagging for schema upgrades, unlike other critical protocol types. When stored in contract storage and later deserialized after a schema change, it will fail, permanently freezing VDRF evaluation functionality for all initialized nodes with no recovery path due to immutable commitment verification.

## Impact
**High**

## Finding Description

**Location:** 
- Primary: [1](#0-0) 
- Storage: [2](#0-1) 
- Serialization: [3](#0-2) 
- Verification: [4](#0-3) 

**Intended Logic:** 
The protocol should support future schema upgrades for `OffchainSecret` while maintaining backward compatibility with previously stored secrets, similar to other protocol types that use versioned enums. [5](#0-4) 

**Actual Logic:** 
`OffchainSecret` is defined as a plain struct without version tagging and serialized using raw bincode. [6](#0-5)  When stored via the `Mapping` trait, it uses `encode::serialize()` which applies bincode without version prefixes. [7](#0-6)  During initialization, the contract verifies that `hash(&secret)` matches the immutable commitment stored in `node_config.comm`. [4](#0-3)  These commitments are set during contract deployment and stored permanently in contract state. [8](#0-7) 

**Exploit Scenario:**
1. Contract is deployed with nodes having commitments computed from `OffchainSecret` v0 schema
2. Nodes initialize successfully, storing v0 secrets in contract storage
3. Protocol team releases an upgrade requiring a schema change to `OffchainSecret` (e.g., adding a new field, changing the randomizer type, or updating VDRF primitives)
4. When nodes attempt VDRF evaluation, `OffchainSecrets::load()` tries to deserialize stored v0 data with v1 schema, which fails due to bincode incompatibility [9](#0-8) 
5. The deserialization returns `None`, causing `VdrfNodeNotInitialized` errors [10](#0-9) 
6. Nodes cannot re-initialize with v1 secrets because `hash(v1_secret) ≠ node_config.comm` (which contains `hash(v0_secret)`), causing commitment verification failure
7. The check preventing re-initialization only triggers if deserialization succeeds [11](#0-10) 

**Security Failure:** 
Permanent freezing of VDRF evaluation functionality across all initialized nodes, with no recovery mechanism. This breaks the core association system that depends on VDRF evaluations for email-to-account associations and related recovery operations.

## Impact Explanation

**Affected Components:**
- All initialized off-chain nodes with stored `OffchainSecret` data
- VDRF evaluation endpoint `/association/vdrf/eval` [12](#0-11) 
- MSK retrieval endpoint `/association/get_secret_share` [13](#0-12) 
- Association upload functionality [14](#0-13) 

**Severity:**
- **Critical outage:** All VDRF-dependent operations fail for 100% of initialized nodes (exceeds the ≥25% threshold for critical outage)
- **Permanent freezing:** No self-recovery mechanism exists; requires contract migration or hard fork
- **Cascading failure:** Email-account associations cannot be created or verified, blocking user account management
- **No workaround:** Cannot re-initialize with updated secrets due to immutable commitment mismatch

This directly matches the in-scope high-severity impact: "Permanent freezing of secrets or accounts (requiring a hard fork or intervention to fix)" and "Critical API/contract outage preventing account recovery or backup reconstruction for ≥25% of users."

## Likelihood Explanation

**Trigger Conditions:**
- Any protocol upgrade requiring `OffchainSecret` schema changes
- Normal contract operation after upgrade deployment

**Likelihood Factors:**
- **High probability:** The codebase demonstrates clear intent for versioning (using `v0:` prefixes everywhere and versioned enums for similar types)
- **Inevitable:** As the protocol matures, cryptographic primitives may need upgrades (larger key sizes, new algorithms, additional security parameters)
- **System-wide impact:** Affects all nodes simultaneously upon schema change
- **No gradual rollout:** The failure mode is binary—either all secrets deserialize or none do

The vulnerability will certainly manifest if the protocol attempts any schema evolution for `OffchainSecret`, `VdrfPublicKey`, or `VdrfSecretKeyShare` types, which are all stored without version prefixes.

## Recommendation

**Primary Fix:** Implement version tagging for `OffchainSecret` using the existing `versioned_enum!` macro pattern used throughout the codebase:

```rust
// In api/src/init.rs
versioned_enum!(
    #[derive(Clone)]
    OffchainSecret,
    V0(OffchainSecretV0) = 0
);

#[derive(Serialize, Deserialize, Clone)]
pub struct OffchainSecretV0 {
    pub public_key: VdrfPublicKey,
    pub secret_share: VdrfSecretKeyShare,
    pub randomizer: [u8; 32],
}
```

**Additional Measures:**
1. Update `StoredOffchainSecret` to use the versioned enum [15](#0-14) 
2. Implement migration logic for existing v0 secrets during upgrade transitions
3. Consider version-aware commitment verification that can validate both old and new schema hashes during transition periods
4. Add integration tests verifying forward compatibility (deserializing old secrets with new code)

This approach mirrors the existing pattern used for `MskRecord`, `Association`, `BackupCiphertext`, and `GuardianShare`. [5](#0-4) [16](#0-15) 

## Proof of Concept

**Test File:** `lib/tests/offchain_secret_version_compatibility.rs`

**Setup:**
1. Create a v0 `OffchainSecret` with VDRF keys and randomizer
2. Serialize it using bincode (simulating current storage)
3. Store the serialized bytes and compute commitment hash
4. Modify the `OffchainSecret` struct definition to add a new field (simulating schema upgrade)

**Trigger:**
1. Attempt to deserialize the stored v0 bytes with the modified struct definition
2. Observe deserialization failure due to missing field
3. Create a new v1 secret with the additional field
4. Compute hash of v1 secret
5. Verify that `hash(v1_secret) ≠ hash(v0_secret)`

**Observation:**
The test will demonstrate:
- V0 secrets cannot be deserialized after schema change (returns error)
- V1 secrets produce different commitment hashes, preventing re-initialization
- No recovery path exists without contract state modification

This confirms the vulnerability: any schema change to `OffchainSecret` permanently breaks VDRF functionality with no self-recovery mechanism, requiring hard fork intervention.

**Notes**

The vulnerability is particularly critical because:

1. **System-wide impact:** Unlike user-specific data (accounts, backups), `OffchainSecret` affects infrastructure nodes that serve all users
2. **Cascading failure:** VDRF evaluation is foundational to the association system, so its failure blocks multiple user-facing features
3. **Immutable commitments:** The on-chain commitments cannot be updated without contract migration, creating a deadlock situation
4. **Pattern inconsistency:** The codebase already has a robust versioning system (`versioned_enum!` macro with comprehensive tests [17](#0-16) ), making this omission anomalous

The protocol clearly anticipates schema evolution (evidenced by `v0:` separators in `Tagged` implementations and versioned enums for all major types), making this lack of version support for `OffchainSecret` a critical oversight that will cause operational failure during any future cryptographic upgrades.

### Citations

**File:** api/src/init.rs (L8-17)
```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct OffchainSecret {
    pub public_key: VdrfPublicKey,
    pub secret_share: VdrfSecretKeyShare,
    pub randomizer: [u8; 32],
}

impl swafe_lib::encode::Tagged for OffchainSecret {
    const SEPARATOR: &'static str = "v0:offchain-secret";
}
```

**File:** contracts/src/http/endpoints/init.rs (L22-36)
```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct StoredOffchainSecret {
    pub node_id: StrEncoded<NodeId>,
    pub secret: init::OffchainSecret, // Direct storage of OffchainSecret
}

#[derive(ReadWriteState, Serialize, Deserialize, Clone, Default)]
pub struct OffchainSecrets {}

impl Mapping for OffchainSecrets {
    type Key = ();
    type Value = StoredOffchainSecret;

    const COLLECTION_NAME: &'static str = "map:node-secret";
}
```

**File:** contracts/src/http/endpoints/init.rs (L44-46)
```rust
    if OffchainSecrets::load(&mut ctx, ()).is_some() {
        return Err(ServerError::VdrfNodeAlreadyInitialized.into());
    }
```

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

**File:** lib/src/association/mod.rs (L18-28)
```rust
versioned_enum!(
    #[derive(Clone)]
    MskRecord,
    V0(MskRecordV0) = 0
);

versioned_enum!(
    #[derive(Clone)]
    Association,
    V0(AssociationV0) = 0
);
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

**File:** contracts/src/http/endpoints/association/vdrf/eval.rs (L23-59)
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

    create_json_response(
        200,
        &Response {
            eval_share: encode::StrEncoded(evaluation_result),
        },
    )
    .map_err(|e| e.into())
}
```

**File:** contracts/src/http/endpoints/association/get_secret_share.rs (L35-36)
```rust
    let stored_secret =
        OffchainSecrets::load(&mut ctx, ()).ok_or(ServerError::VdrfNodeNotInitialized)?;
```

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L45-46)
```rust
    let stored_secret =
        OffchainSecrets::load(&mut ctx, ()).ok_or(ServerError::VdrfNodeNotInitialized)?;
```

**File:** lib/src/backup/v0.rs (L71-80)
```rust
versioned_enum!(
    #[derive(Clone)]
    BackupCiphertext,
    V0(BackupCiphertextV0) = 0
);

versioned_enum!(
    #[derive(Clone)]
    GuardianShare,
    V0(GuardianShareV0) = 0
```

**File:** lib/src/venum.rs (L240-324)
```rust
    fn forward_compatibility_deserialize_old_variant_with_new_enum() {
        // Old version: only V0 and V1
        versioned_enum!(
            #[derive(Debug, PartialEq)]
            OldEnum,
            V0(String) = 0,
            V1(u32) = 1
        );

        // New version: adds V2 and V3
        versioned_enum!(
            #[derive(Debug, PartialEq)]
            NewEnum,
            V0(String) = 0,
            V1(u32) = 1,
            V2(bool) = 2,
            V3(f64) = 3
        );

        // Serialize old variants using OldEnum
        let old_v0 = OldEnum::V0("forward".to_string());
        let old_v1 = OldEnum::V1(2024);

        let bytes_v0 = serialize(&old_v0).expect("serialize old_v0");
        let bytes_v1 = serialize(&old_v1).expect("serialize old_v1");

        // Deserialize using NewEnum
        let new_v0: NewEnum = deserialize(&bytes_v0).expect("deserialize new_v0");
        let new_v1: NewEnum = deserialize(&bytes_v1).expect("deserialize new_v1");

        assert_eq!(new_v0, NewEnum::V0("forward".to_string()));
        assert_eq!(new_v1, NewEnum::V1(2024));
    }

    #[test]
    fn forward_compatibility_with_removed_unused_variants() {
        // Old version: V0, V1, V2 (unused), V3
        versioned_enum!(
            #[derive(Debug, PartialEq)]
            OldEnumWithUnused,
            V0(String) = 0,
            V1(u32) = 1,
            V2(bool) = 2, // unused
            V3(f64) = 3
        );

        // New version: V0, V1, V3 (V2 removed)
        versioned_enum!(
            #[derive(Debug, PartialEq)]
            NewEnumWithoutUnused,
            V0(String) = 0,
            V1(u32) = 1,
            V3(f64) = 3
        );

        // Serialize old variants using OldEnumWithUnused
        let old_v0 = OldEnumWithUnused::V0("removed_unused".to_string());
        let old_v1 = OldEnumWithUnused::V1(2025);
        let old_v3 = OldEnumWithUnused::V3(2.718);

        let bytes_v0 = serialize(&old_v0).expect("serialize old_v0");
        let bytes_v1 = serialize(&old_v1).expect("serialize old_v1");
        let bytes_v3 = serialize(&old_v3).expect("serialize old_v3");

        // Deserialize using NewEnumWithoutUnused
        let new_v0: NewEnumWithoutUnused = deserialize(&bytes_v0).expect("deserialize new_v0");
        let new_v1: NewEnumWithoutUnused = deserialize(&bytes_v1).expect("deserialize new_v1");
        let new_v3: NewEnumWithoutUnused = deserialize(&bytes_v3).expect("deserialize new_v3");

        assert_eq!(
            new_v0,
            NewEnumWithoutUnused::V0("removed_unused".to_string())
        );
        assert_eq!(new_v1, NewEnumWithoutUnused::V1(2025));
        assert_eq!(new_v3, NewEnumWithoutUnused::V3(2.718));

        // If we try to deserialize a removed variant, it should error
        let old_v2 = OldEnumWithUnused::V2(true);
        let bytes_v2 = serialize(&old_v2).expect("serialize old_v2");
        let result_v2: Result<NewEnumWithoutUnused, _> = deserialize(&bytes_v2);
        assert!(
            result_v2.is_err(),
            "Deserializing removed variant should error"
        );
    }
```
