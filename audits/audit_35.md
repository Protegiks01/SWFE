## Title
Email-Account Correlation via Public Verification Key Linkage in Association System

## Summary
When an attacker compromises a minority of off-chain nodes, they can correlate VDRF evaluations (EmailKey) with specific on-chain accounts by matching the user verification key (`user_pk`) stored in off-chain `MskRecord` mappings with the publicly accessible verification key (`sig`) in `AccountState`. This breaks the privacy guarantee stated in README.md:193-194 that "Leaking an off-chain node's state does not reveal user emails or their association to on-chain contracts."

## Impact
**Medium**

## Finding Description

**Location:** 
- `lib/src/association/v0.rs` lines 139-149 (MskRecordFixed structure) [1](#0-0) 

- `lib/src/account/v0.rs` lines 230-238 (AccountStateV0 structure) [2](#0-1) 

- `contracts/src/http/endpoints/account/get.rs` lines 18-36 (public account retrieval endpoint) [3](#0-2) 

**Intended Logic:** 
The system is designed to hide email-account associations using VDRF evaluations as privacy-preserving lookup keys. According to README.md lines 193-194, when off-chain nodes are compromised, the leaked state should not reveal associations between emails and on-chain contracts. [4](#0-3) 

**Actual Logic:** 
The same `VerificationKey` appears in two places:
1. In `MskRecordFixed.user_pk` (stored off-chain, mapped by EmailKey derived from VDRF evaluation) [5](#0-4) 

2. In `AccountStateV0.sig` (publicly accessible via `/account/get` endpoint with no authentication) [6](#0-5) 

Both are set to the same value - the user's signature verification key, as confirmed in the association request generation: [7](#0-6) 

And in the account state update: [8](#0-7) 

**Exploit Scenario:**
1. Attacker compromises a minority of off-chain nodes (within the threat model stated in README.md lines 191-196)
2. Attacker extracts the association storage mapping from the compromised node: `EmailKey → MskRecord` where MskRecord contains `user_pk` [9](#0-8) 

3. Attacker queries the public `/account/get` endpoint for all accounts (no authentication required) to retrieve their `AccountState` containing `sig` [10](#0-9) 

4. Attacker matches `MskRecord.user_pk == AccountState.sig` to link EmailKey (VDRF evaluation) with specific AccountId

**Security Failure:** 
This breaks the privacy guarantee that off-chain node compromise does not reveal email-account associations. While the attacker doesn't learn the actual email address (VDRF protects that), they can correlate which VDRF evaluation (deterministic for a given email) belongs to which on-chain account, violating the unlinkability property.

## Impact Explanation

**Assets Affected:** User privacy and anonymity guarantees for email-account associations.

**Severity:** The damage is significant because:
1. **Breaks explicit security guarantee**: Violates README.md's stated guarantee that minority node compromise doesn't reveal associations
2. **Enables targeted attacks**: If an attacker later learns a user's email (via social engineering, data breaches, etc.), they can retroactively link it to the specific on-chain account
3. **Permanent linkage**: Once the correlation is established, it cannot be undone - the same verification key persists across the account's lifetime
4. **Compromises VDRF privacy**: The VDRF system's purpose is to hide email-account associations, but this linkage renders that protection ineffective for compromised nodes

This constitutes "unintended smart contract behaviour" where the contract fails to maintain the privacy properties it's designed to provide, potentially exposing users to targeted phishing, social engineering, or legal/regulatory actions based on their on-chain activity.

## Likelihood Explanation

**Who can trigger:** Any attacker who compromises even a single off-chain node can extract the complete association mapping from that node's storage.

**Conditions required:** 
- Compromise of at least one off-chain node (explicitly within the threat model)
- Public access to account states via `/account/get` endpoint (available by design)

**Frequency:** 
- Can be exploited immediately upon node compromise
- Affects all existing associations stored on the compromised node
- No special timing or coordination required
- Attack is deterministic and can be automated

The likelihood is **high** given that:
1. Off-chain node compromise is explicitly part of the threat model being considered
2. No authentication is required for account state retrieval
3. The correlation can be performed entirely offline once data is extracted

## Recommendation

**Mitigation Strategy:**

1. **Remove verification key from MskRecord**: Instead of storing `user_pk` directly in `MskRecordFixed`, derive a node-specific or email-specific commitment that cannot be correlated with the on-chain `AccountState.sig`.

2. **Alternative approach - Blind verification**: Implement a zero-knowledge proof or blind signature scheme where association verification doesn't require exposing the actual verification key in the stored record.

3. **Rotate keys per association**: Use different signing keys for associations versus on-chain account operations, breaking the direct linkage.

**Specific implementation suggestion:**
```rust
// In MskRecordFixed, replace:
pub(super) user_pk: VerificationKey,

// With a blinded commitment:
pub(super) user_pk_commitment: [u8; 32], // Hash(user_pk || email || salt)
```

This would require modifications to the verification logic in `AssociationRequestEmail::verify()` to check commitments rather than direct key equality, but would prevent the correlation attack while maintaining security.

## Proof of Concept

**File:** `lib/src/association/v0.rs` (add to the `tests` module)

**Test Function:** `test_verification_key_correlation_leak`

**Setup:**
1. Create an association with `Association::create_association()` to generate `EncapsulatedMsk` and RIK
2. Generate an `AssociationRequestEmail` for a specific node using `gen_association_request()`
3. Create an `AccountSecrets` instance and generate its public `AccountState` using `state()`
4. Simulate off-chain node storage by storing the `MskRecord` (from `AssociationRequestEmail.verify()`)

**Trigger:**
1. Extract `user_pk` from the `MskRecord.fixed.user_pk` field (simulating compromised node data access)
2. Extract `sig` from the publicly accessible `AccountState` 
3. Compare the two verification keys for equality

**Observation:**
The test demonstrates that `user_pk == sig`, proving that an attacker with access to off-chain node storage can correlate EmailKey-mapped associations with specific on-chain accounts. This confirms the privacy leak where the same verification key creates a direct linkage between VDRF evaluations and account identities, violating the privacy guarantee stated in README.md that compromised node state doesn't reveal associations.

The test would show that for every association stored in off-chain node mappings, the `user_pk` field directly matches the `sig` field in the corresponding account's public state, enabling trivial correlation attacks.

## Notes

This vulnerability is particularly concerning because:
1. The VDRF system was specifically designed to prevent email-account correlation
2. The README explicitly guarantees this scenario should not be possible
3. The same verification key serving dual purposes (association validation + account authentication) creates an unnecessary linkage
4. The attack requires no cryptographic breaks - only simple data comparison
5. It affects all users who have created email associations via the system

### Citations

**File:** lib/src/association/v0.rs (L139-149)
```rust
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct MskRecordFixed {
    /// User's signature public key
    pub(super) user_pk: VerificationKey,
    /// Encrypted RIK data (contains signing key and MSK secret share from RIK)
    pub(super) enc_rik: EncryptedMsk,
    /// Pedersen commitments (C_0, ..., C_{threshold-1})
    pub(super) commits: Vec<PedersenCommitment>,
    /// Signature of Knowledge proof
    pub(super) sok_proof: SokProof,
}
```

**File:** lib/src/association/v0.rs (L444-444)
```rust
                user_pk: self.sk_user.verification_key(),
```

**File:** lib/src/account/v0.rs (L230-238)
```rust
pub(crate) struct AccountStateV0 {
    cnt: u32, // current count of operations
    act: AccountCiphertext,
    pub(crate) rec: RecoveryStateV0,
    sig: sig::VerificationKey,
    pke: pke::EncryptionKey,
    backups: Vec<BackupCiphertext>, // backups to store
    recover: Vec<BackupCiphertext>, // backups to recover
}
```

**File:** lib/src/account/v0.rs (L708-708)
```rust
            sig: self.sig.verification_key(),
```

**File:** contracts/src/http/endpoints/account/get.rs (L18-36)
```rust
pub fn handler(
    _ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request: Request = deserialize_request_body(&request)?;
    let account: AccountState = state
        .get_account(request.account_id.0)
        .ok_or_else(|| ServerError::NotFound("Account not found".to_string()))?;

    create_json_response(
        200,
        &Response {
            account_state: StrEncoded(account),
        },
    )
    .map_err(|e| e.into())
}
```

**File:** README.md (L193-194)
```markdown
- Snapshot of corrupted off-chain node states hides user emails and account associations.
- Leaking an off-chain node's state does not reveal user emails or their association to on-chain contracts.
```

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L23-31)
```rust
#[derive(ReadWriteState, Serialize, Deserialize, Clone, Default)]
pub struct MskRecordCollection {}

impl Mapping for MskRecordCollection {
    type Key = EmailKey;
    type Value = MskRecord;

    const COLLECTION_NAME: &'static str = "map:associations";
}
```
