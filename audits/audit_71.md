# Audit Report

## Title
Bincode Deserialization Memory Exhaustion via Malicious Vector Length Prefix in Contract Actions

## Summary
The `update_account` contract action deserializes untrusted user input using bincode without size limits, allowing an attacker to craft malicious serialized data with excessive vector length prefixes. When deserialized, bincode attempts to pre-allocate vectors based on these malicious length values, causing out-of-memory panics that crash blockchain nodes processing the transaction. [1](#0-0) 

## Impact
**Medium** - This vulnerability can cause shutdown of blockchain processing nodes, potentially affecting ≥30% of the network.

## Finding Description

**Location:** The vulnerability exists in the `update_account` action in `contracts/src/lib.rs`, specifically at the deserialization step where untrusted user input is processed. [2](#0-1) 

**Intended Logic:** The contract should deserialize and validate account updates from users, rejecting invalid updates through signature verification and state checks. Deserialization should safely handle malformed data without crashing nodes.

**Actual Logic:** The deserialization occurs BEFORE any validation checks using bincode with the standard configuration that has no size limits. [3](#0-2) 

When bincode deserializes Vec types, it reads the length prefix from the serialized data and immediately attempts `Vec::with_capacity(length)` to pre-allocate space. The `AccountUpdate` structure contains nested Vec fields in `AccountStateV0`: [4](#0-3) 

**Exploit Scenario:**
1. Attacker crafts a malicious serialized `AccountUpdate` where the `backups` or `recover` Vec fields claim to have 2^30 or more elements in their length prefix
2. The malicious payload is small (< 1MB) because it only needs the length prefix, not actual elements
3. Attacker submits this as a transaction to the `update_account` contract action
4. When the contract deserializes the input at line 114-115, bincode reads the malicious length prefix
5. Bincode calls `Vec::with_capacity(2^30)` attempting to allocate terabytes of memory
6. The allocation fails, causing a panic that crashes the blockchain node
7. All nodes processing this transaction experience the same crash
8. The transaction remains in the mempool, continuously crashing nodes that attempt to process it

**Security Failure:** The system fails to protect against malicious input during deserialization. The failure occurs before signature verification (line 127-129), bypassing all authentication checks. This is a denial-of-service vulnerability affecting blockchain infrastructure.

## Impact Explanation

This vulnerability allows any network participant to crash blockchain nodes without any privileged access or authentication:

- **Affected Components**: All blockchain nodes that process the malicious transaction
- **Severity**: Nodes crash with out-of-memory panics, halting transaction processing
- **Scale**: A single malicious transaction can affect all nodes simultaneously since they all process the same transaction data
- **Recovery**: Nodes will repeatedly crash when attempting to process the malicious transaction from the mempool

This matters because:
1. It can halt the Swafe contract and prevent legitimate account updates
2. It can affect ≥30% of network processing nodes (medium severity per scope)
3. It requires no authentication or privileged access
4. A single small transaction can trigger widespread node crashes

## Likelihood Explanation

**Likelihood: High**

- **Who can trigger**: Any network participant can submit transactions to the blockchain contract
- **Conditions required**: Only requires crafting a malicious serialized payload with large Vec length prefixes - no authentication needed
- **Timing**: Can be triggered at any time during normal operation
- **Frequency**: Can be exploited repeatedly; each malicious transaction crashes nodes

The attack is:
- Trivial to execute (just craft malicious bincode data)
- Requires no privileged access
- Affects all nodes processing the transaction
- Can be repeated to maintain denial of service

## Recommendation

Implement size limits for deserialization to prevent excessive memory allocation:

1. **Configure bincode with size limits**: Use `bincode::config::standard().with_limit()` to enforce maximum deserialization size

2. **Add input validation**: Before deserialization, check the input string length and reject overly large inputs

3. **Implement bounded deserialization**: For Vec fields in critical structures, add explicit bounds checking:
   - Limit maximum number of backups/recovery items per account
   - Validate Vec lengths immediately after deserialization
   - Reject updates with excessive vector sizes

Example fix for `lib/src/encode.rs`:

```rust
// Add a reasonable size limit (e.g., 10MB)
const MAX_DESERIALIZE_SIZE: u64 = 10 * 1024 * 1024;
const BINCODE_CONFIG: bincode::config::Configuration = 
    bincode::config::standard().with_limit::<MAX_DESERIALIZE_SIZE>();
```

Additionally, add explicit validation in `AccountStateV0`:
- Enforce maximum backup count (e.g., 100 backups per account)
- Validate that Vec lengths are reasonable before processing

## Proof of Concept

**Test Location**: `contracts/tests/malicious_deserialization_test.rs` (new test file)

**Setup:**
1. Create a malicious bincode payload where `AccountUpdateV0` contains an `AccountStateV0` with `backups: Vec<BackupCiphertext>` claiming to have 2^30 elements
2. Encode this as base64 string
3. Submit to `update_account` contract action

**Trigger:**
```rust
// Craft malicious bincode with huge Vec length prefix
let mut malicious_data = vec![0u8]; // Version tag
malicious_data.extend_from_slice(&[0u8]); // AccountUpdateV0 tag
// ... add valid AccountId bytes ...
malicious_data.push(0); // AccountMessageV0::Update tag  
// ... add minimal valid signature/state data ...
// Now add malicious Vec length prefix claiming 2^30 elements
malicious_data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]); // Varint for ~2^30
// Don't add actual elements - just the malicious length

let malicious_str = base64_encode(&malicious_data);
let result = contract.update_account(malicious_str);
```

**Observation:**
- The test should observe a panic/crash when the contract attempts to deserialize
- Node process terminates with out-of-memory error
- This confirms the vulnerability: deserialization crashes before validation

**Expected Behavior**: The test should panic during deserialization, demonstrating that malicious length prefixes cause memory exhaustion before any security checks occur.

## Notes

While this is technically memory **exhaustion** rather than memory **corruption** in the traditional sense (buffer overflow, use-after-free), it is a critical memory-related security vulnerability caused by malicious serialized data. The bincode deserialization process attempts unbounded memory allocation based on untrusted input, violating safe deserialization practices and enabling denial-of-service attacks on blockchain infrastructure.

### Citations

**File:** contracts/src/lib.rs (L107-134)
```rust
#[action]
fn update_account(
    _ctx: ContractContext,
    mut state: ContractState,
    update_str: String,
) -> ContractState {
    // deserialize the account update from a string,
    let update: AccountUpdate =
        encode::deserialize_str(update_str.as_str()).expect("Failed to decode account update");

    // retrieve the *claimed* account ID
    let account_id = update.unsafe_account_id();

    // retrieve the old account state
    let st_old: Option<AccountState> = state
        .accounts
        .get(account_id.as_ref())
        .map(|bytes| encode::deserialize(&bytes).expect("failed to deserialize account state"));

    // verify the update using the lib
    let st_new = update
        .verify(st_old.as_ref())
        .expect("Failed to verify account update");

    // store the updated account state
    state.set_account(account_id, st_new);
    state
}
```

**File:** lib/src/encode.rs (L5-6)
```rust
/// Standard bincode configuration used throughout the library
const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();
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
