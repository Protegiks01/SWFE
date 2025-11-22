## Title
Malformed Signatures in AccountUpdate Cause Contract Action to Panic

## Summary
The `update_account` smart contract action uses `.expect()` when deserializing user-provided `AccountUpdate` data, which causes a panic when the input contains malformed signature bytes. This creates unintended smart contract behavior and violates the error handling pattern used elsewhere in the codebase.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The `update_account` action should gracefully handle invalid or malformed input by returning an error response, similar to how HTTP endpoints handle errors using the `Result` type and error conversion functions. [2](#0-1) 

**Actual Logic:** 
The contract action uses `.expect()` on the deserialization result, which causes a panic when deserialization fails. The `AccountUpdate` structure contains signatures that are deserialized from user input: [3](#0-2) 

These signatures contain cryptographic elements (G1Affine points and Fr scalars) that use custom deserializers: [4](#0-3) [5](#0-4) 

When malformed bytes are provided for these cryptographic elements, the arkworks deserialization functions return an error, which bubbles up through the deserialization chain and causes the `.expect()` to panic.

**Exploit Scenario:**
1. An attacker crafts an `AccountUpdate` with invalid signature bytes (e.g., bytes that don't represent a valid G1Affine point or Fr scalar)
2. The attacker base64-encodes this malformed structure
3. The attacker calls the `update_account` contract action with this malformed string
4. At line 115, the contract attempts to deserialize: `encode::deserialize_str(update_str.as_str()).expect("Failed to decode account update")`
5. The deserialization fails because the signature bytes are invalid
6. The `.expect()` causes a panic in the contract action

**Security Failure:** 
This violates the smart contract's expected error handling behavior. Instead of gracefully returning an error, the contract panics on malformed user input. This constitutes "unintended smart contract behaviour" as defined in the in-scope impacts.

## Impact Explanation

This vulnerability affects the core account update functionality of the Swafe smart contract. When triggered:

1. The contract action panics instead of handling the error gracefully
2. Depending on how Partisia handles contract panics, this could:
   - Cause the transaction to fail unexpectedly
   - Potentially make the contract temporarily unavailable
   - Create inconsistent state if the panic occurs mid-execution
3. It violates user expectations and the error handling pattern established in the HTTP endpoints

The same issue exists at line 124 where stored account state is deserialized: [6](#0-5) 

If stored account data somehow becomes corrupted, any attempt to update that account would panic.

This matters because the `update_account` action is a public entry point that any user can call, and it should handle all possible inputs gracefully without panicking.

## Likelihood Explanation

This vulnerability is highly likely to be triggered:
- **Who can trigger it:** Any user who can submit transactions to the Partisia blockchain can call the `update_account` action with arbitrary input
- **Conditions required:** Normal operation - an attacker simply needs to craft malformed signature bytes in an `AccountUpdate` structure
- **Frequency:** Can be triggered at will by any malicious actor sending crafted transactions

The vulnerability is straightforward to exploit and requires no special privileges, timing, or rare conditions.

## Recommendation

Replace `.expect()` calls with proper error handling that returns `Result` types. The contract should follow the pattern used in HTTP endpoints:

1. Change the `update_account` action signature to return a `Result` type
2. Use `?` operator or proper error handling instead of `.expect()`
3. Convert errors to appropriate responses rather than panicking

Example fix for line 115:
```rust
let update: AccountUpdate = encode::deserialize_str(update_str.as_str())
    .map_err(|_| "Failed to decode account update")?;
```

Similarly, the `get_account()` helper function should return `Result<Option<AccountState>, Error>` instead of using `.expect()`: [7](#0-6) 

## Proof of Concept

**File:** `lib/src/account/tests.rs` - Add a new test function `test_malformed_signature_deserialization_failure`

**Setup:**
1. Create a valid `AccountUpdate` structure with proper signatures
2. Serialize it to bytes using bincode
3. Corrupt the signature bytes to make them invalid (e.g., set all signature bytes to 0xFF which is not a valid compressed G1Affine point)
4. Base64-encode the corrupted bytes

**Trigger:**
1. Attempt to deserialize the corrupted base64 string using `encode::deserialize_str::<AccountUpdate>(&malformed_string)`
2. This simulates what happens when `update_account` receives malformed input at line 115

**Observation:**
The deserialization should return an error (not panic), demonstrating that the underlying deserialization properly handles invalid input. However, when `.expect()` is called on this error (as in the contract code), it would cause a panic. The test should verify that:
- The deserialization returns `Err` variant
- The error message indicates deserialization failure
- In the contract context, this would trigger the `.expect()` panic

This demonstrates that malformed signatures can indeed cause panics in the contract action, confirming the security question's concern.

### Citations

**File:** contracts/src/lib.rs (L34-38)
```rust
    fn get_account(&self, id: AccountId) -> Option<AccountState> {
        self.accounts
            .get(id.as_ref())
            .map(|data| encode::deserialize(&data).expect("failed to deserialize account"))
    }
```

**File:** contracts/src/lib.rs (L115-115)
```rust
        encode::deserialize_str(update_str.as_str()).expect("Failed to decode account update");
```

**File:** contracts/src/lib.rs (L124-124)
```rust
        .map(|bytes| encode::deserialize(&bytes).expect("failed to deserialize account state"));
```

**File:** contracts/src/http/error.rs (L62-110)
```rust
pub fn contract_error_to_http_response(error: ContractError) -> HttpResponseData {
    let (status_code, message): (u32, String) = match error {
        ContractError::LibError(swafe_error) => {
            let status_code = match swafe_error {
                SwafeError::CryptoError(_) => 400,
                SwafeError::SerializationError(_) => 400,
                SwafeError::InvalidParameter(_) => 400,
                SwafeError::VerificationFailed(_) => 400,
                SwafeError::DecryptionFailed => 400,
                SwafeError::AuthenticationFailed => 401,
                SwafeError::ProofVerificationFailed => 400,
                SwafeError::InvalidCommitmentCount => 400,
                SwafeError::InvalidData(_) => 400,
                SwafeError::CertificateExpired => 400,
                SwafeError::CertificateFromFuture => 400,
                SwafeError::SignatureVerificationFailed => 400,
                SwafeError::InvalidInput(_) => 400,
                SwafeError::NotEnoughSharesForReconstruction => 400,
                SwafeError::VdrfEvaluationVerificationFailed => 400,
                SwafeError::InvalidAccountStateVersion => 400,
                SwafeError::InsufficientShares => 400,
                SwafeError::InvalidNonce => 400,
                SwafeError::InvalidShare => 400,
                SwafeError::BackupNotFound => 404,
                SwafeError::InvalidSignature => 400,
                SwafeError::InvalidRecoveryKey => 400,
                SwafeError::InvalidOperation(_) => 400,
            };
            (status_code, swafe_error.to_string())
        }
        ContractError::ServerError(server_error) => {
            let status_code = match server_error {
                ServerError::VdrfNodeNotInitialized => 503,
                ServerError::VdrfNodeAlreadyInitialized => 409,
                ServerError::InvalidRequestBody => 400,
                ServerError::SerializationError(_) => 400,
                ServerError::InvalidParameter(_) => 400,
                ServerError::NotFound(_) => 404,
            };
            (status_code, server_error.to_string())
        }
    };

    // Create JSON error response
    let error_response = ErrorResponse { error: message };
    let json_str = crate::http::json::to_string(&error_response)
        .unwrap_or_else(|_| crate::http::json::json_error("Failed to serialize error response"));
    HttpResponseData::new_with_str(status_code, &json_str)
}
```

**File:** lib/src/account/v0.rs (L299-309)
```rust
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AccountUpdateFullV0 {
    sig: sig::Signature,
    state: AccountStateV0,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AccountUpdateRecoveryV0 {
    pke: pke::EncryptionKey, // encryption key for recovery response
    sig: sig::Signature,     // signature from recovery signing key
}
```

**File:** lib/src/crypto/pairing.rs (L82-113)
```rust
        pub fn deserialize<'de, D>(deserializer: D) -> Result<G1Affine, D::Error>
        where
            D: Deserializer<'de>,
        {
            use serde::de::{SeqAccess, Visitor};

            struct G1Visitor;

            impl<'de> Visitor<'de> for G1Visitor {
                type Value = G1Affine;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a 48-byte G1 element")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<G1Affine, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut bytes = [0u8; 48];
                    for byte in &mut bytes {
                        *byte = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("Not enough bytes for G1"))?;
                    }
                    G1Affine::deserialize_compressed(&bytes[..])
                        .map_err(|e| A::Error::custom(format!("Failed to deserialize G1: {}", e)))
                }
            }

            deserializer.deserialize_tuple(48, G1Visitor)
        }
```

**File:** lib/src/crypto/pairing.rs (L144-175)
```rust
        pub fn deserialize<'de, D>(deserializer: D) -> Result<Fr, D::Error>
        where
            D: Deserializer<'de>,
        {
            use serde::de::{SeqAccess, Visitor};

            struct FrVisitor;

            impl<'de> Visitor<'de> for FrVisitor {
                type Value = Fr;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a 32-byte Fr element")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Fr, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut bytes = [0u8; 32];
                    for byte in &mut bytes {
                        *byte = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("Not enough bytes for Fr"))?;
                    }
                    Fr::deserialize_compressed(&bytes[..])
                        .map_err(|e| A::Error::custom(format!("Failed to deserialize Fr: {}", e)))
                }
            }

            deserializer.deserialize_tuple(32, FrVisitor)
        }
```
