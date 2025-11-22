## Title
Contract Upgrade with Variant Removal Permanently Freezes Accounts Due to Deserialization Panic

## Summary
The Swafe smart contract stores serialized `AccountState` enums in persistent storage but uses `.expect()` when deserializing them. When a contract upgrade removes an enum variant from `AccountState`, `AccountMessageV0`, or `CombinedSecret`, any accounts stored with the removed variant will cause the contract to panic during deserialization, permanently freezing those accounts.

## Impact
**High**

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended Logic:** 
The versioned enum system is designed to support forward compatibility when adding new variants. Contract upgrades should be able to add new state versions (e.g., V1, V2) while maintaining backward compatibility with existing V0 accounts.

**Actual Logic:**
The `versioned_enum!` macro deserializes enum variants by matching a u8 discriminant tag against known variants: [3](#0-2) 

When an unknown tag is encountered (e.g., after removing a variant), deserialization returns an error with "invalid enum variant". The contract's `get_account()` and `update_account()` functions use `.expect()` which panics on this error, causing the transaction to fail.

The test suite explicitly demonstrates this behavior: [4](#0-3) 

**Exploit Scenario:**
1. Initial state: Users create accounts with `AccountState::V0` containing various nested structures
2. Contract upgrade: Developers deploy a new contract version that removes an unused variant from `AccountMessageV0`, `CombinedSecret`, or adds then removes intermediate variants
3. Deserialization failure: Any account that was stored with the removed variant structure cannot be deserialized
4. Permanent freeze: The contract panics when attempting to `get_account()` or process `update_account()` for affected accounts
5. No recovery: Without state migration logic, these accounts remain permanently inaccessible

**Security Failure:**
The contract violates the availability invariant by permanently freezing user accounts. The use of `.expect()` transforms recoverable deserialization errors into unrecoverable panics, preventing any future access to affected accounts.

## Impact Explanation

**Affected Assets:**
- User accounts and their encrypted master secret keys (MSK)
- Account recovery capabilities and guardian-based social recovery
- All backups associated with frozen accounts

**Severity of Damage:**
- Accounts become permanently inaccessible—users cannot update, recover, or access their secrets
- The encrypted MSK stored in the account state cannot be retrieved, effectively causing permanent loss of user data
- No on-chain mechanism exists to migrate or recover frozen accounts
- This requires either a hard fork or manual intervention by contract administrators to resolve

**System Impact:**
The vulnerability directly contradicts Swafe's core value proposition as a secure key management system. Users trust the protocol to maintain persistent access to their secrets, but contract upgrades can inadvertently revoke this access without any warning or migration path.

## Likelihood Explanation

**Triggering Conditions:**
- Contract upgrades that remove enum variants are explicitly supported by the versioned enum design philosophy
- The test suite demonstrates this is an expected behavior pattern for "removing unused variants" [5](#0-4) 

**Frequency:**
- Occurs during normal contract maintenance when developers remove variants they believe are unused
- Developers have no visibility into which variant values exist in production storage
- Even a single account stored with a removed variant will trigger panics affecting that account permanently

**Who Can Trigger:**
- Not triggered by attackers, but by normal protocol upgrades performed by trusted administrators
- However, the impact affects all users whose accounts happened to use the removed variant structure
- This is a systemic risk inherent to the current contract architecture

## Recommendation

Implement graceful deserialization error handling in the contract:

1. **Replace `.expect()` with proper error handling:**
   - Change `get_account()` to return `Option<AccountState>` or handle errors gracefully
   - In `update_account()`, return a contract error instead of panicking

2. **Add state migration support:**
   - Before removing any variant, implement an explicit migration action that converts all existing data to a new format
   - Add a contract method to enumerate and migrate affected accounts

3. **Implement a fallback mechanism:**
   - Add a default/migration variant that can capture unknown tags
   - Store the raw bytes when encountering unknown variants, allowing future recovery

4. **Add pre-upgrade validation:**
   - Implement off-chain tooling to scan storage and identify which variants are actually in use
   - Prevent removal of variants that have live data in storage

## Proof of Concept

**File:** `lib/src/venum.rs` (add to existing test module)

**Test Function:** `test_contract_panic_on_removed_variant`

**Setup:**
1. Create an `AccountState` enum with variants V0, V1, V2
2. Serialize an account using V1 variant (simulating a stored account)
3. Simulate a contract upgrade by defining a new enum without V1 (only V0, V2)
4. Attempt to deserialize the stored V1 data with the new enum definition

**Trigger:**
Call the deserialization function (mimicking `get_account()`) with `.expect()` on data containing the removed V1 variant tag.

**Observation:**
The code panics with "failed to deserialize account", demonstrating that the contract would halt when encountering accounts stored with removed variants. This confirms that affected accounts become permanently inaccessible after such an upgrade.

The existing test at lines 316-323 already demonstrates the core behavior—removed variants fail to deserialize. The vulnerability manifests because the contract uses `.expect()` instead of handling this error gracefully.

### Citations

**File:** contracts/src/lib.rs (L34-38)
```rust
    fn get_account(&self, id: AccountId) -> Option<AccountState> {
        self.accounts
            .get(id.as_ref())
            .map(|data| encode::deserialize(&data).expect("failed to deserialize account"))
    }
```

**File:** contracts/src/lib.rs (L121-125)
```rust
    let st_old: Option<AccountState> = state
        .accounts
        .get(account_id.as_ref())
        .map(|bytes| encode::deserialize(&bytes).expect("failed to deserialize account state"));

```

**File:** lib/src/venum.rs (L103-112)
```rust
                        match tag {
                            $(
                                $value => {
                                    let data: $type = seq.next_element()?
                                        .ok_or_else(|| serde::de::Error::custom("missing data"))?;
                                    Ok($name::$variant(data))
                                }
                            ),*
                            _ => Err(serde::de::Error::custom("invalid enum variant"))
                        }
```

**File:** lib/src/venum.rs (L275-294)
```rust
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

```

**File:** lib/src/venum.rs (L316-324)
```rust
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
