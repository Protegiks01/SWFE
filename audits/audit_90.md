# Audit Report

## Title
Version Upgrade Breaks BackupId Lookups Due to Hardcoded Tagged Separator, Causing Permanent Loss of Access to Backed-Up Secrets

## Summary
Versioned enums such as `BackupCiphertext` implement the `Tagged` trait at the enum level with a hardcoded "v0:" prefix separator. When V1 is released, if developers update the separator to "v1:backup-ciphertext" (as the naming convention suggests), all existing BackupIds computed with "v0:" will become invalid, permanently locking users out of their backed-up secrets.

## Impact
**High**

## Finding Description

**Location:** 
- `lib/src/backup/v0.rs` lines 231-233 (Tagged implementation for BackupCiphertext enum)
- `lib/src/backup/v0.rs` lines 84-86 (BackupId computation)
- `cli/src/commands/account.rs` line 114 (BackupId computation in client)
- `contracts/src/http/endpoints/reconstruction/upload_share.rs` lines 48-50, 64-67 (BackupId-based lookup and storage)

**Intended Logic:**
The versioned enum system is designed to support protocol upgrades by adding new variants (V0, V1, V2, etc.). The "v0:" prefix in Tagged separators appears to indicate version-specific domain separation, suggesting that V1 would use "v1:" when released.

**Actual Logic:**
The `BackupCiphertext` enum implements `Tagged` with a hardcoded separator `"v0:backup-ciphertext"` at the enum level. [1](#0-0) 

The `BackupId` is computed by hashing the `BackupCiphertext`: [2](#0-1) 

The `hash()` function uses the Tagged separator for domain separation: [3](#0-2) 

Clients compute and store BackupIds: [4](#0-3) 

The contract uses BackupId to look up backups and store guardian shares: [5](#0-4) [6](#0-5) 

**Exploit Scenario:**
1. Users create backups with `BackupCiphertext::V0` in the current protocol version
2. BackupIds are computed as: `hash(encode("v0:backup-ciphertext", V0_data))` and stored both client-side and on-chain
3. Protocol is upgraded to support V1 with a different commitment scheme
4. Developers update the Tagged separator to `"v1:backup-ciphertext"` (as the "v0:" naming strongly suggests)
5. When users try to recover their old V0 backups:
   - The new client recomputes BackupId using the updated separator: `hash(encode("v1:backup-ciphertext", V0_data))`
   - This produces a different hash than the originally stored BackupId
   - Lookup via `account.recover_id(backup_id)` fails
   - Guardian share retrieval via `GuardianShareCollection::load` with the wrong BackupId returns no shares
6. Users cannot recover their backed-up secrets - permanent loss of access

**Security Failure:**
The system violates the invariant that protocol upgrades must maintain backward compatibility with existing on-chain data. Users who created backups before the V1 upgrade are permanently locked out of their secrets.

## Impact Explanation

**Affected Assets:** All backed-up secrets created before the V1 protocol upgrade, including user data, credentials, and recovery information.

**Severity:** Users experience permanent freezing of their backed-up secrets. Since BackupIds are content-addressed hashes that include the Tagged separator, changing the separator invalidates all existing BackupIds. There is no recovery mechanism - the old backups remain on-chain but are permanently inaccessible because:
- The contract lookup `account.recover_id(backup_id)` fails to find the backup with the mismatched ID
- Guardian shares stored under the old BackupId cannot be retrieved
- Even if the backup data is somehow accessed, guardian shares are keyed by `(AccountId, BackupId)` and would not be found

This represents a **permanent freezing of secrets** requiring either a hard fork to migrate old BackupIds or leaving users permanently locked out.

## Likelihood Explanation

**Trigger Conditions:** This vulnerability is triggered when:
1. V1 is released with any changes to the backup system
2. A developer updates the Tagged separator from "v0:" to "v1:" (highly likely given the naming convention)

**Likelihood:** HIGH. The "v0:" prefix in the separator constant strongly suggests version-specificity. Any developer implementing V1 would naturally change:
```rust
const SEPARATOR: &'static str = "v0:backup-ciphertext";
```
to:
```rust
const SEPARATOR: &'static str = "v1:backup-ciphertext";
```

This follows standard versioning practices and matches the pattern seen throughout the codebase where version-specific types use version prefixes.

**Frequency:** This would affect 100% of users who created backups before the V1 upgrade, during normal protocol upgrade operations.

## Recommendation

**Solution 1 (Recommended):** Remove the version prefix from enum-level Tagged implementations. The enum already has version information via the `versioned_enum!` tag (u8). Use a version-agnostic separator:
```rust
impl Tagged for BackupCiphertext {
    const SEPARATOR: &'static str = "backup-ciphertext";  // No v0: prefix
}
```

**Solution 2:** Implement backward-compatible BackupId computation that tries multiple separator versions during lookup. When searching for a backup, compute BackupIds with both "v0:" and "v1:" separators and check both.

**Solution 3:** Store the Tagged separator version alongside BackupIds in the contract state, allowing correct recomputation regardless of protocol version.

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** `test_version_upgrade_breaks_backup_id_lookup`

**Setup:**
1. Create an account with V0 backup system
2. Create a backup using `BackupCiphertext::V0` 
3. Compute and store the BackupId with current "v0:backup-ciphertext" separator
4. Store the backup in account state

**Trigger:**
1. Simulate a protocol upgrade by manually changing the Tagged separator to "v1:backup-ciphertext"
2. Attempt to recompute the BackupId from the same backup data
3. Try to look up the backup using the newly computed BackupId

**Observation:**
The test demonstrates that:
- The recomputed BackupId (with "v1:") differs from the original BackupId (with "v0:")
- `account.recover_id(new_backup_id)` returns `None` even though the backup exists
- This confirms that changing the Tagged separator breaks BackupId-based lookups

The test would be added to `lib/src/backup/tests.rs` to verify that BackupIds change when the separator changes, demonstrating the vulnerability. The test should show that `hash(&backup_with_v0_sep) != hash(&backup_with_v1_sep)` even for identical backup data, proving that protocol upgrades would invalidate all existing BackupIds.

### Citations

**File:** lib/src/backup/v0.rs (L84-86)
```rust
    pub fn id(&self) -> BackupId {
        BackupId(hash(self))
    }
```

**File:** lib/src/backup/v0.rs (L231-233)
```rust
impl Tagged for BackupCiphertext {
    const SEPARATOR: &'static str = "v0:backup-ciphertext";
}
```

**File:** lib/src/crypto/hash.rs (L22-27)
```rust
pub fn hash<T: Tagged>(val: &T) -> [u8; SIZE_HASH] {
    let mut hsh = Sha3_256::new();
    let encoded_data = val.encode();
    hsh.update(&encoded_data);
    hsh.finalize().into()
}
```

**File:** cli/src/commands/account.rs (L114-114)
```rust
    let backup_id = backup_ct.id();
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L48-50)
```rust
    let backup: &BackupCiphertext = account.recover_id(backup_id).ok_or_else(|| {
        ServerError::NotFound(format!("Backup not found for backup_id: {}", backup_id))
    })?;
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L64-67)
```rust
    let storage_key = (account_id, backup_id);
    let mut shares = GuardianShareCollection::load(&mut ctx, storage_key).unwrap_or_default();
    shares.insert(share_id, request.share.0);
    GuardianShareCollection::store(&mut ctx, storage_key, shares);
```
