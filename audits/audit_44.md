## Title
Guardian Shares Persist in Off-Chain Storage After On-Chain Backup Removal Leading to State Inconsistency

## Summary
The `/reconstruction/get-shares` HTTP endpoint returns guardian shares from off-chain storage without validating that the corresponding backup still exists in the current on-chain account state. When a backup is removed via a successful `update_account` transaction (or when a transaction adding a backup gets rolled back due to blockchain reorganization), the associated guardian shares persist in off-chain storage indefinitely, creating a critical state inconsistency between on-chain and off-chain components. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** 
- Vulnerable endpoint: `contracts/src/http/endpoints/reconstruction/get_shares.rs`, handler function (lines 19-34)
- Missing validation: The endpoint ignores the `state: ContractState` parameter (line 21)
- Contrast with: `contracts/src/http/endpoints/reconstruction/upload_share.rs`, which validates against on-chain state (lines 44-50) [2](#0-1) 

**Intended Logic:** 
Guardian shares should only be retrievable for backups that currently exist in the on-chain account state. The system should maintain consistency between on-chain backup state and off-chain guardian share storage. When a backup is removed from an account, the corresponding guardian shares should either be inaccessible or explicitly validated to exist on-chain before being returned.

**Actual Logic:**
The `get_shares` endpoint simply loads shares from off-chain storage using the provided `(account_id, backup_id)` key and returns them without any validation: [3](#0-2) 

The `_state` parameter is explicitly ignored (underscore prefix), meaning the handler never checks if:
1. The account exists on-chain
2. The backup exists in the account's recovery list
3. The backup is still valid for reconstruction

This contrasts sharply with `upload_share`, which performs thorough validation: [4](#0-3) 

**Exploit Scenario:**

1. **Initial Setup**: User creates Account A with Backup B1 (backup_id = ID1) via successful `update_account` transaction. On-chain state now contains Account A with Backup B1.

2. **Guardian Share Upload**: Guardians upload their shares via `/reconstruction/upload-share`. These shares are validated against the on-chain backup and stored in off-chain `GuardianShareCollection` at key `(A, ID1)`.

3. **Backup Removal**: User decides to remove Backup B1 by calling `AccountSecrets::remove_backup(ID1)` locally and submitting a new `update_account` transaction: [5](#0-4) 

The transaction succeeds and on-chain state is updated - Account A no longer contains Backup B1.

4. **State Inconsistency**: The guardian shares remain in off-chain storage at key `(A, ID1)` because there is no cleanup mechanism: [6](#0-5) 

5. **Unauthorized Access**: Anyone (including the user or an attacker who cached the original BackupCiphertext) can call `/reconstruction/get-shares` with `(A, ID1)` and receive the guardian shares for a backup that no longer exists on-chain.

**Alternative Scenario - Blockchain Reorganization:**
1. Transaction to add Backup B1 is included in a block and appears confirmed
2. Guardians immediately upload shares based on this state
3. Blockchain reorganization reverts the block containing the transaction
4. On-chain state rolls back - Backup B1 never existed in finalized state
5. Guardian shares persist in off-chain storage for a backup that was never permanently committed

**Security Failure:**
- **State Consistency Violation**: Off-chain storage is not synchronized with on-chain state changes
- **Privacy Violation**: Shares for deleted backups remain accessible, potentially exposing sensitive recovery information the user intended to revoke
- **Unauthorized Secret Reconstruction**: If an attacker cached the `BackupCiphertext` before removal, they can combine it with the persisted guardian shares to reconstruct secrets that should no longer be recoverable

## Impact Explanation

**Affected Assets:**
- Master secret keys protected by social recovery backups
- User privacy regarding backup composition and guardian selection
- System integrity through state consistency

**Severity of Damage:**
1. **Privacy Breach**: When users remove backups (e.g., to change guardian sets or threshold parameters), they expect all recovery data to become inaccessible. However, guardian shares persist indefinitely, exposing recovery infrastructure details.

2. **Potential Secret Compromise**: If an attacker or malicious off-chain node cached the `BackupCiphertext` data before removal, they can:
   - Retrieve the orphaned guardian shares via `get_shares` 
   - Reconstruct the original secret if they have threshold shares
   - This violates the user's intent to revoke access by removing the backup

3. **Resource Exhaustion**: Off-chain storage accumulates stale guardian shares with no cleanup mechanism, leading to unbounded growth and potential storage exhaustion over time.

4. **State Desynchronization**: The fundamental assumption that on-chain and off-chain storage remain consistent is violated, potentially causing client library errors, reconstruction failures, or incorrect security assumptions in dependent systems.

**Why This Matters:**
The Swafe protocol's security model relies on cryptographic binding between backups and their guardian shares. When this binding is broken through state inconsistency, the system cannot guarantee that secrets remain protected according to user-specified policies. Users who remove backups expect complete revocation of recovery capability, but the system silently maintains partial recovery data.

## Likelihood Explanation

**Who Can Trigger:**
- Any user who removes a backup from their account
- Any participant with knowledge of a `(account_id, backup_id)` pair
- Blockchain reorganizations (affecting all users)

**Required Conditions:**
- Normal account operations (backup removal is a legitimate feature via `remove_backup()` method)
- No special privileges required - the vulnerability exists in the standard workflow
- Can occur whenever `update_account` successfully modifies backup lists

**Frequency:**
- **Immediate**: Occurs every time a backup is removed and guardian shares had been previously uploaded
- **Persistent**: State inconsistency persists indefinitely once created (no cleanup mechanism exists)
- **Likely**: Users commonly update guardian sets, change thresholds, or reorganize backups during account lifetime
- **Blockchain reorgs**: While less frequent, reorganizations are normal blockchain behavior that can trigger this vulnerability

The vulnerability is highly likely because:
1. Backup removal is a standard operation users will perform
2. No cleanup or validation mechanism exists to prevent the inconsistency
3. The `get_shares` endpoint is designed to be called frequently during reconstruction workflows

## Recommendation

**Immediate Fix:**
Add validation in the `get_shares` handler to verify the backup exists on-chain before returning shares:

```rust
pub fn handler(
    mut ctx: OffChainContext,
    state: ContractState,  // Remove underscore prefix
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request = deserialize_request_body::<Request>(&request)?;
    let account_id = request.account_id.0;
    let backup_id = request.backup_id.0;
    
    // NEW: Validate backup exists on-chain
    let account = state
        .get_account(account_id)
        .ok_or_else(|| ServerError::NotFound("Account not found".to_string()))?;
    
    let _backup = account.recover_id(backup_id).ok_or_else(|| {
        ServerError::NotFound(format!("Backup not found for backup_id: {}", backup_id))
    })?;
    
    // Continue with existing logic
    let shares: Vec<_> = GuardianShareCollection::load(&mut ctx, (account_id, backup_id))
        .unwrap_or_default()
        .values()
        .cloned()
        .map(StrEncoded)
        .collect();
    create_json_response(200, &Response { shares }).map_err(|e| e.into())
}
```

**Long-term Solution:**
Implement a cleanup mechanism that removes guardian shares from off-chain storage when backups are removed. This could be:
1. A new HTTP endpoint `/reconstruction/delete-shares` that removes shares for a deleted backup
2. Automatic cleanup triggered by monitoring on-chain account update events
3. Time-based expiration for guardian shares with periodic validation against on-chain state

## Proof of Concept

**Test File:** Add to `contracts/java-test/src/test/java/com/partisia/blockchain/contract/SwafeContractTest.java`

**Test Function Name:** `testOrphanedGuardianSharesAfterBackupRemoval`

**Setup:**
1. Initialize contract with VDRF nodes and test execution engines
2. Create owner account (Account A) with allocated account state
3. Create guardian accounts (G1, G2, G3) with t=2 threshold
4. Generate Backup B1 with secret data
5. Add B1 to Account A and submit successful `update_account` transaction
6. Guardians upload their shares via `/reconstruction/upload-share` endpoint
7. Verify shares are stored by calling `/reconstruction/get-shares` - should return 3 shares

**Trigger:**
1. Generate account update that removes Backup B1 using CLI command `remove-backup-from-account` (hypothetical, or manually construct AccountUpdate)
2. Submit successful `update_account` transaction removing B1
3. Verify on-chain state: Query account via `/account/get` and confirm B1 no longer exists in recovery list
4. Call `/reconstruction/get-shares` with (AccountA_id, B1_id)

**Observation:**
1. **Expected behavior**: `get-shares` should return error "Backup not found" since B1 was removed from on-chain account
2. **Actual behavior**: `get-shares` successfully returns 3 guardian shares for the deleted backup
3. **Test assertion**: The test should detect that shares are returned for a non-existent backup, confirming the state inconsistency vulnerability
4. **Additional check**: Verify that if BackupCiphertext was cached, combining it with the returned shares allows secret reconstruction despite backup removal

The test demonstrates that off-chain guardian shares persist after on-chain backup removal, violating state consistency and enabling potential unauthorized secret reconstruction.

### Citations

**File:** contracts/src/http/endpoints/reconstruction/get_shares.rs (L19-34)
```rust
pub fn handler(
    mut ctx: OffChainContext,
    _state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request = deserialize_request_body::<Request>(&request)?;
    let account_id = request.account_id.0;
    let backup_id = request.backup_id.0;
    let shares: Vec<_> = GuardianShareCollection::load(&mut ctx, (account_id, backup_id))
        .unwrap_or_default()
        .values()
        .cloned()
        .map(StrEncoded)
        .collect();
    create_json_response(200, &Response { shares }).map_err(|e| e.into())
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L23-31)
```rust
#[derive(ReadWriteState, Serialize, Deserialize, Clone, Default)]
pub struct GuardianShareCollection {}

impl Mapping for GuardianShareCollection {
    type Key = (AccountId, BackupId);
    type Value = BTreeMap<u32, GuardianShare>;

    const COLLECTION_NAME: &'static str = "map:guardian_shares";
}
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L33-56)
```rust
pub fn handler(
    mut ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request: Request = deserialize_request_body(&request)?;

    let backup_id = request.backup_id.0;
    let account_id = request.account_id.0;

    let account = state
        .get_account(account_id)
        .ok_or_else(|| ServerError::NotFound("Account not found".to_string()))?;

    let backup: &BackupCiphertext = account.recover_id(backup_id).ok_or_else(|| {
        ServerError::NotFound(format!("Backup not found for backup_id: {}", backup_id))
    })?;

    // The share id will be in the range [0, |shares|)
    let share_id = backup
        .verify(&request.share.0)
        .map_err(|_| ServerError::InvalidParameter("Invalid guardian share".to_string()))?;

```

**File:** lib/src/account/v0.rs (L510-514)
```rust
    pub fn remove_backup(&mut self, id: BackupId) {
        self.dirty = true;
        self.backups.retain(|ct| ct.id() != id);
        self.recover.retain(|ct| ct.id() != id);
    }
```
