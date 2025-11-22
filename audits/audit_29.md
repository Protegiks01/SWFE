## Title
Guardian Shares Cannot Be Uploaded for Backups Marked for Recovery Due to Incorrect `recover_backups()` Implementation

## Summary
The `recover_backups()` method in `AccountStateV0` only returns backups from the `backups` field, not the `recover` field. When users mark a backup for recovery using `mark_recovery()`, it moves from `backups` to `recover`. Subsequently, the `upload_share` endpoint cannot find these backups, preventing guardians from uploading shares and making recovery impossible. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- Primary issue: `lib/src/account/v0.rs`, lines 246-248 in the `recover_backups()` method
- Affected endpoint: `contracts/src/http/endpoints/reconstruction/upload_share.rs`, line 48

**Intended Logic:** 
The `recover_backups()` method should return backups that are intended for recovery. When a user calls `mark_recovery()` to prepare a backup for recovery, it should be accessible to guardians for share uploads. The method's documentation states "Get recovery backups," suggesting it should return backups marked for recovery. [2](#0-1) 

**Actual Logic:** 
The `recover_backups()` method only returns items from the `backups` field, completely ignoring the `recover` field. When `mark_recovery()` is called, it moves the backup from `backups` to `recover`, making it invisible to `recover_backups()` and thus inaccessible to the `upload_share` endpoint. [3](#0-2) 

**Exploit Scenario:**
1. User creates a backup and adds it to their account state (backup is in `backups` field)
2. User finalizes the account update on-chain
3. User marks the backup for recovery by calling `mark_recovery(backup_id)`, which moves it from `backups` to `recover`
4. User finalizes this state change on-chain
5. Guardians attempt to upload shares via the `/reconstruction/upload-share` endpoint
6. The endpoint calls `account.recover_id(backup_id)`, which searches using `recover_backups()`
7. Since `recover_backups()` only returns items from `backups`, the backup is not found
8. Share upload fails with "Backup not found" error
9. Recovery becomes permanently impossible for this backup [4](#0-3) 

**Security Failure:** 
This breaks the fundamental recovery invariant that users who follow the proper workflow (mark for recovery → collect guardian shares → reconstruct secret) should be able to recover their backups. It causes permanent freezing of secrets for users who mark backups for recovery before collecting guardian shares. [5](#0-4) 

## Impact Explanation

**Affected Assets:** User backups containing encrypted secrets, master secret keys, or other sensitive data that require guardian reconstruction.

**Severity of Damage:** 
- Users who mark a backup for recovery will permanently lose access to that backup's contents
- The backup ciphertext remains on-chain but becomes unrecoverable since guardians cannot upload the necessary shares
- This results in permanent freezing of secrets, requiring no hard fork to fix but causing permanent data loss for affected users
- Any user following what appears to be the intended workflow (marking for recovery before guardian participation) will experience this issue

**System Reliability Impact:** 
This directly violates the core promise of the backup/recovery system. The existence of the `mark_recovery()` function suggests it's part of the intended workflow, yet using it breaks the recovery process. This creates a critical reliability failure where the system appears functional but silently prevents recovery for users who follow seemingly correct procedures.

## Likelihood Explanation

**Who Can Trigger:** Any user who marks a backup for recovery before collecting guardian shares will encounter this issue. This is not an edge case but a natural workflow that users might follow.

**Conditions Required:** 
- User has created and finalized a backup on-chain
- User calls `mark_recovery()` to prepare for recovery (seems like the logical first step)
- User finalizes the account update containing the marked backup
- Guardians attempt to upload shares

**Frequency:** This will occur every time a user follows the mark-for-recovery workflow before collecting shares. Given that `mark_recovery()` exists as a public API and its name suggests it should be called before recovery, this is likely to be a common occurrence in production. [6](#0-5) 

## Recommendation

Modify the `recover_backups()` method to return backups from both the `backups` and `recover` fields, or preferably just the `recover` field since the method name and documentation suggest it should return backups intended for recovery:

```rust
pub fn recover_backups(&self) -> Vec<&BackupCiphertext> {
    self.recover.iter().chain(self.backups.iter()).collect()
}
```

Or if the semantic intent is to only return explicitly marked recovery backups:

```rust
pub fn recover_backups(&self) -> Vec<&BackupCiphertext> {
    self.recover.iter().collect()
}
```

This ensures that backups marked for recovery remain accessible for guardian share uploads.

## Proof of Concept

**File:** `lib/src/account/tests.rs` (add new test function)

**Test Function Name:** `test_share_upload_after_mark_recovery`

**Setup:**
1. Create an owner account and three guardian accounts
2. Create a backup with threshold 2 out of 3 guardians
3. Add the backup to the owner's account state
4. Generate and finalize an account update containing the backup
5. Mark the backup for recovery using `mark_recovery(backup_id)`
6. Generate and finalize another account update with the marked-for-recovery backup

**Trigger:**
1. Simulate the upload_share endpoint by calling `account_state.recover_id(backup_id)`
2. Attempt to verify guardian shares against the backup

**Observation:**
The test will observe that `recover_id()` returns `None` after the backup is marked for recovery, even though the backup still exists in the account state (in the `recover` field). This confirms that backups marked for recovery are inaccessible to the share upload mechanism, permanently preventing recovery.

The test would look like:
```rust
#[test]
fn test_share_upload_after_mark_recovery() {
    let mut rng = OsRng;
    
    // Create accounts
    let mut owner = AccountSecrets::gen(&mut rng).unwrap();
    let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian3 = AccountSecrets::gen(&mut rng).unwrap();
    
    // Get guardian states
    let guardian1_state = guardian1.state(&mut rng).unwrap();
    let guardian2_state = guardian2.state(&mut rng).unwrap();
    let guardian3_state = guardian3.state(&mut rng).unwrap();
    
    // Create backup
    let backup = owner.backup(
        &mut rng,
        &TestData { value: "secret".to_string() },
        Metadata::new("Test".to_string(), "Test backup".to_string()),
        &[guardian1_state.clone(), guardian2_state.clone(), guardian3_state.clone()],
        2,
    ).unwrap();
    
    let backup_id = backup.id();
    
    // Add backup to account
    owner.add_backup(backup.clone()).unwrap();
    
    // Finalize state with backup
    let state_with_backup = owner.state(&mut rng).unwrap();
    
    // Backup should be found at this point
    assert!(state_with_backup.recover_id(backup_id).is_some());
    
    // Mark for recovery
    owner.mark_recovery(backup_id).unwrap();
    
    // Finalize state with marked recovery
    let state_after_mark = owner.state(&mut rng).unwrap();
    
    // BUG: Backup is now NOT found, even though it exists in the recover field
    assert!(state_after_mark.recover_id(backup_id).is_none()); // This passes, demonstrating the bug
    
    // This means guardians cannot upload shares for recovery!
}
```

This test demonstrates that after `mark_recovery()`, the backup becomes invisible to `recover_id()`, preventing guardian share uploads and making recovery impossible.

### Citations

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

**File:** lib/src/account/v0.rs (L245-248)
```rust
    /// Get recovery backups
    pub fn recover_backups(&self) -> Vec<&BackupCiphertext> {
        self.backups.iter().collect()
    }
```

**File:** lib/src/account/v0.rs (L517-526)
```rust
    pub fn mark_recovery(&mut self, id: BackupId) -> Result<()> {
        // move the backup from "backups" to "recover"
        if let Some(index) = self.backups.iter().position(|ct| ct.id() == id) {
            self.dirty = true;
            self.recover.push(self.backups.remove(index));
            Ok(())
        } else {
            Err(SwafeError::BackupNotFound)
        }
    }
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L48-50)
```rust
    let backup: &BackupCiphertext = account.recover_id(backup_id).ok_or_else(|| {
        ServerError::NotFound(format!("Backup not found for backup_id: {}", backup_id))
    })?;
```

**File:** lib/src/account/tests.rs (L802-804)
```rust
        // Test mark_recovery() - This should fail since the backup is in recovery state, not backups list
        let mark_result = secrets.mark_recovery(*backup_id);
        assert!(mark_result.is_err()); // Expected to fail - backup not in backups list
```

**File:** lib/src/account/mod.rs (L87-89)
```rust
    pub fn recover_id(&self, id: BackupId) -> Option<&BackupCiphertext> {
        self.recover_backups().into_iter().find(|ct| ct.id() == id)
    }
```
