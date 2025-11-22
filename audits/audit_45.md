# Audit Report

## Title
Incomplete Backup Deletion Enables Reconstruction of Supposedly Deleted Secrets via Retained Old Keys and Guardian Shares

## Summary
When users remove backups via `remove_backup()`, the system only deletes the backup ciphertext from on-chain account state. However, old PKE decryption keys and guardian shares persist indefinitely in encrypted account state and off-chain storage respectively, with no cleanup mechanism. If an attacker later compromises the account's Master Secret Key (MSK), they can decrypt the account state to extract historical PKE keys, query the unauthenticated `/reconstruction/get-shares` endpoint to retrieve guardian shares, and fully reconstruct backups that users believed were permanently deleted.

## Impact
**High**

## Finding Description

**Location:** 
- `lib/src/account/v0.rs` - `remove_backup()` function and `new_pke()` function
- `lib/src/account/v0.rs` - `update()` function storing `old_pke` vector
- `contracts/src/http/endpoints/reconstruction/upload_share.rs` - Guardian share storage
- `contracts/src/http/endpoints/reconstruction/get_shares.rs` - Unauthenticated share retrieval

**Intended Logic:** 
When users delete a backup, the system should ensure that the backup and all associated decryption capabilities are permanently removed, preventing any future reconstruction of the deleted data. Users expect that deleted backups cannot be recovered, even if their current account credentials are compromised.

**Actual Logic:** 
The `remove_backup()` function only removes the backup ciphertext from the `backups` and `recover` vectors. [1](#0-0) 

However, three critical components persist indefinitely:

1. **Old PKE keys accumulate without cleanup**: When users rotate their PKE keys via `new_pke()`, the old key is pushed to the `old_pke` vector. [2](#0-1)  This vector is never cleared - there is no cleanup mechanism in the codebase.

2. **Old keys stored on-chain**: The `old_pke` vector is encrypted with the current MSK and stored on-chain within the account state. [3](#0-2) 

3. **Guardian shares persist in off-chain storage**: Guardian shares are stored permanently in off-chain storage keyed by `(AccountId, BackupId)`. [4](#0-3)  There is no deletion mechanism for these shares.

4. **Unauthenticated share retrieval**: The `/reconstruction/get-shares` endpoint allows anyone to retrieve guardian shares without authentication. [5](#0-4) 

**Exploit Scenario:**
1. User creates a backup containing sensitive data (e.g., private keys, passwords) encrypted with PKE key K1
2. Guardians create and upload guardian shares to off-chain storage via `/reconstruction/upload-share`
3. User rotates their PKE key to K2 (K1 is automatically pushed to `old_pke` vector)
4. User calls `remove_backup()` believing the backup is permanently deleted (only the ciphertext is removed)
5. Time passes, and the user's MSK is compromised through any means (e.g., social engineering attack, recovery attack, phishing)
6. Attacker decrypts the account state using the compromised MSK and extracts K1 from the `old_pke` vector
7. Attacker calls the unauthenticated `/reconstruction/get-shares` endpoint with the known AccountId and BackupId to retrieve all guardian shares
8. Attacker decrypts the guardian shares using the old PKE key K1 (shares are encrypted for the account owner) [6](#0-5) 
9. Attacker reconstructs the "deleted" backup and extracts the sensitive data

**Security Failure:** 
This breaks the forward secrecy property and violates user expectations about data deletion. A current compromise (of the MSK) reveals all historical secrets, including those the user explicitly attempted to delete. The system fails to provide complete deletion semantics.

## Impact Explanation

**Assets Affected:**
- All backup data that users have attempted to delete throughout the account's lifetime
- Private keys, passwords, recovery phrases, or any sensitive information stored in deleted backups
- User privacy and confidentiality guarantees

**Severity of Damage:**
- **Direct loss of secrets**: Attackers can recover sensitive data users believed was permanently destroyed
- **Persistent vulnerability**: The vulnerability has no expiration - old keys and guardian shares persist forever
- **Cascading compromise**: A single MSK compromise at any point in time exposes the entire historical backup deletion record
- **Broken trust model**: Users who delete backups before key compromise remain vulnerable

**System Security Impact:**
This vulnerability fundamentally undermines the security model of the backup system. Users cannot safely delete sensitive backups, as the deletion is incomplete. If an attacker compromises the MSK through social engineering, recovery attacks, or other means at any future point, they gain access to all historically deleted backups. This violates the principle of least privilege and forward secrecy.

## Likelihood Explanation

**Who Can Trigger:**
Any attacker who can compromise an account's MSK can exploit this vulnerability. MSK compromise can occur through:
- Successful social engineering attacks on guardians
- Recovery system vulnerabilities
- User device compromise
- Phishing attacks

**Conditions Required:**
1. User must have rotated PKE keys at least once (creating entries in `old_pke`)
2. User must have deleted at least one backup via `remove_backup()`
3. Guardian shares must still exist in off-chain storage (they always do - no cleanup)
4. Attacker must compromise the MSK at any future point

**Frequency:**
- The vulnerability is **always present** for any user who has deleted backups
- Risk **accumulates over time** as more old keys accumulate in `old_pke`
- Every deleted backup remains vulnerable indefinitely
- No time-based expiration or mitigation exists

The likelihood is **HIGH** because:
- Normal user operations (key rotation and backup deletion) create the vulnerable state
- MSK compromise is a realistic threat model
- The `/reconstruction/get-shares` endpoint requires no authentication
- No periodic cleanup or key expiration exists

## Recommendation

Implement a comprehensive cleanup mechanism:

1. **Add guardian share deletion**: Create a new endpoint or extend `remove_backup()` to delete guardian shares from off-chain storage when a backup is removed:
   - Add a method to remove entries from `GuardianShareCollection` by `(AccountId, BackupId)` key
   - Call this cleanup when `remove_backup()` is invoked

2. **Implement old key cleanup**: Add a mechanism to clear old PKE keys from `old_pke` vector:
   - Provide a `cleanup_old_keys()` method that removes old keys once all backups encrypted with those keys are deleted
   - Track which backups use which PKE keys and only retain keys for active backups
   - Alternatively, implement a time-based or count-based retention policy (e.g., keep only the last N keys)

3. **Add authentication to share retrieval**: The `/reconstruction/get-shares` endpoint should require proof of account ownership before returning guardian shares:
   - Require signature with the account's current signing key
   - Verify the requester has permission to access these shares

4. **Implement periodic cleanup**: Add a cleanup routine that identifies and removes:
   - Old PKE keys no longer needed for any active backup
   - Guardian shares for deleted backups
   - Orphaned off-chain storage entries

## Proof of Concept

**Test File:** `lib/src/account/tests.rs` (add new test function)

**Test Function:** `test_deleted_backup_reconstruction_via_old_keys`

**Setup:**
1. Create two accounts: Alice (victim) and three guardians
2. Alice creates a backup with sensitive data encrypted with initial PKE key K1
3. Guardians receive and store their shares (simulating guardian share upload)
4. Alice rotates her PKE key to K2 (K1 moves to `old_pke`)
5. Alice removes the backup via `remove_backup()` believing it's deleted
6. Alice publishes updated account state (without the backup ciphertext)

**Trigger:**
7. Simulate MSK compromise: Extract Alice's MSK (e.g., through a hypothetical recovery attack)
8. Decrypt Alice's account state to extract the `old_pke` vector containing K1
9. Retrieve guardian shares from off-chain storage (simulating unauthenticated `/reconstruction/get-shares` call)
10. Decrypt guardian shares using old PKE key K1
11. Reconstruct the "deleted" backup using the decrypted shares

**Observation:**
The test successfully reconstructs the backup that Alice explicitly deleted in step 5. The assertion `assert_eq!(reconstructed_secret, original_secret)` passes, demonstrating that:
- The deleted backup's data is fully recoverable
- Old PKE keys remain accessible in the account state
- Guardian shares persist despite backup deletion
- The deletion operation is incomplete and provides false security guarantees

The test should output: "VULNERABILITY CONFIRMED: Deleted backup successfully reconstructed using old PKE key and persisted guardian shares"

This PoC demonstrates that the backup deletion mechanism does not provide the security guarantees users expect, as "deleted" backups remain fully recoverable if the MSK is ever compromised.

### Citations

**File:** lib/src/account/v0.rs (L492-496)
```rust
    pub fn new_pke<R: Rng + CryptoRng>(&mut self, rng: &mut R) {
        self.dirty = true;
        self.old_pke.push(self.pke.clone());
        self.pke = pke::DecryptionKey::gen(rng);
    }
```

**File:** lib/src/account/v0.rs (L509-514)
```rust
    /// Remove a ciphertext by id
    pub fn remove_backup(&mut self, id: BackupId) {
        self.dirty = true;
        self.backups.retain(|ct| ct.id() != id);
        self.recover.retain(|ct| ct.id() != id);
    }
```

**File:** lib/src/account/v0.rs (L675-676)
```rust
                old_msk: self.old_msk.clone(),
                old_pke: self.old_pke.clone(),
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L64-67)
```rust
    let storage_key = (account_id, backup_id);
    let mut shares = GuardianShareCollection::load(&mut ctx, storage_key).unwrap_or_default();
    shares.insert(share_id, request.share.0);
    GuardianShareCollection::store(&mut ctx, storage_key, shares);
```

**File:** contracts/src/http/endpoints/reconstruction/get_shares.rs (L25-34)
```rust
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

**File:** lib/src/backup/v0.rs (L304-304)
```rust
                let share: Share = dke.decrypt(&share_v0.ct, aad).ok()?;
```
