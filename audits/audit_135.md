# Audit Report

## Title
Backup Encryption Keys Not Bound to User Identity Allowing Cross-User Metadata Decryption with Shared MSK

## Summary
The backup encryption key derivation in `lib/src/backup/v0.rs` does not include any user-specific identifiers (such as AccountId) in the key derivation function. This allows two different users who share the same Master Secret Key (MSK) to decrypt each other's backup metadata without authorization, as backup ciphertexts are publicly accessible through the contract's HTTP endpoints.

## Impact
**Medium**

## Finding Description

**Location:** 
- Key derivation: `lib/src/backup/v0.rs`, lines 404 and 316
- Metadata decryption: `lib/src/backup/v0.rs`, lines 316-319
- Public account access: `contracts/src/http/endpoints/account/get.rs`, lines 25-27

**Intended Logic:** 
Backup encryption should provide cryptographic isolation between users. Each user's backups should only be decryptable by that user (with their MSK) and their designated guardians. Even if two users somehow share the same MSK, their backups should remain isolated through additional user-specific binding.

**Actual Logic:** 
The metadata encryption key (`key_meta`) is derived solely from the MSK and the backup's share commitments, without including the AccountId or any user-specific identifier. [1](#0-0)  The key derivation uses `kdfn(sym_key, &KDFMetakey { comms: &comms })` where `sym_key` is the MSK and `comms` comes from the backup ciphertext. [2](#0-1) 

During recovery, the metadata decryption only requires the MSK and the publicly-accessible backup ciphertext: [3](#0-2)  The metadata includes potentially sensitive information: name, description, threshold, and timestamp. [4](#0-3) 

**Exploit Scenario:**
1. User A (AccountId = A, MSK = X) creates a backup containing sensitive information
2. User B (AccountId = B, MSK = X) has the same MSK through any means (key reuse, collision, or shared secret scenario)
3. User B queries the public `/account/get` endpoint to retrieve User A's account state [5](#0-4) 
4. The account state includes all backup ciphertexts in the `backups` vector [6](#0-5) 
5. User B extracts User A's backup ciphertext (containing `comms` and encrypted metadata)
6. User B uses their shared MSK to derive the same `key_meta` as User A
7. User B successfully decrypts User A's backup metadata, revealing the backup name, description, threshold, and creation timestamp

**Security Failure:** 
This violates the privacy isolation between users. Backup metadata can contain sensitive information (e.g., "Bitcoin wallet seed", "Bank account password") that should not be accessible to other users even if they somehow share the same MSK. The lack of user-specific binding in the key derivation allows cross-user metadata exposure.

## Impact Explanation

**Assets Affected:**
- Backup metadata (name, description, threshold, timestamp) for all users
- User privacy and confidentiality expectations

**Severity of Damage:**
- User B can read User A's backup metadata without authorization
- Backup names and descriptions may contain sensitive information revealing what secrets are stored
- While the actual secret data remains protected by guardian shares, the metadata exposure constitutes a significant privacy violation
- This undermines the security model where each user's backups should be cryptographically isolated

**Why This Matters:**
Users expect their backup metadata to be private. Revealing backup names like "Recovery phrase for wallet with 10 BTC" or "Admin password for production server" provides valuable information to attackers and violates user privacy. The protocol should ensure cryptographic separation between users' data, even in the unlikely event of MSK collision.

## Likelihood Explanation

**Who Can Trigger:**
Any user who shares the same MSK with another user can exploit this vulnerability. While MSK collision is unlikely under normal circumstances, the security question explicitly asks us to consider this scenario.

**Required Conditions:**
1. Two users must have identical MSKs (accepted premise)
2. Attacker must know or suspect the MSK collision exists
3. Backup ciphertexts are publicly accessible via the `/account/get` endpoint (always true)
4. No additional authentication or authorization checks prevent cross-user access

**Frequency:**
Once the conditions are met, the attack can be executed repeatedly against any backup. The vulnerability is deterministic and does not require timing-specific conditions or race conditions.

## Recommendation

Modify the key derivation functions to include the AccountId as a binding parameter:

1. **Update `KDFMetakey` structure** to include the AccountId:
```rust
#[derive(Serialize)]
struct KDFMetakey<'a> {
    account_id: &'a AccountId,
    comms: &'a [ShareComm],
}
```

2. **Update `BackupKDFInput` structure** to include the AccountId:
```rust
#[derive(Serialize)]
struct BackupKDFInput<'a> {
    account_id: &'a AccountId,
    key: &'a sym::Key,
    secret: sss::Secret,
}
```

3. **Pass AccountId through the backup creation and recovery flows** to ensure it's available for key derivation. The `AADBackup` already contains the AccountId but is only used for guardian share encryption; it should also be used in the KDF.

4. **Update both `new` and `recover` functions** in `BackupCiphertextV0` to pass and use the AccountId in key derivation.

This ensures that even with identical MSKs, different users will derive different encryption keys due to their unique AccountIds, providing proper cryptographic isolation.

## Proof of Concept

**Test File:** `lib/src/backup/tests.rs` (add new test function)

**Test Function Name:** `test_cross_user_metadata_decryption_with_shared_msk`

**Setup:**
1. Create two AccountSecrets instances (User A and User B) with **identical** MSKs
2. User A creates a backup with sensitive metadata (name: "Bitcoin Wallet Seed", description: "DO NOT SHARE")
3. Simulate User B obtaining User A's backup ciphertext (as it would be available from the public `/account/get` endpoint)

**Trigger:**
1. User B attempts to decrypt the metadata using their MSK (which equals User A's MSK)
2. User B derives `key_meta` using `kdfn(userB_msk.as_bytes(), &KDFMetakey { comms: &userA_backup.comms })`
3. User B calls `sym::open(&key_meta, &userA_backup.data, &sym::EmptyAD)` to decrypt the metadata

**Observation:**
The test should demonstrate that User B successfully decrypts User A's metadata, revealing the sensitive backup name and description. This confirms the vulnerability: backup metadata is not cryptographically bound to the account owner, allowing cross-user decryption when MSKs are shared.

The test should include assertions showing:
- User B can derive the correct `key_meta`
- User B can successfully decrypt the `BackupMetadata` structure
- User B can read User A's backup name, description, threshold, and timestamp
- This violates the expected privacy isolation between users

### Citations

**File:** lib/src/backup/v0.rs (L206-212)
```rust
struct BackupMetadata {
    name: String,         // user defined name for secret
    desc: String,         // user defined description for secret
    data: AEADCiphertext, // encrypted data
    threshold: u32,       // threshold for the secret
    timestamp: u64,       // timestamp of the backup
}
```

**File:** lib/src/backup/v0.rs (L215-217)
```rust
struct KDFMetakey<'a> {
    comms: &'a [ShareComm],
}
```

**File:** lib/src/backup/v0.rs (L316-319)
```rust
        let key_meta: sym::Key = kdfn(sym, &KDFMetakey { comms: &self.comms });

        // decrypt the metadata
        let meta: BackupMetadata = sym::open(&key_meta, &self.data, &sym::EmptyAD)?;
```

**File:** lib/src/backup/v0.rs (L404-404)
```rust
        let key_meta: [u8; sym::SIZE_KEY] = kdfn(sym_key, &KDFMetakey { comms: &comms });
```

**File:** contracts/src/http/endpoints/account/get.rs (L25-27)
```rust
    let account: AccountState = state
        .get_account(request.account_id.0)
        .ok_or_else(|| ServerError::NotFound("Account not found".to_string()))?;
```

**File:** lib/src/account/v0.rs (L236-236)
```rust
    backups: Vec<BackupCiphertext>, // backups to store
```
