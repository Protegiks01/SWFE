## Audit Report

## Title
Guardian Share Upload Endpoint Lacks Recovery PKE Binding, Enabling Denial-of-Service on Account Recovery

## Summary
The `upload_share` endpoint in `contracts/src/http/endpoints/reconstruction/upload_share.rs` lacks authentication metadata to verify that uploaded guardian shares are encrypted to the current recovery PKE key. The Request struct only validates cryptographic signatures but does not bind shares to the active recovery session, allowing attackers to upload outdated shares from previous recovery attempts and block account recovery. [1](#0-0) 

## Impact
**Medium Severity** - Temporary freezing of recovery operations affecting users attempting account recovery.

## Finding Description

**Location:** 
- Primary vulnerability: [2](#0-1) 
- Missing PKE binding check at: [3](#0-2) 

**Intended Logic:** 
When guardians upload shares during account recovery, the shares should be encrypted to the current recovery PKE key that the account owner possesses. The upload endpoint should ensure that only shares encrypted for the active recovery session are accepted and stored.

**Actual Logic:** 
The handler only verifies that the GuardianShare has a valid signature against the backup's commitments. It does not verify that the share's ciphertext is encrypted to the recovery PKE key currently active in the account state. The verification function only checks signature validity, not ciphertext binding: [4](#0-3) 

The comments explicitly state that "different multiple versions of the same share are all equivalent" and allow overwriting: [5](#0-4) 

However, this assumption is invalid when recovery PKE keys change between recovery attempts.

**Exploit Scenario:**

1. User initiates account recovery, generating a new ephemeral recovery PKE key (PKE₁) and corresponding decryption key (DK₁): [6](#0-5) 

2. Guardian processes the recovery request and creates GuardianShare₁ encrypted to PKE₁: [7](#0-6) 

3. Attacker intercepts GuardianShare₁ (e.g., through network monitoring or compromised communication channel)

4. User re-initiates recovery (due to timeout, error, or wanting to restart), generating a NEW recovery PKE key (PKE₂) and decryption key (DK₂). The recovery PKE can be overwritten: [8](#0-7) 

5. Guardian creates GuardianShare₂ encrypted to PKE₂

6. Before or after the guardian uploads GuardianShare₂, the attacker uploads the intercepted GuardianShare₁

7. Since both shares have valid signatures (signed with the same guardian signing key from the backup), GuardianShare₁ passes verification and overwrites GuardianShare₂

8. When the user retrieves shares and attempts to complete recovery, the decryption fails because GuardianShare₁ is encrypted to the old PKE₁, but the user only has DK₂: [9](#0-8) 

9. Recovery is blocked until the guardian re-uploads the correct share

**Security Failure:** 
The vulnerability breaks the liveness property of account recovery. An attacker can cause denial-of-service by preventing users from successfully recovering their accounts, even when the threshold number of guardians have approved the recovery request.

## Impact Explanation

**Affected Assets:**
- Master Secret Keys (MSK) become temporarily inaccessible during recovery
- Account ownership verification is delayed
- User access to encrypted backups is frozen

**Severity of Damage:**
- Recovery operations are temporarily blocked, preventing users from regaining access to their accounts
- If the attacker intercepts shares from multiple guardians (t or more), the threshold cannot be met with valid shares, effectively freezing the account until all affected guardians re-upload
- Users must coordinate with guardians for re-upload, adding significant friction and delay to the recovery process
- In worst case, if guardians are unavailable or unresponsive, the account could remain frozen indefinitely

**System Reliability Impact:**
This vulnerability undermines the core recovery guarantee that users can recover accounts with email + guardian approval. An active attacker can repeatedly block recovery attempts by uploading old shares whenever new recovery sessions are initiated.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant who can intercept guardian shares, including:
- Network-level attackers with packet capture capabilities
- Compromised intermediate nodes or proxies
- Attackers monitoring the reconstruction endpoint
- Participants with access to old guardian share uploads

**Required Conditions:**
- User must re-initiate recovery at least once (creating multiple recovery PKE keys)
- Attacker must obtain guardian shares from a previous recovery attempt
- Timing: Attacker must upload old shares before or shortly after guardians upload current shares

**Exploitation Frequency:**
- Recovery re-initiation is common in practice (timeouts, errors, user mistakes)
- Guardian shares are transmitted over potentially observable channels
- Once an attacker obtains old shares, they can be replayed indefinitely for future recovery attempts
- The attack can be automated to monitor for new recovery initiations and immediately upload old shares

## Recommendation

Add a recovery PKE binding check to the upload_share handler:

1. **Retrieve Current Recovery PKE:** When validating an upload, fetch the current recovery PKE from the account state
2. **Verify Ciphertext Binding:** Add a check that the GuardianShare's ciphertext can only be decrypted by the current recovery PKE (or verify it was created for the current recovery session)
3. **Add Session Identifier:** Include a recovery session ID in the AccountState that changes with each initiation, and require GuardianShares to include this session ID in their signed content
4. **Reject Stale Shares:** Explicitly reject shares that were created for previous recovery sessions

Example mitigation in `upload_share.rs`:

```rust
// After line 50, add:
let recovery_pke = account
    .rec
    .pke
    .as_ref()
    .ok_or_else(|| ServerError::InvalidParameter("Recovery not initiated".to_string()))?;

// Before line 66, add a binding check or session verification
// Option 1: Include recovery_pke hash in signature
// Option 2: Add recovery session counter and verify it matches
```

Alternatively, modify the GuardianShare structure to include a recovery session identifier that gets signed along with the ciphertext.

## Proof of Concept

**Test File:** Add to `lib/src/account/tests.rs`

**Test Function:** `test_recovery_pke_binding_vulnerability`

**Setup:**
1. Create an account with 3 guardians and threshold t=2
2. User calls `initiate_recovery()` to start first recovery session (generates PKE₁)
3. Guardian 1 calls `check_for_recovery()` to generate GuardianShare₁ encrypted to PKE₁
4. Store GuardianShare₁ (simulating attacker interception)
5. User calls `initiate_recovery()` again to start second recovery session (generates PKE₂)
6. Guardian 1 calls `check_for_recovery()` with updated account state to generate GuardianShare₂ encrypted to PKE₂

**Trigger:**
1. Upload GuardianShare₁ (old share) via the upload_share endpoint
2. Observe that it passes verification (signature is still valid)
3. Upload GuardianShare₂ (current share) 
4. Re-upload GuardianShare₁ to overwrite GuardianShare₂

**Observation:**
1. Both uploads succeed (both have valid signatures from the same guardian)
2. Attempt to call `complete_recovery()` with the retrieved shares
3. The decryption fails with an error because GuardianShare₁ cannot be decrypted with the current recovery DK₂
4. Recovery is blocked despite having threshold guardians' approval

The test demonstrates that the upload endpoint accepts shares encrypted to outdated recovery PKE keys, allowing denial-of-service attacks on recovery operations.

### Citations

**File:** api/src/reconstruction/upload_share.rs (L8-13)
```rust
#[derive(Serialize, Deserialize)]
pub struct Request {
    pub account_id: StrEncoded<AccountId>,
    pub backup_id: StrEncoded<BackupId>,
    pub share: StrEncoded<GuardianShare>,
}
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L33-74)
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

    // Update the share mapping for this backup
    // usually, the share will not already exist in this map:
    // we allow overwriting in case of a buggy client library and to
    // simplify a client which fails during the upload process: it can simply retry all uploads.
    //
    // Potentially different multiple versions of the same share are all equivalent.
    // Hence no replay protection is required here.
    let storage_key = (account_id, backup_id);
    let mut shares = GuardianShareCollection::load(&mut ctx, storage_key).unwrap_or_default();
    shares.insert(share_id, request.share.0);
    GuardianShareCollection::store(&mut ctx, storage_key, shares);

    let response = Response {
        success: true,
        message: "Share uploaded successfully".to_string(),
    };
    create_json_response(200, &response).map_err(|e| e.into())
}
```

**File:** lib/src/backup/v0.rs (L342-354)
```rust
    pub fn verify(&self, share: &GuardianShareV0) -> Result<u32, SwafeError> {
        if share.idx > self.comms.len() as u32 {
            return Err(SwafeError::InvalidShare);
        }
        self.comms[share.idx as usize].vk.verify(
            &share.sig,
            &SignedEncryptedShare {
                ct: &share.ct,
                idx: share.idx,
            },
        )?;
        Ok(share.idx)
    }
```

**File:** lib/src/account/v0.rs (L145-162)
```rust
    pub fn complete(&self, shares: &[GuardianShare]) -> Result<MasterSecretKey> {
        // recover the social secret share from the backup
        let msk_ss_social: MskSecretShareSocial = match &self.rec.social {
            BackupCiphertext::V0(v0) => {
                v0.recover(&self.dkey, &self.msk_ss_rik, &EmptyInfo, shares)?
            }
        };

        // derive the MSK decryption key from both secret shares
        let msk_dec_key = derive_msk_decryption_key(
            &self.acc,
            &MskSecretShareRik::new(self.msk_ss_rik),
            &msk_ss_social,
        );

        // decrypt the MSK using the derived key
        sym::open(&msk_dec_key, &self.rec.enc_msk, &self.acc)
    }
```

**File:** lib/src/account/v0.rs (L195-197)
```rust
        // generate new keys for this recovery session
        let dkey = pke::DecryptionKey::gen(rng);

```

**File:** lib/src/account/v0.rs (L753-754)
```rust
        // reencrypt the share for the requester's recovery PKE key
        Ok(Some(secret_share.send_for_recovery(rng, state)?))
```

**File:** lib/src/account/v0.rs (L828-829)
```rust
                    // Set the recovery PKE to indicate recovery has been initiated
                    rec.pke = Some(recovery.pke);
```
