# Audit Report

## Title
Off-By-One Error in Guardian Share Index Validation Enables Denial-of-Service on Recovery Flow

## Summary
A critical off-by-one error exists in `BackupCiphertextV0::verify()` at line 343 of `lib/src/backup/v0.rs`. The bounds check uses `>` instead of `>=`, allowing a guardian share with `idx = comms.len()` to pass validation but then trigger an out-of-bounds array access panic. This vulnerability can be exploited via the `/reconstruction/upload-share` endpoint to cause a denial-of-service, preventing legitimate account recovery operations. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** The vulnerability exists in `BackupCiphertextV0::verify()` function in `lib/src/backup/v0.rs` at line 343, and is exploitable through the upload_share handler in `contracts/src/http/endpoints/reconstruction/upload_share.rs` at lines 53-55. [1](#0-0) [2](#0-1) 

**Intended Logic:** The verify function should reject any guardian share with an index outside the valid range `[0, comms.len())`. When a backup is created with `n` guardians, valid share indices are `0, 1, 2, ..., n-1`. [3](#0-2) 

**Actual Logic:** The bounds check at line 343 uses `if share.idx > self.comms.len() as u32`, which allows `share.idx == self.comms.len()` to pass. For a backup with 3 guardians (`comms.len() = 3`), indices 0, 1, 2 are valid, but index 3 passes the check (`3 > 3` is false). The subsequent array access at line 346 (`self.comms[share.idx as usize]`) then attempts to access `self.comms[3]`, causing an out-of-bounds panic.

**Exploit Scenario:**
1. Attacker observes a backup ciphertext with `n` guardians (e.g., 3 guardians with indices 0, 1, 2)
2. Attacker crafts a `GuardianShareV0` structure with `idx = n` (e.g., `idx = 3`)
3. Attacker submits this malicious share to the `/reconstruction/upload-share` endpoint
4. The endpoint handler calls `backup.verify(&request.share.0)` which panics
5. The contract handler crashes, preventing any further share uploads
6. Legitimate guardians cannot upload their shares
7. Account recovery is blocked for all users of this backup

**Security Failure:** This breaks the availability guarantees of the reconstruction system. The panic causes a denial-of-service on the upload-share endpoint, preventing legitimate guardians from submitting shares and blocking the account recovery flow. No authentication is required to trigger this vulnerability.

## Impact Explanation

This vulnerability has severe consequences for the Swafe protocol:

- **Asset Impact:** Users cannot recover their accounts or backed-up secrets when this attack is triggered. This effectively locks users out of their master secret keys and any assets controlled by those keys.

- **System Availability:** The `/reconstruction/upload-share` endpoint becomes unusable, preventing all guardian share submissions. This affects not just the targeted backup but potentially all concurrent recovery operations if the panic crashes the contract handler.

- **Recovery Flow Disruption:** The guardian-based social recovery mechanism is one of Swafe's core features. This vulnerability completely breaks that functionality, leaving users unable to recover from lost devices or compromised recovery keys. [4](#0-3) 

- **No Privilege Required:** Any network participant can exploit this vulnerability by crafting a malicious guardian share. No special permissions, keys, or trusted role access is needed.

## Likelihood Explanation

**Who can trigger it:** Any unprivileged network participant can exploit this vulnerability. The attacker only needs to observe a backup ciphertext (which may be publicly available or obtained through social engineering) and craft a malicious share with an out-of-bounds index.

**Conditions required:** The vulnerability is trivially exploitable during normal operation. Whenever the `/reconstruction/upload-share` endpoint is available and processing share submissions, an attacker can send the malicious payload. No special timing, race conditions, or complex prerequisites are required.

**Frequency:** This can be exploited repeatedly and immediately. An attacker can continuously submit malicious shares to deny service to legitimate recovery operations. Each malicious share submission triggers the panic, making the attack highly effective and easy to repeat.

**Practical exploitability:** The vulnerability is extremely likely to be exploited in a production environment because:
- The attack is simple to execute (just modify one integer field)
- The impact is immediate and severe (DoS on critical functionality)
- There is no cost or barrier to the attacker
- The vulnerability is in a critical user-facing endpoint

## Recommendation

**Immediate Fix:** Change the bounds check in `BackupCiphertextV0::verify()` from `>` to `>=`:

```rust
pub fn verify(&self, share: &GuardianShareV0) -> Result<u32, SwafeError> {
    if share.idx >= self.comms.len() as u32 {  // Changed from >
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

**Additional Safeguards:**
1. Add explicit documentation of the valid index range in the `GuardianShareV0` struct
2. Consider adding assertions in `BackupCiphertextV0::new()` to verify that the number of commitments matches the number of guardians
3. Add unit tests specifically testing boundary conditions (indices 0, n-1, n, n+1) for the verify function [1](#0-0) 

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** `test_guardian_share_index_out_of_bounds_panic`

**Setup:**
1. Create an account owner and 3 guardians
2. Create a backup with threshold 2 using the 3 guardians
3. Obtain the guardian states for encryption

**Trigger:**
1. Get a legitimate `GuardianShare` from guardian1
2. Serialize it to bytes using bincode
3. Manually modify the serialized idx field from a valid index (0, 1, or 2) to an out-of-bounds index (3)
4. Deserialize back to `GuardianShare`
5. Call `backup.verify(&malicious_share)`

**Observation:**
The test should catch a panic when `verify()` attempts to access `self.comms[3]` on a comms vector with length 3. The panic occurs at line 346 before signature verification, confirming the off-by-one error in the bounds check at line 343. [1](#0-0) 

**Alternative PoC via HTTP endpoint:**
1. Deploy the contract with the vulnerable code
2. Create a backup and register it
3. Send an HTTP request to `/reconstruction/upload-share` with a `GuardianShare` containing `idx = comms.len()`
4. Observe that the handler panics and the endpoint becomes unavailable
5. Verify that legitimate guardians cannot upload shares afterward [2](#0-1) 

**Expected behavior after fix:**
The verify function should return `Err(SwafeError::InvalidShare)` for any share with `idx >= comms.len()`, preventing the panic and rejecting invalid shares gracefully.

### Citations

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

**File:** lib/src/backup/v0.rs (L383-399)
```rust
        let pts: Vec<BackupShareV0> = (0..guardians.len())
            .map(|i| BackupShareV0 {
                sk: sig::SigningKey::gen(rng),
                share: shares[i].clone(),
            })
            .collect();

        // Form commitments to each share
        // note: this is fine because they have high entropy
        // and hence it is hiding if we assume that hash
        // can be modelled as a random oracle
        let comms: Vec<ShareComm> = (0..guardians.len())
            .map(|i| ShareComm {
                vk: pts[i].sk.verification_key(),
                hash: hash(&ShareHash { share: &shares[i] }),
            })
            .collect();
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
