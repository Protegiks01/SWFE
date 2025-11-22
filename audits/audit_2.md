## Title
Mixed Guardian Shares from Sequential Recovery Attempts Leading to Permanent Account Lockout

## Summary
When a user initiates multiple account recovery attempts with different encryption keys, guardian shares encrypted to different PKE values accumulate in the same storage location without validation. This causes recovery to fail permanently when shares encrypted to outdated keys cannot be decrypted, resulting in permanent loss of account access if the user no longer has their Master Secret Key.

## Impact
**High**

## Finding Description

**Location:** 
The vulnerability spans multiple components:
- Guardian share submission without PKE validation: [1](#0-0) 
- Share decryption and silent filtering: [2](#0-1) 
- Recovery state PKE setting: [3](#0-2) 
- Social backup persistence across recovery attempts: [4](#0-3) 

**Intended Logic:** 
When a user initiates recovery, guardians should encrypt their shares to the current recovery PKE stored in `RecoveryStateV0.pke`. The system should ensure all guardian shares are encrypted to the same PKE so the user can decrypt them when completing recovery with the corresponding decryption key.

**Actual Logic:** 
The system has several flaws that allow shares encrypted to different PKEs to accumulate:

1. When initiating recovery, `rec.pke` is updated but `rec.social` (the social backup) remains unchanged [5](#0-4) 

2. Guardian shares are stored keyed by `(AccountId, BackupId)` where `BackupId` is the hash of the social backup [6](#0-5) 

3. The upload_share endpoint validates share signatures but does NOT validate that shares are encrypted to the current `rec.pke` [7](#0-6) 

4. During recovery completion, shares that fail to decrypt are silently filtered out rather than causing an error [8](#0-7) 

5. No mechanism exists to clear old guardian shares when a new recovery is initiated.

**Exploit Scenario:**

1. User initiates Recovery #1: Contract state updated to `rec.pke = Some(pke_1)`, user receives `recovery_secrets_1` with `dke_1`
2. Guardian A queries account state, sees `rec.pke = Some(pke_1)`, encrypts their share to `pke_1` [9](#0-8) 
3. Guardian A submits share to upload_share endpoint, stored in `GuardianShareCollection[(account_id, social_backup_id)][guardian_a_idx]`
4. User loses `dke_1` or makes an error, initiates Recovery #2: Contract state updated to `rec.pke = Some(pke_2)`, user receives `recovery_secrets_2` with `dke_2`
5. Guardian B queries updated state, sees `rec.pke = Some(pke_2)`, encrypts their share to `pke_2`
6. Guardian B submits share to same storage location (same `social_backup_id`)
7. User retrieves all shares via get_shares endpoint
8. User attempts to complete recovery with `dke_2` [10](#0-9) 
9. Guardian A's share (encrypted to `pke_1`) fails to decrypt with `dke_2` and is silently dropped [11](#0-10) 
10. If threshold requires both guardians (e.g., threshold=2), recovery fails with `InsufficientShares` error [12](#0-11) 
11. User permanently loses access to account if they no longer have the MSK

**Security Failure:** 
The system violates the recovery availability invariant. Once a user initiates recovery and guardians submit shares, restarting the recovery process (with a new PKE) causes those shares to become unusable, potentially leaving the user permanently locked out of their account. This breaks the fundamental guarantee that recovery can restore account access.

## Impact Explanation

**Affected Assets:**
- User's Master Secret Key (MSK) - cannot be recovered
- All secrets encrypted with the MSK
- User's entire account access
- Potentially user funds if the account controls financial assets

**Severity of Damage:**
- **Permanent account lockout**: If a user initiates multiple recovery attempts and loses their last decryption key, they permanently lose access to their account
- **Loss of funds/secrets**: All data protected by the MSK becomes permanently inaccessible
- **No recovery path**: Unlike temporary DoS issues, this is permanent and unrecoverable without intervention

**System Reliability Impact:**
This vulnerability fundamentally undermines the recovery mechanism's reliability. Users who need to restart a recovery process (a reasonable action if they make a mistake or lose a decryption key) may inadvertently lock themselves out permanently. This makes the recovery system fragile and dangerous to use in practice.

The issue qualifies as an in-scope "Permanent freezing of secrets or accounts" impact, as users can become permanently locked out without any way to recover their secrets or account access.

## Likelihood Explanation

**Who Can Trigger:**
- Any user who initiates recovery multiple times (e.g., due to losing a recovery decryption key, making an error, or changing their mind)
- Honest guardians operating normally (no malicious behavior required)

**Conditions Required:**
1. User must initiate recovery at least twice with different PKEs
2. Different guardians must query the account state at different points in time (before/after the second recovery initiation)
3. At least one guardian must submit a share encrypted to an outdated PKE
4. The recovery threshold must require shares from both the "old PKE" and "new PKE" guardians

**Frequency/Likelihood:**
- **Medium to High likelihood**: Users may need to restart recovery for legitimate reasons (lost decryption key, error in recovery process, etc.)
- **Timing window is broad**: The vulnerability triggers whenever guardians poll the state at different times during sequential recovery attempts
- **No special privileges required**: Normal user operations combined with honest guardian behavior can trigger this
- **Silent failure**: Users won't know shares are incompatible until recovery fails at the final step
- **Production impact expected**: In any system with multiple recovery attempts, this will occur

This is not a theoretical edge case but a realistic scenario that will affect users in production environments where recovery processes may need to be restarted.

## Recommendation

**Immediate Fixes:**

1. **Clear old shares on new recovery**: When processing a Recovery message that changes `rec.pke`, clear all existing guardian shares for that account's social backup from `GuardianShareCollection`:
   - In `verify_update()` after line 829, add logic to clear shares when `rec.pke` changes
   - Use the off-chain context to delete the storage entry for `(account_id, social_backup_id)`

2. **Validate PKE in upload_share**: Modify the upload_share handler to verify shares are encrypted to the current `rec.pke`:
   - After line 46 in upload_share.rs, extract the current `rec.pke` from the account state
   - Attempt to decrypt the share ciphertext using the recovery PKE
   - Reject shares that cannot be decrypted with the current recovery PKE
   - Return an error indicating the share is encrypted to an outdated PKE

3. **Include PKE identifier in GuardianShare**: Modify `GuardianShareV0` to include the PKE it was encrypted to:
   - Add a `pke: pke::EncryptionKey` field to track which recovery attempt the share belongs to
   - Validate this field matches the current `rec.pke` during upload and recovery

**Alternative Design:**
Consider versioning recovery attempts by including a recovery nonce/counter that increments with each initiation, and key guardian shares by `(AccountId, BackupId, RecoveryNonce)` to naturally separate shares from different attempts.

## Proof of Concept

**File:** `lib/src/account/tests.rs`

**Test Function:** `test_multiple_recovery_attempts_mixed_shares`

**Setup:**
1. Create an account with 3 guardians and threshold=2
2. Setup recovery using `update_recovery()` and `add_association()`
3. Get initial account state

**Trigger:**
1. Initiate Recovery #1 with `initiate_recovery()` using RIK, obtaining `recovery_secrets_1` with `dke_1` and `pke_1`
2. Process recovery update to set `rec.pke = Some(pke_1)`
3. Guardian 1 calls `check_for_recovery()` with the updated state (sees `pke_1`), generates share encrypted to `pke_1`
4. Initiate Recovery #2 with `initiate_recovery()` again (simulating user restarting recovery), obtaining `recovery_secrets_2` with `dke_2` and `pke_2`
5. Process the second recovery update to set `rec.pke = Some(pke_2)`
6. Guardian 2 calls `check_for_recovery()` with the newly updated state (sees `pke_2`), generates share encrypted to `pke_2`
7. Collect both guardian shares in a vector
8. Call `recovery_secrets_2.complete(&[guardian_share_1, guardian_share_2])`

**Observation:**
The recovery completion will fail with `SwafeError::InsufficientShares` because:
- Guardian 1's share is encrypted to `pke_1` but user has `dke_2`
- When `recover()` attempts to decrypt Guardian 1's share with `dke_2`, it fails and is filtered out (line 304 of backup/v0.rs)
- Only Guardian 2's share successfully decrypts
- With only 1 valid share but threshold=2, the check at line 322 fails
- The test demonstrates that mixed shares from sequential recovery attempts cause permanent recovery failure

The test confirms that guardian shares encrypted to different PKEs cannot coexist and will cause recovery to fail when a user attempts to complete recovery with the latest decryption key, potentially resulting in permanent account lockout.

### Citations

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

**File:** lib/src/backup/v0.rs (L160-166)
```rust
        let recovery_pke =
            match owner {
                AccountState::V0(state) => state.rec.pke.as_ref().ok_or_else(|| {
                    SwafeError::InvalidOperation("Recovery not started".to_string())
                })?,
            };
        let ct = recovery_pke.encrypt(rng, &self.share.share, &EmptyInfo);
```

**File:** lib/src/backup/v0.rs (L297-313)
```rust
        // Verify and decrypt each share
        // Ignore invalid and duplicate shares
        let shares: Vec<(u32, Share)> = shares
            .iter()
            .filter_map(|share| {
                let GuardianShare::V0(share_v0) = share;
                let id = self.verify(share_v0).ok()?;
                let share: Share = dke.decrypt(&share_v0.ct, aad).ok()?;
                if self.comms[id as usize].hash == hash(&ShareHash { share: &share }) {
                    Some((id, share))
                } else {
                    None
                }
            })
            .collect::<BTreeMap<u32, Share>>()
            .into_iter()
            .collect();
```

**File:** lib/src/backup/v0.rs (L322-324)
```rust
        if shares.len() < meta.threshold as usize {
            return Err(SwafeError::InsufficientShares);
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

**File:** lib/src/account/v0.rs (L171-226)
```rust
    pub fn initiate_recovery<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        acc: AccountId,
        rik: &RecoveryInitiationKey,
    ) -> Result<(AccountUpdate, RecoverySecrets)> {
        // decrypt AssociationsV0 using RIK
        let encap = self
            .rec
            .assoc
            .iter()
            .find_map(|assoc| {
                // attempt to decrypt the encapsulated key using RIK
                let encap = sym::open::<EncapV0, _>(rik.as_bytes(), &assoc.encap, &acc).ok()?;

                // check if the verification key matches the expected one
                if encap.key_sig.verification_key() != assoc.sig {
                    None
                } else {
                    Some(encap)
                }
            })
            .ok_or(SwafeError::InvalidRecoveryKey)?;

        // generate new keys for this recovery session
        let dkey = pke::DecryptionKey::gen(rng);

        // sign the recovery request with the signing key from RIK
        let sig = encap.key_sig.sign(
            rng,
            &RecoveryRequestMessage {
                account_id: acc,
                recovery_pke: dkey.encryption_key(),
            },
        );

        // create the recovery update
        let update = AccountUpdate::V0(AccountUpdateV0 {
            acc,
            msg: AccountMessageV0::Recovery(AccountUpdateRecoveryV0 {
                pke: dkey.encryption_key(),
                sig,
            }),
        });

        // return public update (for contract upload) and secret data (for final recovery)
        Ok((
            update,
            RecoverySecrets {
                acc,
                rec: self.rec.clone(),
                msk_ss_rik: *encap.msk_ss_rik.as_bytes(),
                dkey,
            },
        ))
    }
```

**File:** lib/src/account/v0.rs (L710-716)
```rust
            rec: RecoveryStateV0 {
                pke: None,
                assoc,
                // TODO: unfortunately we cannot generate this anew every time
                social: self.recovery.social.clone(),
                enc_msk,
            },
```

**File:** lib/src/account/v0.rs (L802-831)
```rust
            AccountMessageV0::Recovery(recovery) => {
                // Handle recovery update: set the recovery pke field in the account state
                let mut new_state = old.clone();

                {
                    let rec = &mut new_state.rec;
                    // Verify the recovery request signature
                    let recovery_msg = RecoveryRequestMessage {
                        account_id: self.acc,
                        recovery_pke: recovery.pke.clone(),
                    };

                    // Find the matching association and verify signature
                    let mut verified = false;
                    for assoc in &rec.assoc {
                        // Verify signature using the recovery signing key from associations
                        if assoc.sig.verify(&recovery.sig, &recovery_msg).is_ok() {
                            verified = true;
                            break;
                        }
                    }

                    if !verified {
                        return Err(SwafeError::InvalidSignature);
                    }

                    // Set the recovery PKE to indicate recovery has been initiated
                    rec.pke = Some(recovery.pke);
                }
                Ok(new_state)
```
