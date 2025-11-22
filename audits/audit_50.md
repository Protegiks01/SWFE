## Title
Account Recovery Failure Due to Mid-Recovery State Updates Causing Guardian Share Verification Mismatch

## Summary
A critical race condition exists in the account recovery flow where the account owner can update recovery parameters (via `update_recovery()` and `update()`) after a recovery has been initiated but before it completes. This causes guardian shares signed with new keys to fail verification against the old recovery state snapshot, permanently blocking legitimate recovery attempts.

## Impact
**High**

## Finding Description

**Location:** 
- Primary issue in `lib/src/account/v0.rs` in the `verify_update()` function (lines 786-834)
- Guardian share generation in `lib/src/account/v0.rs` `check_for_recovery()` (lines 726-756)  
- Recovery completion in `lib/src/account/v0.rs` `RecoverySecrets::complete()` (lines 145-162)
- Guardian share verification in `lib/src/backup/v0.rs` `verify()` and `recover()` (lines 290-354) [1](#0-0) 

**Intended Logic:**
The recovery system should allow users to initiate recovery, collect guardian shares, and complete recovery to regain access to their Master Secret Key. Once recovery is initiated (indicated by `rec.pke` being set), the recovery state should remain stable until completion.

**Actual Logic:**
The `verify_update()` function allows regular account updates (`AccountMessageV0::Update`) even when recovery is active (`rec.pke.is_some()`). When processing regular updates (lines 789-800), there is NO check to prevent updates during active recovery. This allows the account owner to call `update_recovery()` which regenerates `msk_ss_social`, creates a new social backup with new random guardian signing keys, and re-encrypts `enc_msk` with new shares. [2](#0-1) 

**Exploit Scenario:**

1. **User initiates recovery (Version N):**
   - User reads on-chain `AccountStateV0` at version N
   - Calls `initiate_recovery()` which creates `RecoverySecrets` containing:
     - `rec.social`: Social backup from version N with signing key verification keys in `comms`
     - `rec.enc_msk`: MSK encrypted with key derived from version N shares
   - Uploads recovery request to chain (sets `rec.pke`) [3](#0-2) 

2. **Account owner updates recovery parameters (Version N+1):**
   - Owner calls `update_recovery()` which generates NEW `msk_ss_social`
   - This creates NEW social backup with NEW random signing keys for guardians (line 385 in `backup/v0.rs`)
   - Calls `update()` which creates NEW `enc_msk` encrypted with NEW shares
   - Submits update to chain (version increments to N+1) [4](#0-3) 

3. **Guardians provide shares from new state:**
   - Guardians call `check_for_recovery()` with current on-chain state (version N+1)
   - Line 745: They decrypt shares from `rec_st.social` (the NEW backup from version N+1)
   - They sign shares with NEW signing keys from NEW backup
   - Return guardian shares to user [5](#0-4) 

4. **Recovery completion fails:**
   - User calls `complete()` with their `RecoverySecrets` from version N
   - Calls `recover()` on OLD social backup with guardian shares from NEW backup
   - Line 303: `verify()` checks signatures against OLD verification keys in `self.comms`
   - Guardian shares were signed with NEW keys, verification FAILS
   - Line 305: Even if signature somehow passed, hash check would fail [6](#0-5) [7](#0-6) 

**Security Failure:**
The system fails to maintain consistency between the recovery state snapshot captured at initiation and the on-chain state that guardians reference. This breaks the recovery invariant that once initiated, recovery should proceed to completion with consistent parameters.

## Impact Explanation

**Affected Assets:** Master Secret Keys, account access, and any secrets protected by the account.

**Severity:** Users attempting legitimate recovery can be permanently locked out of their accounts because:

1. Guardian shares from the new state cannot verify against the old recovery snapshot
2. The recovery cannot be re-initiated without access to the account signing key
3. If this occurs during a genuine recovery scenario (user lost access), they have no alternative path to regain access
4. The MSK remains permanently inaccessible, freezing all account secrets

**System Impact:** This directly leads to **permanent freezing of secrets or accounts** which is listed as a valid high-severity impact in the contest rules. Users who are genuinely attempting recovery (because they lost access to their account) will be unable to complete the process and will permanently lose access to their Master Secret Key and all associated secrets.

## Likelihood Explanation

**Who can trigger:** This can occur through normal protocol operations:
- Any account owner can update their recovery parameters at any time
- Recovery can be initiated by anyone with a valid Recovery Initiation Key (RIK)

**Conditions required:** 
- User initiates recovery (legitimate use case)
- Account owner updates recovery parameters before recovery completes (can happen accidentally or as part of normal account maintenance)
- Guardians provide shares (legitimate guardian behavior)

**Frequency:** This can occur whenever there's a timing overlap between:
- An ongoing recovery process (which may take hours/days to collect guardian shares)
- Account maintenance operations by the owner

The likelihood is **HIGH** because:
1. Recovery processes naturally take time (collecting shares from multiple guardians)
2. Account owners may not be aware that recovery is in progress
3. The system provides no warning or prevention mechanism
4. No explicit state synchronization is enforced

## Recommendation

Add a check in `verify_update()` to prevent regular account updates when recovery is active:

```rust
AccountMessageV0::Update(auth) => {
    let st = auth.state;
    
    // NEW CHECK: Prevent updates during active recovery
    if old.rec.pke.is_some() {
        return Err(SwafeError::InvalidOperation(
            "Cannot update account while recovery is in progress".to_string()
        ));
    }
    
    // version must increase by exactly one
    if Some(st.cnt) != old.cnt.checked_add(1) {
        return Err(SwafeError::InvalidAccountStateVersion);
    }
    
    // ... rest of verification
}
```

Alternatively, implement version tracking in `RecoverySecrets` and have guardians verify they're providing shares for the correct version of the recovery state.

## Proof of Concept

**File:** `lib/src/account/tests.rs`

**Test Function:** `test_recovery_fails_after_concurrent_update`

**Setup:**
1. Create account with 3 guardians and threshold of 2
2. Set up recovery with `update_recovery()`
3. Upload account state to simulate on-chain storage
4. Initiate recovery with RIK, obtaining `RecoverySecrets`
5. Upload recovery request to chain (sets `rec.pke`)

**Trigger:**
6. Account owner calls `update_recovery()` again to generate NEW recovery parameters
7. Account owner calls `update()` and uploads version N+1 to chain
8. Guardians call `check_for_recovery()` against version N+1 state
9. Guardians provide guardian shares signed with NEW keys

**Observation:**
10. User attempts `RecoverySecrets::complete()` with guardian shares
11. The `recover()` call fails at the `verify()` step because:
    - Guardian shares are signed with NEW signing keys (from version N+1)
    - RecoverySecrets contains OLD social backup (from version N)
    - Verification keys in OLD backup's commitments don't match NEW signatures
12. Test should observe that `complete()` returns an error (likely `SwafeError::InvalidSignature` or `SwafeError::InvalidShare`)
13. This demonstrates that a legitimate recovery attempt permanently fails due to the concurrent update

**Expected Result:** The test should show that recovery completion fails even though the user followed all correct procedures and guardians provided valid shares, confirming the vulnerability causes permanent account lockout.

## Notes

This vulnerability exists because the system assumes a single atomic recovery flow but allows state modifications during the multi-step recovery process. The lack of synchronization between the user's recovery snapshot (`RecoverySecrets`) and the on-chain state that guardians reference creates an exploitable inconsistency. While guardians and the account owner are trusted parties, this is not malicious behavior—it's a timing issue in normal operations that breaks a critical security invariant.

### Citations

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

**File:** lib/src/account/v0.rs (L532-554)
```rust
    pub fn update_recovery<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        guardians: &[AccountState],
        threshold: usize,
    ) -> Result<()> {
        // mark dirty
        self.dirty = true;

        // generate fresh "social secret"
        self.recovery.msk_ss_social = MskSecretShareSocial::gen(rng);

        // generate new ciphertext
        self.recovery.social = create_recovery(
            rng,
            self.acc,
            &self.recovery.msk_ss_rik,
            &self.recovery.msk_ss_social,
            guardians,
            threshold,
        )?;
        Ok(())
    }
```

**File:** lib/src/account/v0.rs (L742-754)
```rust
        // decrypt our share
        let guardian_secrets = self.clone();
        let secret_share = guardian_secrets
            .decrypt_share_recovery(acc, &rec_st.social)
            .ok_or_else(|| {
                SwafeError::InvalidOperation(
                    "Guardian not authorized for this recovery or failed to decrypt share"
                        .to_string(),
                )
            })?;

        // reencrypt the share for the requester's recovery PKE key
        Ok(Some(secret_share.send_for_recovery(rng, state)?))
```

**File:** lib/src/account/v0.rs (L786-834)
```rust
    /// Verify an update to the account returns the new state of the account
    pub(super) fn verify_update(self, old: &AccountStateV0) -> Result<AccountStateV0> {
        match self.msg {
            AccountMessageV0::Update(auth) => {
                let st = auth.state;
                // version must increase by exactly one
                if Some(st.cnt) != old.cnt.checked_add(1) {
                    return Err(SwafeError::InvalidAccountStateVersion);
                }

                // verify signature using old verification key
                old.sig.verify(&auth.sig, &st)?;

                // Return the new state as provided in the update
                Ok(st)
            }
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
            }
        }
    }
```

**File:** lib/src/backup/v0.rs (L290-340)
```rust
    pub fn recover<M: Tagged + DeserializeOwned, A: Tagged>(
        &self,
        dke: &pke::DecryptionKey,
        sym: &sym::Key,
        aad: &A,
        shares: &[GuardianShare],
    ) -> Result<M, SwafeError> {
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

        // derive the metadata key
        let key_meta: sym::Key = kdfn(sym, &KDFMetakey { comms: &self.comms });

        // decrypt the metadata
        let meta: BackupMetadata = sym::open(&key_meta, &self.data, &sym::EmptyAD)?;

        // check that we have enough shares to meet the threshold
        if shares.len() < meta.threshold as usize {
            return Err(SwafeError::InsufficientShares);
        }

        // recover the secret using Shamir's Secret Sharing
        let secret: sss::Secret = sss::recover(
            &shares
                .into_iter()
                .take(meta.threshold as usize)
                .map(|(idx, share)| (idx as usize, share))
                .collect::<Vec<_>>()[..],
        );

        // derive the data encryption key
        let key_data: sym::Key = kdfn(&BackupKDFInput { key: sym, secret }, &EmptyInfo);

        // decrypt the data
        sym::open(&key_data, &meta.data, &sym::EmptyAD)
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

**File:** lib/src/backup/v0.rs (L383-388)
```rust
        let pts: Vec<BackupShareV0> = (0..guardians.len())
            .map(|i| BackupShareV0 {
                sk: sig::SigningKey::gen(rng),
                share: shares[i].clone(),
            })
            .collect();
```
