# Audit Report

## Title
Guardian Share Replay Attack Enables Denial of Service on Account Recovery

## Summary
The Swafe protocol lacks a mechanism to bind GuardianShares to specific recovery sessions. GuardianShares from a previous recovery session can be replayed into a new recovery session's storage, causing decryption failures and preventing legitimate account recovery. This occurs in the guardian share storage system where shares are indexed only by `(AccountId, BackupId)` without any session identifier.

## Impact
**Medium**

## Finding Description

**Location:** 
- Primary: `contracts/src/http/endpoints/reconstruction/upload_share.rs` (lines 23-31, 52-67)
- Secondary: `lib/src/backup/v0.rs` (lines 44-48, 290-340)
- Secondary: `contracts/src/http/endpoints/reconstruction/get_shares.rs` (lines 19-34)

**Intended Logic:** 
When a user initiates a recovery session, guardians should provide fresh GuardianShares encrypted for that specific session's recovery PKE key. Each recovery session should be isolated, and shares from previous sessions should not interfere with the current session.

**Actual Logic:** 
GuardianShares are stored in a `BTreeMap<u32, GuardianShare>` keyed only by `(AccountId, BackupId)` [1](#0-0) , with no recovery session identifier. The code explicitly states "no replay protection is required" [2](#0-1) , allowing shares to be overwritten without session validation.

When a GuardianShare is created, it is signed over only `SignedEncryptedShare { idx, ct }` [3](#0-2) , which does not include the recovery session's PKE key or any session identifier. The signature verification in `BackupCiphertextV0::verify()` only checks that the share was signed by a legitimate guardian [4](#0-3) , but does not validate that the share is encrypted for the current recovery session.

**Exploit Scenario:**
1. Alice initiates Recovery Session 1, generating `recovery_pke_1` and `dkey_1` [5](#0-4) 
2. Guardians respond by creating shares encrypted with `recovery_pke_1` using `send_for_recovery()` [6](#0-5) 
3. Guardian shares are uploaded to contract storage at key `(account_id, backup_id)` [7](#0-6) 
4. Alice successfully completes Recovery Session 1
5. Later, Alice initiates Recovery Session 2 with new `recovery_pke_2` and `dkey_2`
6. An attacker or buggy client uploads the OLD shares from Session 1 (still encrypted with `recovery_pke_1`)
7. The old shares pass signature verification because they are validly signed by guardians
8. Alice retrieves all shares from storage [8](#0-7) 
9. Alice attempts to decrypt shares with `dkey_2`, but shares encrypted with `recovery_pke_1` fail decryption [9](#0-8) 
10. Recovery fails with `InsufficientShares` error [10](#0-9) 

**Security Failure:** 
This breaks the availability guarantee for account recovery. The same BackupCiphertext (identified by BackupId) is reused across multiple recovery sessions, but the recovery PKE key changes each time. Without session binding, old shares remain valid for storage upload but are incompatible with the new session's decryption key, causing denial of service.

## Impact Explanation

**Affected Assets:** Account recovery operations are blocked, preventing users from regaining access to their Master Secret Keys (MSKs) and associated cryptographic secrets.

**Severity of Damage:** Users cannot complete legitimate recovery sessions when old shares are replayed. This is particularly severe if:
- The user has lost their MSK and recovery is their only way to regain access
- Time-sensitive recovery is needed (e.g., to access funds or critical data)
- The attack is repeated across multiple recovery attempts, causing persistent denial of service

**System Reliability Impact:** This vulnerability undermines the core value proposition of the social recovery system. Users who trust the guardian-based recovery mechanism may find themselves permanently locked out of their accounts if an attacker continuously replays old shares, or if buggy clients accidentally upload stale shares.

This falls under the in-scope impact: **"Temporary freezing of transactions or recovery operations"** as recovery sessions are blocked when old shares are replayed.

## Likelihood Explanation

**Who Can Trigger:** Any participant who has access to GuardianShares from a previous recovery session can trigger this vulnerability. This includes:
- The account owner themselves (if they accidentally replay old shares due to client bugs)
- Any party who monitored or stored previous recovery session data
- Guardians who might resubmit old shares due to client errors

**Required Conditions:**
- The account must have completed at least one recovery session previously
- A new recovery session must be initiated with a different recovery PKE key
- Old shares from the previous session must be uploaded to the contract before or after new shares

**Frequency:** This can occur in normal operation whenever:
- A user initiates multiple recovery sessions over the lifetime of their account
- Client implementations have bugs that cause share caching or incorrect resubmission
- Network issues cause guardians to retry share uploads with stale data

The likelihood is **MEDIUM to HIGH** because:
1. Multiple recovery sessions per account are a normal use case
2. No explicit session management or expiration is implemented
3. The storage structure actively enables this by allowing overwrites without session validation
4. The comment in the code explicitly states no replay protection is needed, suggesting this was not considered during design

## Recommendation

Implement recovery session binding for GuardianShares:

1. **Add Session Identifier:** Include the recovery PKE key (or a hash of it) as part of the storage key for GuardianShares, changing from `(AccountId, BackupId)` to `(AccountId, BackupId, RecoveryPkeHash)`.

2. **Session Validation:** In `upload_share.rs`, validate that uploaded shares are encrypted for the current active recovery session by:
   - Checking that `account_state.rec.pke` is set (recovery is active)
   - Computing a session identifier from the current `recovery_pke`
   - Storing shares under the session-specific key

3. **Share Expiration:** When a new recovery is initiated, clear or expire shares from previous sessions for the same BackupId.

4. **Signature Binding:** Modify `SignedEncryptedShare` to include the recovery PKE key in the signed data, ensuring shares are cryptographically bound to their intended recovery session:
```rust
struct SignedEncryptedShare<'a> {
    idx: u32,
    ct: &'a pke::Ciphertext,
    recovery_pke: &'a pke::EncryptionKey, // Add this field
}
```

5. **Update Verification:** Modify `BackupCiphertextV0::verify()` to check that the recovery PKE key in the signature matches the current session's PKE key.

## Proof of Concept

**Test File:** `lib/src/account/tests.rs`

**Test Function Name:** `test_guardian_share_replay_across_recovery_sessions`

**Setup:**
1. Create an account with MSK and set up 3 guardians with threshold=2
2. Call `update_recovery()` to configure social recovery
3. Call `add_association()` to generate a RIK for recovery initiation

**Trigger:**
1. Initiate Recovery Session 1 using `initiate_recovery()` which generates `recovery_pke_1` and `dkey_1`
2. Update account state with the recovery request
3. Have guardians call `check_for_recovery()` to generate `share1_session1` and `share2_session1` encrypted with `recovery_pke_1`
4. Call `recovery_secrets.complete(&shares)` successfully to complete Session 1
5. Initiate Recovery Session 2 using `initiate_recovery()` again, generating NEW `recovery_pke_2` and `dkey_2`
6. Update account state with the new recovery request
7. **Attack:** Instead of getting fresh guardian shares, reuse `share1_session1` and `share2_session1` from Session 1
8. Call `recovery_secrets.complete(&old_shares)` with shares from Session 1

**Observation:**
The test should observe that:
- Step 4 succeeds (Session 1 completes successfully)
- Step 8 FAILS with `SwafeError::InsufficientShares` because the shares from Session 1 are encrypted with `recovery_pke_1` and cannot be decrypted with `dkey_2` from Session 2
- The decryption failure occurs in `BackupCiphertextV0::recover()` at the `dke.decrypt()` call, causing those shares to be filtered out
- With insufficient valid shares, the threshold is not met, demonstrating successful denial of service

This test confirms that old GuardianShares from a previous recovery session can interfere with a new recovery session, preventing legitimate account recovery.

### Citations

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

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L57-63)
```rust
    // Update the share mapping for this backup
    // usually, the share will not already exist in this map:
    // we allow overwriting in case of a buggy client library and to
    // simplify a client which fails during the upload process: it can simply retry all uploads.
    //
    // Potentially different multiple versions of the same share are all equivalent.
    // Hence no replay protection is required here.
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L64-67)
```rust
    let storage_key = (account_id, backup_id);
    let mut shares = GuardianShareCollection::load(&mut ctx, storage_key).unwrap_or_default();
    shares.insert(share_id, request.share.0);
    GuardianShareCollection::store(&mut ctx, storage_key, shares);
```

**File:** lib/src/backup/v0.rs (L50-58)
```rust
#[derive(Serialize)]
struct SignedEncryptedShare<'a> {
    idx: u32,
    ct: &'a pke::Ciphertext,
}

impl Tagged for SignedEncryptedShare<'_> {
    const SEPARATOR: &'static str = "v0:signed-encrypted-share";
}
```

**File:** lib/src/backup/v0.rs (L154-179)
```rust
    /// Send the share encrypted for a specific recovery PKE key
    pub fn send_for_recovery<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        owner: &AccountState,
    ) -> Result<GuardianShare, SwafeError> {
        let recovery_pke =
            match owner {
                AccountState::V0(state) => state.rec.pke.as_ref().ok_or_else(|| {
                    SwafeError::InvalidOperation("Recovery not started".to_string())
                })?,
            };
        let ct = recovery_pke.encrypt(rng, &self.share.share, &EmptyInfo);
        let sig = self.share.sk.sign(
            rng,
            &SignedEncryptedShare {
                ct: &ct,
                idx: self.idx,
            },
        );
        Ok(GuardianShare::V0(GuardianShareV0 {
            ct,
            idx: self.idx,
            sig,
        }))
    }
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

**File:** lib/src/backup/v0.rs (L321-324)
```rust
        // check that we have enough shares to meet the threshold
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
