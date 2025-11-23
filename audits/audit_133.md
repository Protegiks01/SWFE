## Audit Report

## Title
Guardian Share Replay Attack Across Recovery Sessions Enables Permanent Account Recovery Denial-of-Service

## Summary
An unprivileged attacker can permanently prevent account recovery by replaying valid guardian shares from a previous recovery session into a new recovery session. Guardian shares are stored indexed only by `(account_id, backup_id)` without session-specific tracking, and the upload endpoint lacks authentication and replay protection. Since each recovery session uses a different ephemeral PKE key but shares the same `backup_id`, an attacker can overwrite freshly encrypted shares with stale shares encrypted to an obsolete key, causing decryption to fail permanently.

## Impact
**High**

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 

**Intended Logic:** 
The reconstruction endpoints should allow guardians to upload shares for a specific recovery session, enabling the account owner to later retrieve them and complete recovery. Guardian shares for each recovery session should be isolated and protected from replay attacks.

**Actual Logic:** 
The system fails to track recovery sessions when storing guardian shares. Shares are indexed only by `(account_id, backup_id)` where `backup_id = hash(rec.social)`. [4](#0-3)  The `rec.social` backup ciphertext remains unchanged across multiple recovery sessions initiated via `initiate_recovery()` and only updates when `update_recovery()` is explicitly called. [5](#0-4) 

Each recovery session generates a fresh PKE keypair (`dkey`, `recovery_pke`), [6](#0-5)  and guardians encrypt their shares to this session-specific `recovery_pke`. [7](#0-6)  However, the upload endpoint allows overwriting shares with the same `share_id` for the same `(account_id, backup_id)` without any session validation or authentication. [8](#0-7)  The code comments incorrectly claim "different multiple versions of the same share are all equivalent" - this is false when shares are encrypted to different recovery PKE keys.

**Exploit Scenario:**
1. Victim initiates recovery session 1 via `initiate_recovery()`, generating `recovery_pke_1`
2. Guardians detect the pending recovery and create shares encrypted to `recovery_pke_1`
3. Guardians upload these shares via `/reconstruction/upload-share`
4. Attacker (any unprivileged user) downloads all shares via `/reconstruction/get-shares` (no authentication required) [9](#0-8) 
5. Victim abandons session 1 (e.g., loses recovery secrets file)
6. Victim later initiates recovery session 2, generating a NEW `recovery_pke_2`
7. On-chain state updates `rec.pke = Some(recovery_pke_2)`, overwriting the previous value [10](#0-9) 
8. Guardians create NEW shares encrypted to `recovery_pke_2` and upload them (these overwrite session 1 shares in storage)
9. Attacker re-uploads the saved shares from session 1, which pass signature verification [11](#0-10)  but are encrypted to the wrong key
10. These stale shares overwrite the fresh session 2 shares in storage (same `backup_id`)
11. Victim attempts to complete recovery with `dkey_2`
12. `RecoverySecrets::complete()` tries to decrypt shares [12](#0-11) 
13. PKE decryption fails because shares are encrypted to `recovery_pke_1` but victim has `dkey_2` [13](#0-12) 
14. Recovery permanently fails; attacker can repeat this attack indefinitely

**Security Failure:** 
The system violates the replay protection invariant. Guardian share signatures remain cryptographically valid across recovery sessions, but the associated ciphertexts become unusable when replayed into a different session. This enables permanent denial-of-service on account recovery.

## Impact Explanation

This vulnerability leads to **permanent freezing of accounts**, which is explicitly listed as a High-severity in-scope impact. When an account owner loses access to their Master Secret Key (MSK) and relies on social recovery, an attacker can prevent recovery indefinitely by continuously replaying stale guardian shares.

**Assets affected:** The victim's MSK, which protects all secrets and funds associated with the account, becomes permanently inaccessible. Without the MSK and with recovery blocked, the account is effectively frozen.

**Damage severity:** This is catastrophic for users who have lost their MSK and depend on social recovery as their only recovery path. The attack can be repeated indefinitely, making recovery impossible without manual intervention or a protocol upgrade. Unlike temporary denial-of-service on HTTP endpoints (which is out-of-scope per README), this is permanent denial-of-service on the core recovery functionality itself.

**System reliability impact:** This fundamentally breaks the social recovery guarantee that the protocol promises to users. Any unprivileged attacker can permanently disable the recovery mechanism for any account by passively observing and later replaying guardian shares.

## Likelihood Explanation

**Who can trigger it:** Any unprivileged network participant. The `/reconstruction/get-shares` and `/reconstruction/upload-share` endpoints have no authentication, allowing anyone to retrieve and re-upload shares. [14](#0-13) 

**Conditions required:** 
- Victim must initiate recovery at least twice (abandoned first attempt, or multiple recovery attempts over time)
- Guardians must respond by uploading shares for both sessions
- Attacker must observe and save shares from the first session

**Frequency:** This attack is highly likely in practice because:
1. Users often abandon recovery attempts (e.g., lost recovery secrets file, interrupted process)
2. Guardian shares are publicly retrievable without authentication
3. The same `backup_id` persists across recovery sessions unless `update_recovery()` is explicitly called
4. No rate limiting or monitoring exists to detect suspicious share re-uploads

The attack becomes certain once an attacker has saved shares from any previous recovery session, as they can replay these shares indefinitely into all future recovery attempts.

## Recommendation

Implement session-specific tracking for guardian shares:

1. **Add recovery session identifier:** Include the `recovery_pke` (or a hash/nonce derived from it) in the storage key. Change from `(account_id, backup_id)` to `(account_id, backup_id, recovery_session_id)` where `recovery_session_id` is derived from the current `rec.pke` value.

2. **Bind shares to session:** Modify `GuardianShareV0` signature to include the `recovery_pke` it was encrypted for, ensuring shares cannot be validated in the wrong session: [15](#0-14) 

3. **Verify session on upload:** In the upload handler, verify that submitted shares match the current on-chain `rec.pke` value before accepting them: [16](#0-15) 

4. **Clean up stale sessions:** When a new recovery session starts (when `rec.pke` changes), automatically invalidate all shares from previous sessions.

5. **Add authentication (optional):** Consider restricting upload access to verified guardians or requiring proof of authorization.

## Proof of Concept

**File:** `lib/src/account/tests.rs`

**Test function:** `test_guardian_share_replay_across_sessions`

**Setup:**
1. Create an account with 3 guardians (threshold 2)
2. Setup recovery and add RIK association
3. Initiate recovery session 1, get guardians to provide shares
4. Save these shares before completing recovery

**Trigger:**
1. Abandon session 1 (don't complete recovery)
2. Initiate recovery session 2 with a NEW recovery PKE
3. Guardians provide NEW shares encrypted to the new recovery PKE
4. Simulate attacker re-uploading OLD shares from session 1 (would happen via upload endpoint)
5. Attempt to complete recovery with `dkey_2` and the OLD shares

**Observation:**
The test demonstrates that:
- OLD shares pass signature verification (signatures are still valid)
- PKE decryption with `dkey_2` fails because shares are encrypted to `recovery_pke_1`, not `recovery_pke_2`
- Recovery permanently fails even though guardians provided valid responses
- The error occurs during the `decrypt` phase in `BackupCiphertextV0::recover`, not during signature verification

This confirms that replayed guardian shares cause permanent denial-of-service on account recovery, as the shares are cryptographically bound to a different session's encryption key.

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

**File:** lib/src/account/v0.rs (L802-832)
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
            }
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

**File:** lib/src/backup/v0.rs (L84-86)
```rust
    pub fn id(&self) -> BackupId {
        BackupId(hash(self))
    }
```

**File:** lib/src/backup/v0.rs (L155-179)
```rust
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

**File:** lib/src/crypto/pke/v0.rs (L68-92)
```rust
    pub fn decrypt<M: Tagged + DeserializeOwned, A: Tagged>(
        &self,
        ct: &Ciphertext,
        ctx: &A,
    ) -> Result<M, SwafeError> {
        // compute shared secret
        let mut ikm = vec![];
        (ct.tp * self.sk)
            .into_affine()
            .serialize_compressed(&mut ikm)
            .unwrap();

        // decrypt with symmetric encryption
        sym::open(
            &kdfn(
                &ikm,
                &DiffieHellmanCtx {
                    tp: ct.tp,
                    pk: self.encryption_key().0,
                },
            ),
            &ct.ct,
            ctx,
        )
    }
```
