## Title
Guardian Share Replay Attack Enables Denial of Service on Account Recovery

## Summary
The `DecryptedShareV0::send_for_recovery()` method lacks replay protection mechanisms, allowing attackers to capture guardian shares from previous recovery attempts and replay them during subsequent recovery attempts. This can prevent legitimate users from completing account recovery by overwriting valid shares with invalid ones, causing a denial of service on the recovery process.

## Impact
**Medium**

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 

**Intended Logic:** 
Guardian shares should be uniquely bound to a specific recovery attempt. Each time a user initiates recovery, guardians should generate fresh shares encrypted for that specific recovery session's public key, and old shares from previous recovery attempts should not interfere with new attempts.

**Actual Logic:** 
The `send_for_recovery()` method generates guardian shares without any replay protection:
- The signature only covers the ciphertext and index [3](#0-2) 
- No nonce, timestamp, or recovery session identifier is included
- Guardian shares are stored in the contract under `(AccountId, BackupId)` key [4](#0-3) 
- The contract allows unrestricted overwriting of shares at the same index
- When a new recovery is initiated, the old guardian shares are never cleared [5](#0-4) 

**Exploit Scenario:**

1. **Initial Recovery (Recovery #1):**
   - User initiates recovery with recovery public key PKE1 [6](#0-5) 
   - Guardians submit shares encrypted for PKE1
   - Attacker captures all guardian shares from this attempt
   - User completes or abandons recovery

2. **Subsequent Recovery (Recovery #2):**
   - User initiates new recovery with different recovery public key PKE2
   - Contract updates state with new PKE2 but doesn't clear old shares [7](#0-6) 
   - Some guardians submit new shares encrypted for PKE2

3. **Attack:**
   - Attacker replays old shares from Recovery #1 (encrypted for PKE1)
   - Contract verifies signatures which remain valid [8](#0-7) 
   - Old shares overwrite new valid shares in storage
   - User retrieves shares but they're encrypted for wrong key (PKE1 instead of PKE2)
   - Decryption fails during recovery completion [9](#0-8) 
   - Recovery fails with insufficient valid shares

**Security Failure:** 
This breaks the recovery availability guarantee. An attacker can prevent users from recovering their accounts by continuously replaying old shares, causing a persistent denial of service on the recovery mechanism.

## Impact Explanation

**Affected Assets:** User accounts requiring recovery are rendered inaccessible. Master secret keys cannot be recovered, effectively freezing the user's account and any associated secrets or funds.

**Severity of Damage:** 
- Users who need to recover their accounts (e.g., after device loss) become permanently locked out
- The attack can target specific users by monitoring their recovery attempts
- No special privileges required - any network observer can capture and replay shares
- The attack is repeatable for each recovery attempt, making the account permanently unrecoverable

**System Impact:** 
This violates the core security guarantee that legitimate users can recover their accounts through the guardian-based recovery mechanism. It creates a practical denial of service where the recovery feature becomes unusable when under attack.

## Likelihood Explanation

**Who Can Trigger:**
Any unprivileged network participant who can observe HTTP traffic to the contract's `/reconstruction/upload-share` endpoint can capture guardian shares and replay them [10](#0-9) 

**Conditions Required:**
- User must have attempted recovery at least once previously (to provide shares for capture)
- User attempts recovery again
- Attacker observes and captures the original guardian shares

**Frequency:**
The attack can be executed every time a user attempts recovery. Since recovery attempts are observable on-chain (through account state updates), an attacker can systematically target users and replay old shares immediately after new recovery attempts are initiated.

## Recommendation

Implement replay protection by binding guardian shares to specific recovery sessions:

1. **Include Recovery PKE in Signature:** Modify `SignedEncryptedShare` to include the recovery public key that the share is encrypted for. Update the signature generation to cover this field [11](#0-10) 

2. **Clear Old Shares on New Recovery:** When a recovery update is processed, clear all guardian shares for that `(AccountId, BackupId)` from `GuardianShareCollection` before storing the new recovery state [7](#0-6) 

3. **Validate Share Freshness:** Add validation in the contract's `upload_share` handler to verify that the encrypted share can be decrypted with the current recovery PKE before accepting it

4. **Add Recovery Session Nonce:** Include a monotonic counter in the account's recovery state that increments with each recovery initiation, and require guardian shares to include this nonce in their signatures.

## Proof of Concept

**File:** `lib/src/account/tests.rs` (add new test function)

**Test Function:** `test_guardian_share_replay_attack`

**Setup:**
1. Initialize account with 3 guardians (G0, G1, G2) and threshold 2
2. Create a backup with social recovery
3. User initiates Recovery #1, generating PKE1/DKE1
4. All guardians generate and submit shares encrypted for PKE1
5. User successfully completes Recovery #1 using shares
6. User performs account update, resetting `rec.pke` to None [12](#0-11) 

**Trigger:**
1. User initiates Recovery #2, generating new PKE2/DKE2 (different from PKE1)
2. Guardians G0 and G1 generate and submit NEW shares encrypted for PKE2
3. Attacker replays ALL old shares from Recovery #1 (encrypted for PKE1), overwriting G0 and G1's new shares
4. User attempts to retrieve shares and complete recovery using DKE2

**Observation:**
- Retrieved shares are encrypted for PKE1, not PKE2
- Decryption with DKE2 fails for all shares (returns None in filter_map) [13](#0-12) 
- Recovery completion returns `SwafeError::InsufficientShares` despite having threshold number of guardians willing to help
- The test confirms that replayed old shares can deny service to legitimate recovery attempts

### Citations

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

**File:** contracts/src/lib.rs (L107-134)
```rust
#[action]
fn update_account(
    _ctx: ContractContext,
    mut state: ContractState,
    update_str: String,
) -> ContractState {
    // deserialize the account update from a string,
    let update: AccountUpdate =
        encode::deserialize_str(update_str.as_str()).expect("Failed to decode account update");

    // retrieve the *claimed* account ID
    let account_id = update.unsafe_account_id();

    // retrieve the old account state
    let st_old: Option<AccountState> = state
        .accounts
        .get(account_id.as_ref())
        .map(|bytes| encode::deserialize(&bytes).expect("failed to deserialize account state"));

    // verify the update using the lib
    let st_new = update
        .verify(st_old.as_ref())
        .expect("Failed to verify account update");

    // store the updated account state
    state.set_account(account_id, st_new);
    state
}
```

**File:** api/src/reconstruction/upload_share.rs (L6-6)
```rust
pub const PATH: &str = "/reconstruction/upload-share";
```
