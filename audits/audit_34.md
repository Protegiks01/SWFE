## Title
Competing Recovery Requests Enable Denial-of-Service on Account Recovery Process

## Summary
The recovery verification logic in `AccountUpdateV0::verify_update()` does not check whether recovery is already in progress before accepting a new recovery request. This allows an attacker with a valid Recovery Initiation Key (RIK) to observe when recovery is initiated (via publicly queryable `rec.pke` field) and launch competing recovery requests that overwrite the original recovery PKE, causing indefinite denial-of-service on the legitimate account owner's recovery attempt.

## Impact
**Medium**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The recovery system should allow an account owner to initiate recovery using any valid RIK associated with their account. Once recovery is initiated, guardians should encrypt shares for the recovery PKE, enabling the owner to complete recovery by collecting sufficient guardian shares.

**Actual Logic:** 
The `verify_update()` function accepts `AccountMessageV0::Recovery` messages and sets `rec.pke = Some(recovery.pke)` without checking if `rec.pke` is already `Some(...)`, meaning recovery is already in progress. This allows multiple recovery requests to overwrite each other's recovery PKE values.

**Exploit Scenario:**
1. An account has multiple legitimate RIKs (e.g., one per device or email address) - this is a standard feature as shown in: [2](#0-1) 

2. Legitimate owner initiates recovery using RIK_A, generating `pke_A` as their recovery encryption key

3. The account state becomes publicly queryable via `/account/get` endpoint: [3](#0-2) 

4. The `RecoveryStateV0.pke` field indicates recovery is in progress: [4](#0-3) 

5. Attacker (who compromised RIK_B) monitors the account state, detects `rec.pke.is_some()` indicating recovery started

6. Attacker immediately initiates their own recovery using RIK_B, generating `pke_B`

7. The contract accepts this second recovery request and overwrites `rec.pke = Some(pke_B)` without checking if recovery was already in progress

8. Guardians check recovery status and encrypt shares for the current PKE in state: [5](#0-4) [6](#0-5) 

9. Guardian shares are now encrypted for `pke_B` (attacker's key) instead of `pke_A` (legitimate owner's key)

10. Legitimate owner cannot complete recovery with their `RecoverySecrets` containing the decryption key for `pke_A`: [7](#0-6) 

11. Attacker can repeat steps 6-10 indefinitely, preventing any recovery attempt from completing

**Security Failure:** 
The system fails to enforce the invariant that once recovery is initiated, it should either complete successfully or explicitly fail - not be arbitrarily overwritten by competing requests. This breaks the availability guarantee for the recovery process.

## Impact Explanation

**Affected Assets/Processes:**
- Account recovery process for accounts with multiple RIKs
- Master Secret Key (MSK) recovery for affected accounts
- Any secrets or funds protected by the MSK

**Severity of Damage:**
- Legitimate account owner is permanently locked out of recovery if attacker maintains the denial-of-service
- User cannot regain access to their MSK, effectively losing control of all secrets and assets protected by that key
- This creates a ransom scenario where the attacker may demand payment to stop interfering with recovery

**System Security/Reliability:**
- Violates the fundamental availability requirement that legitimate owners can recover their accounts
- The multi-RIK feature, intended for convenience and redundancy, becomes an attack vector
- Users lose trust in the recovery system's reliability

## Likelihood Explanation

**Who Can Trigger:**
- Any party who has compromised at least one valid RIK associated with the target account
- This includes: attackers who compromised one of the user's email addresses, stolen/leaked RIKs from one device, or malicious insiders who were granted recovery access

**Required Conditions:**
- Target account must have multiple RIKs (common scenario for users with multiple devices/emails)
- Legitimate owner must initiate recovery (happens during normal account recovery operations)
- Attacker must monitor the public account state (requires no special privileges, only calling `/account/get` endpoint)

**Frequency:**
- Can occur whenever a user attempts account recovery
- Attacker can repeat the attack indefinitely with minimal cost (just signing recovery requests with their compromised RIK)
- High likelihood in practice because multi-RIK accounts are the standard use case

## Recommendation

Add a check in `verify_update()` to reject recovery requests when recovery is already in progress:

```rust
AccountMessageV0::Recovery(recovery) => {
    let mut new_state = old.clone();
    
    {
        let rec = &mut new_state.rec;
        
        // Check if recovery is already in progress
        if rec.pke.is_some() {
            return Err(SwafeError::RecoveryAlreadyInProgress);
        }
        
        // ... rest of existing verification logic
        
        // Set the recovery PKE to indicate recovery has been initiated
        rec.pke = Some(recovery.pke);
    }
    Ok(new_state)
}
```

Additionally, consider implementing a mechanism to explicitly cancel or complete recovery (setting `rec.pke` back to `None`) to allow recovery to be reattempted if the first attempt fails legitimately.

## Proof of Concept

**Test File:** `lib/src/account/tests.rs`

**Test Function:** Add new test `test_competing_recovery_requests_denial_of_service()`

**Setup:**
1. Create account with MSK and generate initial account state
2. Setup recovery with 3 guardians, threshold 2
3. Add two RIKs to the account (simulating multi-device setup): `rik_legitimate` and `rik_attacker`
4. Publish the account state to contract

**Trigger:**
1. Legitimate owner initiates recovery using `rik_legitimate`, creating `recovery_request_1` with `pke_1`
2. Verify and apply `recovery_request_1` to get `state_after_first_recovery`
3. Attacker monitors account state via `/account/get` (simulated by directly accessing state)
4. Attacker observes `rec.pke.is_some()` indicating recovery in progress
5. Attacker immediately initiates competing recovery using `rik_attacker`, creating `recovery_request_2` with `pke_2`
6. Verify and apply `recovery_request_2` to get `state_after_second_recovery`
7. Guardians respond to the recovery request in `state_after_second_recovery`, generating shares
8. Legitimate owner attempts to complete recovery using `recovery_secrets_1` (containing decryption key for `pke_1`)

**Observation:**
The test should demonstrate that:
1. Both recovery requests are accepted (no error thrown despite overwriting)
2. Guardian shares are encrypted for `pke_2` (attacker's key), not `pke_1` (legitimate owner's key)
3. Legitimate owner's `recovery_secrets_1.complete(&guardian_shares)` fails because shares are encrypted for wrong PKE
4. This proves the denial-of-service: legitimate owner cannot complete their recovery attempt

The test confirms the vulnerability by showing that competing recovery requests can overwrite each other, causing the legitimate recovery attempt to fail.

### Citations

**File:** lib/src/account/v0.rs (L100-106)
```rust
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct RecoveryStateV0 {
    pub pke: Option<pke::EncryptionKey>, // this is set iff. recovery has been started
    pub(crate) assoc: Vec<AssociationsV0>, // encryption of the recovery authorization key
    pub(crate) social: BackupCiphertext, // social backup ciphertext
    pub(crate) enc_msk: sym::AEADCiphertext, // encrypted MSK (encrypted with key derived from RIK and social shares)
}
```

**File:** lib/src/account/v0.rs (L137-163)
```rust
impl RecoverySecrets {
    /// Complete recovery of the master secret key
    ///
    /// This function takes the account state and recovery secrets,
    /// along with guardian shares, and reconstructs the MSK using the dual-recovery approach.
    ///
    /// # Arguments
    /// * `shares` - Guardian shares from the social recovery system
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
}
```

**File:** lib/src/account/v0.rs (L605-619)
```rust
    pub fn add_association<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<RecoveryInitiationKey> {
        self.dirty = true;

        // generate fresh RIK for this association
        let rik = RecoveryInitiationKey::gen(rng);

        // Add to existing associations
        self.recovery
            .assoc
            .push(AssociationSecretV0 { rik: rik.clone() });
        Ok(rik)
    }
```

**File:** lib/src/account/v0.rs (L736-755)
```rust
        // check if recovery has been initiated
        let rec_st = &requester_state_v0.rec;
        if rec_st.pke.is_none() {
            return Ok(None); // Recovery not initiated yet
        }

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

**File:** contracts/src/http/endpoints/account/get.rs (L18-36)
```rust
pub fn handler(
    _ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request: Request = deserialize_request_body(&request)?;
    let account: AccountState = state
        .get_account(request.account_id.0)
        .ok_or_else(|| ServerError::NotFound("Account not found".to_string()))?;

    create_json_response(
        200,
        &Response {
            account_state: StrEncoded(account),
        },
    )
    .map_err(|e| e.into())
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
