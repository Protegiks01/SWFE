## Title
Race Condition in Association Revocation Enables Front-Running Attack for Unauthorized Account Recovery

## Summary
A race condition exists between association revocation and recovery initiation that allows an attacker with a revoked Recovery Initiation Key (RIK) to front-run the revocation transaction and complete unauthorized account recovery. The vulnerability occurs because recovery initiation does not increment the account version counter and verifies against the current on-chain state without checking for pending revocation updates, creating an exploitable timing window.

## Impact
**High**

## Finding Description

**Location:** 
- Primary vulnerability in `lib/src/account/v0.rs`, `AccountUpdateV0::verify_update()` method (lines 802-832)
- Related code in `AccountSecretsV0::revoke_association()` (lines 621-632) and `AccountSecretsV0::update()` (lines 634-724)
- Contract processing in `contracts/src/lib.rs`, `update_account` action (lines 107-134) [1](#0-0) 

**Intended Logic:** 
When an account owner revokes an association using `revoke_association()`, the revoked RIK should immediately become invalid and unable to initiate recovery. The revocation update should atomically prevent any recovery initiation using that RIK.

**Actual Logic:**
Recovery initiation and association revocation operate on different transaction types with non-atomic state verification:

1. **Recovery messages** (line 802-832): Clone the old state without incrementing the version counter, verify signatures against associations in the old state, and set `rec.pke` to indicate recovery has begun [2](#0-1) 

2. **Regular update messages** (line 789-800): Increment the version counter by 1, requiring strict version sequencing [3](#0-2) 

3. The contract processes these independently with no cross-transaction atomicity checks [4](#0-3) 

**Exploit Scenario:**

1. Account is at version N with associations [X, Y, Z]
2. Owner decides to revoke association X:
   - Calls `revoke_association(&X)` locally
   - Generates update transaction (version N → N+1) with associations [Y, Z]
   - Submits revocation transaction to blockchain

3. Attacker (who possesses RIK X) monitors the blockchain mempool or state
4. Attacker detects the pending revocation transaction
5. Attacker generates recovery initiation using X from the current on-chain state (version N)
   - Calls `initiate_recovery(X)` which returns `(recovery_update, recovery_secrets)` [5](#0-4) 
   
6. Attacker front-runs by submitting recovery transaction before revocation confirms

7. **Blockchain processes recovery first:**
   - Reads version N state with associations [X, Y, Z]
   - Verifies X's signature against current associations ✓
   - Sets `rec.pke = Some(recovery_pke)` in version N
   - Stores modified version N state

8. **Guardians respond during timing window:**
   - Query state and see `rec.pke` is set [6](#0-5) 
   - Generate and provide guardian shares encrypted to recovery PKE

9. **Revocation processes second:**
   - Updates state from version N to N+1
   - Removes association X from list
   - Clears `rec.pke = None` in the update [7](#0-6) 

10. **Attack completes offline:**
    - Attacker has `RecoverySecrets` from step 5
    - Attacker collected guardian shares in step 8
    - Attacker calls `recovery_secrets.complete(shares)` to recover MSK [8](#0-7) 

**Security Failure:** 
The invariant that "only authorized associations can initiate recovery" is violated. The owner's explicit revocation of an association is rendered ineffective due to non-atomic transaction processing, allowing unauthorized account recovery and master secret key compromise.

## Impact Explanation

**Assets Affected:**
- Master Secret Key (MSK) of the compromised account
- All secrets encrypted under the account's control
- Account ownership and control

**Severity of Damage:**
- Complete compromise of account security
- Attacker gains full access to the master secret key
- Permanent loss of account control for the legitimate owner
- All backups and secrets become accessible to the attacker

**Why This Matters:**
This vulnerability fundamentally breaks the security guarantee of association revocation. Users rely on the ability to immediately revoke compromised RIKs (e.g., when suspecting an email account compromise or losing access to a recovery method). The race condition means that revocation cannot provide timely protection against an adversary who monitors blockchain state and can act within the timing window between transaction submission and confirmation.

## Likelihood Explanation

**Who Can Trigger:**
Any attacker who possesses a valid RIK for an account, including:
- Former trusted parties whose access is being revoked
- Attackers who compromised an email account associated with a RIK
- Malicious insiders who obtained a RIK before being detected

**Conditions Required:**
- Attacker must possess a valid RIK before revocation is confirmed on-chain
- Attacker must monitor blockchain mempool or state for revocation transactions
- Attacker must submit recovery initiation transaction before revocation confirms
- Timing window depends on block time (typically seconds to minutes on Partisia)

**Frequency:**
- Can be triggered whenever an account owner attempts to revoke an association
- Front-running is a well-known blockchain attack technique
- The timing window exists in every revocation attempt
- Guardian response automation makes the attack window exploitable

**Realistic Exploitation:**
This is highly realistic because:
1. Mempool monitoring is standard practice in blockchain security
2. Front-running tools are readily available
3. The attack window (one block time) is sufficient for guardian share collection
4. The attack requires only one malicious actor with a RIK, not collusion
5. Automated guardian systems would respond during the window

## Recommendation

Implement one or more of the following mitigations:

1. **Add version increment to recovery initiation:** Modify recovery messages to increment the account version counter, forcing strict ordering with revocation updates. This makes recovery and revocation transactions conflict, ensuring only one can succeed.

2. **Check for pending recovery before allowing revocation:** In `verify_update()` for Update messages, reject revocation updates if `rec.pke` is already set, forcing the owner to wait for recovery to complete or timeout before revoking.

3. **Add revocation nonce/timestamp:** Include a revocation timestamp or nonce in associations, and verify during recovery initiation that the RIK hasn't been marked for revocation within a grace period.

4. **Implement recovery timeout:** Add a mandatory waiting period after recovery initiation before guardians can provide shares, giving the owner time to submit a canceling update if they detect unauthorized recovery.

**Recommended Fix (Option 1 - Version Increment):**
Modify the Recovery message verification to increment the version counter:

```rust
// In verify_update(), Recovery case:
let mut new_state = old.clone();
new_state.cnt = old.cnt.checked_add(1).ok_or(SwafeError::InvalidAccountStateVersion)?;
// ... rest of verification
```

This ensures recovery initiation and revocation updates cannot both succeed on the same base version, eliminating the race condition.

## Proof of Concept

**File:** `lib/src/account/tests.rs`

**Test Function:** Add new test `test_revocation_race_condition_vulnerability()`

**Setup:**
1. Create an account with guardians and recovery configured
2. Add association X to the account
3. Publish the account state (version N) with association X

**Trigger:**
1. Owner generates revocation update (version N → N+1) removing X
2. Attacker generates recovery initiation using X based on version N
3. Simulate blockchain processing recovery transaction first:
   - Call `recovery_update.verify(Some(&account_state))` - succeeds, sets rec.pke
   - Store this as `intermediate_state` (version N with rec.pke set)
4. Guardians see intermediate_state with rec.pke set
5. Guardians generate and return shares based on intermediate_state
6. Simulate blockchain processing revocation second:
   - Call `revocation_update.verify(Some(&intermediate_state))` - succeeds, produces version N+1
   
**Observation:**
The test demonstrates that:
- Both transactions succeed in sequence (no atomic conflict)
- Recovery was initiated with association X
- Guardians provided shares during the window
- Attacker can call `recovery_secrets.complete(shares)` to recover MSK
- Revocation cleared rec.pke but cannot undo the already-collected shares
- The attack succeeds despite the owner's revocation intent

The test confirms the vulnerability: association X was used to initiate recovery even though the owner intended to revoke it, demonstrating the race condition allows unauthorized recovery with revoked credentials.

### Citations

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

**File:** lib/src/account/v0.rs (L736-740)
```rust
        // check if recovery has been initiated
        let rec_st = &requester_state_v0.rec;
        if rec_st.pke.is_none() {
            return Ok(None); // Recovery not initiated yet
        }
```

**File:** lib/src/account/v0.rs (L789-800)
```rust
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
