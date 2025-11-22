## Title
Recovery State Rollback Vulnerability Allows Cancellation of Initiated Account Recovery

## Summary
The account recovery mechanism in `lib/src/account/v0.rs` allows recovery state to be rolled back after initialization. When a user initiates account recovery, the `rec.pke` field is set to indicate recovery is in progress. However, any subsequent regular account update resets this field to `None`, effectively canceling the recovery. This occurs because regular updates hardcode `pke: None` and there is no validation to prevent rolling back an active recovery state. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** The vulnerability exists in the account update logic in `lib/src/account/v0.rs`, specifically:
- Line 711 where regular updates hardcode `pke: None` 
- Lines 802-831 where recovery updates are processed without incrementing the version counter
- Lines 789-800 where regular updates are verified without checking for active recovery state [2](#0-1) 

**Intended Logic:** Once account recovery is initiated by setting `rec.pke = Some(...)`, the recovery should proceed until guardians provide their shares and the user completes recovery. The recovery state should not be reversible by regular account updates.

**Actual Logic:** 
1. When recovery is initiated via `initiate_recovery()`, a recovery update is created that sets `rec.pke = Some(recovery_pke)` 
2. However, this recovery update does NOT increment the account version counter - it clones the old state and only modifies the `rec.pke` field
3. When a regular update is created via `AccountSecrets::update()`, it explicitly sets `rec.pke = None` regardless of the current recovery state
4. The verification logic for regular updates only checks that the version counter increments by 1 and the signature is valid - it does NOT check whether an active recovery is being rolled back [3](#0-2) [4](#0-3) 

**Exploit Scenario:**
1. User initiates account recovery using their Recovery Initiation Key (RIK), creating a recovery update that sets `rec.pke = Some(...)`
2. The recovery update is submitted to the contract and verified - the on-chain state now has `rec.pke = Some(...)` indicating recovery is in progress
3. Either the legitimate user (if they still have access to their signing key) or an attacker (who compromised the signing key) creates a regular account update
4. The regular update has `cnt` incremented by 1 (passing version validation) and `rec.pke = None` (hardcoded)
5. The update is verified using the old signing key (which is still valid) and accepted
6. The on-chain state is updated with `rec.pke = None`, effectively canceling the recovery
7. Guardians who check for pending recovery requests will now find `rec.pke.is_none()` and return `Ok(None)`, unable to provide shares [5](#0-4) 

**Security Failure:** This breaks the core security property that "Recovery of an account only occurs when more than the specified threshold of Guardians has approved the request." An attacker with access to the signing key can indefinitely prevent recovery by continuously rolling back recovery attempts, while the legitimate user cannot recover their account even with guardian assistance.

## Impact Explanation

**Affected Assets and Processes:**
- Master Secret Keys (MSK) of users attempting account recovery
- Account ownership and access for users who have lost their primary credentials but initiated recovery
- The integrity of the social recovery mechanism as a whole

**Severity of Damage:**
- **For legitimate users:** If a user loses their device but has the signing key backed up elsewhere, they might accidentally cancel their own recovery by making any regular update (e.g., rotating keys, adding backups)
- **For attacked accounts:** An attacker who has compromised the signing key can permanently prevent the legitimate user from recovering their account through the social recovery mechanism. The attacker can monitor the blockchain for recovery initiations and immediately submit a regular update to cancel it
- **System-wide impact:** This undermines the core value proposition of Swafe - the ability to recover accounts through social guardians. Users cannot rely on recovery if it can be trivially canceled

**Why This Matters:**
The social recovery mechanism is a critical security feature designed to help users recover access when they lose their primary credentials. If recovery can be canceled by anyone with the (potentially compromised) signing key, the entire recovery mechanism becomes ineffective. This is particularly severe because:
1. It creates a permanent denial-of-service condition for recovery
2. It gives attackers who compromise signing keys absolute control, preventing legitimate recovery
3. It violates the fundamental security invariant that guardian-based recovery should work independently of the signing key

## Likelihood Explanation

**Who Can Trigger It:**
- Any entity with access to the account's signing key, including:
  - The legitimate account owner (accidentally)
  - An attacker who has compromised the signing key

**Required Conditions:**
- Account recovery must be initiated (setting `rec.pke = Some(...)`)
- The actor must have access to the signing key from before the recovery
- The actor must submit a regular account update

**Frequency:**
- **High likelihood in adversarial scenarios:** If an attacker has compromised the signing key (the exact scenario that recovery is designed to address), they can trivially and repeatedly cancel any recovery attempts by the legitimate user
- **Moderate likelihood in normal operation:** A legitimate user who has backed up their signing key might accidentally cancel their own recovery by making routine account updates
- **Occurs immediately:** The rollback happens as soon as the regular update is processed on-chain, with no delay or additional conditions required

This is not a rare edge case - it's a fundamental flaw in how recovery state is managed relative to regular updates.

## Recommendation

Add validation in the `verify_update` function to prevent rolling back an active recovery:

1. In `AccountUpdateV0::verify_update()` for regular updates, add a check before accepting the new state:
   ```rust
   // Prevent rolling back an initiated recovery
   if old.rec.pke.is_some() && st.rec.pke.is_none() {
       return Err(SwafeError::InvalidOperation(
           "Cannot cancel an initiated recovery with a regular update".to_string()
       ));
   }
   ```

2. Alternatively, modify the `AccountSecrets::update()` function to preserve the current recovery state instead of hardcoding `pke: None`. The user should decrypt the current on-chain state and use its `rec.pke` value when creating updates.

3. Consider adding a separate explicit "cancel recovery" operation that requires additional authorization or can only be performed by the recovery signing key, ensuring recovery cancellation is intentional and controlled.

## Proof of Concept

**File:** `lib/src/account/tests.rs`

**Test Function:** `test_recovery_state_rollback_vulnerability`

**Setup:**
1. Create an account with `AccountSecrets::gen()`
2. Setup recovery with 3 guardians and threshold of 2
3. Add an association (RIK) for recovery
4. Create initial account state by calling `update()` and verifying it

**Trigger:**
1. Initiate recovery using `initiate_recovery()` with the RIK
2. Verify the recovery update - confirm `rec.pke.is_some()` in the resulting state
3. Decrypt the state to get `AccountSecrets` 
4. Make any modification (e.g., `new_pke()`) to set `dirty = true`
5. Create a regular update using `update()`
6. Verify this update against the recovery state

**Observation:**
1. The regular update is accepted and verified successfully
2. The resulting state has `rec.pke = None` - the recovery has been rolled back
3. Guardians calling `check_for_recovery()` on this state return `Ok(None)` because `rec.pke.is_none()`
4. The recovery is permanently canceled despite being properly initiated

The test demonstrates that the recovery state can be rolled back to `pke = None` after being initialized to `pke = Some(...)`, violating the invariant that recovery should proceed once initiated until guardians provide shares.

## Notes

This vulnerability is particularly critical because:
1. It completely undermines the social recovery mechanism, which is a core security feature of Swafe
2. It gives attackers who compromise signing keys the ability to prevent recovery indefinitely
3. It can occur accidentally when legitimate users make routine updates
4. The fix is straightforward - add validation to prevent `rec.pke` from being rolled back from `Some` to `None` in regular updates

### Citations

**File:** lib/src/account/v0.rs (L634-723)
```rust
    /// Produce an update transaction to store the new state of the abstract account
    pub fn update<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<AccountUpdate> {
        // new version of the account state
        let cnt = if self.dirty { self.cnt + 1 } else { self.cnt };

        // generate *all* the associations
        // this hides which association is being updated/added/removed
        let assoc = self
            .recovery
            .assoc
            .iter()
            .map(|assoc| {
                // generate keys for recovery authorization
                let key_sig = sig::SigningKey::gen(rng);

                // create EncapV0 with the recovery key
                let encap = sym::seal(
                    rng,
                    assoc.rik.as_bytes(),
                    &EncapV0 {
                        key_sig: key_sig.clone(),
                        msk_ss_rik: self.recovery.msk_ss_rik.clone(),
                    },
                    self.acc(),
                );

                // create new AssociationsV0
                AssociationsV0 {
                    sig: key_sig.verification_key(),
                    encap,
                }
            })
            .collect();

        // encrypt the secret state
        let act = AccountCiphertext(sym::seal(
            rng,
            self.msk.as_bytes(),
            &CombinedSecret::V0(CombinedSecretV0 {
                sig: self.sig.clone(),
                pke: self.pke.clone(),
                old_msk: self.old_msk.clone(),
                old_pke: self.old_pke.clone(),
                recovery: RecoverySecretV0 {
                    msk_ss_social: self.recovery.msk_ss_social.clone(),
                    msk_ss_rik: self.recovery.msk_ss_rik.clone(),
                    guardians: self.recovery.guardians.clone(),
                    threshold: self.recovery.threshold,
                    assoc: self.recovery.assoc.clone(),
                },
            }),
            &AccountStateV0Ad {
                account_id: self.acc,
                version: cnt,
            },
        ));

        // derive MSK decryption key and encrypt MSK
        let enc_msk = sym::seal(
            rng,
            &derive_msk_decryption_key(
                self.acc(),
                &self.recovery.msk_ss_rik,
                &self.recovery.msk_ss_social,
            ),
            &self.msk,
            self.acc(),
        );

        let st = AccountStateV0 {
            cnt,
            backups: self.backups.clone(),
            recover: self.recover.clone(),
            pke: self.pke.encryption_key(),
            sig: self.sig.verification_key(),
            act,
            rec: RecoveryStateV0 {
                pke: None,
                assoc,
                // TODO: unfortunately we cannot generate this anew every time
                social: self.recovery.social.clone(),
                enc_msk,
            },
        };

        let sig = self.old_sig.sign(rng, &st);
        Ok(AccountUpdate::V0(AccountUpdateV0 {
            acc: self.acc,
            msg: AccountMessageV0::Update(AccountUpdateFullV0 { sig, state: st }),
        }))
```

**File:** lib/src/account/v0.rs (L736-740)
```rust
        // check if recovery has been initiated
        let rec_st = &requester_state_v0.rec;
        if rec_st.pke.is_none() {
            return Ok(None); // Recovery not initiated yet
        }
```

**File:** lib/src/account/v0.rs (L786-800)
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
