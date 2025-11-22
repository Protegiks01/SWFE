## Title
Recovery Request Race Condition Enabling Account Hijacking Through rec.pke Overwrite

## Summary
The account recovery system fails to prevent multiple concurrent recovery requests, allowing an attacker with a valid Recovery Initiation Key (RIK) to overwrite a legitimate user's in-progress recovery by replacing the `rec.pke` field. This causes guardians to encrypt their shares to the attacker's public key instead of the legitimate user's key, enabling complete account takeover through MSK theft. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** The vulnerability exists in `lib/src/account/v0.rs`, specifically in the `verify_update` method at line 829, where recovery PKE is set without validation. [2](#0-1) 

**Intended Logic:** The recovery system should allow only one active recovery request at a time. Once a legitimate user initiates recovery by setting `rec.pke`, subsequent recovery attempts should be rejected until the first recovery completes or is explicitly cancelled.

**Actual Logic:** The `verify_update` method unconditionally sets `rec.pke = Some(recovery.pke)` at line 829 without checking if `rec.pke` is already `Some(_)`. This allows any subsequent recovery request with a valid RIK signature to overwrite the existing recovery PKE, replacing the legitimate user's encryption key with an attacker's key.

**Exploit Scenario:**

1. **Initial Recovery:** Legitimate user initiates account recovery using their RIK, generating a fresh PKE keypair and submitting an `AccountUpdateRecoveryV0` message. The contract processes this and sets `rec.pke = Some(user_pke)`.

2. **Attack Window Opens:** The moment `rec.pke` is set on-chain, guardians can see a pending recovery request. However, this also signals to an attacker that they can hijack the recovery.

3. **Attacker Overwrites Recovery:** An attacker who has obtained a valid RIK (through email compromise, phishing, or if they have a different valid RIK for the same account) creates their own recovery request with their own PKE keypair and submits it to the contract.

4. **No Validation Allows Overwrite:** The `verify_update` method verifies the attacker's RIK signature is valid (line 818-820) but does NOT check if `rec.pke.is_some()` before overwriting it at line 829. [3](#0-2) 

5. **Guardians Encrypt to Wrong Key:** Guardians checking for pending recovery via `check_for_recovery` (line 727-755) retrieve the CURRENT value of `rec.pke` at line 738, which now contains the attacker's public key. [4](#0-3) 

6. **Share Encryption to Attacker:** When guardians call `send_for_recovery`, it retrieves `state.rec.pke` and encrypts the guardian share to it (line 162-166 in backup/v0.rs). Since this field now contains the attacker's key, shares are encrypted for the attacker. [5](#0-4) 

7. **Account Hijack Complete:** The attacker collects threshold guardian shares (all encrypted to their key), uses their recovery decryption key to complete recovery, and obtains the victim's MasterSecretKey. The legitimate user's recovery fails because their shares are encrypted to a key they don't control.

**Security Failure:** The critical invariant that "only the account owner may successfully recover their account" is broken. An unprivileged attacker with RIK access (not requiring trusted role compromise) can steal the MasterSecretKey by exploiting the race condition during the recovery window.

## Impact Explanation

**Assets Affected:** The account's MasterSecretKey (MSK), which is the root secret for all account operations, cryptographic keys, and potentially linked financial assets.

**Damage Severity:** 
- **Complete Key Compromise:** The attacker obtains the MSK, giving them full control over the victim's account
- **Loss of Funds:** Any assets or secrets protected by the MSK become accessible to the attacker
- **Permanent Account Loss:** The legitimate user cannot complete their recovery and loses access permanently
- **Guardian Trust Violation:** Well-intentioned guardians unknowingly assist the attacker by encrypting shares to the malicious recovery key

**System Security Impact:** This vulnerability fundamentally breaks the recovery security model. The RIK, which should enable recovery initiation, becomes an account hijacking tool. Even if guardians carefully verify recovery requests, they have no way to distinguish between legitimate and malicious recovery attempts since both produce valid signatures.

## Likelihood Explanation

**Who Can Trigger:** Any attacker who obtains a valid RIK for the target account. RIKs can be compromised through:
- Email account compromise (if the user requested RIK via email association)
- Phishing attacks targeting email credentials
- Multiple RIKs for the same account (if the user created multiple associations)
- Insider threat (anyone with legitimate RIK access)

**Required Conditions:**
- Target account must have recovery configured with guardians
- Legitimate user must initiate recovery (creating the attack window)
- Attacker must observe the on-chain recovery initiation (public information)
- Attacker must act before guardians complete processing the legitimate request

**Exploitation Frequency:** 
- **High Likelihood:** The vulnerability is easily exploitable once the conditions are met. The attack window exists for the entire duration between recovery initiation and guardian share collection.
- **Common Scenario:** Recovery is a critical operation typically performed when users lose access, a stressful situation where they're vulnerable to social engineering and may not notice suspicious activity.
- **Race Condition Window:** Modern blockchain transactions process in seconds to minutes, providing ample time for an attacker monitoring the chain to submit a competing recovery request.

## Recommendation

Add a check in the `verify_update` method to reject recovery requests when `rec.pke` is already set:

```rust
AccountMessageV0::Recovery(recovery) => {
    let mut new_state = old.clone();
    
    {
        let rec = &mut new_state.rec;
        
        // CHECK: Reject if recovery is already in progress
        if rec.pke.is_some() {
            return Err(SwafeError::InvalidOperation(
                "Recovery already in progress".to_string()
            ));
        }
        
        // Verify the recovery request signature
        let recovery_msg = RecoveryRequestMessage {
            account_id: self.acc,
            recovery_pke: recovery.pke.clone(),
        };
        
        // ... rest of verification logic
```

Additionally, consider implementing:
1. **Recovery Cancellation Mechanism:** Allow the account owner to explicitly cancel a pending recovery using their current signing key
2. **Time-locked Recovery:** Add a minimum time delay between recovery initiation and guardian share collection to allow detection of unauthorized attempts
3. **Recovery State Clearing:** Automatically clear `rec.pke` after successful recovery completion or explicit cancellation

## Proof of Concept

**Test File:** `lib/src/account/tests.rs`

**Test Function:** `test_recovery_race_condition_hijack`

**Setup:**
1. Create victim account with 3 guardians (threshold 2)
2. Setup recovery and generate a RIK for the victim account
3. Simulate attacker obtaining the same RIK (or having a different valid RIK for the same account)

**Trigger:**
1. Victim initiates legitimate recovery, submitting first recovery update to contract
2. Contract applies first recovery update, setting `rec.pke = Some(victim_pke)`
3. Attacker observes on-chain state and initiates second recovery with their own PKE
4. Contract applies second recovery update, overwriting `rec.pke = Some(attacker_pke)`
5. Guardians check for pending recovery and generate shares encrypted to current `rec.pke` (attacker's key)

**Observation:**
- Both recovery updates are accepted by `verify_update` (vulnerability confirmed)
- Guardian shares are encrypted to attacker's PKE, not victim's PKE
- Attacker can successfully complete recovery and obtain victim's MSK
- Victim's recovery fails because they cannot decrypt the shares
- Test demonstrates complete account hijacking through race condition

The test should be added to `lib/src/account/tests.rs` following the pattern of existing recovery tests like `test_full_recovery_integration` but with two competing recovery initiations to demonstrate the race condition vulnerability.

### Citations

**File:** lib/src/account/v0.rs (L736-740)
```rust
        // check if recovery has been initiated
        let rec_st = &requester_state_v0.rec;
        if rec_st.pke.is_none() {
            return Ok(None); // Recovery not initiated yet
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
