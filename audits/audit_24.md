## Title
Recovery Re-Initialization Allows Hijacking of Guardian Approval

## Summary
The `verify_update()` function in the account recovery system does not check whether recovery has already been initiated before allowing a new recovery initialization. This allows an attacker with a valid Recovery Initiation Key (RIK) to re-initiate recovery after it has already been started, changing the recovery encryption key and hijacking guardian approval intended for another party. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** The vulnerability exists in `lib/src/account/v0.rs` in the `verify_update()` function, specifically in the `AccountMessageV0::Recovery` branch that handles recovery initialization updates.

**Intended Logic:** The recovery system should ensure that once recovery has been initiated, guardians' approval applies to the specific recovery requester who initiated it. Multiple valid RIKs (associations) should not be able to interfere with each other's recovery attempts.

**Actual Logic:** The `verify_update()` function sets `rec.pke = Some(recovery.pke)` without checking if `rec.pke` is already `Some`. This allows anyone with a valid RIK to overwrite an existing recovery request by re-initiating recovery with a different encryption key. [2](#0-1) 

**Exploit Scenario:**
1. An account owner creates multiple associations (e.g., one for themselves and one for a backup service provider) using `add_association()`, each generating a different RIK.
2. The legitimate owner loses access and initiates recovery using their RIK, creating encryption key PKE_A and corresponding decryption key DK_A. The contract sets `rec.pke = Some(PKE_A)`.
3. An attacker (who possesses a different valid RIK for the same account) initiates recovery using their RIK, creating PKE_B and DK_B. The contract processes this and sets `rec.pke = Some(PKE_B)`, overwriting PKE_A.
4. Guardians check the current account state on-chain and see `rec.pke = PKE_B`. They call `check_for_recovery()` which encrypts their shares to PKE_B. [3](#0-2) 

5. The attacker collects the guardian shares (which are encrypted to PKE_B) and completes recovery using DK_B to decrypt the shares and reconstruct the Master Secret Key (MSK).
6. The legitimate owner cannot decrypt the guardian shares because they only have DK_A, not DK_B.

**Security Failure:** This breaks the invariant that guardians' approval should apply to a specific recovery requester. Guardians intend to approve the legitimate owner's recovery, but their approval (in the form of encrypted shares) becomes usable by an attacker with a different valid RIK. This effectively allows bypassing the requirement for guardians to approve the attacker's specific recovery attempt.

## Impact Explanation

**Assets Affected:** The Master Secret Key (MSK) is compromised, which is the root secret for the entire account. This leads to complete account takeover.

**Severity:** An attacker who gains access to one valid RIK (e.g., through a compromised backup service, social engineering, or other means) can hijack any ongoing recovery attempt and gain full control of the account. The legitimate owner is locked out while the attacker obtains the MSK.

**Systemic Impact:** This vulnerability undermines the entire guardian-based recovery system. Users cannot safely create multiple associations for redundancy, as any association holder can hijack recoveries initiated by other associations. This violates the fundamental trust model where guardians approve specific recovery requests.

## Likelihood Explanation

**Who Can Trigger:** Any party with a valid RIK for the target account can exploit this vulnerability. This includes:
- Backup service providers given an association
- Compromised devices with stored RIKs
- Former trusted parties who retained their RIK

**Conditions Required:** 
- The account must have multiple associations (multiple valid RIKs)
- A legitimate recovery attempt must be in progress or about to start
- The attacker must submit their recovery initialization before guardians provide shares to the legitimate requester, or the guardians must check the on-chain state after the attacker's re-initialization

**Frequency:** This can occur whenever an account with multiple associations undergoes recovery. Given that multiple associations are a recommended practice for redundancy, and that accounts may legitimately use backup services that require their own RIK, this vulnerability is highly exploitable in normal operational scenarios.

## Recommendation

Add a check in the `verify_update()` function to prevent re-initialization when recovery is already in progress:

```rust
AccountMessageV0::Recovery(recovery) => {
    let mut new_state = old.clone();
    {
        let rec = &mut new_state.rec;
        
        // Prevent re-initialization if recovery already in progress
        if rec.pke.is_some() {
            return Err(SwafeError::InvalidOperation(
                "Recovery already initiated".to_string()
            ));
        }
        
        // ... existing verification logic ...
        
        rec.pke = Some(recovery.pke);
    }
    Ok(new_state)
}
```

Additionally, consider implementing a mechanism for guardians to cryptographically commit to which specific association (or requester identity) they are approving, preventing approval from being usable by a different association.

## Proof of Concept

**File:** `lib/src/account/tests.rs`

**Test Function:** Add a new test function `test_recovery_hijacking_via_reinitialization()`

**Setup:**
1. Create an account with 3 guardians and threshold 2
2. Call `add_association()` twice to create two valid RIKs (RIK_A for Alice, RIK_B for Bob)
3. Submit the account update to establish the associations on-chain

**Trigger:**
1. Alice initiates recovery using RIK_A, creating (PKE_A, DK_A)
2. Submit Alice's recovery update to the contract via `verify_update()`
3. Bob immediately initiates recovery using RIK_B, creating (PKE_B, DK_B)
4. Submit Bob's recovery update to the contract via `verify_update()` - this overwrites `rec.pke`
5. Guardians call `check_for_recovery()` on the updated state and provide shares
6. Bob calls `RecoverySecrets.complete()` with the guardian shares
7. Alice attempts to call `RecoverySecrets.complete()` with the same guardian shares

**Observation:**
- Bob's recovery succeeds (he successfully recovers the MSK)
- Alice's recovery fails (she cannot decrypt the guardian shares because they're encrypted to PKE_B, not PKE_A)
- The test demonstrates that Bob hijacked the guardian approval intended for Alice
- This confirms the vulnerability: recovery re-initialization allows bypassing the intended guardian approval for a specific requester

### Citations

**File:** lib/src/account/v0.rs (L726-755)
```rust
    /// Guardian: Check if there's a pending recovery request and generate guardian share
    pub fn check_for_recovery<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        acc: AccountId,       // account id of the account
        state: &AccountState, // state of the account
    ) -> Result<Option<GuardianShare>> {
        // get requester's state details
        let AccountState::V0(requester_state_v0) = state;

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
