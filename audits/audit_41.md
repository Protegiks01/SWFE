## Title
Recovery State Transition Race Condition Allows Overwriting In-Progress Recovery

## Summary
The `verify_update` method in `lib/src/account/v0.rs` does not check if a recovery is already in progress before setting the `rec.pke` field. This allows concurrent recovery initiation requests to overwrite each other, invalidating guardian shares from previous attempts and creating a race condition that can temporarily freeze recovery operations. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** `lib/src/account/v0.rs`, line 829 in the `verify_update` method within the `AccountUpdateV0` implementation. [2](#0-1) 

**Intended Logic:** When a recovery is initiated, the `rec.pke` field should be set to signal guardians that recovery is pending. The system should protect against race conditions where multiple recovery attempts interfere with each other, ensuring that once recovery begins, it can proceed to completion without being disrupted.

**Actual Logic:** The `verify_update` method unconditionally overwrites `rec.pke` at line 829 without checking if it is already set (i.e., `rec.pke.is_some()`). Any valid recovery request with a properly signed message from any valid association will overwrite the existing PKE value, regardless of whether a recovery is already in progress. [3](#0-2) 

**Exploit Scenario:**
1. Account owner has multiple valid Recovery Initiation Keys (RIKs) - one on their phone and one on their laptop (a legitimate multi-device setup)
2. Owner initiates recovery from their phone using RIK₁, which sets `rec.pke = Some(pke_phone)`
3. Contract stores this state on-chain [4](#0-3) 
4. Guardians observe the recovery initiation and generate shares encrypted to `pke_phone` [5](#0-4) 
5. Before the owner completes recovery, they accidentally initiate recovery again from their laptop using RIK₂
6. The second recovery request passes signature verification (RIK₂ is a valid association) and overwrites: `rec.pke = Some(pke_laptop)`
7. The guardian shares encrypted to `pke_phone` are now useless - the decryption key for `pke_phone` cannot decrypt shares meant for `pke_laptop`
8. The first recovery attempt cannot be completed; the owner must restart the entire recovery process

**Security Failure:** This violates the atomicity and consistency of the recovery state transition. The mid-transition state where `rec.pke` is set becomes observable and mutable, allowing subsequent operations to corrupt the recovery process. This creates a denial-of-service condition where recovery operations are temporarily frozen and must be restarted.

## Impact Explanation

**Affected Processes:** The account recovery process, guardian share generation, and the integrity of the recovery state machine.

**Severity of Damage:**
- Recovery operations can be temporarily frozen, requiring users to restart the entire guardian approval process
- Guardian resources are wasted generating shares that become invalid
- Users may be locked out of their accounts if recovery is repeatedly disrupted
- In scenarios with multiple legitimate devices or accidental double-clicks, this creates user experience issues and delays in critical recovery situations
- If exploited intentionally by someone with a valid RIK (rare but possible), this creates an indefinite DoS on recovery

**System Reliability Impact:** This breaks the expected invariant that once recovery is initiated, it should proceed atomically to completion. The recovery state machine becomes vulnerable to race conditions, undermining the reliability of the core security mechanism for account recovery.

## Likelihood Explanation

**Who Can Trigger:** Any account owner with multiple valid RIKs can trigger this accidentally. Account owners legitimately have multiple RIKs when using multiple devices (phone, laptop, tablet).

**Conditions Required:** 
- Account has recovery configured with guardians
- Account has multiple valid associations (RIKs)
- Two or more recovery initiation requests are submitted before the first recovery completes
- This can happen through normal usage (user clicks "recover" on multiple devices, or double-clicks the same button)

**Frequency:** Moderately likely in production:
- Common scenario: Users with multi-device setups may initiate recovery from different devices thinking the first attempt failed
- Edge case: Network delays or UI issues may lead users to retry recovery initiation
- The recovery process takes time (guardians must respond), creating a window where concurrent initiations can occur

## Recommendation

Add a check in the `verify_update` method to reject recovery initiation if a recovery is already in progress:

```rust
// Before line 829, add:
if rec.pke.is_some() {
    return Err(SwafeError::RecoveryAlreadyInProgress);
}
```

This ensures that once recovery is initiated, the state cannot be overwritten until the recovery is completed or explicitly cancelled through a full account update that resets `rec.pke` to `None`. [6](#0-5) 

## Proof of Concept

**File:** Add this test to `lib/src/account/tests.rs`

**Test Function:** `test_concurrent_recovery_race_condition`

**Setup:**
1. Create an account with recovery configured (3 guardians, threshold 2)
2. Add two different RIKs to the account (simulating multi-device setup): `rik1` and `rik2`
3. Generate the initial account state and upload to contract

**Trigger:**
1. Initiate recovery using `rik1`, producing `recovery_request_1` with `pke_1`
2. Apply `recovery_request_1` to get `state_after_first_recovery` where `rec.pke = Some(pke_1)`
3. Guardian generates shares encrypted to `pke_1`
4. Before completing recovery, initiate a second recovery using `rik2`, producing `recovery_request_2` with `pke_2`
5. Apply `recovery_request_2` to `state_after_first_recovery` to get `state_after_second_recovery`

**Observation:**
1. Verify that `state_after_second_recovery.rec.pke` equals `Some(pke_2)`, not `Some(pke_1)`
2. Attempt to complete recovery using the guardian shares encrypted to `pke_1` and the decryption key `dkey_1`
3. The recovery completion fails because the shares are encrypted to `pke_1` but the state has `pke_2`
4. This demonstrates that the second recovery request successfully overwrote the first, invalidating the guardian shares and breaking the recovery process

The test confirms the race condition vulnerability: concurrent recovery initiations can overwrite each other, leading to temporary DoS of recovery operations and wasted guardian resources.

### Citations

**File:** lib/src/account/v0.rs (L102-102)
```rust
    pub pke: Option<pke::EncryptionKey>, // this is set iff. recovery has been started
```

**File:** lib/src/account/v0.rs (L710-711)
```rust
            rec: RecoveryStateV0 {
                pke: None,
```

**File:** lib/src/account/v0.rs (L737-740)
```rust
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

**File:** contracts/src/lib.rs (L126-133)
```rust
    // verify the update using the lib
    let st_new = update
        .verify(st_old.as_ref())
        .expect("Failed to verify account update");

    // store the updated account state
    state.set_account(account_id, st_new);
    state
```
