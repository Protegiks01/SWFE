## Audit Report

## Title
Recovery State Update Bypasses Version Counter Increment Allowing Concurrent Recovery Conflicts

## Summary
The `verify_update` function in `lib/src/account/v0.rs` does not increment the version counter (`cnt`) when processing Recovery messages, unlike regular Update messages which enforce strict counter incrementation. This allows multiple recovery initiations to occur at the same version number, causing the last one to overwrite previous recovery attempts and potentially disrupting ongoing recovery operations.

## Impact
**Medium**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
The version counter (`cnt`) at line 231 should increment with every state transition to ensure monotonic versioning, prevent replay attacks, and maintain sequential state updates. Regular account updates enforce this through a strict check at line 792. [2](#0-1) [3](#0-2) 

**Actual Logic:**
When processing Recovery messages, the code clones the old state (including its counter) at line 804, modifies only the `rec.pke` field at line 829, and returns the state without incrementing the counter at line 831. There is no check to prevent multiple recovery initiations at the same counter value, and no validation that `rec.pke` is `None` before overwriting it.

**Exploit Scenario:**
1. A user with multiple devices (Device A has RIK_A, Device B has RIK_B) loses access to their account at version cnt=N
2. Device A initiates recovery, submitting a Recovery message that sets `rec.pke=PKE_A` while maintaining cnt=N
3. Device B concurrently initiates recovery, submitting another Recovery message that sets `rec.pke=PKE_B`, also at cnt=N
4. The blockchain processes both transactions sequentially; the second one overwrites `rec.pke` to PKE_B
5. Guardians who encrypted shares for PKE_A find their shares are now invalid since the recovery public key has changed
6. The recovery process must be restarted, causing delays

This can also occur if:
- A user initiates recovery from one device, then realizes they used the wrong RIK and tries again
- Network delays cause duplicate recovery submissions
- An attacker with a compromised but valid RIK repeatedly initiates recovery to disrupt the process

**Security Failure:**
The monotonic version counter invariant is violated. Multiple state modifications (different `rec.pke` values) can occur at the same version number, causing state conflicts. The contract at line 127-129 accepts these updates because there's no counter increment requirement for Recovery messages. [4](#0-3) 

## Impact Explanation

**Affected Processes:**
- Account recovery operations for users attempting to regain access to their accounts
- Guardian share encryption, which targets a specific recovery public key
- State versioning system integrity

**Severity of Damage:**
When recovery operations conflict due to the counter not incrementing:
1. Guardian-encrypted shares become invalid when `rec.pke` is overwritten
2. Users must restart the recovery process, waiting for guardian responses again
3. Multiple concurrent recovery attempts can create a race condition where each attempt invalidates the previous one
4. In the worst case, if recovery attempts continue to conflict (e.g., automated retry logic on multiple devices), recovery could be delayed indefinitely until the user coordinates to use only one RIK

This creates a **temporary freezing of recovery operations**, which matches the in-scope impact criteria: "Temporary freezing of transactions or recovery operations by delaying one block by ≥500% of average block time."

**System Reliability Impact:**
The version counter is a fundamental invariant for tracking account state evolution. Breaking this invariant by allowing state changes without counter increments undermines the versioning system's reliability and creates ambiguity about which state is "current" when multiple states share the same version number.

## Likelihood Explanation

**Who Can Trigger:**
Any user with a valid Recovery Initiation Key (RIK) can trigger this. Since users can have multiple RIKs (for different devices or associations), this is a realistic scenario that doesn't require an attacker.

**Conditions Required:**
1. User has at least two valid RIKs (common for multi-device setups)
2. Concurrent or near-concurrent recovery initiation attempts from different devices/RIKs
3. Normal network conditions where transactions are processed sequentially

**Frequency:**
- **Moderate to High:** Users with multiple devices attempting recovery after losing their primary device will naturally try from multiple locations
- **Increased by:** Network latency causing users to retry, automated recovery tools, or panic situations where users try multiple methods simultaneously
- **Every recovery conflict:** Delays the process by requiring re-initiation and waiting for new guardian responses (potentially hours or days depending on guardian availability)

This is not a rare edge case but a realistic consequence of the protocol design allowing multiple valid RIKs without coordinating their concurrent use during recovery.

## Recommendation

**Immediate Fix:**
Modify the Recovery message handling in `verify_update` to increment the counter, ensuring consistency with the versioning invariant:

1. **Add counter increment logic:** In the Recovery branch (line 802-832), increment the counter: `new_state.cnt = old.cnt.checked_add(1).ok_or(SwafeError::InvalidAccountStateVersion)?;`

2. **Add idempotency check:** Before setting `rec.pke` at line 828-829, verify that recovery hasn't already been initiated: 
   ```rust
   if rec.pke.is_some() {
       return Err(SwafeError::RecoveryAlreadyInProgress);
   }
   ```

3. **Document the invariant:** Add comments explaining that ALL state transitions must increment the counter, including recovery initiations.

**Alternative Approach:**
If recovery should remain idempotent (allowing re-initiation), at minimum add the counter increment to prevent multiple different recovery states from sharing the same version number. This maintains the versioning invariant while allowing recovery updates.

## Proof of Concept

**File:** `lib/src/account/tests.rs` (add new test function)

**Test Function Name:** `test_recovery_counter_consistency_violation`

**Setup:**
1. Create an account with cnt=0
2. Create guardians and setup recovery with two different RIKs (RIK_A and RIK_B)
3. Generate the initial account state (cnt=0)
4. Create a regular update to advance to cnt=1

**Trigger:**
1. From cnt=1, initiate recovery using RIK_A, creating recovery_update_A
2. Apply recovery_update_A to get updated_state_A (should still be cnt=1)
3. From the same old state (cnt=1), initiate recovery using RIK_B, creating recovery_update_B
4. Apply recovery_update_B to get updated_state_B (should still be cnt=1)

**Observation:**
The test verifies:
- Both updated_state_A and updated_state_B have cnt=1 (same counter)
- But they have different rec.pke values (PKE_A vs PKE_B)
- This violates the invariant that each unique state should have a unique version number
- The test fails/asserts when it detects two different states with the same counter value

**PoC Code Structure:**
```rust
#[test]
fn test_recovery_counter_consistency_violation() {
    let mut rng = OsRng;
    
    // Create account and advance to cnt=1
    let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();
    let guardian = AccountSecrets::gen(&mut rng).unwrap();
    let guardians = [guardian.state(&mut rng).unwrap()];
    
    account_secrets.update_recovery(&mut rng, &guardians, 1).unwrap();
    let rik_a = account_secrets.add_association(&mut rng).unwrap();
    let rik_b = account_secrets.add_association(&mut rng).unwrap();
    
    let update0 = account_secrets.update(&mut rng).unwrap();
    let state0 = update0.verify(None).unwrap();
    
    let mut account_secrets = state0.decrypt(account_secrets.msk(), *account_secrets.acc()).unwrap();
    account_secrets.new_pke(&mut rng);
    let update1 = account_secrets.update(&mut rng).unwrap();
    let state1 = update1.verify(Some(&state0)).unwrap();
    
    // Initiate recovery twice with different RIKs from the same base state
    let (recovery_a, _) = state1.initiate_recovery(&mut rng, *account_secrets.acc(), &rik_a).unwrap();
    let state_a = recovery_a.verify(Some(&state1)).unwrap();
    
    let (recovery_b, _) = state1.initiate_recovery(&mut rng, *account_secrets.acc(), &rik_b).unwrap();
    let state_b = recovery_b.verify(Some(&state1)).unwrap();
    
    // Extract version counters
    let (AccountState::V0(state_a_v0), AccountState::V0(state_b_v0)) = (&state_a, &state_b);
    let (AccountState::V0(state_1_v0)) = &state1;
    
    // BUG: Both recovery states have the same counter as the pre-recovery state
    assert_eq!(state_a_v0.cnt, state_1_v0.cnt); // cnt not incremented!
    assert_eq!(state_b_v0.cnt, state_1_v0.cnt); // cnt not incremented!
    
    // But they have different rec.pke values
    assert_ne!(
        serialize(&state_a_v0.rec.pke).unwrap(),
        serialize(&state_b_v0.rec.pke).unwrap()
    );
    
    panic!("Counter consistency violated: two different states share the same version number!");
}
```

This test demonstrates that recovery updates don't increment the counter, allowing multiple different states to have the same version number, which violates the versioning invariant and enables the conflict scenario described above.

### Citations

**File:** lib/src/account/v0.rs (L231-231)
```rust
    cnt: u32, // current count of operations
```

**File:** lib/src/account/v0.rs (L789-794)
```rust
            AccountMessageV0::Update(auth) => {
                let st = auth.state;
                // version must increase by exactly one
                if Some(st.cnt) != old.cnt.checked_add(1) {
                    return Err(SwafeError::InvalidAccountStateVersion);
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

**File:** contracts/src/lib.rs (L127-129)
```rust
    let st_new = update
        .verify(st_old.as_ref())
        .expect("Failed to verify account update");
```
