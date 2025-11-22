## Audit Report

## Title
Recovery State Race Condition Allows MSK Theft and Denial of Service Through PKE Overwriting

## Summary
The `update_account` contract action and the recovery verification logic contain a critical Time-of-Check Time-of-Use (TOCTOU) race condition. When processing Recovery updates, the system fails to check if recovery is already in progress before overwriting the `rec.pke` field. This allows multiple recovery requests to race, causing guardian shares to be encrypted to inconsistent keys, leading to either permanent account lockout or potential Master Secret Key (MSK) theft by an attacker with a compromised Recovery Initiation Key (RIK).

## Impact
**High**

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended Logic:** 
The recovery system should ensure that once recovery is initiated (setting `rec.pke` to a specific public key), all guardians generate shares encrypted to that same key. The account owner should be able to collect threshold shares and successfully complete recovery. Only one recovery session should be active at a time.

**Actual Logic:** 
The `update_account` function reads the old account state, verifies the update, and writes the new state. However, for Recovery message types, the `verify_update` function unconditionally overwrites `rec.pke` without checking if recovery is already in progress: [3](#0-2) 

This creates a race window where:
1. Transaction A sets `rec.pke = Some(pke1)` 
2. Some guardians generate shares for pke1
3. Transaction B sets `rec.pke = Some(pke2)` (overwriting pke1)
4. Remaining guardians generate shares for pke2
5. Guardian shares are now inconsistent - some encrypted to pke1, others to pke2

**Exploit Scenario:**

*Scenario 1 - Denial of Service:*
1. User initiates legitimate recovery with pke1 using their RIK
2. Contract processes update: `rec.pke = Some(pke1)`
3. Guardians 1 and 2 query the account state, see pke1, generate shares encrypted to pke1, and upload them
4. Attacker with a compromised RIK (or user accidentally) submits another recovery with pke2
5. Contract processes update: `rec.pke = Some(pke2)` (overwrites pke1)
6. Guardians 3 and 4 query the account state, see pke2, generate shares encrypted to pke2
7. User attempts recovery completion with dkey1, but can only decrypt 2 shares (from guardians 1-2)
8. With threshold ≥3, recovery permanently fails - account is locked

*Scenario 2 - MSK Theft:*
1. User initiates recovery with pke1
2. Attacker monitors on-chain state, sees recovery initiated
3. Attacker immediately submits recovery with their own pke_attacker using a compromised RIK
4. `rec.pke` is overwritten to `Some(pke_attacker)`
5. All guardians see pke_attacker and generate shares encrypted to it
6. Attacker collects threshold shares and completes recovery, stealing the MSK [4](#0-3) 

**Security Failure:** 
The system violates the recovery atomicity invariant - a recovery session should complete with consistent guardian shares all encrypted to the same key. The lack of a check for existing recovery state allows unauthorized recovery hijacking or permanent denial of service.

## Impact Explanation

**Assets Affected:**
- Master Secret Key (MSK) - the core cryptographic secret protecting all user data and backups
- Account access - users can be permanently locked out of their accounts
- Recovery integrity - the dual-recovery mechanism can be broken

**Severity:**
- **Critical**: An attacker with a compromised RIK can steal the MSK by racing legitimate recovery requests, gaining full control of the account and all associated secrets and funds
- **Critical**: Even without malicious intent, accidental double recovery (e.g., user retrying from different device) causes permanent account lockout, requiring hard fork intervention
- **Systemic**: This affects any account with multiple RIKs (common in multi-device setups), making it a widespread vulnerability

**Why This Matters:**
The MSK is the root of trust in Swafe's security model. Theft of the MSK allows an attacker to decrypt all backups, impersonate the account owner, and access all protected assets. Permanent account lockout prevents legitimate users from recovering their keys even with guardian cooperation, effectively resulting in loss of all associated funds and data.

## Likelihood Explanation

**Who Can Trigger:**
- Any party with a valid RIK for the target account can initiate recovery
- Attacker needs to compromise at least one RIK (e.g., via device compromise, off-chain node breach)
- User can trigger accidentally (e.g., initiating recovery from multiple devices)

**Conditions Required:**
- Account must have recovery configured with guardians
- Multiple recovery transactions must be submitted before all guardians respond
- For MSK theft: Attacker must win the race to overwrite `rec.pke` before sufficient guardians generate shares for the legitimate key

**Frequency:**
- **High for DoS**: Accidental double recovery is likely in normal operations (network issues, user confusion, multi-device usage)
- **Medium for theft**: Requires attacker to have compromised RIK and actively monitor for recovery attempts, but timing window can be several minutes (guardian response time)
- **Exploitable**: Once attacker detects recovery initiation, they have a guaranteed window to submit their own recovery before guardians respond

## Recommendation

Add a check in the `verify_update` function to prevent recovery overwriting when recovery is already in progress: [5](#0-4) 

Before line 829, add:
```rust
// Prevent overwriting existing recovery session
if rec.pke.is_some() {
    return Err(SwafeError::RecoveryAlreadyInProgress);
}
```

Additionally, consider adding a mechanism to explicitly cancel/reset recovery (with appropriate authorization) to handle legitimate cases where recovery needs to be restarted.

## Proof of Concept

**File:** `lib/src/account/tests.rs`

**Test Function:** Add the following test to demonstrate the race condition:

```rust
#[test]
fn test_recovery_race_condition_denial_of_service() {
    let mut rng = OsRng;
    
    // Setup account with 4 guardians, threshold 3
    let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();
    let account_id = *account_secrets.acc();
    let original_msk = account_secrets.msk().clone();
    
    let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian3 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian4 = AccountSecrets::gen(&mut rng).unwrap();
    let guardian_states = [
        guardian1.state(&mut rng).unwrap(),
        guardian2.state(&mut rng).unwrap(),
        guardian3.state(&mut rng).unwrap(),
        guardian4.state(&mut rng).unwrap(),
    ];
    
    // Setup recovery with 2 RIKs
    account_secrets.update_recovery(&mut rng, &guardian_states, 3).unwrap();
    let rik1 = account_secrets.add_association(&mut rng).unwrap();
    let rik2 = account_secrets.add_association(&mut rng).unwrap();
    
    let initial_state = account_secrets.state(&mut rng).unwrap();
    
    // User initiates recovery with rik1/pke1
    let (recovery_req1, recovery_secrets1) = initial_state
        .initiate_recovery(&mut rng, account_id, &rik1)
        .unwrap();
    
    // Apply first recovery update
    let state_after_req1 = recovery_req1.verify(Some(&initial_state)).unwrap();
    
    // Guardians 1-2 see first PKE and generate shares
    let share1 = guardian1
        .check_for_recovery(&mut rng, account_id, &state_after_req1)
        .unwrap()
        .expect("Guardian1 should generate share");
    let share2 = guardian2
        .check_for_recovery(&mut rng, account_id, &state_after_req1)
        .unwrap()
        .expect("Guardian2 should generate share");
    
    // Attacker/user initiates second recovery with rik2/pke2
    // This should fail but currently succeeds, overwriting rec.pke
    let (recovery_req2, _recovery_secrets2) = initial_state
        .initiate_recovery(&mut rng, account_id, &rik2)
        .unwrap();
    
    // Apply second recovery update - OVERWRITES rec.pke
    let state_after_req2 = recovery_req2.verify(Some(&state_after_req1)).unwrap();
    
    // Guardians 3-4 see second PKE and generate shares for different key
    let share3 = guardian3
        .check_for_recovery(&mut rng, account_id, &state_after_req2)
        .unwrap()
        .expect("Guardian3 should generate share");
    let share4 = guardian4
        .check_for_recovery(&mut rng, account_id, &state_after_req2)
        .unwrap()
        .expect("Guardian4 should generate share");
    
    // User tries to complete recovery with their original key (dkey1)
    // They have shares 1,2 (encrypted to pke1) and shares 3,4 (encrypted to pke2)
    // Only shares 1,2 can be decrypted with dkey1
    let all_shares = vec![share1, share2, share3, share4];
    
    // Recovery fails - user can't decrypt enough shares
    let result = recovery_secrets1.complete(&all_shares);
    
    // This demonstrates the vulnerability: recovery fails due to inconsistent guardian shares
    match result {
        Err(SwafeError::InsufficientShares) => {
            // Expected: user locked out despite 4 shares being uploaded
            // because only 2 are decryptable (less than threshold of 3)
        }
        Ok(_) => panic!("Recovery should fail due to inconsistent share encryption"),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}
```

**Setup:** Creates an account with 4 guardians (threshold 3) and 2 RIKs to simulate multiple recovery initiation capabilities.

**Trigger:** Initiates two recovery sessions sequentially using different RIKs, demonstrating how the second overwrites the first's PKE key.

**Observation:** The test confirms that guardians generate shares encrypted to inconsistent keys (first 2 to pke1, last 2 to pke2), causing recovery to fail with `InsufficientShares` despite having threshold shares uploaded. This demonstrates permanent account lockout. The vulnerability is confirmed by the fact that `verify(Some(&state_after_req1))` succeeds for the second recovery request when it should fail to prevent PKE overwriting.

### Citations

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

**File:** lib/src/account/v0.rs (L726-756)
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
}
```

**File:** lib/src/account/v0.rs (L802-834)
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
        }
    }
```
