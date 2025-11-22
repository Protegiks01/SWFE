## Title
Recovery Request Replay Attack Enables Account Takeover via Stale Recovery Key Substitution

## Summary
The recovery request mechanism lacks replay protection, allowing an attacker to replay old, signed recovery requests to overwrite the current recovery public key encryption (PKE) with a stale key. The `RecoveryRequestMessage` structure contains no timestamp, nonce, or counter, and the verification logic does not check if recovery is already initiated before accepting new recovery requests. This enables an attacker who captures a recovery request to force the account to use an old recovery key that the owner may no longer possess, permanently freezing the account.

## Impact
**High**

## Finding Description

**Location:** 
- Primary vulnerability: [1](#0-0) 
- Vulnerable message structure: [2](#0-1) 

**Intended Logic:** 
Recovery requests should be processed exactly once per recovery session. Once a user initiates recovery with a specific recovery PKE key, that should be the key used for the recovery process. The timestamp in backup metadata is intended to provide temporal ordering, but the recovery request itself should be protected against replay attacks.

**Actual Logic:** 
The `RecoveryRequestMessage` structure contains only `account_id` and `recovery_pke` with no timestamp, nonce, or sequence number. [2](#0-1)  When the `verify_update` method processes a recovery message, it verifies the signature against the associations but does NOT check if `rec.pke` is already set to `Some` (indicating recovery is already initiated). [3](#0-2)  It simply overwrites the existing recovery PKE with the new one from the replayed message.

**Exploit Scenario:**
1. User initiates account recovery at time T1 with recovery_pke_1, creating a signed `RecoveryRequestMessage`
2. Attacker observes and captures this signed recovery request (e.g., through network monitoring or chain observation)
3. User later initiates a second recovery at time T2 with recovery_pke_2 (perhaps because they lost access to the first key or want to update it)
4. Attacker replays the old signed recovery request containing recovery_pke_1
5. The contract accepts the replay because the signature is valid and overwrites recovery_pke_2 with recovery_pke_1
6. Guardians now encrypt their shares for recovery_pke_1 instead of recovery_pke_2
7. If the user no longer has the private key for recovery_pke_1, they cannot decrypt the guardian shares and complete recovery

**Security Failure:** 
The lack of replay protection violates the invariant that recovery requests should be fresh and reflect the current intent of the account owner. This enables an attacker to force the use of a stale recovery key, causing permanent account freezing if the owner no longer possesses the corresponding private key.

## Impact Explanation

**Affected Assets:** Master secret keys (MSK), account ownership, and all secrets backed up by the account.

**Severity of Damage:** If a user loses access to an old recovery key and attempts to initiate recovery with a new key, an attacker can replay the old recovery request to make the new recovery impossible. Since the recovery mechanism is the only way to regain access to the MSK when the user has lost their primary credentials, this results in permanent loss of account access. All secrets protected by that MSK become permanently inaccessible.

**Why This Matters:** The Swafe protocol is designed as a key management and recovery system. The ability to recover account access is fundamental to its security model. This vulnerability undermines that core functionality by allowing attackers to sabotage legitimate recovery attempts, effectively weaponizing old recovery requests to permanently freeze accounts. This meets the high-severity criterion of "permanent freezing of secrets or accounts."

## Likelihood Explanation

**Who Can Trigger It:** Any network participant who can observe on-chain transactions can capture signed recovery requests. Once captured, any attacker can replay them at any time in the future.

**Required Conditions:** 
- The attacker must have observed and stored a previous recovery request from the target account
- The user must attempt to initiate recovery a second time (which is a reasonable scenario if they lost the first recovery key)
- The attacker must submit the replay before the user completes the recovery process

**Frequency:** This attack is highly likely in practice because:
1. Recovery requests are publicly observable on-chain
2. Users legitimately need to re-initiate recovery if they lose recovery keys
3. The attack can be executed at any time after capturing the first recovery request
4. There is no expiration or invalidation mechanism for old recovery requests

## Recommendation

Add replay protection to recovery requests by implementing one or more of the following mitigations:

1. **Add a nonce/counter to RecoveryRequestMessage:** Include a monotonically increasing counter that must be strictly greater than the last used counter for recovery requests. [2](#0-1) 

2. **Check recovery state before accepting new requests:** In the `verify_update` method, reject recovery requests if `rec.pke.is_some()`, requiring users to explicitly cancel/reset recovery before initiating a new one. [3](#0-2) 

3. **Add timestamp validation:** Include a timestamp in `RecoveryRequestMessage` and reject requests with timestamps older than a defined window (e.g., 5 minutes, similar to email certificates). [4](#0-3) 

The recommended approach is option 2 combined with option 1, as it provides both protection against replay attacks and ensures explicit user intent for recovery state transitions.

## Proof of Concept

**File:** `lib/src/account/tests.rs`

**Test Function:** `test_recovery_request_replay_attack`

**Setup:**
1. Create an account with recovery configured (3 guardians, threshold 2)
2. Add an association to enable recovery initiation
3. Initiate recovery with the first recovery PKE key (recovery_pke_1)
4. Apply the recovery request to update the account state

**Trigger:**
1. Create a second recovery request with a different recovery PKE key (recovery_pke_2)
2. Apply this second recovery request to update the state (simulating the user wanting to change recovery keys)
3. Replay the first recovery request (captured from step 3 of setup)
4. The replay should be accepted by `verify_update`, overwriting recovery_pke_2 with recovery_pke_1

**Observation:**
The test demonstrates that the replayed recovery request is accepted and overwrites the newer recovery PKE. After the replay:
- The account state's `rec.pke` field contains recovery_pke_1 (from the replay) instead of recovery_pke_2 (from the legitimate second request)
- Guardians would encrypt shares for the old key recovery_pke_1
- If the user no longer has the private key for recovery_pke_1, recovery becomes impossible
- This confirms the replay attack vulnerability and its potential to permanently freeze the account

The test should be structured similar to [5](#0-4)  but with the additional step of replaying the first recovery request after submitting a second one.

### Citations

**File:** lib/src/account/v0.rs (L118-123)
```rust
#[derive(Serialize)]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct RecoveryRequestMessage {
    pub(crate) account_id: AccountId,
    pub(crate) recovery_pke: pke::EncryptionKey,
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

**File:** lib/src/crypto/email_cert.rs (L29-34)
```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct EmailCertificateMessage {
    user_pk: sig::VerificationKey,
    email: String,
    timestamp: u64,
}
```

**File:** lib/src/account/tests.rs (L474-538)
```rust
    fn test_full_recovery_integration() {
        let mut rng = OsRng;

        // Step 1: Create account with MSK
        let mut account_secrets = AccountSecrets::gen(&mut rng).unwrap();
        let account_id = *account_secrets.acc();
        let original_msk = account_secrets.msk().clone();

        // Step 2: Create 3 guardians, threshold 2
        let guardian1 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian2 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian3 = AccountSecrets::gen(&mut rng).unwrap();
        let guardian_states = [
            guardian1.state(&mut rng).unwrap(),
            guardian2.state(&mut rng).unwrap(),
            guardian3.state(&mut rng).unwrap(),
        ];

        // Step 3: Setup recovery with guardians (returns RIK for offchain storage)
        account_secrets
            .update_recovery(&mut rng, &guardian_states, 2)
            .unwrap();
        let rik = account_secrets.add_association(&mut rng).unwrap();

        // Step 4: Simulate account state after setup
        let account_state = account_secrets.state(&mut rng).unwrap();
        let AccountState::V0(account_state_v0) = &account_state;

        // Step 5: Initiate recovery using the RIK
        let (recovery_request, recovery_secrets) = account_state_v0
            .initiate_recovery(&mut rng, account_id, &rik)
            .expect("Failed to initiate recovery");

        // Step 6: Simulate contract processing recovery update using verify_update
        let (AccountUpdate::V0(recovery_update), AccountState::V0(old_state)) =
            (&recovery_request, &account_state);
        let new_state = recovery_update
            .clone()
            .verify_update(old_state)
            .expect("Recovery update should be valid");
        let updated_account_state = AccountState::V0(new_state);

        let guardian_share1 = guardian1
            .check_for_recovery(&mut rng, account_id, &updated_account_state)
            .unwrap()
            .expect("Guardian1 should find pending recovery");

        let guardian_share2 = guardian2
            .check_for_recovery(&mut rng, account_id, &updated_account_state)
            .unwrap()
            .expect("Guardian2 should find pending recovery");

        let guardian_shares = vec![guardian_share1, guardian_share2];

        // Step 7: Use the fixed complete method
        let recovered_msk = recovery_secrets
            .complete(&guardian_shares)
            .expect("Recovery should succeed with proper guardian shares");

        // Step 8: Verify the recovered MSK matches the original
        assert_eq!(
            recovered_msk, original_msk,
            "Recovered MSK should match original"
        );
    }
```
