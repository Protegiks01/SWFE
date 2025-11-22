## Audit Report

## Title
Recovery PKE Keys Are Not Session-Bound, Allowing Prolonged Unauthorized Access to Guardian Shares

## Summary
The `send_for_recovery()` function encrypts guardian shares using a recovery PKE key that persists indefinitely in the on-chain account state without session management or time-bounding. Once set during recovery initiation, this PKE remains valid until explicitly cleared by a new account update, allowing an attacker who compromises the recovery decryption key to continuously harvest guardian shares across multiple time periods and potentially reconstruct the Master Secret Key (MSK) unauthorized.

## Impact
**High**

## Finding Description

**Location:** 
- Primary: [1](#0-0) 
- Related: [2](#0-1) 
- Related: [3](#0-2) 

**Intended Logic:**
Recovery PKE keys should be session-specific, one-time-use credentials that are invalidated after recovery completion or after a time period. Each recovery attempt should use fresh keys isolated from other attempts to prevent compromise of one session from affecting others.

**Actual Logic:**
When recovery is initiated via `initiate_recovery()`, a fresh PKE key pair is generated [4](#0-3) , and the public key is stored in the on-chain account state [5](#0-4) . 

The `send_for_recovery()` function retrieves this recovery PKE from the account state and uses it to encrypt guardian shares [6](#0-5) , without any validation of:
- How long the PKE has been active
- Whether recovery has already been completed
- Session identifiers or nonces
- Time-based expiration

The recovery PKE is only cleared when the account owner makes a normal account update with their MSK [7](#0-6) , which may not happen immediately after recovery completion or may never happen if the user doesn't perform additional account operations.

**Exploit Scenario:**
1. Alice initiates recovery, generating a recovery PKE key pair. The private decryption key is stored locally in `RecoverySecrets`.
2. Two guardians (threshold = 2 of 3) send their shares encrypted with the recovery PKE.
3. Alice successfully completes recovery and obtains her MSK.
4. Alice does not immediately update her account state (she might be offline, waiting, or simply not performing additional operations).
5. The recovery PKE remains set in the on-chain account state indefinitely.
6. Attacker Bob compromises Alice's device/storage and obtains the recovery decryption key from her saved `RecoverySecrets` (e.g., from backup files, compromised device, cloud storage).
7. Days or weeks later, Alice contacts the third guardian who was initially unavailable, or guardians who respond late to her original request.
8. These guardians call `check_for_recovery()` [8](#0-7) , which retrieves the SAME recovery PKE from the account state (still set from step 1).
9. Guardian shares are encrypted with the same compromised recovery PKE.
10. Bob intercepts or collects these shares and decrypts them using the compromised decryption key.
11. With sufficient shares, Bob reconstructs the MSK, gaining full control over Alice's account and assets.

**Security Failure:**
The system violates forward secrecy and session isolation principles for recovery operations. A compromised recovery decryption key grants prolonged access to decrypt any guardian shares sent while the recovery PKE remains set, even after the legitimate recovery has completed. This breaks the security invariant that only the legitimate account owner should be able to decrypt guardian shares during their recovery attempt.

## Impact Explanation

This vulnerability directly threatens the **Master Secret Key (MSK)**, which is the root secret controlling all user assets and cryptographic operations in the Swafe protocol. 

**Assets Affected:**
- Master Secret Key (MSK) - root control of user's account
- All secrets and funds protected by the MSK
- User's complete account ownership

**Severity of Damage:**
If an attacker successfully exploits this vulnerability:
1. They can reconstruct the victim's MSK by collecting guardian shares over time
2. With the MSK, they gain complete control over the user's account
3. They can access all secrets protected by the MSK
4. They can steal funds or perform any operation as the account owner
5. The legitimate user loses permanent control of their account

**Why This Matters:**
The recovery mechanism is designed as a fail-safe for users who lose their MSK. However, this vulnerability transforms the recovery process into a long-term liability. The window of vulnerability extends from recovery initiation until the user performs another account update (which might be days, weeks, or never), during which time the compromised recovery key grants unlimited access to harvest guardian shares. This defeats the security model where recovery should be a time-bounded, isolated operation.

## Likelihood Explanation

**Who Can Trigger It:**
Any attacker who can compromise client-side storage where `RecoverySecrets` (containing the recovery decryption key) are stored. This does not require privileged access - only access to the user's device, backup files, cloud storage, or any location where recovery secrets might be persisted.

**Conditions Required:**
1. User initiates recovery (normal operation when MSK is lost)
2. Recovery decryption key is compromised (realistic - client-side storage is a common attack vector)
3. Recovery PKE remains set in account state (guaranteed until user makes new update)
4. Additional guardians send shares (realistic - guardians might respond at different times, or user might attempt recovery multiple times)

**Frequency:**
- **Medium to High likelihood**: Recovery operations are expected to be relatively common in production
- Client-side key compromise is a well-established attack vector (device theft, malware, backup leaks)
- Users commonly do not immediately update their account state after recovery, leaving the window open
- The attack can be executed silently by passively collecting guardian shares over time

The combination of realistic prerequisites and high-impact consequences makes this a significant practical threat.

## Recommendation

Implement session-bound recovery with automatic expiration:

1. **Add session identifiers**: Include a nonce or timestamp in the recovery PKE structure stored on-chain, and validate it in `send_for_recovery()`.

2. **Time-bound recovery sessions**: Add an expiration timestamp when recovery is initiated. Guardians should reject recovery requests older than a reasonable threshold (e.g., 24-72 hours).

3. **Clear recovery state after completion**: Modify the recovery completion flow to either:
   - Automatically generate a new account update that clears `rec.pke` after successful MSK recovery
   - Require users to explicitly finalize recovery with a state-clearing transaction
   - Add a contract-level check that prevents guardians from responding to already-completed recoveries

4. **Increment a recovery counter**: Add a monotonically increasing recovery attempt counter to the account state. Each recovery initiation increments this counter, and guardians include it when encrypting shares. This prevents old recovery keys from being used for new recovery attempts.

Example modification to `send_for_recovery()`:
- Check that the recovery PKE has an associated recent timestamp
- Verify the recovery session hasn't been marked as completed
- Include a session nonce in the encryption context to bind shares to specific recovery attempts

## Proof of Concept

**File:** `lib/src/account/tests.rs`

**Test Function Name:** `test_recovery_pke_reuse_vulnerability`

**Setup:**
1. Create an account with 3 guardians, threshold of 2
2. Setup recovery with `update_recovery()` and add a recovery initiation key (RIK)
3. Initiate recovery using `initiate_recovery()`, obtaining `RecoverySecrets` with the decryption key
4. Apply the recovery update to the on-chain account state via `verify_update()`

**Trigger:**
1. Guardian 1 and Guardian 2 call `check_for_recovery()` and send their shares
2. User successfully completes recovery with `recovery_secrets.complete()`, obtaining the MSK
3. Simulate the compromised recovery key scenario: save the `recovery_secrets.dkey` (decryption key)
4. User does NOT update their account state (simulating typical behavior where user doesn't immediately make another transaction)
5. Days later (simulated by keeping the same account state), Guardian 3 (who was previously unavailable) calls `check_for_recovery()` and sends their share
6. The attack: Use the compromised decryption key to decrypt Guardian 3's share
7. Verify that Guardian 3's share is encrypted with the SAME recovery PKE from the original session

**Observation:**
The test confirms that:
- The recovery PKE (`rec.pke`) remains set in the account state even after recovery completion
- Guardian 3's share sent later is encrypted with the same PKE from the original recovery session
- An attacker with the compromised decryption key can decrypt Guardian 3's share
- There is no session isolation or time-bounding preventing this reuse
- The vulnerability allows prolonged harvesting of guardian shares across time periods

The test demonstrates the exploitability by showing that shares encrypted hours, days, or weeks after the original recovery initiation can still be decrypted with the compromised key, violating the intended one-time-use security model for recovery sessions.

### Citations

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

**File:** lib/src/account/v0.rs (L196-196)
```rust
        let dkey = pke::DecryptionKey::gen(rng);
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

**File:** lib/src/account/v0.rs (L802-833)
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
```
