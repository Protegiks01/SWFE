After thorough investigation of the recovery flow, account state management, and guardian share generation logic, I have identified a concrete TOCTOU vulnerability.

## Audit Report

## Title
TOCTOU Race Condition in Recovery Initiation Allows Guardian Shares to Become Incompatible Due to Missing Version Control

## Summary
The account recovery mechanism allows multiple recovery initiations without incrementing the version counter, creating a race condition where guardians generate shares encrypted for different recovery public keys. This results in incompatible guardian shares that prevent successful account recovery.

## Impact
**Medium to High**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
Recovery updates should maintain consistency such that all guardians generate shares encrypted for the same recovery public key (PKE). The version counter system is meant to prevent concurrent state modifications from causing inconsistencies.

**Actual Logic:** 
When processing a `AccountMessageV0::Recovery` message, the system clones the old account state and only modifies the `rec.pke` field without incrementing the version counter. The recovery PKE can be overwritten multiple times against the same account version. [2](#0-1) [3](#0-2) 

This contrasts with full account updates (`AccountMessageV0::Update`) which enforce strict version incrementing. [4](#0-3) 

**Exploit Scenario:**
1. Account owner initiates recovery with recovery_pke1 (state becomes: version N, rec.pke = Some(pke1))
2. Guardian 1 queries account state, sees rec.pke = Some(pke1), and calls `check_for_recovery`
3. Guardian 1 generates share encrypted for pke1 via `send_for_recovery` [5](#0-4) 
4. Before Guardian 1 uploads, owner initiates another recovery with recovery_pke2 (perhaps from a different device with another RIK)
5. State becomes: version N (unchanged!), rec.pke = Some(pke2)
6. Guardian 1 uploads share encrypted for pke1
7. Guardian 2 queries the updated state, sees rec.pke = Some(pke2), generates share for pke2
8. When uploading, shares pass verification because `backup.verify` only checks signature validity, not which PKE was used for encryption [6](#0-5) 
9. Owner attempts recovery with pke2's decryption key but cannot decrypt Guardian 1's share (encrypted for pke1)
10. If threshold requires both guardians, recovery fails permanently (unless guardians can be contacted to regenerate)

**Security Failure:** 
The system breaks the invariant that all guardian shares for a recovery session must be decryptable by a single recovery private key. This causes denial-of-service on account recovery operations.

## Impact Explanation

**Affected Assets:**
- Master Secret Key (MSK) becomes unrecoverable through the social recovery mechanism
- All secrets/backups protected by the account become inaccessible
- Account owner is permanently locked out (unless guardians can be re-contacted)

**Severity:**
- **Temporary DoS (Medium):** If guardians are online and responsive, they can re-query the current state and regenerate compatible shares
- **Permanent Lock-out (High):** If guardians are offline, unavailable, or cannot be reached through out-of-band channels, the account owner is permanently locked out, requiring intervention to recover access

**Why This Matters:**
The social recovery mechanism is the primary way for users to regain access to their accounts after losing their master secret key. Breaking this mechanism defeats the core security promise of the Swafe system. Users who depend on social recovery could lose access to all their encrypted secrets and funds.

## Likelihood Explanation

**Who Can Trigger:**
- Account owners with multiple RIKs (one per association) using different devices
- Legitimate users attempting recovery multiple times due to mistakes
- Does not require a malicious attacker—can occur through normal operations

**Required Conditions:**
- Account has recovery configured with guardians
- Multiple recovery initiation requests occur in close succession
- Guardians query account state during the race window

**Frequency:**
- Moderate to high likelihood in production:
  - Users naturally have multiple devices with different RIKs
  - Network latency creates natural race windows
  - Users may legitimately re-initiate recovery if they lose access to the first recovery key
  - No mechanism prevents or detects this race condition

## Recommendation

**Primary Fix:**
Increment the account version counter for Recovery messages, similar to full Updates:

```rust
AccountMessageV0::Recovery(recovery) => {
    let mut new_state = old.clone();
    
    // Increment version counter for recovery updates
    new_state.cnt = old.cnt.checked_add(1)
        .ok_or(SwafeError::InvalidAccountStateVersion)?;
    
    {
        let rec = &mut new_state.rec;
        // ... existing verification logic ...
        rec.pke = Some(recovery.pke);
    }
    Ok(new_state)
}
```

**Additional Safeguards:**
1. Add a check to prevent recovery re-initiation when `rec.pke` is already `Some` unless explicitly revoked through a full account update
2. Clear orphaned guardian shares when recovery PKE changes through a full update
3. Add version/PKE metadata to guardian shares to enable validation at retrieval time

## Proof of Concept

**Test File:** `lib/src/account/tests.rs`

**Test Function:** `test_concurrent_recovery_race_condition`

**Setup:**
1. Create an account with 3 guardians and threshold of 2
2. Setup recovery state with `update_recovery` and add two associations (RIK-A and RIK-B)
3. Generate initial account state

**Trigger:**
1. Initiate recovery using RIK-A, creating recovery_request_A with pke_A
2. Apply recovery_request_A to get state_with_pke_A (version N, rec.pke = Some(pke_A))
3. Guardian 1 queries state_with_pke_A and generates share_1 encrypted for pke_A
4. Initiate another recovery using RIK-B with pke_B against the ORIGINAL account state (before recovery_request_A)
5. Both recovery requests verify against the same original state (version N)
6. Apply recovery_request_B to get state_with_pke_B (version still N, rec.pke = Some(pke_B))
7. Guardian 2 queries state_with_pke_B and generates share_2 encrypted for pke_B
8. Upload both shares (both pass verification)
9. Attempt recovery using pke_B's decryption key

**Observation:**
The test should demonstrate that:
- Both recovery requests successfully verify against the same account version
- Guardian shares are encrypted for different PKEs
- Recovery attempt fails because share_1 (encrypted for pke_A) cannot be decrypted with pke_B's decryption key
- If threshold is 2, recovery is permanently blocked

The vulnerability is confirmed when guardian shares generated during the race window become incompatible, preventing successful recovery completion.

### Citations

**File:** lib/src/account/v0.rs (L792-793)
```rust
                if Some(st.cnt) != old.cnt.checked_add(1) {
                    return Err(SwafeError::InvalidAccountStateVersion);
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

**File:** lib/src/backup/v0.rs (L342-354)
```rust
    pub fn verify(&self, share: &GuardianShareV0) -> Result<u32, SwafeError> {
        if share.idx > self.comms.len() as u32 {
            return Err(SwafeError::InvalidShare);
        }
        self.comms[share.idx as usize].vk.verify(
            &share.sig,
            &SignedEncryptedShare {
                ct: &share.ct,
                idx: share.idx,
            },
        )?;
        Ok(share.idx)
    }
```
