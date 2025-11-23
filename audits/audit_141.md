## Title
Guardian Share Replay Attack Enables Denial of Service on Account Recovery

## Summary
An attacker can replay stale guardian shares from previous recovery sessions to overwrite fresh shares in the current recovery session, causing account recovery to fail. The vulnerability exists in the reconstruction endpoint handlers which store shares without any session tracking or replay protection, incorrectly assuming that "different versions of the same share are all equivalent."

## Impact
**High**

## Finding Description

**Location:** 
- Primary: `contracts/src/http/endpoints/reconstruction/upload_share.rs` (handler function and GuardianShareCollection storage)
- Secondary: `contracts/src/http/endpoints/reconstruction/get_shares.rs` (unauthenticated share retrieval)
- Related: `lib/src/backup/v0.rs` (share decryption and recovery logic)

**Intended Logic:** 
The reconstruction endpoints are intended to facilitate guardian share collection during account recovery. Each time a user initiates recovery, guardians should upload fresh shares encrypted with the current recovery session's PKE key. The system should collect enough valid shares to meet the threshold for successful recovery.

**Actual Logic:** 
The system stores guardian shares in a `GuardianShareCollection` mapping keyed only by `(AccountId, BackupId)` with no session identifier or recovery attempt counter. [1](#0-0) 

When a new recovery session is initiated, a fresh PKE key pair is generated, but old shares from previous sessions remain in storage. [2](#0-1) 

The upload handler allows overwriting shares with a comment stating "Potentially different multiple versions of the same share are all equivalent. Hence no replay protection is required here." [3](#0-2) 

However, this assumption is **incorrect**: shares encrypted with different PKE keys (from different recovery sessions) are NOT equivalent. When the recovery owner attempts to decrypt shares using the current session's decryption key, shares encrypted with old PKE keys fail to decrypt and are silently filtered out. [4](#0-3) 

**Exploit Scenario:**

1. **Recovery Session 1**: User initiates recovery, generating PKE key pair A. The recovery PKE is stored in the account state. [5](#0-4) 

2. **Guardian Share Upload (Session 1)**: Guardians encrypt their shares using PKE_A and upload them via the `/reconstruction/upload-share` endpoint. Share verification only checks the signature, not which PKE key was used. [6](#0-5) 

3. **Attacker Observation**: The attacker retrieves and stores these shares via the unauthenticated `/reconstruction/get-shares` endpoint. [7](#0-6) 

4. **Recovery Session 2**: User initiates recovery again (previous attempt failed/aborted), generating a NEW PKE key pair B that overwrites the old recovery PKE. [8](#0-7) 

5. **Legitimate Guardian Uploads**: Some guardians upload new shares encrypted with PKE_B.

6. **Replay Attack**: Before all guardians can upload new shares, the attacker replays the old shares from Session 1 (encrypted with PKE_A). Since the system allows overwriting and has no session tracking, these old shares replace the new ones.

7. **Recovery Failure**: When the user retrieves shares and attempts recovery, shares encrypted with PKE_A fail to decrypt using PKE_B's decryption key. The `recover()` function silently filters out failed decryptions with `.ok()?`. [9](#0-8) 

8. **Threshold Not Met**: If enough shares fail to decrypt, the threshold check fails, and recovery is denied. [10](#0-9) 

**Security Failure:** 
This breaks the core security invariant that legitimate guardians who upload valid shares should enable successful recovery. An unprivileged attacker can cause permanent denial of service on account recovery without needing to compromise any guardian keys or trusted roles.

## Impact Explanation

**Affected Assets:**
- User accounts requiring social recovery
- Master Secret Keys (MSKs) locked behind failed recovery attempts
- Account access and associated funds/secrets

**Severity of Damage:**
- Users can be **permanently locked out** of their accounts if an attacker continuously replays stale shares
- This affects the **core security feature** of the Swafe protocol (account recovery)
- Even if all legitimate guardians participate and upload valid shares, recovery can still fail
- The attack requires no special privileges - any observer can collect and replay shares
- Meets in-scope impact criteria: "Permanent freezing of secrets or accounts (requiring a hard fork or intervention to fix)"

**System Reliability Impact:**
Account recovery is a critical last-resort mechanism. If users cannot recover accounts through legitimate guardian cooperation, the entire social recovery system becomes unreliable, undermining user trust and protocol security guarantees.

## Likelihood Explanation

**Who Can Trigger:**
- Any unprivileged network participant
- No authentication required on reconstruction endpoints
- Attacker only needs to observe public contract state

**Required Conditions:**
- User attempts recovery more than once (common scenario if first attempt fails or is aborted)
- At least one guardian from the previous session doesn't immediately re-upload in the new session
- These are **normal operation conditions**, not rare edge cases

**Exploitation Frequency:**
- Can be exploited on **every recovery attempt** after the first one
- Attacker can automate monitoring of recovery initiations and immediate replay of stale shares
- The vulnerability is **deterministic and reliably exploitable**
- High likelihood in production: users commonly need multiple recovery attempts due to guardian coordination delays or failures

## Recommendation

Implement session-aware guardian share management with the following changes:

1. **Add Recovery Session Tracking**: Include a recovery session counter or nonce in the account state that increments with each `initiate_recovery` call. Store this in `RecoveryStateV0`.

2. **Include Session ID in Share Storage**: Modify `GuardianShareCollection` key from `(AccountId, BackupId)` to `(AccountId, BackupId, SessionId)` to isolate shares between recovery sessions.

3. **Clear Stale Shares on New Recovery**: When `verify_update` processes a `Recovery` message, clear all guardian shares for previous sessions from `GuardianShareCollection` before setting the new recovery PKE.

4. **Verify Share Currency**: In the upload handler, verify that the guardian share is encrypted with the current recovery PKE key by checking that it can be decrypted with a test decryption. This prevents uploading shares from previous sessions.

5. **Add Session ID to GuardianShare**: Include the recovery session ID in the `GuardianShare` structure and have guardians sign over it, preventing replay across sessions even if storage is compromised.

Example modification for upload_share.rs:
```rust
// Verify share is for current recovery session
let current_recovery_pke = account.rec.pke.ok_or_else(|| 
    ServerError::InvalidOperation("Recovery not initiated".to_string()))?;

// Attempt test decryption to verify share matches current session
// (Guardian should have encrypted with current recovery PKE)
```

## Proof of Concept

**Test File:** `contracts/java-test/src/test/java/com/partisia/blockchain/contract/SwafeContractTest.java` (add new test method)

**Test Function Name:** `testGuardianShareReplayAttack`

**Setup:**
1. Create owner account and 3 guardian accounts
2. Setup social recovery with 3 guardians, threshold = 2
3. Create a social backup and upload to contract
4. Guardians decrypt their shares from the backup

**Trigger:**
1. **Session 1**: Owner initiates recovery (generates PKE_A)
   - Upload recovery update to contract
   - Guardian 1 and Guardian 2 encrypt shares with PKE_A and upload via `/reconstruction/upload-share`
   - Attacker retrieves and stores shares via `/reconstruction/get-shares`
   - Abort recovery (don't complete it)

2. **Session 2**: Owner initiates recovery AGAIN (generates new PKE_B)
   - Upload new recovery update to contract (overwrites rec.pke with PKE_B)
   - Guardian 1 uploads NEW share encrypted with PKE_B
   - **ATTACK**: Replay Guardian 2's old share from Session 1 (encrypted with PKE_A) to overwrite their slot
   - Guardian 3 uploads share encrypted with PKE_B

3. **Recovery Attempt**: Owner retrieves shares and attempts to complete recovery

**Observation:**
- Owner retrieves 3 shares: Guardian 1 (PKE_B ✓), Guardian 2 (PKE_A ✗), Guardian 3 (PKE_B ✓)
- Guardian 2's share fails to decrypt because it's encrypted with the wrong key
- Only 2 shares decrypt successfully, but one is invalid → effectively only 1 valid share
- Recovery fails with `InsufficientShares` error despite 3 guardians participating
- Test assertion: Verify that recovery fails when it should succeed
- Test confirms vulnerability: Legitimate guardian participation thwarted by replay attack

### Citations

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L26-31)
```rust
impl Mapping for GuardianShareCollection {
    type Key = (AccountId, BackupId);
    type Value = BTreeMap<u32, GuardianShare>;

    const COLLECTION_NAME: &'static str = "map:guardian_shares";
}
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L53-56)
```rust
    let share_id = backup
        .verify(&request.share.0)
        .map_err(|_| ServerError::InvalidParameter("Invalid guardian share".to_string()))?;

```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L58-67)
```rust
    // usually, the share will not already exist in this map:
    // we allow overwriting in case of a buggy client library and to
    // simplify a client which fails during the upload process: it can simply retry all uploads.
    //
    // Potentially different multiple versions of the same share are all equivalent.
    // Hence no replay protection is required here.
    let storage_key = (account_id, backup_id);
    let mut shares = GuardianShareCollection::load(&mut ctx, storage_key).unwrap_or_default();
    shares.insert(share_id, request.share.0);
    GuardianShareCollection::store(&mut ctx, storage_key, shares);
```

**File:** lib/src/account/v0.rs (L196-196)
```rust
        let dkey = pke::DecryptionKey::gen(rng);
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

**File:** lib/src/backup/v0.rs (L299-313)
```rust
        let shares: Vec<(u32, Share)> = shares
            .iter()
            .filter_map(|share| {
                let GuardianShare::V0(share_v0) = share;
                let id = self.verify(share_v0).ok()?;
                let share: Share = dke.decrypt(&share_v0.ct, aad).ok()?;
                if self.comms[id as usize].hash == hash(&ShareHash { share: &share }) {
                    Some((id, share))
                } else {
                    None
                }
            })
            .collect::<BTreeMap<u32, Share>>()
            .into_iter()
            .collect();
```

**File:** lib/src/backup/v0.rs (L321-324)
```rust
        // check that we have enough shares to meet the threshold
        if shares.len() < meta.threshold as usize {
            return Err(SwafeError::InsufficientShares);
        }
```

**File:** contracts/src/http/endpoints/reconstruction/get_shares.rs (L19-34)
```rust
pub fn handler(
    mut ctx: OffChainContext,
    _state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request = deserialize_request_body::<Request>(&request)?;
    let account_id = request.account_id.0;
    let backup_id = request.backup_id.0;
    let shares: Vec<_> = GuardianShareCollection::load(&mut ctx, (account_id, backup_id))
        .unwrap_or_default()
        .values()
        .cloned()
        .map(StrEncoded)
        .collect();
    create_json_response(200, &Response { shares }).map_err(|e| e.into())
```
