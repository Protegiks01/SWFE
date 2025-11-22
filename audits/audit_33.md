# Audit Report

## Title
Recovery State Race Condition Allows Concurrent Recovery Overwrites and Denial of Service

## Summary
The recovery update mechanism in `AccountUpdateV0::verify_update()` does not increment the version counter and does not check if a recovery is already in progress before setting `rec.pke`. This allows multiple concurrent recovery requests for the same account to overwrite each other, causing denial of service and potential unauthorized account takeover when an account has multiple email associations. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- Primary vulnerability in `lib/src/account/v0.rs`, function `AccountUpdateV0::verify_update()`, specifically the Recovery message handler at lines 802-832
- The vulnerable state read occurs via `get_account()` in `contracts/src/lib.rs` at lines 121-124 during the `update_account` action [2](#0-1) 

**Intended Logic:** 
The system is designed to support "one recovery at a time" as documented, where an account owner initiates recovery using one of their associated emails/RIKs, and guardians process that single recovery request. The version counter (`cnt` field) should provide conflict detection for concurrent state modifications. [3](#0-2) 

**Actual Logic:** 
When processing a Recovery message type, the code:
1. Clones the old account state without incrementing the version counter
2. Unconditionally sets `rec.pke = Some(recovery.pke)` without checking if `rec.pke` is already `Some(_)`
3. Returns the modified state with the same `cnt` value as the old state

This differs from regular updates which require version counter increments and are protected by the check at line 792: [4](#0-3) 

**Exploit Scenario:**

1. Alice's account has two email associations (email1 with RIK1, email2 with RIK2) as permitted by the invariant "An account may have multiple emails associated for recovery"
2. Alice loses access and initiates recovery using email1:
   - Creates recovery update with `pke_alice`
   - Submits to blockchain via `update_account` action
   - State becomes: `cnt=5, rec.pke=Some(pke_alice)`
3. An attacker (Eve) who has compromised email2 (or a malicious account co-owner) initiates a second recovery:
   - Creates recovery update with `pke_eve` 
   - Both recovery updates have valid signatures from different associations
   - Submits to blockchain
4. When Eve's transaction is processed:
   - `get_account()` reads current state: `cnt=5, rec.pke=Some(pke_alice)`
   - `verify_update()` succeeds because the signature is valid and there's no check preventing overwrite
   - State becomes: `cnt=5, rec.pke=Some(pke_eve)` (overwrites Alice's recovery!)
5. Guardians now see `rec.pke=Some(pke_eve)` and re-encrypt shares for Eve's key
6. Alice cannot complete recovery because her `pke_alice` has been overwritten
7. Eve can complete recovery and gain control of the account/master secret key

**Security Failure:** 
This breaks multiple security invariants:
- Violates atomicity of recovery operations - the last recovery wins with no conflict detection
- Enables unauthorized account takeover when one association holder can override another's legitimate recovery
- Creates denial of service where malicious actors can repeatedly overwrite legitimate recovery attempts
- The version counter mechanism fails to provide the expected protection against concurrent modifications

## Impact Explanation

**Affected Assets:**
- Account master secret keys (MSK)
- Account ownership and control
- Guardian processing effort (wasted if recovery is overwritten)
- Recovery process integrity

**Severity of Damage:**
1. **Account Takeover**: An attacker with access to ANY one of the account's email associations can hijack a legitimate user's recovery attempt and gain control of the account's master secret key, leading to complete compromise
2. **Denial of Service**: Malicious parties can repeatedly initiate new recoveries to overwrite legitimate ones, permanently preventing the real account owner from recovering their account
3. **Guardian Resource Waste**: Guardians who process shares for an overwritten recovery have performed cryptographic operations that become useless
4. **State Inconsistency**: The `get_account` function exposes inconsistent states where different callers (guardians, HTTP endpoints) may see different `rec.pke` values depending on timing

**System Security Impact:**
This matters because it directly violates the documented invariant that "Only the owner of an email should be able to request the recovery of an account" - while technically both parties own valid emails, the design intent is that recoveries should not conflict or override each other. The lack of proper concurrency control undermines the entire recovery security model.

## Likelihood Explanation

**Trigger Conditions:**
- Any unprivileged user who has access to one of an account's associated emails (RIK) can trigger this
- The attack requires the target account to have multiple email associations, which is explicitly supported and encouraged by the protocol
- No special timing or privileged access is required beyond possessing a valid RIK

**Frequency:**
- **High likelihood in normal operations**: Legitimate users might accidentally trigger concurrent recoveries when trying to recover from different devices/emails
- **Intentional exploitation**: An attacker who compromises one of multiple associated emails can systematically DOS or hijack recoveries
- **Every multi-association account is vulnerable**: Given that accounts are designed to have multiple associations for redundancy, this affects a significant portion of users

**Real-world Scenario:**
- User loses device, starts recovery from email1
- User's family member (who has access to email2) also tries to help by starting recovery
- Second recovery overwrites the first
- Both become confused as the first recovery fails mysteriously
- An attacker monitoring the chain could opportunistically inject their own recovery

## Recommendation

Add two critical checks to the Recovery message handler in `verify_update()`:

1. **Prevent overwriting active recoveries**: Check if `rec.pke.is_some()` before allowing a new recovery to be initiated
2. **Increment version counter for recovery updates**: Ensure recovery state changes are tracked by the version counter for proper conflict detection

```rust
AccountMessageV0::Recovery(recovery) => {
    let mut new_state = old.clone();
    
    // NEW: Check if recovery is already in progress
    if new_state.rec.pke.is_some() {
        return Err(SwafeError::InvalidOperation(
            "Recovery already in progress, cannot initiate new recovery".to_string()
        ));
    }
    
    // NEW: Increment version counter for recovery updates
    new_state.cnt = old.cnt.checked_add(1)
        .ok_or(SwafeError::InvalidAccountStateVersion)?;
    
    // Existing verification logic...
    let recovery_msg = RecoveryRequestMessage { /* ... */ };
    // ... signature verification ...
    
    new_state.rec.pke = Some(recovery.pke);
    Ok(new_state)
}
```

This ensures:
- Only one recovery can be active at a time
- Version counter increments provide conflict detection
- Concurrent recovery attempts are properly rejected
- The `get_account` function will return consistent states protected by version control

## Proof of Concept

**File:** `lib/src/account/tests.rs`
**Test Function:** `test_concurrent_recovery_race_condition` (new test to be added)

**Setup:**
1. Create an account with 3 guardians (threshold 2)
2. Add two email associations (RIK1 and RIK2) to the account
3. Generate the initial account state

**Trigger:**
1. User initiates recovery with RIK1 → produces `recovery_update1` with `pke1`
2. Apply `recovery_update1` via `verify_update()` → state becomes `cnt=N, rec.pke=Some(pke1)`
3. Attacker initiates recovery with RIK2 → produces `recovery_update2` with `pke2`
4. Apply `recovery_update2` via `verify_update()` against the updated state from step 2

**Observation:**
The test should observe that:
- Both `verify_update()` calls succeed without error (vulnerability confirmed)
- After step 4, `rec.pke` equals `pke2` (not `pke1`), proving the overwrite occurred
- The version counter remains unchanged (`cnt=N` for both states)
- The first recovery's guardian shares become useless as they encrypted for `pke1`

The test demonstrates that the system allows concurrent recoveries to overwrite each other without any protection mechanism, violating the expected "one recovery at a time" invariant and enabling denial of service or account takeover attacks.

### Citations

**File:** lib/src/account/v0.rs (L230-238)
```rust
pub(crate) struct AccountStateV0 {
    cnt: u32, // current count of operations
    act: AccountCiphertext,
    pub(crate) rec: RecoveryStateV0,
    sig: sig::VerificationKey,
    pke: pke::EncryptionKey,
    backups: Vec<BackupCiphertext>, // backups to store
    recover: Vec<BackupCiphertext>, // backups to recover
}
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
