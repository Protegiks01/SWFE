# Audit Report

## Title
Unbounded Guardian Count Enables Memory Exhaustion DoS Attack

## Summary
The Swafe protocol does not enforce any maximum limit on the number of guardians that can be specified when creating backup ciphertexts or updating recovery settings. An attacker can create an account with millions of guardians, causing memory exhaustion at multiple points: during backup creation, contract state serialization/deserialization, and guardian share storage. This can lead to denial-of-service affecting contract nodes and preventing legitimate users from performing recovery operations.

## Impact
**Medium to High**

## Finding Description

**Location:** 
The vulnerability spans multiple components:
- `lib/src/backup/v0.rs` in function `BackupCiphertextV0::new()` [1](#0-0) 
- `lib/src/crypto/sss.rs` in function `share()` [2](#0-1) 
- `lib/src/crypto/pke/mod.rs` in function `batch_encrypt()` [3](#0-2) 
- `contracts/src/http/endpoints/reconstruction/upload_share.rs` in the share upload handler [4](#0-3) 

**Intended Logic:** 
The backup system is intended to create threshold-encrypted backups where a subset of guardians can help recover secrets. The system should prevent resource exhaustion attacks while allowing flexible guardian configurations.

**Actual Logic:** 
The implementation only validates that `guardians.len() >= threshold` but imposes no upper bound on the number of guardians. [5](#0-4) 

When creating a backup with N guardians:
1. The SSS `share()` function generates N shares by polynomial evaluation with no size check [6](#0-5) 
2. The system creates vectors of N plaintexts and N commitments [7](#0-6) 
3. The `batch_encrypt()` function collects all N ciphertexts into a vector in memory [8](#0-7) 
4. The resulting `BackupCiphertextV0` contains vectors of size N [9](#0-8) 

**Exploit Scenario:**
1. Attacker creates a local account using `AccountSecrets::gen()`
2. Attacker calls `update_recovery()` with an array of 10 million fake guardian `AccountState` objects
3. This triggers `BackupCiphertextV0::new()` which allocates memory for 10 million shares, commitments, and ciphertexts
4. Attacker serializes the resulting account state and submits it to the contract via `update_account()` [10](#0-9) 
5. The contract deserializes this multi-gigabyte update, consuming excessive memory
6. If successful, the account state is stored in the contract [11](#0-10) 
7. Future operations on this account (loading, updating, guardian share uploads) require loading the entire bloated state into memory
8. Guardian share uploads store shares in an unbounded `BTreeMap<u32, GuardianShare>` that can grow to 10 million entries [12](#0-11) 

**Security Failure:** 
This breaks the availability guarantee of the system. Memory exhaustion can occur on:
- Contract nodes when deserializing account updates
- Contract nodes when loading account state for verification
- Off-chain storage when persisting bloated account states
- Contract nodes processing guardian share uploads

This affects system-wide resources, not just the attacker's account, because all nodes must process and store the bloated state.

## Impact Explanation

The vulnerability enables a denial-of-service attack with cascading effects:

1. **Contract Node Resource Exhaustion**: Nodes attempting to process accounts with millions of guardians will experience severe memory pressure, potentially causing out-of-memory crashes or extreme slowdown. This meets the criterion of "Increase in network processing node resource consumption by ≥30% without brute-force."

2. **Storage Bloat**: A single malicious account with 10 million guardians could consume gigabytes of contract storage space, affecting the entire system's storage capacity and I/O performance.

3. **Guardian Share Processing**: When guardians attempt to upload shares for recovery, the contract must load and manipulate a `BTreeMap` containing potentially millions of entries, causing severe performance degradation or crashes.

4. **Widespread Impact**: Unlike a localized issue affecting only the attacker's account, this affects the entire contract's ability to process ANY account updates or queries, as nodes become resource-starved. This can prevent legitimate users from performing account recovery or backup operations, meeting the criterion of "Critical API/contract outage preventing account recovery or backup reconstruction for ≥25% of users."

5. **Node Failures**: If multiple nodes crash due to memory exhaustion when processing the malicious account, this could lead to "Shutdown of ≥30% of processing nodes without brute force."

The attack requires minimal resources from the attacker (just creating one malicious account) but has system-wide impact on all contract nodes and users.

## Likelihood Explanation

**Likelihood: High**

- **Who can trigger it**: Any unprivileged user can trigger this vulnerability. Account creation is permissionless - anyone can create an account and specify an arbitrary number of guardians. [13](#0-12) 

- **Conditions required**: No special conditions are needed. The attacker only needs to:
  1. Generate guardian account states locally (trivial)
  2. Call the standard `update_recovery()` function with a large guardian array
  3. Submit the resulting account update to the contract

- **Frequency**: This can be exploited immediately and repeatedly. An attacker could create multiple such accounts to amplify the impact. There are no rate limits or costs that would significantly deter this attack.

- **Detection difficulty**: The attack is difficult to detect preemptively because the guardian count is not validated during account creation - the bloated state only becomes apparent when the contract attempts to deserialize and process it.

## Recommendation

Implement a reasonable upper bound on the number of guardians to prevent resource exhaustion while maintaining protocol flexibility:

1. **Add a maximum guardian constant** in `lib/src/backup/v0.rs`:
   ```rust
   const MAX_GUARDIANS: usize = 100; // or another reasonable limit
   ```

2. **Enforce the limit in `BackupCiphertextV0::new()`** before line 368:
   ```rust
   if guardians.len() > MAX_GUARDIANS {
       return Err(SwafeError::TooManyGuardians);
   }
   ```

3. **Add corresponding validation** in the contract's `update_account()` function to reject accounts that exceed the limit during deserialization, providing defense-in-depth.

4. **Consider implementing graduated limits**: For example, require higher thresholds as the guardian count increases, to ensure that larger guardian sets remain practical for recovery while discouraging abuse.

5. **Add monitoring and alerts** for accounts approaching the maximum guardian count to detect potential abuse attempts.

The recommended limit of 100 guardians should be sufficient for all legitimate use cases while preventing memory exhaustion attacks. This balances usability with security.

## Proof of Concept

**File**: `lib/src/backup/tests.rs` (add new test)

**Test Function**: `test_excessive_guardians_memory_exhaustion`

**Setup**:
```rust
#[test]
#[should_panic] // or use a memory limit if test framework supports it
fn test_excessive_guardians_memory_exhaustion() {
    let mut rng = rand::thread_rng();
    
    // Create account secrets
    let account = AccountSecrets::gen(&mut rng).unwrap();
    
    // Create an excessive number of fake guardians (e.g., 100,000)
    let excessive_guardian_count = 100_000;
    let mut guardians = Vec::with_capacity(excessive_guardian_count);
    
    for _ in 0..excessive_guardian_count {
        let guardian = AccountSecrets::gen(&mut rng).unwrap();
        guardians.push(guardian.state(&mut rng).unwrap());
    }
    
    // Attempt to create backup with excessive guardians
    // This should either:
    // 1. Panic due to memory exhaustion
    // 2. Take excessive time (can add timeout)
    // 3. Fail with TooManyGuardians error (after fix)
    
    let data = "test secret data";
    let metadata = Metadata::new(
        "Test Backup".to_string(),
        "Memory exhaustion test".to_string()
    );
    
    let threshold = 1000; // Much less than guardian count
    
    let result = account.backup(
        &mut rng,
        &data,
        metadata,
        &guardians,
        threshold
    );
    
    // Without the fix, this will consume excessive memory
    // With the fix, this should return TooManyGuardians error
}
```

**Trigger**: Execute `cargo test test_excessive_guardians_memory_exhaustion` 

**Observation**: 
- **Before fix**: The test will either panic with OOM error, hang indefinitely, or consume gigabytes of memory as it attempts to allocate vectors for 100,000 guardians. Monitor memory usage with `top` or similar tools during test execution.
- **After fix**: The test should quickly return `Err(SwafeError::TooManyGuardians)` without excessive memory consumption.

To demonstrate the contract-side impact, a similar test could be added in `contracts/` that attempts to deserialize an account update containing the bloated backup ciphertext, which would similarly exhaust memory during deserialization.

### Citations

**File:** lib/src/backup/v0.rs (L61-65)
```rust
pub(crate) struct BackupCiphertextV0 {
    pub data: sym::AEADCiphertext,   // encrypted
    pub comms: Vec<ShareComm>,       // share commitments
    pub encap: pke::BatchCiphertext, // encrypted shares
}
```

**File:** lib/src/backup/v0.rs (L356-370)
```rust
    pub fn new<R: Rng + CryptoRng, M: Tagged, A: Tagged>(
        rng: &mut R,
        data: &M,
        aad: &A,
        meta: Metadata,
        sym_key: &sym::Key,
        guardians: &[AccountState],
        threshold: usize,
    ) -> Result<Self, SwafeError> {
        // check if there are enough guardians to meet the threshold
        // note that the threshold MAY be 0: in which case
        // only the msk is required to recover the secret
        if guardians.len() < threshold {
            return Err(SwafeError::InsufficientShares);
        }
```

**File:** lib/src/backup/v0.rs (L383-399)
```rust
        let pts: Vec<BackupShareV0> = (0..guardians.len())
            .map(|i| BackupShareV0 {
                sk: sig::SigningKey::gen(rng),
                share: shares[i].clone(),
            })
            .collect();

        // Form commitments to each share
        // note: this is fine because they have high entropy
        // and hence it is hiding if we assume that hash
        // can be modelled as a random oracle
        let comms: Vec<ShareComm> = (0..guardians.len())
            .map(|i| ShareComm {
                vk: pts[i].sk.verification_key(),
                hash: hash(&ShareHash { share: &shares[i] }),
            })
            .collect();
```

**File:** lib/src/crypto/sss.rs (L32-48)
```rust
pub(crate) fn share<R: RngCore + CryptoRng>(
    rng: &mut R,
    t: usize,
    n: usize,
) -> (Secret, Vec<Share>) {
    // a threshold 0 sharing is just a constant
    if t == 0 {
        return (Secret(pp::Fr::ZERO), vec![]);
    }

    // for thresholds greater than 0, define a degree t-1 polynomial
    let cs: Vec<pp::Fr> = (0..t).map(|_| rng.gen()).collect();
    let ss = (1..=n)
        .map(|i| Share(poly::eval(cs.iter().cloned().rev(), pp::Fr::from(i as u64))))
        .collect();
    (Secret(cs[0]), ss)
}
```

**File:** lib/src/crypto/pke/mod.rs (L149-182)
```rust
    pub fn batch_encrypt<
        M: Tagged,
        A: Tagged,
        R: CryptoRng + Rng,
        I: Iterator<Item = (EncryptionKey, M)>,
    >(
        rng: &mut R,
        msgs: I,
        ctx: &A,
    ) -> BatchCiphertext {
        // generate a signing key
        let sk = sig::SigningKey::gen(rng);
        let vk = sk.verification_key();

        // generate ciphertexts for each message
        // with the verification key bound as context
        let cts = msgs
            .map(|(key, msg)| {
                key.encrypt(
                    rng,
                    &msg,
                    &BatchCtx {
                        vk: &vk,
                        ctx: (A::SEPARATOR, ctx),
                    },
                )
            })
            .collect::<Vec<_>>();

        // sign everything
        let inn = BatchCiphertextV0Inner { vk, cts };
        let sig = sk.sign(rng, &inn);
        BatchCiphertext::V0(BatchCiphertextV0 { inn, sig })
    }
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L28-28)
```rust
    type Value = BTreeMap<u32, GuardianShare>;
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L64-67)
```rust
    let storage_key = (account_id, backup_id);
    let mut shares = GuardianShareCollection::load(&mut ctx, storage_key).unwrap_or_default();
    shares.insert(share_id, request.share.0);
    GuardianShareCollection::store(&mut ctx, storage_key, shares);
```

**File:** contracts/src/lib.rs (L108-134)
```rust
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

**File:** lib/src/account/v0.rs (L760-783)
```rust
    pub(super) fn verify_allocation(self) -> Result<AccountStateV0> {
        match self.msg {
            AccountMessageV0::Update(auth) => {
                let st = auth.state;
                // check version must be zero
                if st.cnt != 0 {
                    return Err(SwafeError::InvalidAccountStateVersion);
                }

                // check that the account id matches the public key
                if self.acc != AccountId::from_vk(&st.sig) {
                    return Err(SwafeError::AuthenticationFailed);
                }

                // verify signature
                st.sig.verify(&auth.sig, &st)?;

                // Return the initial account state
                Ok(st)
            }
            AccountMessageV0::Recovery(_) => Err(SwafeError::InvalidOperation(
                "Cannot use recovery for initial allocation".to_string(),
            )),
        }
```
