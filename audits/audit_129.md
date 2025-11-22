# Audit Report

## Title
Non-Atomic Cryptographic State Update in `update_recovery()` Leads to Permanent MSK Freezing

## Summary
The `update_recovery()` function in `lib/src/account/v0.rs` modifies the `msk_ss_social` secret share before validating that the subsequent `create_recovery()` operation can succeed. If `create_recovery()` fails (e.g., due to insufficient guardians), the account is left in an inconsistent state where the secret share and recovery backup are mismatched, causing permanent MSK freezing during recovery attempts. [1](#0-0) 

## Impact
**High**

## Finding Description

### Location
The vulnerability exists in the `update_recovery()` method of `AccountSecrets` at lines 532-554 in `lib/src/account/v0.rs`. [1](#0-0) 

### Intended Logic
The `update_recovery()` function should atomically update both the `msk_ss_social` secret share and the corresponding `recovery.social` backup ciphertext. These two values must remain synchronized because the MSK encryption key is derived from both the RIK and social secret shares, and the social backup must contain the matching secret share for successful recovery. [2](#0-1) 

### Actual Logic
The function performs non-atomic updates:
1. Line 539 sets the dirty flag to true
2. **Line 542 immediately overwrites `self.recovery.msk_ss_social` with a new random value**
3. Lines 545-552 attempt to call `create_recovery()` which can fail [3](#0-2) 

If `create_recovery()` fails (returning `Err(SwafeError::InsufficientShares)` when `guardians.len() < threshold`), the function propagates the error with the `?` operator at line 552. [4](#0-3) 

However, the `AccountSecrets` object is now in an inconsistent state:
- `msk_ss_social` = NEW random value (modified at line 542)
- `recovery.social` = OLD backup ciphertext (never updated due to failure)
- `dirty = true` (set at line 539)

### Exploit Scenario
1. User calls `update_recovery()` with invalid parameters (e.g., threshold=5, guardians.len()=3)
2. The function modifies `msk_ss_social` to a new random value
3. `create_recovery()` fails with `InsufficientShares` error
4. User receives the error but the `AccountSecrets` object remains in memory with inconsistent state
5. User calls `update()` to persist other changes or retries without reloading state
6. The `update()` function checks the dirty flag and creates an `AccountUpdate` with:
   - The NEW `msk_ss_social` (line 678)
   - The OLD `recovery.social` backup (line 714)
   - MSK encrypted with key derived from NEW secret shares (lines 692-701) [5](#0-4) 

7. This inconsistent state is uploaded to the contract and becomes permanent

### Security Failure
The core invariant violated is: **The `msk_ss_social` secret share must always match the secret share encrypted in the `recovery.social` backup ciphertext**. 

When this invariant is broken:
- During recovery, guardians decrypt shares from the OLD backup
- The user attempts to derive the MSK decryption key using both RIK share and the OLD social share from guardians
- But the on-chain encrypted MSK was sealed with a key derived from the NEW social share
- The `complete()` recovery function fails to decrypt the MSK, making it permanently unrecoverable [6](#0-5) 

## Impact Explanation

**Affected Assets:** The Master Secret Key (MSK), which is the core secret for the entire account.

**Severity:** The MSK becomes **permanently frozen and unrecoverable**. When the user attempts account recovery:
1. Guardians provide their shares decrypted from the `recovery.social` backup
2. These shares reconstruct the OLD `msk_ss_social` value
3. The recovery process derives the MSK decryption key using `derive_msk_decryption_key()` with the OLD social share
4. Decryption of `enc_msk` fails because it was encrypted with a key derived from the NEW social share
5. The MSK cannot be recovered through any means - requiring manual intervention or hard fork [7](#0-6) 

This directly satisfies the in-scope impact criterion: **"Permanent freezing of secrets or accounts (requiring a hard fork or intervention to fix)."**

## Likelihood Explanation

**Who can trigger it:** Any normal user during account recovery setup.

**Conditions required:** 
- User calls `update_recovery()` with invalid parameters where `threshold > guardians.len()`
- This is a common user error or can occur from client bugs
- After the error, user must call `update()` before reloading state from the contract

**Frequency:** 
- HIGH likelihood - This can easily occur through:
  - User mistake when configuring recovery thresholds
  - Client-side validation bugs
  - Race conditions in multi-step operations
  - No validation prevents uploading the inconsistent state

The vulnerability is particularly dangerous because:
1. The error message doesn't warn that state is corrupted
2. The dirty flag remains set, encouraging an `update()` call
3. No subsequent validation catches the mismatch
4. The corruption is silent until recovery is actually attempted

## Recommendation

**Fix: Make cryptographic operations atomic by deferring state modifications until all validations pass.**

Modify `update_recovery()` to:
1. Generate the new `msk_ss_social` in a local variable
2. Call `create_recovery()` with the local variable (not the stored field)
3. Only if `create_recovery()` succeeds, update both fields atomically:

```rust
pub fn update_recovery<R: Rng + CryptoRng>(
    &mut self,
    rng: &mut R,
    guardians: &[AccountState],
    threshold: usize,
) -> Result<()> {
    // Generate NEW social secret locally (don't modify self yet)
    let new_msk_ss_social = MskSecretShareSocial::gen(rng);
    
    // Generate new ciphertext (this can fail)
    let new_social = create_recovery(
        rng,
        self.acc,
        &self.recovery.msk_ss_rik,
        &new_msk_ss_social,  // Use local variable
        guardians,
        threshold,
    )?;  // If this fails, we haven't modified any state yet
    
    // Only now, after success, atomically update both fields
    self.dirty = true;
    self.recovery.msk_ss_social = new_msk_ss_social;
    self.recovery.social = new_social;
    Ok(())
}
```

This ensures that either both fields are updated consistently, or neither is modified (on error).

## Proof of Concept

**Test file:** `lib/src/account/tests.rs`

**Test function name:** `test_update_recovery_atomicity_violation`

**Setup:**
1. Create an `AccountSecrets` with `AccountSecrets::gen()`
2. Create 3 guardian accounts
3. Generate initial state with `state()` and `update()`

**Trigger:**
1. Call `update_recovery()` with threshold=5, guardians.len()=3 (intentionally invalid to trigger error)
2. Verify the call returns `Err(SwafeError::InsufficientShares)`
3. Call `update()` to create an AccountUpdate (this persists the inconsistent state)
4. Verify the update and extract the new state
5. Attempt to simulate recovery by:
   - Calling `initiate_recovery()` to start recovery
   - Having guardians generate shares with `check_for_recovery()`
   - Calling `complete()` with the guardian shares

**Observation:**
The test demonstrates that:
1. After the failed `update_recovery()` call, the account's `msk_ss_social` has changed (can verify by inspecting internal state)
2. The `recovery.social` backup still contains the OLD secret share
3. When recovery is attempted using guardian shares from the backup, the `complete()` function fails with decryption error
4. The MSK is permanently unrecoverable

The test confirms the atomicity violation by showing that partial state modifications persist even after an error, leading to permanent account corruption.

### Citations

**File:** lib/src/account/v0.rs (L145-162)
```rust
    pub fn complete(&self, shares: &[GuardianShare]) -> Result<MasterSecretKey> {
        // recover the social secret share from the backup
        let msk_ss_social: MskSecretShareSocial = match &self.rec.social {
            BackupCiphertext::V0(v0) => {
                v0.recover(&self.dkey, &self.msk_ss_rik, &EmptyInfo, shares)?
            }
        };

        // derive the MSK decryption key from both secret shares
        let msk_dec_key = derive_msk_decryption_key(
            &self.acc,
            &MskSecretShareRik::new(self.msk_ss_rik),
            &msk_ss_social,
        );

        // decrypt the MSK using the derived key
        sym::open(&msk_dec_key, &self.rec.enc_msk, &self.acc)
    }
```

**File:** lib/src/account/v0.rs (L329-358)
```rust
fn derive_msk_decryption_key(
    acc: &AccountId,
    msk_ss_rik: &MskSecretShareRik,
    msk_ss_social: &MskSecretShareSocial,
) -> sym::Key {
    // combine the two secret shares for KDF input
    #[derive(Serialize)]
    struct MskRecoveryShares {
        msk_ss_rik: sym::Key,
        msk_ss_social: sym::Key,
    }

    // info for KDF
    #[derive(Serialize)]
    struct MskRecoveryInfo<'a> {
        acc: &'a AccountId,
    }

    impl Tagged for MskRecoveryInfo<'_> {
        const SEPARATOR: &'static str = "v0:msk-recovery-kdf";
    }

    hash::kdfn(
        &MskRecoveryShares {
            msk_ss_rik: *msk_ss_rik.as_bytes(),
            msk_ss_social: *msk_ss_social.as_bytes(),
        },
        &MskRecoveryInfo { acc },
    )
}
```

**File:** lib/src/account/v0.rs (L532-554)
```rust
    pub fn update_recovery<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        guardians: &[AccountState],
        threshold: usize,
    ) -> Result<()> {
        // mark dirty
        self.dirty = true;

        // generate fresh "social secret"
        self.recovery.msk_ss_social = MskSecretShareSocial::gen(rng);

        // generate new ciphertext
        self.recovery.social = create_recovery(
            rng,
            self.acc,
            &self.recovery.msk_ss_rik,
            &self.recovery.msk_ss_social,
            guardians,
            threshold,
        )?;
        Ok(())
    }
```

**File:** lib/src/account/v0.rs (L634-724)
```rust
    /// Produce an update transaction to store the new state of the abstract account
    pub fn update<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<AccountUpdate> {
        // new version of the account state
        let cnt = if self.dirty { self.cnt + 1 } else { self.cnt };

        // generate *all* the associations
        // this hides which association is being updated/added/removed
        let assoc = self
            .recovery
            .assoc
            .iter()
            .map(|assoc| {
                // generate keys for recovery authorization
                let key_sig = sig::SigningKey::gen(rng);

                // create EncapV0 with the recovery key
                let encap = sym::seal(
                    rng,
                    assoc.rik.as_bytes(),
                    &EncapV0 {
                        key_sig: key_sig.clone(),
                        msk_ss_rik: self.recovery.msk_ss_rik.clone(),
                    },
                    self.acc(),
                );

                // create new AssociationsV0
                AssociationsV0 {
                    sig: key_sig.verification_key(),
                    encap,
                }
            })
            .collect();

        // encrypt the secret state
        let act = AccountCiphertext(sym::seal(
            rng,
            self.msk.as_bytes(),
            &CombinedSecret::V0(CombinedSecretV0 {
                sig: self.sig.clone(),
                pke: self.pke.clone(),
                old_msk: self.old_msk.clone(),
                old_pke: self.old_pke.clone(),
                recovery: RecoverySecretV0 {
                    msk_ss_social: self.recovery.msk_ss_social.clone(),
                    msk_ss_rik: self.recovery.msk_ss_rik.clone(),
                    guardians: self.recovery.guardians.clone(),
                    threshold: self.recovery.threshold,
                    assoc: self.recovery.assoc.clone(),
                },
            }),
            &AccountStateV0Ad {
                account_id: self.acc,
                version: cnt,
            },
        ));

        // derive MSK decryption key and encrypt MSK
        let enc_msk = sym::seal(
            rng,
            &derive_msk_decryption_key(
                self.acc(),
                &self.recovery.msk_ss_rik,
                &self.recovery.msk_ss_social,
            ),
            &self.msk,
            self.acc(),
        );

        let st = AccountStateV0 {
            cnt,
            backups: self.backups.clone(),
            recover: self.recover.clone(),
            pke: self.pke.encryption_key(),
            sig: self.sig.verification_key(),
            act,
            rec: RecoveryStateV0 {
                pke: None,
                assoc,
                // TODO: unfortunately we cannot generate this anew every time
                social: self.recovery.social.clone(),
                enc_msk,
            },
        };

        let sig = self.old_sig.sign(rng, &st);
        Ok(AccountUpdate::V0(AccountUpdateV0 {
            acc: self.acc,
            msg: AccountMessageV0::Update(AccountUpdateFullV0 { sig, state: st }),
        }))
    }
```

**File:** lib/src/backup/v0.rs (L365-370)
```rust
        // check if there are enough guardians to meet the threshold
        // note that the threshold MAY be 0: in which case
        // only the msk is required to recover the secret
        if guardians.len() < threshold {
            return Err(SwafeError::InsufficientShares);
        }
```
