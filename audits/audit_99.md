# Audit Report

## Title
Missing Owner Verification in DecryptedShareV0::send() Allows Shares to be Encrypted for Arbitrary Accounts

## Summary
The `DecryptedShareV0::send()` function does not verify that the `owner` parameter corresponds to the account that created the backup. This allows guardian shares to be encrypted for arbitrary accounts instead of the legitimate backup owner, leading to permanent freezing of backups if enough guardians are tricked into using the wrong owner state. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** The vulnerability exists in `lib/src/backup/v0.rs`, specifically in the `DecryptedShareV0::send()` method at lines 132-152.

**Intended Logic:** When a guardian decrypts their share and prepares to send it to the owner during backup recovery, the share should be encrypted specifically for the account owner who created the backup. The system knows the owner's `AccountId` during the `decrypt_share_backupy()` call (used as AAD), and this binding should be preserved to ensure shares can only be encrypted for the correct owner. [2](#0-1) 

**Actual Logic:** The `DecryptedShareV0` structure does not store the owner's `AccountId`, even though this information is available during decryption. The `send()` function accepts an arbitrary `AccountState` parameter and blindly encrypts the share using `owner.encryption_key()` without verifying that this `AccountState` belongs to the actual backup owner. [3](#0-2) 

The guardian's decrypted share structure only contains the share index and the `BackupShareV0`, with no reference to which account owns the backup.

**Exploit Scenario:**
1. Alice creates a backup with guardians G1, G2, G3 (threshold=2) and her `AccountId` is bound to the backup via AAD during creation
2. Alice loses access and initiates recovery, requesting shares from guardians
3. Attacker Mallory intercepts communications or social engineers the guardians
4. Mallory provides guardians with Mallory's `AccountState` instead of Alice's `AccountState`
5. G1 and G2 successfully decrypt their shares using `decrypt_share_backupy(alice_id, backup)` - this works because the correct `AccountId` is provided
6. However, G1 and G2 then call `share.send(rng, mallory_state)` with the wrong `AccountState`
7. The shares are encrypted using Mallory's encryption key instead of Alice's
8. G1 and G2 upload these shares to the contract endpoint [4](#0-3) 

9. The contract verifies the shares' signatures (which are valid since they're signed by the guardian's keys) and accepts them
10. When Alice attempts recovery and fetches the shares, she cannot decrypt them because they were encrypted for Mallory's key
11. The recovery process filters out undecryptable shares [5](#0-4) 

12. If enough guardians (≥ n-t+1) send wrongly encrypted shares, Alice cannot meet the threshold and recovery permanently fails

**Security Failure:** This breaks the fundamental invariant that "only the owner of an account should be able to request the reconstruction of a backup." While the shares themselves are still valid and properly signed, they become unusable by the legitimate owner, effectively causing a permanent denial of service on backup recovery.

## Impact Explanation

**Assets Affected:** The backup secrets (which could be the user's `MasterSecretKey` or other critical data) become permanently inaccessible to the legitimate owner.

**Severity:** This leads to permanent freezing of secrets, which is explicitly listed as HIGH severity in the contest scope. Once shares are uploaded with incorrect encryption, there is no mechanism to:
- Detect that shares are encrypted for the wrong owner until recovery time
- Recover the shares since they're encrypted for someone else's key
- Re-request shares from guardians who may no longer have their decrypted shares

The backup becomes permanently unrecoverable if n-t+1 or more guardians encrypt for the wrong account, as the owner cannot reach the required threshold.

**System Impact:** This vulnerability undermines the entire social recovery mechanism. Users who rely on backup recovery would lose access to their accounts and secrets permanently, with no way to recover without guardian cooperation and the guardians still having access to their original encrypted shares from the backup.

## Likelihood Explanation

**Who Can Trigger:** Any attacker who can:
- Intercept or manipulate communications between the owner and guardians
- Social engineer guardians into using a malicious `AccountState`
- Exploit buggy guardian client implementations that don't properly verify the owner

**Conditions Required:**
- The owner must initiate a backup recovery
- Guardians must be contacted to send shares
- The attacker must successfully provide the wrong `AccountState` to guardians
- Enough guardians (≥ n-t+1) must use the wrong `AccountState`

**Frequency:** While this requires social engineering or interception of guardian communications, it's a realistic attack vector because:
- Guardians are typically friends/family who may not be security experts
- The protocol provides no cryptographic way for guardians to verify the `AccountState` belongs to the correct owner
- Guardian client applications could have bugs that accidentally use the wrong `AccountState`
- The vulnerability could be exploited whenever recovery is needed, which is a critical moment when users are already in distress

## Recommendation

**Fix Strategy:** Add owner verification to the `send()` function by storing the owner's `AccountId` in `DecryptedShareV0` and verifying it matches the provided `AccountState`.

**Specific Changes:**

1. Modify `DecryptedShareV0` to store the owner's `AccountId`:
```rust
pub(crate) struct DecryptedShareV0 {
    pub idx: u32,
    pub share: BackupShareV0,
    pub owner: AccountId,  // Add this field
}
```

2. Update `decrypt_share` to include the owner in the returned share: [6](#0-5) 

3. Modify `send()` to verify the owner:
```rust
pub fn send<R: Rng + CryptoRng>(
    &self,
    rng: &mut R,
    owner: &AccountState,
) -> Result<GuardianShare, SwafeError> {
    // Verify the AccountState belongs to the expected owner
    // by checking if the derived AccountId matches
    let expected_owner_vk = /* derive from owner.sig field */;
    let provided_owner_id = AccountId::from_verification_key(&expected_owner_vk);
    
    if provided_owner_id != self.owner {
        return Err(SwafeError::InvalidOwner);
    }
    
    // ... rest of existing logic
}
```

Alternatively, have `send()` take an `AccountId` parameter and verify it matches the stored owner before encrypting.

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** `test_send_to_wrong_owner`

**Setup:**
1. Create three accounts: owner (Alice), guardian (G1), and attacker (Mallory)
2. Alice creates a backup with G1 as guardian (threshold=1)
3. G1 successfully decrypts their share using `decrypt_share_backupy(alice_id, backup)`

**Trigger:**
4. G1 calls `share.send(rng, mallory_state)` with Mallory's `AccountState` instead of Alice's
5. The function succeeds and returns a `GuardianShare` encrypted for Mallory

**Observation:**
6. When Alice attempts to recover using the wrongly encrypted share, decryption fails
7. The share is filtered out during recovery's `filter_map` operation
8. Alice cannot recover her backup despite having a valid share from G1

The test demonstrates that:
- No error is raised when encrypting for the wrong owner
- The legitimate owner cannot decrypt shares meant for them
- The recovery process silently fails if all shares are encrypted for the wrong account

This confirms the vulnerability: shares can be encrypted for arbitrary accounts, leading to permanent backup unavailability for the legitimate owner.

**Notes**

The vulnerability stems from a design flaw where the owner's `AccountId` is used as AAD during share decryption but is not preserved in the resulting `DecryptedShareV0` structure. While the `AccountState` structure does not directly contain an `AccountId` field, the protocol could derive the expected `AccountId` from the account's verification key and compare it against the stored owner value to prevent this attack. The contract-level signature verification alone is insufficient, as it only validates that shares were signed by valid guardians, not that they're encrypted for the correct recipient.

### Citations

**File:** lib/src/backup/v0.rs (L125-130)
```rust
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct DecryptedShareV0 {
    pub idx: u32,
    pub share: BackupShareV0,
}

```

**File:** lib/src/backup/v0.rs (L132-152)
```rust
    pub fn send<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        owner: &AccountState,
    ) -> Result<GuardianShare, SwafeError> {
        let ct = owner
            .encryption_key()
            .encrypt(rng, &self.share.share, &EmptyInfo);
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

**File:** lib/src/backup/v0.rs (L297-313)
```rust
        // Verify and decrypt each share
        // Ignore invalid and duplicate shares
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

**File:** lib/src/account/v0.rs (L556-562)
```rust
    pub fn decrypt_share_backupy(
        &self,
        acc: AccountId,
        backup: &BackupCiphertext,
    ) -> Option<SecretShare> {
        self.decrypt_share(&AADBackup { acc }, backup)
    }
```

**File:** lib/src/account/v0.rs (L572-603)
```rust
    fn decrypt_share<A: Tagged>(&self, aad: &A, backup: &BackupCiphertext) -> Option<SecretShare> {
        fn decrypt_v0<A: Tagged>(
            v0: &BackupCiphertextV0,
            aad: &A,
            pke: &crate::crypto::pke::DecryptionKey,
        ) -> Option<SecretShare> {
            let (data, index) = pke
                .decrypt_batch::<BackupShareV0, _>(
                    &v0.encap,
                    &EncryptionContext {
                        aad: (A::SEPARATOR, aad),
                        data: &v0.data,
                        comms: &v0.comms,
                    },
                )
                .ok()?;

            Some(SecretShare::V0(DecryptedShareV0 {
                idx: index as u32,
                share: data,
            }))
        }

        match backup {
            BackupCiphertext::V0(v0) => {
                if let Some(share) = decrypt_v0(v0, aad, &self.pke) {
                    return Some(share);
                }
                self.old_pke.last().and_then(|old| decrypt_v0(v0, aad, old))
            }
        }
    }
```

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L33-74)
```rust
pub fn handler(
    mut ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request: Request = deserialize_request_body(&request)?;

    let backup_id = request.backup_id.0;
    let account_id = request.account_id.0;

    let account = state
        .get_account(account_id)
        .ok_or_else(|| ServerError::NotFound("Account not found".to_string()))?;

    let backup: &BackupCiphertext = account.recover_id(backup_id).ok_or_else(|| {
        ServerError::NotFound(format!("Backup not found for backup_id: {}", backup_id))
    })?;

    // The share id will be in the range [0, |shares|)
    let share_id = backup
        .verify(&request.share.0)
        .map_err(|_| ServerError::InvalidParameter("Invalid guardian share".to_string()))?;

    // Update the share mapping for this backup
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

    let response = Response {
        success: true,
        message: "Share uploaded successfully".to_string(),
    };
    create_json_response(200, &response).map_err(|e| e.into())
}
```
