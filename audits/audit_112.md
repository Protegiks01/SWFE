# Audit Report

## Title
Lack of AAD Binding in RIK Encryption Enables Permanent Account Recovery Freezing via Email Association Overwrite

## Summary
The RIK (Recovery Initiation Key) data encryption uses `EmptyAD` without binding to user or email context, combined with missing uniqueness validation in the association upload endpoint. This allows the same email to be associated with multiple accounts, causing the later association to overwrite the earlier one and permanently freeze recovery for the first account. The system states an invariant that "an email should be associated to at most one account at a time," but this is not enforced.

## Impact
**High**

## Finding Description

**Location:** 
- Encryption with EmptyAD: [1](#0-0) 
- Missing uniqueness check: [2](#0-1) 
- Storage overwrite behavior: [3](#0-2) 

**Intended Logic:** 
According to the system documentation, "An email should be associated to at most one account at a time" as a stated invariant. The association system should prevent the same email from being linked to multiple different accounts simultaneously. Each email-to-account association should be unique and protected from overwriting.

**Actual Logic:** 
When a user uploads an MSK association via the `/association/upload_msk` endpoint, the contract:
1. Verifies the email certificate token [4](#0-3) 
2. Creates an `EmailKey` from the email and VDRF evaluation [5](#0-4) 
3. Directly stores the new `MskRecord` without checking if one already exists [2](#0-1) 

The `store()` method performs a simple `storage.insert(key, value)` which overwrites any existing value [6](#0-5) . Additionally, the RIK data is encrypted using `EmptyAD` with no binding to the email, account, or user context [1](#0-0) .

**Exploit Scenario:**
1. Alice creates `Account_A` and associates `email@example.com`:
   - Generates `rik_A` [7](#0-6) 
   - Encrypts `RikSecretData_A` (containing `sig_sk_A` and `msk_ss_rik_A`) with `rik_A` using `EmptyAD` [1](#0-0) 
   - Uploads to nodes under `EmailKey(email@example.com)`

2. Later, Bob (or even Alice herself) associates the same `email@example.com` with `Account_B`:
   - Generates `rik_B`
   - Encrypts `RikSecretData_B` (containing `sig_sk_B` and `msk_ss_rik_B`) with `rik_B` using `EmptyAD`
   - Uploads to nodes under the same `EmailKey(email@example.com)`
   - **The storage overwrites Alice's association completely**

3. Alice attempts to recover `Account_A` using `email@example.com`:
   - She retrieves the `MskRecord` from nodes [8](#0-7) 
   - She gets `RikSecretData_B` encrypted with `rik_B` (not her original data!)
   - She attempts to decrypt using `rik_A` [9](#0-8) 
   - **Decryption fails** because the data was encrypted with `rik_B`, not `rik_A`
   - **Account_A is permanently unrecoverable**

**Security Failure:** 
The stated invariant that "each email associates with at most one account at a time" is violated. The lack of AAD binding prevents any cryptographic detection of context mismatch, and the missing uniqueness validation allows silent overwrites. This results in permanent freezing of account recovery capabilities.

## Impact Explanation

**Affected Assets:** Master secret key recovery path for the first account associated with the overwritten email.

**Severity of Damage:** 
- Users who associated an email with `Account_A` lose the ability to recover that account if the same email is later associated with a different account
- The recovery path is **permanently frozen** – even if the user realizes what happened, they cannot retrieve the original `RikSecretData_A`
- This violates the core security guarantee that users can recover their accounts using verified email associations
- The damage is irreversible without off-chain node intervention or manual database recovery

**System Impact:**
This fundamentally breaks the email-based account recovery system, which is a primary feature of Swafe. Users relying on this recovery mechanism could permanently lose access to their accounts and associated secrets.

## Likelihood Explanation

**Who Can Trigger:** Any user with access to a valid email certificate for a given email address can trigger this vulnerability. This includes:
- The legitimate email owner creating multiple accounts
- An attacker who gains temporary access to an email account
- An attacker who compromises Swafe.io's email verification system

**Required Conditions:**
- The victim must have already associated an email with their account
- The attacker must obtain a valid `EmailCertificate` for the same email (via legitimate verification or by compromising the email temporarily)
- No special timing or race conditions required – the overwrite happens immediately upon upload

**Frequency:**
- Can occur whenever a user attempts to associate an email that's already in use
- Particularly likely during account recovery scenarios where users might try to re-associate an email
- Could be exploited systematically by an attacker who gains temporary email access to DoS multiple accounts

## Recommendation

Implement a two-part fix:

1. **Add uniqueness validation in the upload endpoint:**
```rust
// In upload_msk.rs handler, before storing:
if let Some(existing_record) = MskRecordCollection::load(&mut ctx, email_tag) {
    // Extract user_pk from existing record
    let existing_user_pk = match existing_record {
        MskRecord::V0(v0) => &v0.fixed.user_pk,
    };
    
    // Only allow overwrite if same user (account update scenario)
    if existing_user_pk != user_pk {
        return Err(ServerError::InvalidParameter(
            "Email already associated with a different account".to_string()
        ).into());
    }
}
```

2. **Bind RIK encryption to user/email context:**
Change the encryption to bind to user context:
```rust
// In association/v0.rs, create_encrypted_msk function:
#[derive(Serialize)]
struct RikAAD {
    user_pk: sig::VerificationKey,
}

impl Tagged for RikAAD {
    const SEPARATOR: &'static str = "v0:rik-aad";
}

let ciphertext = symmetric::seal(
    rng,
    rik.as_bytes(),
    &CombinedSecretData::V0 { rik_data },
    &RikAAD { user_pk: sig_sk.verification_key() },  // Bind to user context
);
```

This provides defense-in-depth: even if the uniqueness check is bypassed, the AAD binding ensures decryption failures can be detected and attributed to context mismatches.

## Proof of Concept

**File:** `lib/tests/association_overwrite_test.rs` (new test file)

**Setup:**
1. Create two separate user accounts with different signing keys (`user_A` and `user_B`)
2. Generate email certificate for `email@example.com` for both users
3. Create RIK associations for both accounts using the same email

**Trigger:**
1. User A creates and uploads association for `email@example.com` with `Account_A`
2. User B creates and uploads association for the same `email@example.com` with `Account_B`
3. Verify that User B's upload succeeds (should be rejected but isn't)
4. User A attempts to retrieve and decrypt their RIK data using the email

**Observation:**
The test demonstrates that:
1. User A's original association is silently overwritten (no error returned)
2. When User A retrieves the MskRecord, it contains User B's data
3. User A's decryption fails with `SwafeError::DecryptionFailed`
4. User A cannot recover their account through the email association
5. The invariant "email associates with at most one account at a time" is violated

The test should fail on the vulnerable code, demonstrating the permanent loss of recovery capability.

### Citations

**File:** lib/src/association/v0.rs (L345-350)
```rust
        let ciphertext = symmetric::seal(
            rng,
            rik.as_bytes(),
            &CombinedSecretData::V0 { rik_data },
            &symmetric::EmptyAD,
        );
```

**File:** lib/src/association/v0.rs (L381-382)
```rust
        let rik = RecoveryInitiationKey::gen(rng);
        let msk_ss_rik = MskSecretShareRik::gen(rng);
```

**File:** lib/src/association/v0.rs (L526-530)
```rust
        let combined_secret: CombinedSecretData = symmetric::open(
            rik.as_bytes(),
            &encrypted_data.ciphertext,
            &symmetric::EmptyAD,
        )?;
```

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L54-55)
```rust
    let (email, user_pk) =
        EmailCert::verify(&swafe_pk, &node_id, &request.token.0, ctx.current_time())?;
```

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L58-58)
```rust
    let email_tag: EmailKey = EmailKey::new(&vdrf_pk, &email, request.vdrf_eval.0)?;
```

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L60-64)
```rust
    MskRecordCollection::store(
        &mut ctx,
        email_tag,
        request.association.0.verify(user_pk, &node_id)?,
    );
```

**File:** contracts/src/storage.rs (L21-27)
```rust
    fn store(ctx: &mut OffChainContext, key: Self::Key, value: Self::Value) {
        let mut storage: OffChainStorage<Vec<u8>, Vec<u8>> =
            ctx.storage(Self::COLLECTION_NAME.as_bytes());
        let key = encode::serialize(&key).unwrap();
        let value = encode::serialize(&value).unwrap();
        storage.insert(key, value);
    }
```

**File:** contracts/src/http/endpoints/association/get_secret_share.rs (L48-49)
```rust
    let msk_record = MskRecordCollection::load(&mut ctx, email_tag)
        .ok_or_else(|| ServerError::InvalidParameter("MSK record not found".to_string()))?;
```
