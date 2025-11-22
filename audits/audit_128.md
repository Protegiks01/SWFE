# Audit Report

## Title
Guardian Share Encryption Lacks Owner Identity Binding Allowing Share Misdirection

## Summary
The `send()` function in the backup recovery system encrypts guardian shares without cryptographically binding them to the intended owner's identity. This allows an attacker to trick guardians into encrypting shares for the attacker's encryption key instead of the legitimate owner's key, enabling unauthorized backup reconstruction.

## Impact
**High**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
When a guardian encrypts their decrypted share for transmission to the owner, the encryption should be cryptographically bound to the intended recipient's identity (AccountId) to prevent misdirection. The owner who created the backup should be the only one able to decrypt the guardian shares.

**Actual Logic:** 
The `send()` function encrypts the guardian share using only the provided `AccountState`'s encryption key, with `EmptyInfo` as the associated data: [2](#0-1) 

This creates no cryptographic binding between the encrypted share and the intended owner's identity. The signature only covers the ciphertext and index, not any owner identifier: [3](#0-2) 

The CLI function accepts both parameters as user-provided strings without verification: [4](#0-3) 

**Exploit Scenario:**
1. Alice creates a backup with guardians Bob and Carol (threshold = 2)
2. Alice marks the backup for recovery
3. Bob decrypts his share for Alice's backup using the correct AccountId
4. Attacker Eve social-engineers or intercepts Bob's CLI invocation
5. Eve provides her own `AccountState` (containing Eve's encryption key) instead of Alice's
6. Bob executes `guardian_send_share` with his decrypted share but Eve's account state
7. The share gets encrypted with Eve's PKE key instead of Alice's
8. Eve can decrypt Bob's share with her private key
9. Eve repeats with Carol to obtain threshold shares
10. Eve reconstructs Alice's backed-up secret

**Security Failure:** 
The confidentiality guarantee of the backup system is violated. Guardian shares meant for one owner can be redirected to an attacker, allowing unauthorized backup reconstruction and compromise of secrets.

## Impact Explanation

**Assets Affected:**
- All data backed up using the Swafe backup system, including Master Secret Keys, recovery keys, and any user secrets
- Account ownership and control (if MSK is recovered)

**Severity:**
- **Direct compromise of private keys/secrets:** An attacker gains access to secrets they should not be able to decrypt
- **Complete bypass of guardian authorization:** The threshold system's security is defeated since shares can be redirected
- **Loss of confidentiality:** Backed-up data is exposed to unauthorized parties

**System Impact:**
This fundamentally breaks the security model of the backup and recovery system. Users who trust guardians to protect their secrets will have those secrets exposed if guardians are tricked into using the wrong AccountState during the send operation.

## Likelihood Explanation

**Who can trigger:**
Any attacker who can influence guardian behavior through social engineering, man-in-the-middle attacks on CLI inputs, or compromised client-side components that provide inputs to the guardian CLI tools.

**Conditions required:**
- Guardian must have already decrypted their share (normal operation after owner marks backup for recovery)
- Attacker must substitute the `owner_account_state_str` parameter when guardian calls `guardian_send_share`
- This is realistic in scenarios where: guardians use web interfaces that could serve malicious data, guardians copy-paste account states from untrusted sources, or automated systems process attacker-controlled inputs

**Frequency:**
Can be exploited every time a backup recovery is initiated. The vulnerability is deterministic and always exploitable when the conditions are met. With threshold cryptography, an attacker only needs to successfully redirect shares from the minimum threshold number of guardians.

## Recommendation

Bind the encryption to the owner's AccountId by including it as the associated data (context) for PKE encryption:

1. Modify `DecryptedShareV0::send()` to accept the owner's `AccountId` as a parameter
2. Create a tagged context structure containing the AccountId:
```rust
#[derive(Serialize)]
struct OwnerContext {
    account_id: AccountId,
}
impl Tagged for OwnerContext {
    const SEPARATOR: &'static str = "v0:owner-context";
}
```
3. Use this context in the encryption call instead of `EmptyInfo`: [2](#0-1) 

4. Update the corresponding `recover()` function to use the same context when decrypting: [5](#0-4) 

5. Update CLI to extract and verify the AccountId from the AccountState before calling send()

This ensures that guardian shares can only be decrypted by the owner whose AccountId was bound to the encryption, preventing misdirection attacks.

## Proof of Concept

**File:** `lib/src/backup/tests.rs`

**Test Function:** `test_guardian_share_misdirection_attack`

**Setup:**
1. Create Alice's account with guardians Bob and Carol (threshold 2)
2. Create Alice's backup with test data
3. Create Eve's account (attacker)
4. Bob and Carol decrypt their shares for Alice's backup

**Trigger:**
1. Bob calls `send()` with Eve's AccountState instead of Alice's
2. Carol calls `send()` with Eve's AccountState instead of Alice's
3. Eve attempts to recover using the misdirected shares with her own decryption key

**Observation:**
The test demonstrates that:
1. Bob and Carol's shares are successfully encrypted for Eve's key
2. Eve can decrypt both shares using her private key
3. Eve can reconstruct Alice's secret without Alice's private key
4. This violates the confidentiality guarantee that only Alice should be able to recover her backup

The vulnerable code allows the attack to succeed, confirming the security failure. A properly fixed implementation would cause decryption to fail when the AccountId doesn't match the intended owner.

### Citations

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

**File:** lib/src/backup/v0.rs (L304-304)
```rust
                let share: Share = dke.decrypt(&share_v0.ct, aad).ok()?;
```

**File:** cli/src/commands/backup.rs (L140-155)
```rust
pub fn guardian_send_share(
    secret_share_str: String,
    owner_account_state_str: String,
    output: PathBuf,
) -> Result<()> {
    let mut rng = thread_rng();

    let secret_share: SecretShare = encode::deserialize_str(&secret_share_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode secret share: {}", e))?;

    let owner_state: AccountState = encode::deserialize_str(&owner_account_state_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode owner account state: {}", e))?;

    let guardian_share = secret_share
        .send(&mut rng, &owner_state)
        .map_err(|e| anyhow::anyhow!("Failed to create guardian share: {:?}", e))?;
```
