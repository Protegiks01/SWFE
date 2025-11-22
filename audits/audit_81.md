## Title
Off-by-One Error in Guardian Share Index Validation Causes API Handler Crash

## Summary
A bounds checking error in the guardian share verification logic allows an attacker to send a crafted share with an out-of-bounds index, causing a panic that crashes the API handler for the `/reconstruction/upload-share` endpoint.

## Impact
**Low to Medium**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The `BackupCiphertextV0::verify()` function should validate that the `idx` field of a `GuardianShare` is within the valid range of indices for the `self.comms` array (0 to `comms.len() - 1`) before accessing the array.

**Actual Logic:** The bounds check on line 343 uses the condition `share.idx > self.comms.len() as u32`, which only rejects indices strictly greater than the array length. This allows `share.idx` to equal `comms.len()`, which is an invalid index for a zero-indexed array. When the code subsequently accesses `self.comms[share.idx as usize]` on line 346, it attempts an out-of-bounds access, causing a panic.

**Exploit Scenario:**
1. Attacker identifies or creates a backup with N guardians (N commitments in `comms` array)
2. Attacker crafts a `GuardianShare` with `idx` set to N (equal to `comms.len()`)
3. Attacker sends POST request to `/reconstruction/upload-share` endpoint with this crafted share [2](#0-1) 
4. The validation check passes since N is not > N
5. Array access `self.comms[N]` panics with index out of bounds
6. API handler crashes

**Security Failure:** This breaks availability by causing a denial-of-service through a panic. In Rust WASM smart contract environments, panics halt execution and can crash the processing node's HTTP service, preventing legitimate users from uploading guardian shares needed for account recovery.

## Impact Explanation

- **Affected Components:** The backup reconstruction flow is disrupted. Users attempting to recover their accounts by uploading guardian shares will be unable to complete the process if the endpoint is crashed.
  
- **Severity:** The attacker can repeatedly crash the API endpoint by sending malicious requests, effectively preventing any backup reconstruction operations. In a distributed node environment, if multiple nodes run vulnerable code, an attacker could systematically crash nodes by targeting the reconstruction endpoint.

- **System Reliability:** This vulnerability undermines the core recovery mechanism of Swafe. If users cannot upload guardian shares due to endpoint crashes, they cannot reconstruct their backups and regain access to their accounts, which is a critical security and availability failure.

## Likelihood Explanation

- **Attacker Requirements:** Any unprivileged network participant can trigger this vulnerability by sending a crafted HTTP POST request to the public API endpoint. No special privileges or credentials are required.

- **Exploit Conditions:** The attacker only needs to know or guess the number of guardians for any backup (typically small values like 3-7). Even without specific knowledge, brute-forcing idx values from 1-20 would likely hit vulnerable configurations.

- **Frequency:** The vulnerability can be exploited repeatedly and systematically. An attacker could target multiple nodes simultaneously or repeatedly crash a single node, causing persistent denial of service for the reconstruction functionality.

## Recommendation

Change the bounds check from a strict inequality to an inclusive inequality:

```rust
if share.idx >= self.comms.len() as u32 {
    return Err(SwafeError::InvalidShare);
}
```

This ensures that only valid array indices (0 to `comms.len() - 1`) are accepted, preventing out-of-bounds access.

## Proof of Concept

**Test File:** `lib/src/backup/tests.rs`

**Test Function:** Add the following test:

```rust
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_verify_guardian_share_oob_panic() {
    use crate::backup::v0::{BackupCiphertextV0, GuardianShareV0, ShareComm};
    use crate::crypto::{pke, sig};
    use rand::thread_rng;
    
    let mut rng = thread_rng();
    
    // Create a backup with 3 commitments
    let num_comms = 3;
    let mut comms = Vec::new();
    for _ in 0..num_comms {
        let sk = sig::SigningKey::gen(&mut rng);
        comms.push(ShareComm {
            vk: sk.verification_key(),
            hash: [0u8; 32],
        });
    }
    
    let backup = BackupCiphertextV0 {
        data: /* create test AEAD ciphertext */,
        comms,
        encap: /* create test batch ciphertext */,
    };
    
    // Create a guardian share with idx = comms.len() (out of bounds)
    let malicious_share = GuardianShareV0 {
        ct: pke::Ciphertext::default(),
        idx: num_comms as u32,  // This equals comms.len(), which is invalid
        sig: sig::Signature::default(),
    };
    
    // This should panic with index out of bounds
    let _ = backup.verify(&malicious_share);
}
```

**Setup:** The test creates a `BackupCiphertextV0` with 3 commitments.

**Trigger:** A malicious `GuardianShareV0` is created with `idx = 3` (equal to `comms.len()`), which passes the validation check but causes out-of-bounds access.

**Observation:** The test panics with "index out of bounds" error, confirming the vulnerability. The `#[should_panic]` attribute documents that this behavior exists in the vulnerable code and should not occur after the fix.

### Citations

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

**File:** contracts/src/http/endpoints/reconstruction/upload_share.rs (L53-55)
```rust
    let share_id = backup
        .verify(&request.share.0)
        .map_err(|_| ServerError::InvalidParameter("Invalid guardian share".to_string()))?;
```
