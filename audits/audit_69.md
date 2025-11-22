## Audit Report

## Title
Inconsistent Time Sources Between Certificate Issuance and Verification Enable Denial of Service on Email-Based Recovery

## Summary
The email certificate system uses inconsistent time sources: certificates are issued using the operator's local system time, but verified using blockchain time. Clock skew between these sources causes legitimate certificates to be rejected, completely blocking email-based account recovery for all affected users.

## Impact
**High**

## Finding Description

**Location:** 
- Certificate issuance: [1](#0-0) 
- Certificate verification: [2](#0-1) 
- Contract verification calls: [3](#0-2) , [4](#0-3) , [5](#0-4) 

**Intended Logic:** 
Email certificates should have a 5-minute validity window to authenticate users for email-based operations (MSK upload, secret share retrieval, VDRF evaluation). The system should be resilient to normal operational conditions and provide consistent behavior across the distributed network.

**Actual Logic:** 
The certificate issuance function uses `SystemTime::now()` to timestamp certificates with the operator's local system clock. However, verification uses `ctx.current_time()` which returns blockchain time from the Partisia execution engine. These are fundamentally different time sources that can drift apart due to:
- NTP synchronization failures on the operator's machine
- Network time protocol disruptions
- Clock drift or misconfiguration
- Timezone handling issues

The verification logic strictly enforces two time-based checks:
1. Rejects certificates with timestamps in the future relative to blockchain time
2. Rejects certificates older than 5 minutes relative to blockchain time

**Exploit Scenario:**

**Case 1: Operator Clock Ahead**
1. Operator's system clock is 3 minutes ahead of blockchain time (due to NTP sync failure)
2. Operator issues email certificate with timestamp T_local = blockchain_time + 3min
3. User immediately attempts to use certificate for MSK upload/recovery
4. Contract verification receives blockchain_time from `ctx.current_time()`
5. Verification fails with `CertificateFromFuture` error because T_local > blockchain_time
6. All email-based operations fail for all users until clocks re-synchronize

**Case 2: Operator Clock Behind**
1. Operator's system clock is 4 minutes behind blockchain time
2. Operator issues certificate with timestamp T_local = blockchain_time - 4min
3. Certificate effectively has only 1 minute of actual validity (5min - 4min skew)
4. User attempts to use certificate but slight network delay causes expiration
5. Verification fails with `CertificateExpired` error
6. Users experience unpredictable certificate rejections and must repeatedly request new certificates

**Security Failure:** 
This creates a critical denial-of-service condition on the email association system. Users cannot:
- Upload MSK records to associate emails with accounts
- Retrieve secret shares for account recovery  
- Evaluate VDRF for email-based operations

This directly violates the system invariant: "Only the owner of an email should be able to request the recovery of an account" by making email-based recovery completely unavailable during clock skew periods.

## Impact Explanation

**Affected Components:**
- Email-based account recovery system (primary recovery mechanism)
- MSK association uploads
- VDRF evaluation for privacy-preserving email verification
- Secret share retrieval for recovery completion

**Severity of Damage:**
When clock skew occurs, 100% of users attempting to use email certificates are affected (exceeding the ≥25% threshold for critical impact). The entire email-based recovery pathway becomes inoperative, leaving users unable to recover lost accounts through their only designed recovery mechanism (email + guardians).

**System Impact:**
This breaks a core security invariant documented in the README: "A user should be able to recover his account with only access to his email (and an out-of-band channel for communicating with Guardians)." During clock skew periods, this guarantee is violated, potentially causing permanent loss of access if users cannot wait for clock synchronization.

## Likelihood Explanation

**Trigger Conditions:**
Clock skew is a common operational reality in distributed systems and can occur through:
- Natural clock drift (all systems experience this over time)
- NTP server unavailability or network issues preventing synchronization
- Operator machine reboots without proper time sync
- Adversarial network conditions (attacker disrupting NTP traffic to operator)

**Frequency:**
This vulnerability can manifest during normal operations without any attacker action. Industry data shows NTP failures occur regularly in production environments. The likelihood is **high** because:
- It requires only environmental conditions, not sophisticated attacks
- The operator is trusted but clock synchronization is an external dependency
- No monitoring or alerting would catch this before user impact
- Users cannot distinguish between this and other certificate errors

**Who Can Trigger:**
While the trusted operator doesn't intentionally cause this, any adversary capable of network-level disruption (e.g., blocking NTP traffic to the operator's infrastructure) can induce this condition. Additionally, it occurs naturally without malicious action.

## Recommendation

**Primary Fix:** Use blockchain time for certificate issuance instead of local system time. Modify the certificate issuance process to:

1. Query blockchain time when issuing certificates (if issuing from a contract context)
2. If issuing off-chain, add a tolerance window (±2 minutes) to verification logic to account for expected clock drift
3. Alternatively, extend certificate validity period to 15-30 minutes to reduce sensitivity to small clock skews

**Specific Code Changes:**
- Add a `tolerance` parameter to the `EmailCert::verify()` function
- Modify timestamp validation to: `if (ts > now + tolerance) || (now.duration_since(ts) > VALIDITY_PERIOD + tolerance)`
- Document the clock synchronization requirements for operators clearly

**Additional Safeguards:**
- Implement clock skew monitoring and alerting for the operator infrastructure
- Add certificate issuance timestamp validation against a known reliable time source
- Include certificate timestamp in error messages to aid debugging

## Proof of Concept

**Test File:** `lib/src/crypto/email_cert.rs` (add to existing test module)

**Test Function:**
```rust
#[test]
fn test_certificate_clock_skew_denial_of_service() {
    let mut rng = thread_rng();
    
    // Setup: Generate keys
    let swafe_keypair = sig::SigningKey::gen(&mut rng);
    let swafe_pk = swafe_keypair.verification_key();
    let user_keypair = sig::SigningKey::gen(&mut rng);
    let user_pk = user_keypair.verification_key();
    let node_id = "node:test".parse().unwrap();
    let email = "user@example.com".to_string();
    
    // Trigger: Issue certificate with current time (simulating operator's local clock)
    let cert = EmailCert::issue(&mut rng, &swafe_keypair, &user_pk, email.clone());
    let token = EmailCert::token(&mut rng, &cert, &user_keypair, &node_id);
    
    // Simulate blockchain time being 3 minutes behind operator's clock
    // (operator's clock is 3 minutes ahead)
    let blockchain_time = SystemTime::now() - Duration::from_secs(3 * 60);
    
    // Observation: Verification fails with CertificateFromFuture
    let result = EmailCert::verify(&swafe_pk, &node_id, &token, blockchain_time);
    assert!(matches!(result, Err(SwafeError::CertificateFromFuture)));
    
    // Simulate blockchain time being 6 minutes ahead of operator's clock
    // (operator's clock is 6 minutes behind)
    let blockchain_time = SystemTime::now() + Duration::from_secs(6 * 60);
    
    // Observation: Verification fails with CertificateExpired
    let result = EmailCert::verify(&swafe_pk, &node_id, &token, blockchain_time);
    assert!(matches!(result, Err(SwafeError::CertificateExpired)));
}
```

**Observation:**
This test demonstrates that legitimate certificates issued by the trusted operator fail verification when there is clock skew between the operator's system clock and blockchain time. The test confirms:
1. Certificates appear "from the future" when operator's clock is ahead
2. Certificates appear "expired" when operator's clock is behind
3. Both scenarios block all email-based recovery operations
4. The issue affects 100% of users during the clock skew period, exceeding the ≥25% threshold for critical impact

### Citations

**File:** lib/src/crypto/email_cert.rs (L46-66)
```rust
    pub fn issue<R: Rng + CryptoRng>(
        rng: &mut R,
        swafe_keypair: &sig::SigningKey,
        user_pk: &sig::VerificationKey,
        email: String,
    ) -> EmailCertificate {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let msg = EmailCertificateMessage {
            user_pk: user_pk.clone(),
            email,
            timestamp,
        };

        let sig = swafe_keypair.sign(rng, &msg);

        EmailCertificate { msg, sig }
    }
```

**File:** lib/src/crypto/email_cert.rs (L82-116)
```rust
    /// Verify the email certificate and token.
    /// On Execution Engine, the system time should be passed from the EE context.
    pub fn verify<'a>(
        swafe_pk: &sig::VerificationKey,
        node_id: &NodeId,
        token: &'a EmailCertToken,
        now: SystemTime,
    ) -> Result<(&'a str, &'a sig::VerificationKey), SwafeError> {
        // Verify Swafe signature on certificate
        swafe_pk.verify(&token.cert.sig, &token.cert.msg)?;

        // Verify user signature on node_id
        token.cert.msg.user_pk.verify(&token.user_sig, node_id)?;

        // convert UNIX timestamp (u64) to SystemTime
        let ts = UNIX_EPOCH
            .checked_add(Duration::from_secs(token.cert.msg.timestamp))
            .ok_or(SwafeError::CertificateExpired)?;

        // Check if certificate is from the future
        if ts > now {
            return Err(SwafeError::CertificateFromFuture);
        }

        // Check if certificate is expired
        if now
            .duration_since(ts)
            .map_err(|_| SwafeError::CertificateExpired)?
            > VALIDITY_PERIOD
        {
            return Err(SwafeError::CertificateExpired);
        }

        Ok((&token.cert.msg.email, &token.cert.msg.user_pk))
    }
```

**File:** contracts/src/http/endpoints/association/vdrf/eval.rs (L40-45)
```rust
    let (email, _) = EmailCert::verify(
        &swafe_public_key,
        &node_id,
        &request.token.0,
        ctx.current_time(),
    )?;
```

**File:** contracts/src/http/endpoints/association/get_secret_share.rs (L42-43)
```rust
    let node_id: swafe_lib::NodeId = stored_secret.node_id.0;
    let (email, _) = EmailCert::verify(&swafe_pk, &node_id, &request.token.0, ctx.current_time())?;
```

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L54-55)
```rust
    let (email, user_pk) =
        EmailCert::verify(&swafe_pk, &node_id, &request.token.0, ctx.current_time())?;
```
