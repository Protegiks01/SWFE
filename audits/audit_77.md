## Title
Clock Skew Between Certificate Issuance and Blockchain Verification Causes Denial of Service for Account Recovery

## Summary
Email certificates are issued using the Swafe-io server's system time but verified using blockchain time on off-chain nodes. The certificate verification logic has zero time skew tolerance, causing legitimate certificates to be rejected when blockchain time lags even slightly behind the issuing server's clock. This creates inconsistent acceptance across nodes and can prevent users from completing email association or account recovery operations.

## Impact
**Medium**

## Finding Description

**Location:** 
The vulnerability exists in the certificate verification logic in `lib/src/crypto/email_cert.rs` (lines 88-116) and its usage across all contract HTTP endpoints that verify certificates. [1](#0-0) 

**Intended Logic:** 
Email certificates should be valid for 5 minutes from issuance, allowing users sufficient time to complete association uploads or recovery operations across multiple off-chain nodes. The certificate system should tolerate minor clock differences between the issuing server and blockchain nodes.

**Actual Logic:** 
The `EmailCert::verify()` function performs strict timestamp validation with zero tolerance for clock skew: [2](#0-1) 

Certificates are issued with timestamp `T = SystemTime::now()` from Swafe-io's server clock: [3](#0-2) 

But verification uses blockchain time `B = ctx.current_time()`: [4](#0-3) [5](#0-4) [6](#0-5) 

If `B < T` (blockchain time lags behind server time), the certificate is immediately rejected with `CertificateFromFuture` error, even if issued legitimately seconds ago.

**Exploit Scenario:**
1. User initiates email-based account recovery by verifying email ownership with Swafe-io
2. Swafe-io issues email certificate with timestamp `T = SystemTime::now()` (e.g., `T = 1000000000`)
3. User immediately attempts to upload MSK association or retrieve secret shares from multiple off-chain nodes
4. Off-chain node A has blockchain time `B_A = 999999999` (1 second behind)
5. Node A rejects certificate with `CertificateFromFuture` error, returning HTTP 400
6. Off-chain node B has blockchain time `B_B = 1000000001` (1 second ahead)  
7. Node B accepts the certificate
8. If the system requires threshold `t` nodes to participate in recovery and fewer than `t` nodes accept the certificate due to clock skew, recovery fails completely
9. User cannot complete association or recover their account

**Security Failure:**
This violates the availability requirement that "users should be able to recover accounts with only access to their email." The system experiences temporary freezing of recovery operations due to a subtle logic error in time validation, not requiring any malicious behavior from trusted parties.

## Impact Explanation

The vulnerability affects critical user operations:

1. **Email Association Blocking**: Users cannot upload their Master Secret Key (MSK) associations to off-chain nodes when clock skew exists, preventing initial account setup for email-based recovery.

2. **Account Recovery Denial**: During account recovery, users must retrieve secret shares from multiple nodes (typically `n-1` threshold). If blockchain time on some nodes lags behind the certificate issuance time, those nodes reject the certificate. If fewer than threshold nodes accept the certificate, recovery fails entirely.

3. **Reduced Effective Validity Window**: Even when blockchain time is ahead of server time, network propagation delays and processing time consume the 5-minute validity period. Combined with clock skew, users have significantly less than the advertised 5 minutes to complete operations.

4. **Inconsistent Multi-Node Behavior**: In a distributed blockchain, different off-chain nodes may have slightly different views of "current time." A certificate can be simultaneously valid on some nodes and invalid on others, creating unpredictable behavior.

The test suite demonstrates awareness of this issue by explicitly setting blockchain time 2 minutes ahead as a workaround: [7](#0-6) 

However, this workaround only applies to testing and does not protect production deployments from clock skew issues.

## Likelihood Explanation

This vulnerability is **highly likely** to occur in production:

**Who Can Trigger It:** Any legitimate user attempting email association or account recovery. No special privileges or malicious intent required.

**Conditions Required:** 
- Clock skew between Swafe-io's issuing server and blockchain nodes of even 1 second (common in distributed systems)
- Normal network propagation delays (typical)
- User attempting multi-node operations requiring threshold participation

**Frequency:**
- Occurs whenever blockchain time lags behind system time at certificate issuance
- In distributed blockchain networks, at least some nodes are likely to have clock skew at any given time
- Affects every user operation requiring email certificate validation
- More severe during network congestion or when users take time to submit transactions after certificate issuance

Clock synchronization challenges are well-known in distributed systems. Even with NTP (Network Time Protocol), clocks can drift seconds apart. The probability of 1+ second skew between independent systems is very high.

## Recommendation

Implement a configurable time skew tolerance in the certificate verification logic:

1. Add a `CLOCK_SKEW_TOLERANCE` constant (e.g., 120 seconds) to allow reasonable clock differences
2. Modify the "future" check to: `if ts > now + CLOCK_SKEW_TOLERANCE`
3. Modify the expiration check to: `if now > ts + VALIDITY_PERIOD + CLOCK_SKEW_TOLERANCE`

Example fix for `lib/src/crypto/email_cert.rs`:

```rust
const VALIDITY_PERIOD: Duration = Duration::from_secs(5 * 60);
const CLOCK_SKEW_TOLERANCE: Duration = Duration::from_secs(120); // 2 minutes

// Check if certificate is from the future (with tolerance)
if ts > now.checked_add(CLOCK_SKEW_TOLERANCE).unwrap_or(now) {
    return Err(SwafeError::CertificateFromFuture);
}

// Check if certificate is expired (with tolerance)
let max_age = VALIDITY_PERIOD.checked_add(CLOCK_SKEW_TOLERANCE).unwrap();
if now.duration_since(ts).map_err(|_| SwafeError::CertificateExpired)? > max_age {
    return Err(SwafeError::CertificateExpired);
}
```

This maintains security (certificates still expire within reasonable time) while providing resilience against inevitable clock skew in distributed systems.

## Proof of Concept

**File:** `lib/src/crypto/email_cert.rs`  
**Test Function:** Add new test `test_email_cert_clock_skew_rejection`

**Setup:**
1. Generate Swafe keypair and user keypair
2. Issue email certificate at timestamp `T`
3. Create email certificate token

**Trigger:**
1. Attempt to verify certificate with blockchain time `now = T - 1 second` (blockchain slightly behind)
2. Observe verification failure with `CertificateFromFuture` error

**Observation:**
The test demonstrates that a legitimate, freshly-issued certificate is rejected when blockchain time is even 1 second behind the issuing server's clock. This confirms the vulnerability:

```rust
#[test]
fn test_email_cert_clock_skew_rejection() {
    let mut rng = thread_rng();
    
    let swafe_keypair = sig::SigningKey::gen(&mut rng);
    let swafe_pk = swafe_keypair.verification_key();
    let user_keypair = sig::SigningKey::gen(&mut rng);
    let user_pk = user_keypair.verification_key();
    
    let email = "user@example.com".to_string();
    let node_id = "node:test".parse().unwrap();
    
    // Issue certificate at time T
    let cert = EmailCert::issue(&mut rng, &swafe_keypair, &user_pk, email.clone());
    let token = EmailCert::token(&mut rng, &cert, &user_keypair, &node_id);
    
    // Get the certificate timestamp
    let cert_time = UNIX_EPOCH
        .checked_add(Duration::from_secs(cert.msg.timestamp))
        .unwrap();
    
    // Simulate blockchain time 1 second behind certificate issuance
    let blockchain_time = cert_time - Duration::from_secs(1);
    
    // Verification should fail with CertificateFromFuture
    let result = EmailCert::verify(&swafe_pk, &node_id, &token, blockchain_time);
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SwafeError::CertificateFromFuture));
    
    // This demonstrates legitimate certificate rejected due to clock skew
    // In production, this prevents users from completing association/recovery
}
```

The test fails (correctly detects the issue) by showing that a freshly issued certificate cannot be verified when blockchain time is minimally behind system time, confirming the vulnerability's exploitability in real-world conditions.

### Citations

**File:** lib/src/crypto/email_cert.rs (L52-55)
```rust
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
```

**File:** lib/src/crypto/email_cert.rs (L88-116)
```rust
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

**File:** contracts/src/http/endpoints/association/upload_msk.rs (L54-55)
```rust
    let (email, user_pk) =
        EmailCert::verify(&swafe_pk, &node_id, &request.token.0, ctx.current_time())?;
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

**File:** contracts/java-test/src/test/java/com/partisia/blockchain/contract/SwafeContractTest.java (L110-112)
```java
    // setup block time 2 min later to ensure that the email certificate time is not greater than
    // the block time.
    resetSystemTime(120000L);
```
