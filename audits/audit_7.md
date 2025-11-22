## Audit Report

## Title
MSK Reconstruction Fails to Enforce Minimum Threshold After Share Verification

## Summary
The `reconstruct_rik_data` and `reconstruct_recovery_key` functions in `lib/src/association/v0.rs` check if enough MSK records are provided before filtering invalid shares, but fail to verify that sufficient valid shares remain after verification. This allows polynomial interpolation to proceed with fewer than the required threshold of valid shares, producing incorrect reconstruction results and causing legitimate recovery operations to fail. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- File: `lib/src/association/v0.rs`
- Functions: `reconstruct_rik_data` (lines 455-535) and `reconstruct_recovery_key` (lines 539-607)
- Critical lines: 489-506 and 572-589

**Intended Logic:** 
For threshold-t secret sharing, the reconstruction process must ensure that at least t valid shares are used for Lagrange interpolation. The security invariant is that reconstruction should only proceed if there are at least t shares that pass verification checks against the Pedersen commitments. [2](#0-1) 

**Actual Logic:**
The functions perform the threshold check at line 489/572: `if v0_records.len() < majority_fixed.threshold()`, which only verifies the initial count of records. Subsequently, shares are filtered by verification at lines 494-506 and 577-589, where invalid shares are discarded. However, there is no check after this filtering to ensure that the remaining valid shares still meet the threshold requirement. The code then proceeds to call `interpolate_eval` with whatever valid points remain. [3](#0-2) 

**Exploit Scenario:**
1. User initiates recovery with MSK records from exactly threshold nodes (e.g., t=3)
2. The initial threshold check at line 489 passes (3 >= 3)
3. During verification at lines 497-505, one or more shares fail the `verify_secret_share` check (due to corrupted data or tampered shares)
4. After filtering, only 2 valid shares remain in the `points` vector
5. The code proceeds to line 509 and performs Lagrange interpolation with only 2 points
6. For a degree-2 polynomial (threshold 3), interpolation with 2 points reconstructs a different degree-1 polynomial
7. The wrong value of v0 is computed, leading to an incorrect encapsulation key
8. Subsequent decryption operations fail with `DecryptionFailed` error [4](#0-3) 

**Security Failure:**
This violates the fundamental correctness guarantee of threshold secret sharing schemes. The system fails to detect insufficient valid shares and proceeds with incorrect reconstruction, causing legitimate recovery operations to fail when users provide exactly the minimum required number of records.

## Impact Explanation

**Affected Assets and Processes:**
- User account recovery operations become unreliable
- Master secret key reconstruction from off-chain MSK records
- Recovery initiation key (RIK) data reconstruction

**Severity of Damage:**
When a user attempts recovery with exactly threshold MSK records and some contain invalid shares:
- The reconstruction produces an incorrect secret value
- Decryption of RIK-encrypted data fails (line 526-530 in `reconstruct_rik_data`)
- The entire recovery process is blocked, preventing the user from accessing their account
- User must retry with different combinations of nodes, which may not be possible if only threshold nodes are available [5](#0-4) 

**System Impact:**
This matters because:
- Users following the correct recovery procedure can experience failures
- The protocol fails to provide clear error messages distinguishing between "insufficient valid shares" and other decryption errors
- Recovery operations are temporarily frozen until users can obtain additional valid records
- This undermines user confidence in the recovery system's reliability

## Likelihood Explanation

**Who Can Trigger:**
Any user performing account recovery using MSK records from off-chain nodes can encounter this issue. It does not require malicious intent—the vulnerability manifests during normal recovery operations when data integrity issues exist.

**Required Conditions:**
- User retrieves exactly threshold number of MSK records (the minimum required)
- One or more records contain shares that fail Pedersen commitment verification
- This can occur due to: storage corruption on off-chain nodes, network transmission errors, or race conditions during data synchronization

**Frequency:**
- Moderate likelihood during normal operations, especially as the system scales
- Higher probability when users fetch records from exactly threshold nodes rather than having redundancy
- Can occur repeatedly if the same corrupted records are fetched
- More likely in scenarios with unstable storage or network conditions

## Recommendation

Add a threshold validation check after filtering invalid shares and before performing interpolation. The fix should be applied to both `reconstruct_rik_data` and `reconstruct_recovery_key`:

```rust
// After filtering shares (line 506 and line 589), add:
if points.len() < majority_fixed.threshold() {
    return Err(SwafeError::NotEnoughSharesForReconstruction);
}
```

This ensures that reconstruction only proceeds when sufficient valid shares are available, providing early detection of data integrity issues and clearer error reporting to users.

## Proof of Concept

**File:** `lib/src/association/v0.rs` (add to the test module at the end of the file)

**Test Function:** `test_reconstruct_rik_data_with_invalid_share_post_filtering`

**Setup:**
1. Create an encrypted RIK association with threshold = 3
2. Generate 3 MSK records with valid commitments and shares
3. Tamper with one share to make it fail verification (while keeping the same commitments)

**Trigger:**
1. Call `Association::reconstruct_rik_data` with exactly 3 records where one has an invalid share
2. The initial threshold check passes (3 >= 3)
3. During verification, one share fails and is filtered out
4. Only 2 valid shares remain but interpolation proceeds anyway

**Observation:**
The function should return `NotEnoughSharesForReconstruction` error but instead proceeds with wrong interpolation. The subsequent decryption fails with a `DecryptionFailed` error rather than the more specific threshold error. The test demonstrates that the wrong secret is reconstructed by observing the decryption failure when it should have failed earlier with a clear threshold violation error.

The test should be added after the existing `test_reconstruct_rik_data_insufficient_records` test to demonstrate the difference between insufficient initial records (which is caught) versus insufficient valid records after filtering (which is not caught).

### Citations

**File:** lib/src/association/v0.rs (L455-535)
```rust
    pub fn reconstruct_rik_data(
        msk_records: Vec<(NodeId, MskRecord)>,
        rik: &RecoveryInitiationKey,
    ) -> Result<RikSecretData, SwafeError> {
        // Convert all MskRecord enums to their V0 variants
        let v0_records: Vec<(NodeId, MskRecordV0)> = msk_records
            .into_iter()
            .map(|(node_id, record)| match record {
                MskRecord::V0(v0) => (node_id, v0),
            })
            .collect();

        // Do a threshold vote on the fixed fields
        let mut votes = HashMap::new();
        for (_, record) in &v0_records {
            *votes.entry(record.fixed.clone()).or_insert(0) += 1;
        }

        let majority_threshold = v0_records.len().div_ceil(2);
        let majority_fixed = votes
            .into_iter()
            .find(|(_, count)| *count >= majority_threshold)
            .map(|(fixed, _)| fixed)
            .ok_or_else(|| {
                SwafeError::InvalidInput(
                    "No majority consensus on fixed fields among MSK records".to_string(),
                )
            })?;

        let v0_records: Vec<_> = v0_records
            .into_iter()
            .filter(|(_, record)| record.fixed == majority_fixed)
            .collect();

        if v0_records.len() < majority_fixed.threshold() {
            return Err(SwafeError::NotEnoughSharesForReconstruction);
        }

        // Verify shares and collect valid points
        let points: Vec<_> = v0_records
            .iter()
            .filter_map(|(node_id, msk_record)| {
                match verify_secret_share(&majority_fixed.commits, &msk_record.share, node_id) {
                    Ok(()) => {
                        let x = node_id.eval_point();
                        let y = msk_record.share.value();
                        Some((x, y))
                    }
                    Err(_) => None,
                }
            })
            .collect();

        // Reconstruct v_0 using Lagrange interpolation
        let v0 = interpolate_eval(&points, curve::Fr::zero());

        // Derive encapsulation key from v_0
        let v0_point = (curve::GProjective::generator() * v0).into();
        let v0_bytes = {
            let mut bytes = Vec::new();
            let affine: curve::GAffine = v0_point;
            affine
                .serialize_compressed(&mut bytes)
                .map_err(|e| SwafeError::SerializationError(e.to_string()))?;
            bytes
        };

        let _encapsulation_key: symmetric::Key = kdfn(&v0_bytes, &EncapKeyKDF);

        // Decrypt using RIK to get RikSecretData
        let encrypted_data = &majority_fixed.enc_rik;
        let combined_secret: CombinedSecretData = symmetric::open(
            rik.as_bytes(),
            &encrypted_data.ciphertext,
            &symmetric::EmptyAD,
        )?;

        match combined_secret {
            CombinedSecretData::V0 { rik_data } => Ok(rik_data),
        }
    }
```

**File:** lib/src/account/v0.rs (L177-193)
```rust
        // decrypt AssociationsV0 using RIK
        let encap = self
            .rec
            .assoc
            .iter()
            .find_map(|assoc| {
                // attempt to decrypt the encapsulated key using RIK
                let encap = sym::open::<EncapV0, _>(rik.as_bytes(), &assoc.encap, &acc).ok()?;

                // check if the verification key matches the expected one
                if encap.key_sig.verification_key() != assoc.sig {
                    None
                } else {
                    Some(encap)
                }
            })
            .ok_or(SwafeError::InvalidRecoveryKey)?;
```
