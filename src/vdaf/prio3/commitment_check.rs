// SPDX-License-Identifier: MPL-2.0

//! Experimental P-256 check on two index shares projected from a vanilla histogram.
//!
//! In one-round Prio3, the Leader sends its locally computed point with its
//! verifier share via a DAP request extension. The Helper returns its point
//! with the verifier message via a proposed versioned DAP response encoding.
//! Both calculate from their own expanded VDAF input share and require this
//! check and Prio3 validity before aggregating. A corrupt aggregator can forge
//! its point; this is not an integrity guarantee against a malicious aggregator.

use crate::field::{Field128, FieldElementWithInteger};
use p256::{elliptic_curve::ff::PrimeField, ProjectivePoint, Scalar};
use subtle::ConstantTimeEq;

/// P-256 scalar corresponding to a canonical Field128 representative.
pub fn scalar(value: u128) -> Scalar {
    let mut repr = p256::FieldBytes::default();
    repr[16..].copy_from_slice(&value.to_be_bytes());
    // P-256's order is greater than 2^128.
    Option::<Scalar>::from(Scalar::from_repr(repr)).expect("u128 fits in P-256 scalar")
}

/// Each honest aggregator calculates this locally from its projected index share and
/// privately delivered scalar share of the report's one-use blinding factor.
pub fn index_point(
    index_share: u128,
    blinding_share: Scalar,
    index_generator: &ProjectivePoint,
    blinding_generator: &ProjectivePoint,
) -> Result<ProjectivePoint, &'static str> {
    if index_share >= Field128::modulus() {
        return Err("noncanonical Field128 index share");
    }
    Ok(*index_generator * scalar(index_share) + *blinding_generator * blinding_share)
}

/// True if the sum of two independently computed points opens the report
/// commitment to the index projected from a verified one-hot measurement. Either comparison
/// is possible because the two field-share representatives may sum to t+p.
pub fn matches_commitment(
    commitment: &ProjectivePoint,
    left: &ProjectivePoint,
    right: &ProjectivePoint,
    index_generator: &ProjectivePoint,
) -> bool {
    let sum = *left + *right;
    let p = scalar(Field128::modulus());
    bool::from(sum.ct_eq(commitment) | sum.ct_eq(&(*commitment + *index_generator * p)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_and_wrong_bucket() {
        // Distinct generators; production derives and pins these by DST.
        let h = ProjectivePoint::GENERATOR * Scalar::from(7u64);
        let r = ProjectivePoint::GENERATOR * Scalar::from(13u64);
        let p = Field128::modulus();
        let rho = Scalar::from(123u64);
        let blind0 = Scalar::from(50u64);
        let blind1 = rho - blind0;
        let commitment = h * scalar(2) + r * rho;

        for left in [0, 1, p - 1] {
            let right = if left <= 2 { 2 - left } else { p - (left - 2) };
            let p0 = index_point(left, blind0, &h, &r).unwrap();
            let p1 = index_point(right, blind1, &h, &r).unwrap();
            assert!(matches_commitment(&commitment, &p0, &p1, &h));
        }

        let p0 = index_point(p - 3, blind0, &h, &r).unwrap();
        let wrong = index_point(4, blind1, &h, &r).unwrap(); // index 1, not 2
        assert!(!matches_commitment(&commitment, &p0, &wrong, &h));
        assert_eq!(
            index_point(p, blind0, &h, &r).unwrap_err(),
            "noncanonical Field128 index share"
        );

        // A corrupt aggregator can force acceptance regardless of its share.
        let forged = commitment + h * scalar(p) - p0;
        assert!(matches_commitment(&commitment, &p0, &forged, &h));
    }
}
