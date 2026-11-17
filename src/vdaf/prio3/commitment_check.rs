// SPDX-License-Identifier: MPL-2.0

//! Experimental P-256 check on two private Field128 tag shares.
//!
//! In one-round Prio3, the Leader sends its locally computed point with its
//! verifier share; the Helper returns its point with the verifier message.
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

/// Each honest aggregator calculates this locally from its tag share and
/// privately delivered scalar share of the report's one-use blinding factor.
pub fn tag_point(
    tag_share: u128,
    blinding_share: Scalar,
    tag_generator: &ProjectivePoint,
    blinding_generator: &ProjectivePoint,
) -> Result<ProjectivePoint, &'static str> {
    if tag_share >= Field128::modulus() {
        return Err("noncanonical Field128 tag share");
    }
    Ok(*tag_generator * scalar(tag_share) + *blinding_generator * blinding_share)
}

/// True if the sum of two independently computed points opens the report
/// commitment to the tag encoded in the Prio3 measurement. Either comparison
/// is possible because the two field-share representatives may sum to t+p.
pub fn matches_commitment(
    commitment: &ProjectivePoint,
    left: &ProjectivePoint,
    right: &ProjectivePoint,
    tag_generator: &ProjectivePoint,
) -> bool {
    let sum = *left + *right;
    let p = scalar(Field128::modulus());
    bool::from(sum.ct_eq(commitment) | sum.ct_eq(&(*commitment + *tag_generator * p)))
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
            let p0 = tag_point(left, blind0, &h, &r).unwrap();
            let p1 = tag_point(right, blind1, &h, &r).unwrap();
            assert!(matches_commitment(&commitment, &p0, &p1, &h));
        }

        let p0 = tag_point(p - 3, blind0, &h, &r).unwrap();
        let wrong = tag_point(4, blind1, &h, &r).unwrap(); // bucket tag 1, not 2
        assert!(!matches_commitment(&commitment, &p0, &wrong, &h));
        assert_eq!(
            tag_point(p, blind0, &h, &r).unwrap_err(),
            "noncanonical Field128 tag share"
        );

        // A corrupt aggregator can force acceptance regardless of its share.
        let forged = commitment + h * scalar(p) - p0;
        assert!(matches_commitment(&commitment, &p0, &forged, &h));
    }
}
