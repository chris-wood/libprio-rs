// SPDX-License-Identifier: MPL-2.0

//! Experimental histogram with a private tag constrained to the selected bucket.
//!
//! The group commitment check is a separate, mandatory aggregation step: this
//! FLP alone does not bind the input to any external commitment.

use crate::{
    field::{Field128, FieldElement},
    flp::{
        gadgets::{Mul, ParallelSum},
        types::Histogram,
        Flp, FlpError, Gadget, Type,
    },
};

/// The private tag is the 1-based bucket index. Only the one-hot vector is aggregated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentBoundHistogram {
    histogram: Histogram<Field128, ParallelSum<Field128, Mul>>,
    length: usize,
}

impl CommitmentBoundHistogram {
    /// Construct a histogram FLP with an extra private field for the selected bucket.
    pub fn new(length: usize, chunk_length: usize) -> Result<Self, FlpError> {
        Ok(Self {
            histogram: Histogram::new(length, chunk_length)?,
            length,
        })
    }

    /// Position of the private tag in each aggregator's untruncated measurement share.
    pub fn tag_index(&self) -> usize {
        self.length
    }
}

impl Flp for CommitmentBoundHistogram {
    type Field = Field128;

    fn gadget(&self) -> Vec<Box<dyn Gadget<Field128>>> {
        self.histogram.gadget()
    }

    fn num_gadgets(&self) -> usize {
        self.histogram.num_gadgets()
    }

    fn valid(
        &self,
        gadgets: &mut Vec<Box<dyn Gadget<Field128>>>,
        input: &[Field128],
        joint_rand: &[Field128],
        num_shares: usize,
    ) -> Result<Vec<Field128>, FlpError> {
        self.valid_call_check(input, joint_rand)?;
        let mut checks =
            self.histogram
                .valid(gadgets, &input[..self.length], joint_rand, num_shares)?;
        let selected = input[..self.length]
            .iter()
            .enumerate()
            .fold(Field128::zero(), |acc, (bucket, bit)| {
                acc + *bit * Field128::from((bucket + 1) as u128)
            });
        checks.push(input[self.length] - selected);
        Ok(checks)
    }

    fn input_len(&self) -> usize {
        self.length + 1
    }
    fn proof_len(&self) -> usize {
        self.histogram.proof_len()
    }
    fn verifier_len(&self) -> usize {
        self.histogram.verifier_len()
    }
    fn joint_rand_len(&self) -> usize {
        self.histogram.joint_rand_len()
    }
    fn eval_output_len(&self) -> usize {
        self.histogram.eval_output_len() + 1
    }
    fn prove_rand_len(&self) -> usize {
        self.histogram.prove_rand_len()
    }
}

impl Type for CommitmentBoundHistogram {
    type Measurement = usize;
    type AggregateResult = Vec<u128>;

    fn encode_measurement(&self, bucket: &usize) -> Result<Vec<Field128>, FlpError> {
        if *bucket >= self.length {
            return Err(FlpError::Encode("bucket outside histogram".to_string()));
        }
        let mut input = self.histogram.encode_measurement(bucket)?;
        input.push(Field128::from((*bucket + 1) as u128));
        Ok(input)
    }

    fn truncate(&self, mut input: Vec<Field128>) -> Result<Vec<Field128>, FlpError> {
        self.truncate_call_check(&input)?;
        input.pop();
        self.histogram.truncate(input)
    }

    fn decode_result(
        &self,
        data: &[Field128],
        num_measurements: usize,
    ) -> Result<Vec<u128>, FlpError> {
        self.histogram.decode_result(data, num_measurements)
    }

    fn output_len(&self) -> usize {
        self.length
    }
}
