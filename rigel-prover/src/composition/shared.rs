use starknet_crypto::{Felt, poseidon_hash_many};

use crate::core::errors::Result;
use crate::core::scalar::Scalar;
use crate::core::sigma;
use crate::core::transcript::Transcript;
use crate::protocols::types::{SigmaProof, SigmaStatement};

/// binary composition-label tree labels are computed recursively with `h(protocol_tag || left_label || right_label)`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompositionLabelTree {
    Leaf(Felt),
    Node(Box<CompositionLabelTree>, Box<CompositionLabelTree>),
}

#[inline]
pub fn append_statement(t: &mut Transcript, stmt: &SigmaStatement) -> Result<()> {
    sigma::absorb_statement(t, stmt)
}

#[inline]
pub fn statement_label(stmt: &SigmaStatement) -> Result<Felt> {
    sigma::statement_label(stmt)
}

#[inline]
pub fn composition_pair_label(protocol_tag: &Felt, left: &Felt, right: &Felt) -> Felt {
    let data = [*protocol_tag, *left, *right];
    poseidon_hash_many(data.iter())
}

#[inline]
pub fn composition_tree_root_label(protocol_tag: &Felt, tree: &CompositionLabelTree) -> Felt {
    match tree {
        CompositionLabelTree::Leaf(label) => *label,
        CompositionLabelTree::Node(left, right) => {
            let left_label = composition_tree_root_label(protocol_tag, left);
            let right_label = composition_tree_root_label(protocol_tag, right);
            composition_pair_label(protocol_tag, &left_label, &right_label)
        }
    }
}

#[inline]
pub fn composition_tree_from_labels(labels: &[Felt]) -> Option<CompositionLabelTree> {
    let (first, rest) = labels.split_first()?;
    let mut tree = CompositionLabelTree::Leaf(*first);
    for next in rest {
        tree =
            CompositionLabelTree::Node(Box::new(tree), Box::new(CompositionLabelTree::Leaf(*next)));
    }
    Some(tree)
}

#[inline]
pub fn fold_composition_labels(protocol_tag: &Felt, labels: &[Felt]) -> Option<Felt> {
    let tree = composition_tree_from_labels(labels)?;
    Some(composition_tree_root_label(protocol_tag, &tree))
}

#[inline]
pub fn append_commitment(
    t: &mut Transcript,
    stmt: &SigmaStatement,
    proof: &SigmaProof,
) -> Result<()> {
    sigma::absorb_commitment(t, stmt, proof)
}

#[inline]
pub fn validate_statement_and_proof(stmt: &SigmaStatement, proof: &SigmaProof) -> Result<()> {
    sigma::validate_statement_and_proof(stmt, proof)
}

#[inline]
pub fn verify_with_challenge(
    stmt: &SigmaStatement,
    proof: &SigmaProof,
    challenge: &Scalar,
) -> Result<()> {
    sigma::verify_with_challenge_allow_zero(stmt, proof, challenge)
}
