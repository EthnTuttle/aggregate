use std::io::Read;

use rand::rngs::ThreadRng;
use schnorr_fun::{Message, Schnorr, Signature};
use secp256kfun::{hash, marker::{NonZero, Public, Zero}, nonce, Point, Scalar, Tag};
use sha2::{Digest, Sha256};

// Functions and operations:
//
// || refers to byte array concatenation.
// The function x[i:j], where x is a byte array and i, j ≥ 0, returns a (j - i)-byte array with a copy of the i-th byte (inclusive) to the j-th byte (exclusive) of x.
// The function bytes(x), where x is an integer, returns the 32-byte encoding of x, most significant byte first.
// The function bytes(P), where P is a point, returns bytes(x(P)).
// The function len(x) where x is a byte array returns the length of the array.
// The function int(x), where x is a 32-byte array, returns the 256-bit unsigned integer whose most significant byte first encoding is x.
// The function has_even_y(P), where P is a point for which not is_infinite(P), returns y(P) mod 2 = 0.
// The function lift_x(x), where x is a 256-bit unsigned integer, returns the point P for which x(P) = x[2] and has_even_y(P), or fails if x is greater than p-1 or no such point exists. The function lift_x(x) is equivalent to the following pseudocode:
//     Fail if x ≥ p.
//     Let c = x3 + 7 mod p.
//     Let y = c(p+1)/4 mod p.
//     Fail if c ≠ y2 mod p.
//     Return the unique point P such that x(P) = x and y(P) = y if y mod 2 = 0 or y(P) = p-y otherwise.
// The function hashtag(x) where tag is a UTF-8 encoded tag name and x is a byte array returns the 32-byte hash SHA256(SHA256(tag) || SHA256(tag) || x).

fn main() {
    // Use synthetic nonces
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone());
    // Generate your public/private key-pair
    let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    // Sign a variable length message
    let message = Message::<Public>::plain(
        "the-times-of-london",
        b"Chancellor on brink of second bailout for banks",
    );
    // Sign the message with our keypair
    let signature = schnorr.sign(&keypair, message);

    // Get the verifier's key
    let verification_key = keypair.public_key();
    // Check it's valid 🍿
    assert!(schnorr.verify(&verification_key, message, &signature));
}

struct PubKeyMessageTuple {
    pub public_key: Point,
    // because the message is a hash, I think
    pub message: [u8; 32],
}

struct PubKeyMessageRValueTriple {
    pub public_key: Point,
    pub message: [u8; 32],
    // a signature is 64bytes, 32 byte r and 32 byte s, 
    pub r: [u8; 32]
}

struct PubkeyMessageSignatureTriple {
    public_key: Point,
    message: [u8; 32],
    signature: Signature,
}

type AggregateSignature = Vec<u8>;

fn incremental_aggregation(
    aggregate_signature: Vec<u8>,
    pubkey_message_tuple: Vec<PubKeyMessageTuple>,
    pubkey_message_signature_triples: Vec<PubkeyMessageSignatureTriple>,
) -> AggregateSignature {
    let tag: &[u8] = "HalfAgg/randomizer".as_bytes();
    let mut hash_tag = Sha256::default();
    hash_tag.update(tag);
    let tag_hash = hash_tag.finalize().as_slice();
    // Fail if v + u >= 2^16
    let two_to_the_sixteenth = 2_u32.pow(16);
    if pubkey_message_tuple.len() + pubkey_message_signature_triples.len() >= two_to_the_sixteenth.try_into().unwrap() {
        panic!()
    }
    // Fail if len(aggsig) ≠ 32 * (v + 1)
    if aggregate_signature.len() != 32_u32* (pubkey_message_tuple.len() + 1) {
        panic!()
    }
    // For i = 0 .. v-1:
    //  Let (pki, mi) = pm_aggdi
    //  Let ri = aggsig[i⋅32:(i+1)⋅32]
    // extracting the r from the already aggregated signatures (r, s)
    // because we'll need to concatenate these in order to form the final aggregate signature
    let mut pubkey_message_tuples_r_values = vec![];
    for i in 0..pubkey_message_tuple.len() {
        // Let (pki, mi) = pm_aggd[i]
        let PubKeyMessageTuple { public_key, message } = pubkey_message_tuple[i];
        // Let ri = aggsig[i⋅32:(i+1)⋅32]
        let start = i * 32;
        let end = (i + 1) * 32;
        let r = &aggregate_signature[start..end];
        pubkey_message_tuples_r_values.push(
            PubKeyMessageRValueTriple {
                public_key,
                message,
                r: r.try_into().unwrap()
            }
        );
    }
    // now we deconstruct the signature for the ones to be aggregated and combine the s values
    for i in pubkey_message_tuple.len()..(pubkey_message_tuple.len() + pubkey_message_signature_triples.len()) {
        let PubkeyMessageSignatureTriple { public_key, message, signature } = pubkey_message_signature_triples[i];
        let r = signature.R;
        let s = signature.s;
        let z: Scalar;
        if i == 0 {
            z = Scalar::one();
        } else {
            let to_be_hashed = pubkey_message_signature_triples[i];
            
        }
    }


    // the final aggregated signature is all the r values and then the final s value.

    todo!()
}
