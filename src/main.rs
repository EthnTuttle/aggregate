use secp256k1::{
    hashes::{sha256, Hash}, rand::rngs::OsRng, schnorr::Signature, Keypair, Message, PublicKey, Secp256k1
};

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
    let secp = Secp256k1::new();
    let (private_key_1, _public_key_1) = secp.generate_keypair(&mut OsRng);
    let digest_1 = sha256::Hash::hash("be peaceful, not harmless".as_bytes());
    let message_1 = Message::from_digest(digest_1.to_byte_array());

    let _sig_1 = secp.sign_schnorr(&message_1, &Keypair::from_secret_key(&secp, &private_key_1));


    let (private_key_2, _public_key_2) = secp.generate_keypair(&mut OsRng);
    let digest_2 = sha256::Hash::hash("be peaceful, not harmless 2".as_bytes());
    let message_2 = Message::from_digest(digest_2.to_byte_array());

    let _sig_2 = secp.sign_schnorr(&message_2, &Keypair::from_secret_key(&secp, &private_key_2));


}

struct AggregateSignature {}

fn aggregate(pubkeys: Vec<PublicKey>, message: Message, signature: Signature) -> AggregateSignature {
    todo!()
}

fn IncAggregate(agg_sig: AggregateSignature, Vec<PublicKey>,)