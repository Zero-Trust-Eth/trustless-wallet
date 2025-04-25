mod wordlist;

use bitcoin_hashes::{Hash, sha256};

/// mnemonics are 24 words
const NB_WORDS: usize = 24;
/// checksum is 1 byte
const CHECKSUM_BITS: usize = 8;
/// entropy must be 32 bytes
const ENTROPY_LEN: usize = 32;

/// A 24 word mnemonic code.
pub struct Mnemonic {
    /// The indices of the words.
    words: [u16; 24],
}

impl Mnemonic {
    /// Create a new [Mnemonic] from the given entropy.
    /// Entropy must be 256 bits in length.
    pub fn from_entropy(entropy: [u8; ENTROPY_LEN]) -> Mnemonic {
        let mut bits = [false; ENTROPY_LEN * 8 + CHECKSUM_BITS];
        for i in 0..ENTROPY_LEN {
            for j in 0..8 {
                bits[i * 8 + j] = (entropy[i] & (1 << (7 - j))) > 0;
            }
        }

        // we can rely on an external sha256 since it's only being used for generating checksums
        let check = sha256::Hash::hash(&entropy);
        for i in 0..CHECKSUM_BITS {
            bits[8 * ENTROPY_LEN + i] = (check[i / 8] & (1 << (7 - (i % 8)))) > 0;
        }

        let mut words = [0; NB_WORDS];
        for i in 0..NB_WORDS {
            let mut idx = 0;
            for j in 0..11 {
                if bits[i * 11 + j] {
                    idx += 1 << (10 - j);
                }
            }
            words[i] = idx;
        }

        Mnemonic { words }
    }

    /// Returns an iterator over the words of the [Mnemonic].
    pub fn words(&self) -> impl Iterator<Item = &'static str> + Clone + '_ {
        self.words
            .iter()
            .map(move |i| wordlist::WORDS[usize::from(*i)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    #[test]
    fn test_mnemonic() {
        // These vectors are tuples of
        // (entropy, mnemonic)
        let test_vectors = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            ),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            ),
            (
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            ),
            (
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            ),
            (
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            ),
            (
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            ),
            (
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            ),
        ];

        for vector in &test_vectors {
            let mut entropy = [0u8; 32];
            entropy.copy_from_slice(&decode(&vector.0).unwrap());
            let expected_mnemonic = vector.1;

            let mnemonic = Mnemonic::from_entropy(entropy);
            let actual_mnemonic = mnemonic.words().collect::<Vec<_>>().join(" ");

            assert_eq!(expected_mnemonic, actual_mnemonic);
        }
    }
}
