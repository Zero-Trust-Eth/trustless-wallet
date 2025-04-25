mod wordlist;

use bitcoin_hashes::{Hash, sha256};

/// mnemonics must be 24 words
const NB_WORDS: usize = 24;
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
        const CHECKSUM_BITS: usize = 8;

        let mut bits = [false; ENTROPY_LEN + CHECKSUM_BITS];
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
