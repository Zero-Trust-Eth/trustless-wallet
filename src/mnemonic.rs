use crate::bools_to_bytes;
use crate::bytes_to_bools;
use crate::sha256;
use crate::wordlist;

/// A 24 word mnemonic code
pub struct Mnemonic {
    /// The indices of the words
    words: [u16; 24],
}

impl Mnemonic {
    /// Create a new [Mnemonic] from the given entropy.
    pub fn from_entropy(entropy: [bool; 256]) -> Mnemonic {
        // calculate entropy checksum
        let checksum = sha256::Hash::hash(&bools_to_bytes!(entropy))[0];

        // append the first byte of the checksum to our entropy
        let mut bits = Vec::from(entropy);
        bits.extend(bytes_to_bools!(&[checksum]));

        // calculate word indexes & return mnemonic
        let mut words = [0; 24];
        for i in 0..24 {
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

    /// Returns an iterator over the words of the [Mnemonic]
    pub fn words(&self) -> impl Iterator<Item = &'static str> {
        self.words
            .iter()
            .map(move |i| wordlist::WORDS[usize::from(*i)])
    }
}
