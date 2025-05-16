mod mnemonic;
mod sha256;
mod wordlist;
#[macro_use]
pub mod macros;
#[cfg(test)]
mod test_mnemonic;

use mnemonic::Mnemonic;
use std::io::Write;
use std::io::{stdin, stdout};

fn main() {
    // collect 256 bits of entropy from dice rolls
    let mut entropy = Vec::new();
    let mut buffer = String::new();
    'outer: loop {
        print!("Enter dice rolls: ");
        stdout().flush().unwrap();
        buffer.clear();
        if stdin().read_line(&mut buffer).is_ok() {
            for c in buffer.chars() {
                if entropy.len() == 256 {
                    break 'outer;
                }
                // only collect faces 1-4
                match c {
                    '1' => entropy.extend([false, false]),
                    '2' => entropy.extend([false, true]),
                    '3' => entropy.extend([true, false]),
                    '4' => entropy.extend([true, true]),
                    _ => continue,
                }
            }
        }
        let remaining_rolls = (256 - entropy.len()) / 2;
        println!("Remaining dice rolls: {}", remaining_rolls);
    }

    // calculate the mnemonic from the input entropy
    let mnemonic = Mnemonic::from_entropy(entropy.try_into().unwrap());

    // display the mnemonic
    println!("Wordlist:\n---------");
    for (i, word) in mnemonic.words().enumerate() {
        println!("{}: {}", i + 1, word);
    }
}
