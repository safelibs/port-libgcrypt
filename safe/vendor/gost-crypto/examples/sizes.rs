#![allow(missing_docs)]

fn main() {
    println!("Gost28147:   {} bytes", std::mem::size_of::<gost_crypto::Gost28147>());
    println!("Gost341194:  {} bytes", std::mem::size_of::<gost_crypto::Gost341194>());
}
