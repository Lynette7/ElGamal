use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::thread_rng;
use aes::Aes128;
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::Pkcs7;

type Aes128Ecb = Ecb<Aes128, Pkcs7>;

const P: u32 = 23;
const G: u32 = 5;

fn generate_keypair() -> (BigUint, BigUint) {
    let mut rng = thread_rng();
    let private_key = rng.gen_biguint_below(&BigUint::from(P - 1)) + BigUint::one();
    let public_key = BigUint::from(G).modpow(&private_key, &BigUint::from(P));
    (private_key, public_key)
}

fn encrypt(message: &str, recipient_public_key: &BigUint) -> (BigUint, Vec<u8>) {
    let mut rng = thread_rng();
    let k = rng.gen_biguint_below(&BigUint::from(P - 1)) + BigUint::one();
    let shared_secret = recipient_public_key.modpow(&k, &BigUint::from(P));
    
    let c1 = BigUint::from(G).modpow(&k, &BigUint::from(P));
    let key = generate_secret_key_spec(&shared_secret);
    let cipher = Aes128Ecb::new_from_slices(&key, Default::default()).unwrap();
    let c2 = cipher.encrypt_vec(message.as_bytes());
    
    (c1, c2)
}

fn decrypt(c1: &BigUint, c2: &[u8], private_key: &BigUint) -> String {
    let shared_secret = c1.modpow(private_key, &BigUint::from(P));
    let key = generate_secret_key_spec(&shared_secret);
    let cipher = Aes128Ecb::new_from_slices(&key, Default::default()).unwrap();
    let decrypted_data = cipher.decrypt_vec(c2).unwrap();
    String::from_utf8(decrypted_data).unwrap()
}

fn generate_secret_key_spec(secret: &BigUint) -> [u8; 16] {
    let key_bytes = secret.to_bytes_le();
    let mut valid_key_bytes = [0u8; 16];
    for (i, &byte) in key_bytes.iter().enumerate().take(16) {
        valid_key_bytes[i] = byte;
    }
    valid_key_bytes
}

fn main() {
    // Alice generates her keypair
    let (alice_private_key, alice_public_key) = generate_keypair();
    println!("Alice's public key: {}", alice_public_key);

    // Bob wants to send a message to Alice
    let message = "Hello, Alice! This is a secret message.";
    println!("Original message: {}", message);

    // Bob encrypts the message using Alice's public key
    let (c1, c2) = encrypt(message, &alice_public_key);
    println!("Encrypted message:");
    println!("c1: {}", c1);
    println!("c2: {:?}", c2);

    // Alice decrypts the message using her private key
    let decrypted_message = decrypt(&c1, &c2, &alice_private_key);
    println!("Decrypted message: {}", decrypted_message);

    // Now Bob generates his keypair
    let (bob_private_key, bob_public_key) = generate_keypair();
    println!("\nBob's public key: {}", bob_public_key);

    // Alice wants to send a message to Bob
    let message2 = "Hello, Bob! This is also a secret message.";
    println!("Original message: {}", message2);

    // Alice encrypts the message using Bob's public key
    let (c1_2, c2_2) = encrypt(message2, &bob_public_key);
    println!("Encrypted message:");
    println!("c1: {}", c1_2);
    println!("c2: {:?}", c2_2);

    // Bob decrypts the message using his private key
    let decrypted_message2 = decrypt(&c1_2, &c2_2, &bob_private_key);
    println!("Decrypted message: {}", decrypted_message2);
}