use std::collections::HashMap;

use rand::rngs::ThreadRng;
use schnorr_fun::{
    adaptor::{Adaptor, EncryptedSign},
    fun::{g, marker::*, nonce, s, Scalar, G},
    Message, Schnorr,
};
use sha2::{digest::Update, Sha256};

fn main() {
    //////////////////////////////////////////
    // SERVER SIDE OF THE PROTOCOL /////////////
    ///////////////////////////////////////////

    // Initialize Schnorr context
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);

    // Oracle generates its secret key (sk_O)
    let sk_o = Scalar::random(&mut rand::thread_rng());

    // Oracle's public key (PK_O)
    let oracle_keypair = schnorr.new_keypair(sk_o);
    let pk_o = oracle_keypair.public_key().normalize();

    // Oracle generates a secret nonce k_i for the outcome
    let k_i = Scalar::random(&mut rand::thread_rng());

    // Compute R_i = k_i * G
    let r_i = g!(k_i * G).normalize();

    // Oracle publishes PK_O and R_i
    // Participants receive PK_O and R_i

    //////////////////////////////////////////
    // USER SIDE OF THE PROTOCOL /////////////
    ///////////////////////////////////////////

    let alice_sk = Scalar::random(&mut rand::thread_rng());
    let alice_keypair = schnorr.new_keypair(alice_sk);
    let alice_pubkey = alice_keypair.public_key();

    println!("Alice's public key: {:?}", alice_pubkey);

    let outcomes = vec!["Outcome A", "Outcome B", "Outcome C"];

    // Participants compute h_i, T_i, create encrypted signatures, and verify them
    let mut encryption_keys = HashMap::new();
    let mut encrypted_signatures = HashMap::new();

    for outcome in &outcomes {
        // Participants compute h_i = Hash(R_i || PK_O || s_i)
        let r_i_bytes = r_i.normalize().to_bytes_uncompressed();
        let pk_o_bytes = pk_o.normalize().to_bytes_uncompressed();
        let outcome_bytes = outcome.as_bytes();

        println!(
            "Client Hash Inputs for {}: R_i: {:?}, PK_O: {:?}, outcome: {:?}",
            outcome, r_i_bytes, pk_o_bytes, outcome_bytes
        );

        let h_i = Scalar::from_hash(
            Sha256::default()
                .chain(r_i_bytes)
                .chain(pk_o_bytes)
                .chain(outcome_bytes),
        );

        println!("Client h_i for {}: {:?}", outcome, h_i);
        // Compute T_i = R_i + h_i * PK_O
        let t_i_point = g!(r_i + h_i * pk_o).normalize();

        // T_i is used as the encryption key in the adaptor signature
        let encryption_key = t_i_point
            .non_zero()
            .expect("encryption_key should be non-zero");

        encryption_keys.insert(outcome.to_string(), encryption_key);

        // Create the message for the outcome
        let message = Message::<Public>::plain("CET", outcome.as_bytes());

        // Generate the encrypted signature (adaptor signature)
        let encrypted_signature = schnorr.encrypted_sign(&alice_keypair, &encryption_key, message);

        // Verify the encrypted signature
        let is_valid = schnorr.verify_encrypted_signature(
            &alice_pubkey,
            &encryption_key,
            message,
            &encrypted_signature,
        );

        assert!(is_valid, "Encrypted signature verification failed");

        encrypted_signatures.insert(outcome.to_string(), encrypted_signature);
    }

    //////////////////////////////////////////
    // SERVER SIDE OF THE PROTOCOL /////////////
    ///////////////////////////////////////////
    let actual_outcome = "Outcome B";

    let r_i_bytes = r_i.normalize().to_bytes_uncompressed();
    let pk_o_bytes = pk_o.normalize().to_bytes_uncompressed();
    let outcome_bytes = actual_outcome.as_bytes();

    println!(
        "Server Hash Inputs: R_i: {:?}, PK_O: {:?}, outcome: {:?}",
        r_i_bytes, pk_o_bytes, outcome_bytes
    );

    let e = Scalar::from_hash(
        Sha256::default()
            .chain(r_i_bytes)
            .chain(pk_o_bytes)
            .chain(outcome_bytes),
    );

    println!("Server e: {:?}", e);
    let s_oracle = s!(k_i + e * sk_o);

    // Oracle publishes (R_i, s_oracle)
    let s_oracle_non_zero = s_oracle.non_zero().expect("s_oracle should be non-zero");

    //////////////////////////////////////////
    // USER SIDE OF THE PROTOCOL /////////////
    ///////////////////////////////////////////

    let encryption_key = encryption_keys
        .get(actual_outcome)
        .expect("encryption key exists");
    let encrypted_signature = encrypted_signatures
        .get(actual_outcome)
        .expect("encrypted signature exists");
    let message = Message::<Public>::plain("CET", actual_outcome.as_bytes());

    let decrypted_signature =
        schnorr.decrypt_signature(s_oracle_non_zero, encrypted_signature.clone());

    // Verify the decrypted signature
    let is_valid = schnorr.verify(&alice_pubkey, message, &decrypted_signature);
    // During verification
    println!("Decrypted Signature s: {:?}", decrypted_signature.s);
    println!("Decrypted Signature R: {:?}", decrypted_signature.R);
    println!("Computed e during verification: {:?}", e);
    println!("s * G: {:?}", g!(decrypted_signature.s * G).normalize());
    println!(
        "R + e * P: {:?}",
        g!(decrypted_signature.R + e * alice_pubkey).normalize()
    );

    assert!(is_valid, "Decrypted signature verification failed");
    println!(
        "Decrypted and verified signature for the actual outcome: {}",
        actual_outcome
    );

    match schnorr.recover_decryption_key(encryption_key, encrypted_signature, &decrypted_signature)
    {
        Some(decryption_key) => {
            println!("Alice got the decryption key {}", decryption_key)
        }
        None => eprintln!("signature is not the decryption of our original encrypted signature"),
    }
}
