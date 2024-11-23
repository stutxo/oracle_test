use std::{collections::HashMap, vec};

use rand::{rngs::ThreadRng, SeedableRng};
use schnorr_fun::{
    adaptor::{Adaptor, EncryptedSign},
    fun::{g, marker::*, nonce, s, Scalar, G},
    Message, Schnorr,
};
use sha2::{digest::Update, Sha256};
use uuid::Uuid;

fn main() {
    //////////////////////////////////////////
    // SERVER SIDE OF THE PROTOCOL /////////////
    ///////////////////////////////////////////

    // Initialize Schnorr context
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);

    let seed = Uuid::new_v4();

    let mut rng = rand::rngs::StdRng::seed_from_u64(12345);

    let sk_o = Scalar::random(&mut rng);
    let oracle_keypair = schnorr.new_keypair(sk_o);
    let pk_o = oracle_keypair.public_key().normalize();

    // Generate and verify nonce is non-zero
    let k_i = Scalar::random(&mut rng);
    let r_i = g!(k_i * G).normalize();

    // Oracle publishes PK_O and R_i
    // Participants receive PK_O and R_i

    //////////////////////////////////////////
    // USER SIDE OF THE PROTOCOL /////////////
    ///////////////////////////////////////////

    let alice_sk = Scalar::random(&mut rand::thread_rng());
    let alice_keypair = schnorr.new_keypair(alice_sk);
    let alice_pubkey = alice_keypair.public_key();

    let outcomes = vec!["Outcome A", "Outcome B", "Outcome C"];

    // Participants compute h_i, T_i, create encrypted signatures, and verify them
    let mut encryption_keys = HashMap::new();
    let mut encrypted_signatures = HashMap::new();

    for outcome in &outcomes {
        // Participants compute h_i = Hash(R_i || PK_O || s_i)
        let r_i_bytes = r_i.normalize().to_bytes_uncompressed();
        let pk_o_bytes = pk_o.normalize().to_bytes_uncompressed();
        let outcome_bytes = outcome.as_bytes();

        let h_i = Scalar::from_hash(
            Sha256::default()
                .chain(r_i_bytes)
                .chain(pk_o_bytes)
                .chain(outcome_bytes),
        );

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

    let mut test_all_outcomes = Vec::new();
    for outcome in &outcomes {
        // Participants send the actual outcome to the oracle
        // Oracle computes e = Hash(R_i || PK_O || actual_outcome)

        let r_i_bytes = r_i.normalize().to_bytes_uncompressed();
        let pk_o_bytes = pk_o.normalize().to_bytes_uncompressed();
        let outcome_bytes = outcome.as_bytes();

        let e = Scalar::from_hash(
            Sha256::default()
                .chain(r_i_bytes)
                .chain(pk_o_bytes)
                .chain(outcome_bytes),
        );

        let s_oracle = s!(k_i + e * sk_o);

        // Oracle publishes (R_i, s_oracle)
        let s_oracle_non_zero = s_oracle.non_zero().expect("s_oracle should be non-zero");
        test_all_outcomes.push((outcome, s_oracle_non_zero));
    }

    //////////////////////////////////////////
    // USER SIDE OF THE PROTOCOL /////////////
    ///////////////////////////////////////////

    for (outcome, encryption_key) in encryption_keys.iter() {
        for (test_outcome, s_oracle_non_zero) in test_all_outcomes.iter() {
            if *test_outcome == outcome {
                let encrypted_signature = encrypted_signatures
                    .get(outcome)
                    .expect("encrypted signature exists");
                let message = Message::<Public>::plain("CET", outcome.as_bytes());

                let decrypted_signature =
                    schnorr.decrypt_signature(*s_oracle_non_zero, encrypted_signature.clone());

                let r_i_bytes = r_i.normalize().to_bytes_uncompressed();
                let pk_o_bytes = pk_o.normalize().to_bytes_uncompressed();
                let outcome_bytes = outcome.as_bytes();

                let h_i = Scalar::from_hash(
                    Sha256::default()
                        .chain(r_i_bytes)
                        .chain(pk_o_bytes)
                        .chain(outcome_bytes),
                );

                // Verify the decrypted signature
                let is_valid = schnorr.verify(&alice_pubkey, message, &decrypted_signature);
                // During verification
                println!("Decrypted Signature s: {:?}", decrypted_signature.s);
                println!("Decrypted Signature R: {:?}", decrypted_signature.R);
                println!("Computed e during verification: {:?}", h_i);
                println!("s * G: {:?}", g!(decrypted_signature.s * G).normalize());
                println!(
                    "R + e * P: {:?}",
                    g!(decrypted_signature.R + h_i * alice_pubkey).normalize()
                );

                assert!(is_valid, "Decrypted signature verification failed");
                println!(
                    "Decrypted and verified signature for the actual outcome: {}",
                    outcome
                );

                match schnorr.recover_decryption_key(
                    encryption_key,
                    encrypted_signature,
                    &decrypted_signature,
                ) {
                    Some(decryption_key) => {
                        println!("Alice got the decryption key {}", decryption_key)
                    }
                    None => {
                        eprintln!(
                            "signature is not the decryption of our original encrypted signature"
                        )
                    }
                }
            }
        }
    }
}
