use std::{collections::HashMap, vec};

use bitcoin::{
    key::{Keypair, Secp256k1},
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY},
    script::Builder,
    secp256k1::{self, PublicKey},
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, ScriptBuf, XOnlyPublicKey,
};
use rand::{rngs::ThreadRng, SeedableRng};
use schnorr_fun::{
    adaptor::{Adaptor, EncryptedSign},
    fun::{g, marker::*, nonce, s, Scalar, G},
    Message, Schnorr,
};
use sha2::{digest::Update, Sha256};

use anyhow::Result;

fn main() {
    //////////////////////////////////////////
    // SERVER SIDE OF THE PROTOCOL /////////////
    ///////////////////////////////////////////

    // Initialize Schnorr context
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);

    // Generate a random u64
    let seed: u64 = 1616088354130730604;

    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let oracle_secret_key = Scalar::random(&mut rng);
    let oracle_keypair = schnorr.new_keypair(oracle_secret_key);
    let oracle_public_key = oracle_keypair.public_key().normalize();

    // Generate and verify nonce is non-zero
    let nonce_secret: Scalar = Scalar::random(&mut rng);
    let nonce_public_key = g!(nonce_secret * G).normalize();

    // Oracle publishes PK_O and Nonce
    // Participants receive PK_O and Nonce

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

    let nonce_bytes = nonce_public_key.normalize().to_bytes_uncompressed();
    let oracle_public_key_bytes = oracle_public_key.normalize().to_bytes_uncompressed();

    for outcome in &outcomes {
        // Participants compute h_i = Hash(R_i || PK_O || s_i)
        let outcome_bytes = outcome.as_bytes();

        let challenge_hash = Scalar::from_hash(
            Sha256::default()
                .chain(nonce_bytes)
                .chain(oracle_public_key_bytes)
                .chain(outcome_bytes),
        );

        // Compute T_i = R_i + h_i * PK_O
        let encryption_key = g!(nonce_public_key + challenge_hash * oracle_public_key)
            .normalize()
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

    let white_encryption_key = encryption_keys.get("Outcome A").unwrap();
    let black_encryption_key = encryption_keys.get("Outcome B").unwrap();

    let oracle_white_encryption_key =
        XOnlyPublicKey::from_slice(&white_encryption_key.to_xonly_bytes()).unwrap();
    let oracle_black_encryption_key =
        XOnlyPublicKey::from_slice(&black_encryption_key.to_xonly_bytes()).unwrap();

    //get this from bob
    let bob_sk = Scalar::random(&mut rand::thread_rng());
    let bob_keypair = schnorr.new_keypair(bob_sk);

    let alice_pubkey_bytes = PublicKey::from_slice(&alice_keypair.public_key().to_bytes()).unwrap();
    let bob_pubkey_bytes = PublicKey::from_slice(&bob_keypair.public_key().to_bytes()).unwrap();

    let taproot_spend_info = create_script(
        alice_pubkey_bytes,
        bob_pubkey_bytes,
        oracle_white_encryption_key,
        oracle_black_encryption_key,
    )
    .unwrap();

    let address = Address::p2tr_tweaked(taproot_spend_info.output_key(), bitcoin::Network::Signet);
    println!("🔓 address: {:?}", address);

    //////////////////////////////////////////
    // SERVER SIDE OF THE PROTOCOL /////////////
    ///////////////////////////////////////////

    let mut test_all_outcomes = Vec::new();
    for outcome in &outcomes {
        // Participants send the actual outcome to the oracle
        // Oracle computes e = Hash(R_i || PK_O || actual_outcome)

        let outcome_bytes: &[u8] = outcome.as_bytes();

        let signature_hash = Scalar::from_hash(
            Sha256::default()
                .chain(nonce_bytes)
                .chain(oracle_public_key_bytes)
                .chain(outcome_bytes),
        );

        let s_oracle = s!(nonce_secret + signature_hash * oracle_secret_key);

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

                let is_valid = schnorr.verify(&alice_pubkey, message, &decrypted_signature);

                println!("\n{}", outcome);
                assert!(is_valid, "Decrypted signature verification failed");
                println!("{:?}", decrypted_signature);
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

fn create_script(
    white_pub_key: PublicKey,
    bob_pub_key: PublicKey,
    oracle_encryption_key_white: XOnlyPublicKey,
    oracle_encryption_key_black: XOnlyPublicKey,
) -> Result<(TaprootSpendInfo)> {
    println!("🏗️ Creating address for game");
    let secp = Secp256k1::new();

    let combined_pubkey = secp256k1::PublicKey::combine_keys(&[&white_pub_key, &bob_pub_key])
        .expect("Failed to combine keys");

    let white_script = dlchess_script_win(
        XOnlyPublicKey::from_slice(&oracle_encryption_key_white.serialize()).unwrap(),
        white_pub_key.x_only_public_key().0,
    );

    let black_script = dlchess_script_win(
        XOnlyPublicKey::from_slice(&oracle_encryption_key_black.serialize()).unwrap(),
        bob_pub_key.clone().x_only_public_key().0,
    );

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(1, white_script)
        .unwrap()
        .add_leaf(1, black_script)
        .unwrap()
        .finalize(&secp, combined_pubkey.into())
        .unwrap();

    Ok(taproot_spend_info)
}

fn dlchess_script_win(oracle_pubkey: XOnlyPublicKey, player_pubkey: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&oracle_pubkey)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&player_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}
