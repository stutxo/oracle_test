use std::{collections::HashMap, vec};

use bitcoin::{
    consensus::Encodable,
    hashes::{sha256, Hash},
    key::{Keypair, Secp256k1},
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_NOP4},
    script::Builder,
    secp256k1::{self, Message, PublicKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    Address, Amount, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxOut,
    XOnlyPublicKey,
};

use rand::{rngs::ThreadRng, SeedableRng};
use schnorr_fun::{
    adaptor::{Adaptor, EncryptedSign},
    fun::{g, marker::*, nonce, s, Point, Scalar, G},
    Schnorr,
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
        let message = schnorr_fun::Message::<Public>::plain("CET", outcome.as_bytes());

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

                let message = schnorr_fun::Message::<Public>::plain("CET", outcome.as_bytes());

                //do i use this to unlock the oracles script?
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

                //test unlocking the script here

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
) -> Result<TaprootSpendInfo> {
    println!("🏗️ Creating address for game");
    let secp = Secp256k1::new();

    let combined_pubkey = secp256k1::PublicKey::combine_keys(&[&white_pub_key, &bob_pub_key])
        .expect("Failed to combine keys");

    let ctv_receive_address_white_win = TaprootBuilder::new()
        .finalize(&secp, white_pub_key.into())
        .unwrap();

    let ctv_output_address_white_win = Address::p2tr_tweaked(
        ctv_receive_address_white_win.output_key(),
        bitcoin::Network::Signet,
    );

    let white_win_outputs = [TxOut {
        //how to do fees?
        value: Amount::from_sat(100_000),
        script_pubkey: ctv_output_address_white_win.script_pubkey(),
    }];

    let white_win_ctv_hash = calc_ctv_hash(&white_win_outputs);

    let ctv_receive_address_black_win = TaprootBuilder::new()
        .finalize(&secp, white_pub_key.into())
        .unwrap();

    let ctv_output_address_black_win = Address::p2tr_tweaked(
        ctv_receive_address_black_win.output_key(),
        bitcoin::Network::Signet,
    );

    let black_win_outputs = [TxOut {
        //how to do fees?
        value: Amount::from_sat(100_000),
        script_pubkey: ctv_output_address_black_win.script_pubkey(),
    }];

    let black_win_ctv_hash = calc_ctv_hash(&black_win_outputs);

    let white_script = dlchess_script_win_ctv(
        XOnlyPublicKey::from_slice(&oracle_encryption_key_white.serialize()).unwrap(),
        white_win_ctv_hash,
    );

    let black_script = dlchess_script_win_ctv(
        XOnlyPublicKey::from_slice(&oracle_encryption_key_black.serialize()).unwrap(),
        black_win_ctv_hash,
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

// fn dlchess_script_win(oracle_pubkey: XOnlyPublicKey, player_pubkey: XOnlyPublicKey) -> ScriptBuf {
//     Builder::new()
//         .push_x_only_key(&oracle_pubkey)
//         .push_opcode(OP_CHECKSIGVERIFY)
//         .push_x_only_key(&player_pubkey)
//         .push_opcode(OP_CHECKSIG)
//         .into_script()
// }

fn dlchess_script_win_ctv(oracle_pubkey: XOnlyPublicKey, ctv_hash: [u8; 32]) -> ScriptBuf {
    Builder::new()
        .push_slice(ctv_hash)
        .push_opcode(OP_NOP4)
        .push_x_only_key(&oracle_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn calc_ctv_hash(outputs: &[TxOut]) -> [u8; 32] {
    let mut buffer = Vec::new();
    buffer.extend(2_i32.to_le_bytes()); // version
    buffer.extend(0_i32.to_le_bytes()); // locktime
    buffer.extend(1_u32.to_le_bytes()); // inupts len

    let seq = sha256::Hash::hash(&Sequence::default().0.to_le_bytes());
    buffer.extend(seq.to_byte_array()); // sequences

    let outputs_len = outputs.len() as u32;
    buffer.extend(outputs_len.to_le_bytes()); // outputs len

    let mut output_bytes: Vec<u8> = Vec::new();
    for o in outputs {
        o.consensus_encode(&mut output_bytes).unwrap();
    }
    buffer.extend(sha256::Hash::hash(&output_bytes).to_byte_array()); // outputs hash

    buffer.extend(0_u32.to_le_bytes()); // inputs index

    let hash = sha256::Hash::hash(&buffer);
    hash.to_byte_array()
}

// fn spend_win<'a>(
//     unsigned_tx: &'a mut Transaction,
//     prev_tx: Vec<TxOut>,
//     sighash_type: TapSighashType,
//     taproot_spend_info: TaprootSpendInfo,
//     winning_pub_key: &'a Point<Normal>,
//     winning_player: &'a Keypair,
//     oracle_winning_decryption_key: Option<Scalar<Secret, NonZero>>,
// ) -> &'a mut Transaction {
//     println!("Spending for win");
//     let secp = Secp256k1::new();
//     let unsigned_tx_clone = unsigned_tx.clone();

//     let winner_script = dlchess_script_win(
//         XOnlyPublicKey::from_slice(&winning_pub_key.to_xonly_bytes()).unwrap(),
//         winning_player.x_only_public_key().0,
//     );
//     let tap_leaf_hash = TapLeafHash::from_script(&winner_script, LeafVersion::TapScript);
//     let winning_priv_key = Keypair::from_secret_key(
//         &secp,
//         &secp256k1::SecretKey::from_slice(&oracle_winning_decryption_key.unwrap().to_bytes())
//             .unwrap(),
//     );

//     for (index, input) in unsigned_tx.input.iter_mut().enumerate() {
//         let sighash = SighashCache::new(&unsigned_tx_clone)
//             .taproot_script_spend_signature_hash(
//                 index,
//                 &Prevouts::All(&prev_tx),
//                 tap_leaf_hash,
//                 sighash_type,
//             )
//             .expect("failed to construct sighash");

//         let message = Message::from(sighash);
//         let oracle_signature = secp.sign_schnorr_no_aux_rand(&message, &winning_priv_key);
//         let winning_player_signature = secp.sign_schnorr_no_aux_rand(&message, winning_player);

//         let script_ver = (winner_script.clone(), LeafVersion::TapScript);
//         let ctrl_block = taproot_spend_info.control_block(&script_ver).unwrap();

//         input.witness.push(winning_player_signature.serialize());
//         input.witness.push(oracle_signature.serialize());
//         input.witness.push(script_ver.0.into_bytes());
//         input.witness.push(ctrl_block.serialize());
//     }
//     unsigned_tx
// }
