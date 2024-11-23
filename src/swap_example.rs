use anyhow::Result;
use bitcoin::{
    key::Secp256k1,
    secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address,
};
use rand::rngs::ThreadRng;
use schnorr_fun::{
    adaptor::{Adaptor, EncryptedSign},
    fun::{marker::*, nonce, Scalar},
    Message, Schnorr,
};
use sha2::Sha256;

//coinbase bitcoin swap using adaptor signatures
//bob wants onchain bitcoin, alice wants coinbase bitcoin

fn main() {
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);
    // Alice knows: signing_keypair, encryption_key
    let alice_keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    //Alice would use this as her encrypted preimage and share it with bob in her lightning invoice
    let alice_verification_key = alice_keypair.public_key();
    // Bob knows: decryption_key, verification_key

    let bob_decryption_key = Scalar::random(&mut rand::thread_rng());
    let bob_encryption_key = schnorr.encryption_key_for(&bob_decryption_key);

    // Alice creates an encrypted signature and sends it to Bob
    let alice_message = Message::<Public>::plain("text-bitcoin", b"send 1 BTC to Bob");
    let encrypted_signature =
        schnorr.encrypted_sign(&alice_keypair, &bob_encryption_key, alice_message);

    let alice_pubkey =
        secp256k1::PublicKey::from_slice(&alice_keypair.public_key().to_bytes()).unwrap();

    let bob_encryption_pubkey =
        secp256k1::PublicKey::from_slice(&bob_encryption_key.to_bytes()).unwrap();
    let taproot_script_info = create_script(alice_pubkey, bob_encryption_pubkey).unwrap();

    //alice pays the funds to the taproot script address
    let address = Address::p2tr_tweaked(taproot_script_info.output_key(), bitcoin::Network::Signet);
    println!("🔓 address: {:?}", address);

    // Bob verifies the encrypted signature
    assert!(schnorr.verify_encrypted_signature(
        &alice_verification_key,
        &bob_encryption_key,
        alice_message,
        &encrypted_signature
    ));

    // Bob decrypts the signature

    let signature = schnorr.decrypt_signature(bob_decryption_key, encrypted_signature.clone());

    // Bob then spends the transaction and broadcasts the signature to the public (this would be the revealed preimage?) )

    // Once Alice sees it she can recover Bob's secret decryption key and then use this decryption key to spend the funds
    match schnorr.recover_decryption_key(&bob_encryption_key, &encrypted_signature, &signature) {
        Some(decryption_key) => {
            println!("Alice got the decryption key {}", decryption_key)
            // spend funds here (redeem the lightning invoice)
        }
        None => eprintln!("signature is not the decryption of our original encrypted signature"),
    }
}

fn create_script(
    alice_keys: secp256k1::PublicKey,
    bob_encrypted_key: secp256k1::PublicKey,
) -> Result<TaprootSpendInfo> {
    let secp = Secp256k1::new();

    let combined_pubkey = secp256k1::PublicKey::combine_keys(&[&alice_keys, &bob_encrypted_key])
        .expect("Failed to combine keys");

    let taproot_spend_info = TaprootBuilder::new()
        .finalize(&secp, combined_pubkey.into())
        .unwrap();

    Ok(taproot_spend_info)
}
