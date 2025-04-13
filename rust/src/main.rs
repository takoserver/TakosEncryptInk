use ml_kem::{KemCore, MlKem768};
use ml_dsa::{MlDsa65, KeyGen, signature::{Signer, Verifier}};
use ml_kem::kem::Encapsulate;
use ml_kem::kem::Decapsulate;

//暗号化のサンプルコード
fn main() {
    // 安全なランダムシードからChaCha20Rngを初期化
    let mut rng = rand::thread_rng();

// Generate a (decapsulation key, encapsulation key) pair
    let (dk, ek) = MlKem768::generate(&mut rng);

    // Encapsulate a shared key to the holder of the decapsulation key, receive the shared
    // secret `k_send` and the encapsulated form `ct`.
    let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();

    // Decapsulate the shared key and verify that it was faithfully received.
    let k_recv = dk.decapsulate(&ct).unwrap();
    assert_eq!(k_send, k_recv);
    println!("Keys match!1");

    

    let mut rng = rand::thread_rng();
    let kp = MlDsa65::key_gen(&mut rng);

    let msg = b"Hello world";
    let sig = kp.signing_key().sign(msg);

    assert!(kp.verifying_key().verify(msg, &sig).is_ok());

    println!("Keys match!2");
}