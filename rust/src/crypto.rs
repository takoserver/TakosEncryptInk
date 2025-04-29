use ml_kem::{KemCore, MlKem768, array::Array};
use ml_kem::EncodedSizeUser;
use ml_kem::kem::{Encapsulate, Decapsulate};
use rand::rngs::OsRng;
use rand::RngCore;
use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Serialize;

/// 非対称暗号化結果
#[derive(Serialize)]
pub struct AsymmetricEncrypted {
    pub encrypted_data: String,
    pub cipher_text: String,
    pub iv: String,
    pub algorithm: String,
}

/// 非対称暗号化（公開鍵 Base64 → データ文字列 → {encryptedData, cipherText, iv, algorithm}）
pub fn encrypt(
    data: &str,
    public_key_b64: &str,
) -> AsymmetricEncrypted {
    // 公開鍵復元
    let pk_vec = BASE64.decode(public_key_b64).unwrap();
    let pk_arr: Array<u8, <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize> =
        Array::try_from(&pk_vec[..]).unwrap();
    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&pk_arr);

    // KEM 封入
    let mut rng = OsRng;
    let (ct_arr, shared_arr) = ek.encapsulate(&mut rng).unwrap();
    let shared = shared_arr.as_slice();

    // IV 生成
    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut iv);

    // AES-GCM 暗号化
    let cipher = Aes256Gcm::new_from_slice(shared).unwrap();
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = cipher.encrypt(nonce, data.as_bytes()).unwrap();

    AsymmetricEncrypted {
        encrypted_data: BASE64.encode(ciphertext),
        cipher_text: BASE64.encode(ct_arr.as_slice()),
        iv: BASE64.encode(iv),
        algorithm: "AES-GCM".into(),
    }
}

/// 非対称復号（encryptedData, cipherText, iv, 秘密鍵 Base64 → 平文文字列）
pub fn decrypt(
    encrypted_data_b64: &str,
    cipher_text_b64: &str,
    iv_b64: &str,
    private_key_b64: &str,
) -> String {
    // 秘密鍵復元
    let sk_vec = BASE64.decode(private_key_b64).unwrap();
    let sk_arr: Array<u8, <<MlKem768 as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize> =
        Array::try_from(&sk_vec[..]).unwrap();
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&sk_arr);

    // データ復元
    let ct_vec = BASE64.decode(cipher_text_b64).unwrap();
    let ct_arr: Array<u8, <MlKem768 as KemCore>::CiphertextSize> =
        Array::try_from(&ct_vec[..]).unwrap();
    let iv = BASE64.decode(iv_b64).unwrap();
    let encrypted = BASE64.decode(encrypted_data_b64).unwrap();

    // KEM 復号
    let shared_arr = dk.decapsulate(&ct_arr).unwrap();
    let shared = shared_arr.as_slice();

    // AES-GCM 復号
    let cipher = Aes256Gcm::new_from_slice(shared).unwrap();
    let nonce = Nonce::from_slice(&iv);
    let plaintext = cipher.decrypt(nonce, encrypted.as_ref()).unwrap();
    String::from_utf8(plaintext).unwrap()
}

/// 対称暗号化結果
#[derive(Serialize)]
pub struct SymmetricEncrypted {
    pub encrypted_data: String,
    pub iv: String,
    pub algorithm: String,
}

/// 対称暗号化（共通鍵 Base64 → データ文字列 → {encryptedData, iv, algorithm}）
pub fn encrypt_with_symmetric_key(
    data: &str,
    key_b64: &str,
) -> SymmetricEncrypted {
    let key_bytes = BASE64.decode(key_b64).unwrap();
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).unwrap();
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = cipher.encrypt(nonce, data.as_bytes()).unwrap();

    SymmetricEncrypted {
        encrypted_data: BASE64.encode(ciphertext),
        iv: BASE64.encode(iv),
        algorithm: "AES-GCM".into(),
    }
}

/// 対称復号（encryptedData, iv, 共通鍵 Base64 → 平文文字列）
pub fn decrypt_with_symmetric_key(
    encrypted_data_b64: &str,
    iv_b64: &str,
    key_b64: &str,
) -> String {
    let key_bytes = BASE64.decode(key_b64).unwrap();
    let iv = BASE64.decode(iv_b64).unwrap();
    let encrypted = BASE64.decode(encrypted_data_b64).unwrap();

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).unwrap();
    let nonce = Nonce::from_slice(&iv);
    let plaintext = cipher.decrypt(nonce, encrypted.as_ref()).unwrap();
    String::from_utf8(plaintext).unwrap()
}
