use ml_kem::{array::Array, kem::{Decapsulate, Encapsulate}, KemCore, MlKem768};
use ml_kem::EncodedSizeUser;
use ml_dsa::{MlDsa65, KeyGen, signature::{Signer, Verifier, SignatureEncoding}};
use rand::{thread_rng, Rng, CryptoRng};
use takos_encrypt_ink_rs::generate_master_key;



fn main() {
    let key = generate_master_key();
    println!("{}", key.0);
}

/*
// B64文字列をVec<u8>に戻す
fn from_b64_to_vec(b64: &str) -> Vec<u8> {
    BASE64.decode(b64).unwrap()
}

// キー生成
fn generate_keypair<R: Rng + CryptoRng>(rng: &mut R) -> (<MlKem768 as KemCore>::DecapsulationKey, <MlKem768 as KemCore>::EncapsulationKey) {
    MlKem768::generate(rng)
}

// 封入: CiphertextとSharedKeyを返す
fn encapsulate<R: Rng + CryptoRng>(ek: &<MlKem768 as KemCore>::EncapsulationKey, rng: &mut R) -> (Array<u8, <MlKem768 as KemCore>::CiphertextSize>, Array<u8, <MlKem768 as KemCore>::SharedKeySize>) {
    ek.encapsulate(rng).unwrap()
}

// Base64エンコード
fn to_b64(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

// Base64から各種キーとCiphertextを復元
fn decode_keys(
    ek_b64: &str,
    dk_b64: &str,
    ct_b64: &str,
) -> (
    <MlKem768 as KemCore>::EncapsulationKey,
    <MlKem768 as KemCore>::DecapsulationKey,
    Array<u8, <MlKem768 as KemCore>::CiphertextSize>,
) {
    let ek_vec = from_b64_to_vec(ek_b64);
    let ek_arr: Array<u8, <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize> = Array::try_from(&ek_vec[..]).unwrap();
    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_arr);

    let dk_vec = from_b64_to_vec(dk_b64);
    let dk_arr: Array<u8, <<MlKem768 as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize> = Array::try_from(&dk_vec[..]).unwrap();
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_arr);

    let ct_vec = from_b64_to_vec(ct_b64);
    let ct_arr: Array<u8, <MlKem768 as KemCore>::CiphertextSize> = Array::try_from(&ct_vec[..]).unwrap();

    (ek, dk, ct_arr)
}

// 復号: SharedKeyをVec<u8>として返す
fn decapsulate(
    dk: &<MlKem768 as KemCore>::DecapsulationKey,
    ct: &Array<u8, <MlKem768 as KemCore>::CiphertextSize>,
) -> Vec<u8> {
    let shared: Array<u8, <MlKem768 as KemCore>::SharedKeySize> = dk.decapsulate(ct).unwrap();
    shared.as_slice().to_vec()
}

// ML-DSA署名キーをBase64にエンコード
fn signing_key_to_b64<P: ml_dsa::MlDsaParams>(signing_key: &ml_dsa::SigningKey<P>) -> String {
    to_b64(&signing_key.encode().as_ref())
}

// ML-DSA検証キーをBase64にエンコード
fn verifying_key_to_b64<P: ml_dsa::MlDsaParams>(verifying_key: &ml_dsa::VerifyingKey<P>) -> String {
    to_b64(&verifying_key.encode().as_ref())
}

// ML-DSA署名をBase64にエンコード
fn signature_to_b64<P: ml_dsa::MlDsaParams>(signature: &ml_dsa::Signature<P>) -> String {
    to_b64(&signature.to_bytes())
}

// Base64から署名キーを復元
fn signing_key_from_b64(b64_str: &str) -> ml_dsa::SigningKey<MlDsa65> {
    let bytes = from_b64_to_vec(b64_str);
    let bytes_array = <ml_dsa::EncodedSigningKey<MlDsa65>>::try_from(&bytes[..]).unwrap();
    ml_dsa::SigningKey::<MlDsa65>::decode(&bytes_array)
}

// Base64から検証キーを復元
fn verifying_key_from_b64(b64_str: &str) -> ml_dsa::VerifyingKey<MlDsa65> {
    let bytes = from_b64_to_vec(b64_str);
    let bytes_array = <ml_dsa::EncodedVerifyingKey<MlDsa65>>::try_from(&bytes[..]).unwrap();
    ml_dsa::VerifyingKey::<MlDsa65>::decode(&bytes_array)
}

// Base64から署名を復元
fn signature_from_b64(b64_str: &str) -> Option<ml_dsa::Signature<MlDsa65>> {
    let bytes = from_b64_to_vec(b64_str);
    let bytes_array = <ml_dsa::EncodedSignature<MlDsa65>>::try_from(&bytes[..]).unwrap();
    ml_dsa::Signature::<MlDsa65>::decode(&bytes_array)
}

fn main() {
    let mut rng = thread_rng();

    // キー生成と封入
    let (dk, ek) = generate_keypair(&mut rng);
    let (ct_arr, ss_arr) = encapsulate(&ek, &mut rng);
    let ss_send = ss_arr.as_slice().to_vec();

    // Base64エンコード
    let ek_b64 = to_b64(ek.as_bytes().as_slice());
    let dk_b64 = to_b64(dk.as_bytes().as_slice());
    let ct_b64 = to_b64(ct_arr.as_slice());

    // デコードと復号
    let (_ek2, dk2, decoded_ct) = decode_keys(&ek_b64, &dk_b64, &ct_b64);
    let ss_recv = decapsulate(&dk2, &decoded_ct);
    assert_eq!(ss_send, ss_recv);

    println!("復号結果が一致しました！");

    // ML-DSA鍵生成とBase64操作テスト
    let mut rng = rand::thread_rng();
    let kp = MlDsa65::key_gen(&mut rng);

    let msg = b"Hello world";
    let sig = kp.signing_key().sign(msg);

    // 署名キー、検証キー、署名をBase64エンコード
    let signing_key_b64 = signing_key_to_b64(kp.signing_key());
    let verifying_key_b64 = verifying_key_to_b64(kp.verifying_key());
    let sig_b64 = signature_to_b64(&sig);

    println!("署名キー (Base64): {}", signing_key_b64);
    println!("検証キー (Base64): {}", verifying_key_b64);
    println!("署名 (Base64): {}", sig_b64);

    // Base64から署名キー、検証キー、署名を復元
    let _decoded_signing_key = signing_key_from_b64(&signing_key_b64);
    let decoded_verifying_key = verifying_key_from_b64(&verifying_key_b64);
    let decoded_sig = signature_from_b64(&sig_b64).unwrap();

    // 復元した鍵と署名で検証
    assert!(decoded_verifying_key.verify(msg, &decoded_sig).is_ok());
    println!("ML-DSA: 署名検証に成功しました！");

    // 統合テストを実行
} */