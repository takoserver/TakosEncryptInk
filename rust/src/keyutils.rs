use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ml_kem::{array::Array, EncodedSizeUser, KemCore, MlKem768};
use ml_kem::kem::{Encapsulate, Decapsulate};
use ml_dsa::{EncodedSigningKey, MlDsa65, MlDsa87, SigningKey, KeyGen};
use ml_dsa::signature::{Signer, SignatureEncoding};
use rand::{rngs::OsRng, RngCore};
use serde_json;

/// ML‑KEM‑768 鍵ペア生成 (Base64)
pub fn generate_kem_key_pair() -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let (dec, enc) = MlKem768::generate(&mut rng);
    let pk = BASE64.encode(enc.as_bytes().as_slice());
    let sk = BASE64.encode(dec.as_bytes().as_slice());
    Ok((pk, sk))
}

/// ML‑DSA‑65 鍵ペア生成 (Base64)
pub fn generate_dsa65_key_pair() -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let kp = MlDsa65::key_gen(&mut rng);
    let sk = BASE64.encode(kp.signing_key().encode());
    let pk = BASE64.encode(kp.verifying_key().encode());
    Ok((pk, sk))
}

/// ML‑DSA‑87 鍵ペア生成 (Base64)
pub fn generate_dsa87_key_pair() -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    // wasm32ではスレッド生成がサポートされないため、直接生成
    #[cfg(target_arch = "wasm32")]
    {
        let kp = MlDsa87::key_gen(&mut rng);
        let sk = BASE64.encode(kp.signing_key().encode());
        let pk = BASE64.encode(kp.verifying_key().encode());
        return Ok((pk, sk));
    }
    // それ以外では既存のスレッド生成版を利用
    #[cfg(not(target_arch = "wasm32"))]
    {
        let handle = std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let kp = MlDsa87::key_gen(&mut rng);
                let sk = BASE64.encode(kp.signing_key().encode());
                let pk = BASE64.encode(kp.verifying_key().encode());
                (pk, sk)
            })?;
        let (pk, sk) = handle.join().map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Thread panicked: {:?}", e))
        })?;
        Ok((pk, sk))
    }
}

/// 対称鍵生成 (256bit → Base64)
pub fn generate_symmetric_key() -> String {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    BASE64.encode(&key)
}

/// 署名鍵ペア検証 (秘密鍵で試し署名→公開鍵で検証)
pub fn is_valid_key_pair_sign(pub_json: &str, priv_json: &str) -> bool {
    let data = b"test";
    // JSONパース
    let pub_val = match serde_json::from_str::<serde_json::Value>(pub_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let priv_val = match serde_json::from_str::<serde_json::Value>(priv_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    // keyType, keyフィールド取得
    let ptype = pub_val.get("keyType").and_then(|v| v.as_str()).unwrap_or("");
    let stype = priv_val.get("keyType").and_then(|v| v.as_str()).unwrap_or("");
    let pkey = pub_val.get("key").and_then(|v| v.as_str()).unwrap_or("");
    let skey = priv_val.get("key").and_then(|v| v.as_str()).unwrap_or("");
    // マスターキーの場合
    if ptype == "masterKeyPublic" && stype == "masterKeyPrivate" {
        if let Ok(sig) = crate::signature::sign_with_mlds87(skey, data) {
            return crate::signature::verify_with_mlds87(pkey, data, &sig);
        }
    } else {
        if let Ok(sig) = crate::signature::sign_with_mlds65(skey, data) {
            return crate::signature::verify_with_mlds65(pkey, data, &sig);
        }
    }
    false
}

/// 暗号化鍵ペア検証 (encapsulate→decapsulate 比較)
pub fn is_valid_key_pair_encrypt(pub_json: &str, priv_json: &str) -> bool {
    let mut rng = OsRng;
    // JSONパース
    let pub_val = match serde_json::from_str::<serde_json::Value>(pub_json) { Ok(v) => v, Err(_) => return false };
    let priv_val = match serde_json::from_str::<serde_json::Value>(priv_json) { Ok(v) => v, Err(_) => return false };
    // keyフィールド取得
    let pkey = match pub_val.get("key").and_then(|v| v.as_str()) { Some(k) => k, None => return false };
    let skey = match priv_val.get("key").and_then(|v| v.as_str()) { Some(k) => k, None => return false };
    // Base64デコード
    let pkb = match BASE64.decode(pkey) { Ok(b) => b, Err(_) => return false };
    let skb = match BASE64.decode(skey) { Ok(b) => b, Err(_) => return false };
    // EncapsulationKey生成・封入
    let pk_arr: Array<u8, <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize> = match Array::try_from(&pkb[..]) { Ok(a) => a, Err(_) => return false };
    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&pk_arr);
    let (ct_arr, sh1) = match ek.encapsulate(&mut rng) { Ok(res) => res, Err(_) => return false };
    // DecapsulationKey生成・復号
    let sk_arr: Array<u8, <<MlKem768 as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize> = match Array::try_from(&skb[..]) { Ok(a) => a, Err(_) => return false };
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&sk_arr);
    let sh2 = match dk.decapsulate(&ct_arr) { Ok(res) => res, Err(_) => return false };
    // 共有秘密比較
    sh1.as_slice() == sh2.as_slice()
}

/// ML‑DSA‑65 鍵検証
pub fn is_valid_dsa65_key(key_b64: &str, is_public: bool) -> bool {
    if let Ok(bytes) = BASE64.decode(key_b64) {
        if is_public { return bytes.len() == 1952; }
        if let Ok(arr) = <EncodedSigningKey<MlDsa65>>::try_from(&bytes[..]) {
            let sk = SigningKey::<MlDsa65>::decode(&arr);
            let sig_bytes = sk.sign(b"test").to_bytes();
            return sig_bytes.len() > 0;
        }
    }
    false
}

/// ML‑DSA‑87 鍵検証
pub fn is_valid_dsa87_key(key_b64: &str, is_public: bool) -> bool {
    if let Ok(bytes) = BASE64.decode(key_b64) {
        if is_public { return bytes.len() == 2592; }
        if let Ok(arr) = <EncodedSigningKey<MlDsa87>>::try_from(&bytes[..]) {
            let sk = SigningKey::<MlDsa87>::decode(&arr);
            let sig_bytes = sk.sign(b"test").to_bytes();
            return sig_bytes.len() > 0;
        }
    }
    false
}

/// ML‑KEM‑768 鍵検証 (長さチェック)
pub fn is_valid_kem_key(key_b64: &str, is_public: bool) -> bool {
    if let Ok(bytes) = BASE64.decode(key_b64) {
        return if is_public { bytes.len() == 1184 } else { bytes.len() == 2400 };
    }
    false
}

/// 対称鍵検証 (長さチェックのみ)
pub fn is_valid_symmetric_key(key_b64: &str) -> bool {
    if let Ok(bytes) = BASE64.decode(key_b64) {
        bytes.len() == 32
    } else {
        false
    }
}

/// ランダム文字列生成
pub fn generate_random_string(len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                          abcdefghijklmnopqrstuvwxyz\
                          0123456789";
    let mut rng = OsRng;
    (0..len)
        .map(|_| {
            let idx = (rng.next_u32() as usize) % CHARS.len();
            CHARS[idx] as char
        })
        .collect()
}
