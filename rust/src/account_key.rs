use std::time::{SystemTime, UNIX_EPOCH};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json;
use crate::r#type::{AccountKey, EncryptedData};
use crate::utils::key_hash;
use crate::crypto::{encrypt, decrypt};
use crate::master_key::sign_master_key;
use crate::keyutils::is_valid_kem_key;

/// アカウント鍵ペア生成 (JSON文字列＋署名)
pub fn generate_account_key(
    master_public_json: &str,
    master_private_json: &str,
) -> Option<(String, String, String)> {
    if !crate::master_key::is_valid_master_key_public(master_public_json)
        || !crate::master_key::is_valid_master_key_private(master_private_json)
    {
        return None;
    }
    let (pub_b64, priv_b64) = crate::keyutils::generate_kem_key_pair().ok()?;
    #[cfg(target_arch = "wasm32")]
    let timestamp = 0u64;
    #[cfg(not(target_arch = "wasm32"))]
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH).ok()?
        .as_millis() as u64;
    let pub_obj = AccountKey {
        key_type: "accountKeyPublic".into(),
        key: pub_b64.clone(),
        algorithm: "ML-KEM-768".into(),
        timestamp,
    };
    let priv_obj = AccountKey {
        key_type: "accountKeyPrivate".into(),
        key: priv_b64.clone(),
        algorithm: "ML-KEM-768".into(),
        timestamp,
    };
    let pub_json = serde_json::to_string(&pub_obj).ok()?;
    let priv_json = serde_json::to_string(&priv_obj).ok()?;
    let mh = key_hash(master_public_json);
    let sign = sign_master_key(master_private_json, &pub_json, &mh)?;
    Some((pub_json, priv_json, sign))
}

/// 公開鍵 JSON 検証
pub fn is_valid_account_key_public(json: &str) -> bool {
    if let Ok(ak) = serde_json::from_str::<AccountKey>(json) {
        ak.key_type == "accountKeyPublic"
            && ak.algorithm == "ML-KEM-768"
            && is_valid_kem_key(&ak.key, true)
    } else {
        false
    }
}

/// 秘密鍵 JSON 検証
pub fn is_valid_account_key_private(json: &str) -> bool {
    if let Ok(ak) = serde_json::from_str::<AccountKey>(json) {
        ak.key_type == "accountKeyPrivate"
            && ak.algorithm == "ML-KEM-768"
            && is_valid_kem_key(&ak.key, false)
    } else {
        false
    }
}

/// アカウント鍵による暗号化 (EncryptedData JSON)
pub fn encrypt_data_account_key(
    key_json: &str,
    data: &str,
) -> Option<String> {
    if !is_valid_account_key_public(key_json) {
        return None;
    }
    let ak: AccountKey = serde_json::from_str(key_json).ok()?;
    let enc = encrypt(data, &ak.key);
    let ed = EncryptedData {
        key_type: "accountKey".into(),
        key_hash: key_hash(key_json),
        encrypted_data: enc.encrypted_data,
        iv: enc.iv,
        algorithm: Some(enc.algorithm),
        cipher_text: Some(enc.cipher_text),
    };
    serde_json::to_string(&ed).ok()
}

/// EncryptedData JSON 検証
pub fn is_valid_encrypted_data_account_key(json: &str) -> bool {
    if let Ok(ed) = serde_json::from_str::<EncryptedData>(json) {
        ed.key_type == "accountKey"
            && ed.algorithm.as_deref() == Some("AES-GCM")
            && BASE64.decode(&ed.key_hash).map(|v| v.len() == 32).unwrap_or(false)
            && BASE64.decode(&ed.iv).map(|v| v.len() == 12).unwrap_or(false)
            && BASE64.decode(&ed.encrypted_data).is_ok()
            && ed.cipher_text.as_ref()
                .and_then(|ct| BASE64.decode(ct).ok())
                .is_some()
    } else {
        false
    }
}

/// アカウント鍵による復号
pub fn decrypt_data_account_key(
    key_json: &str,
    encrypted_json: &str,
) -> Option<String> {
    if !is_valid_account_key_private(key_json)
        || !is_valid_encrypted_data_account_key(encrypted_json)
    {
        return None;
    }
    let ak: AccountKey = serde_json::from_str(key_json).ok()?;
    let ed: EncryptedData = serde_json::from_str(encrypted_json).ok()?;
    let ciphertext = ed.cipher_text.as_ref()?;
    Some(decrypt(&ed.encrypted_data, ciphertext, &ed.iv, &ak.key))
}

/// EncryptedAccountKey 検証 (エイリアス)
pub fn is_valid_encrypted_account_key(json: &str) -> bool {
    is_valid_encrypted_data_account_key(json)
}
