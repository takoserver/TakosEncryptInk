use crate::r#type::MasterKey;
use crate::signature::{create_signature_object_mlds87, verify_with_mlds87};
use crate::keyutils::{generate_dsa87_key_pair, is_valid_dsa87_key};
use serde_json;

/// マスター鍵ペア生成 (Base64 JSON文字列)
pub fn generate_master_key() -> (String, String) {
    let (pub_b64, priv_b64) = generate_dsa87_key_pair().unwrap();
    let pub_obj = MasterKey { key_type: "masterKeyPublic".into(), key: pub_b64 };
    let priv_obj = MasterKey { key_type: "masterKeyPrivate".into(), key: priv_b64 };
    (
        serde_json::to_string(&pub_obj).unwrap(),
        serde_json::to_string(&priv_obj).unwrap(),
    )
}

/// マスター鍵署名作成
pub fn sign_master_key(
    key_json: &str,
    data: &str,
    pub_key_hash: &str,
) -> Option<String> {
    let mk: MasterKey = serde_json::from_str(key_json).ok()?;
    if mk.key_type != "masterKeyPrivate" { return None; }
    create_signature_object_mlds87(&mk.key, data.as_bytes(), pub_key_hash, "masterKey").ok()
}

/// マスター鍵署名検証
pub fn verify_master_key(
    key_json: &str,
    sign_json: &str,
    data: &str,
) -> bool {
    let mk: MasterKey = match serde_json::from_str(key_json) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if mk.key_type != "masterKeyPublic" { return false; }
    let sign: crate::r#type::Sign = match serde_json::from_str(sign_json) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if sign.key_type != "masterKey" { return false; }
    verify_with_mlds87(&mk.key, data.as_bytes(), &sign.signature)
}

/// マスター鍵バリデーション (秘密鍵)
pub fn is_valid_master_key_private(key_json: &str) -> bool {
    if let Ok(mk) = serde_json::from_str::<MasterKey>(key_json) {
        mk.key_type == "masterKeyPrivate"
            && is_valid_dsa87_key(&mk.key, false)
    } else { false }
}

/// マスター鍵バリデーション (公開鍵)
pub fn is_valid_master_key_public(key_json: &str) -> bool {
    if let Ok(mk) = serde_json::from_str::<MasterKey>(key_json) {
        mk.key_type == "masterKeyPublic"
            && is_valid_dsa87_key(&mk.key, true)
    } else { false }
}

/// 署名オブジェクト形式のバリデーション
pub fn is_valid_sign_master_key(sign_json: &str) -> bool {
    if let Ok(obj) = serde_json::from_str::<crate::r#type::Sign>(sign_json) {
        obj.key_type == "masterKey"
            && obj.algorithm.as_deref() == Some("ML-DSA-87")
    } else { false }
}
