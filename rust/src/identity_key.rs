use crate::r#type::IdentityKey;
use crate::signature::{create_signature_object_mlds65, verify_with_mlds65};
use crate::keyutils::generate_dsa65_key_pair;
use crate::core::is_valid_uuid_v7;
use crate::master_key::{is_valid_master_key_private, is_valid_master_key_public, sign_master_key};
use crate::utils::key_hash;
use chrono::Utc;
use serde_json;

/// 秘密鍵で IdentityKey に署名
pub fn sign_identity_key(
    key_json: &str,
    data: &str,
    key_hash: &str,
) -> Option<String> {
    let ik: IdentityKey = serde_json::from_str(key_json).ok()?;
    if ik.key_type != "identityKeyPrivate" { return None; }
    create_signature_object_mlds65(&ik.key, data.as_bytes(), key_hash, "identityKey").ok()
}

/// 公開鍵で IdentityKey の署名検証
pub fn verify_identity_key(
    key_json: &str,
    sign_json: &str,
    data: &str,
) -> bool {
    let ik: IdentityKey = match serde_json::from_str(key_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if ik.key_type != "identityKeyPublic" { return false; }
    let sign: crate::r#type::Sign = match serde_json::from_str(sign_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if sign.key_type != "identityKey" { return false; }
    verify_with_mlds65(&ik.key, data.as_bytes(), &sign.signature)
}

/// IdentityKey を生成し、マスター鍵で署名
pub fn generate_identity_key(
    uuid: &str,
    master_public_json: &str,
    master_private_json: &str,
) -> Option<(String, String, String)> {
    if !is_valid_uuid_v7(uuid) { return None; }
    if !is_valid_master_key_private(master_private_json) { return None; }
    if !is_valid_master_key_public(master_public_json)  { return None; }
    let (pub_b64, priv_b64) = generate_dsa65_key_pair().ok()?;
    #[cfg(target_arch = "wasm32")]
    let timestamp = 0u64;
    #[cfg(not(target_arch = "wasm32"))]
    let timestamp = Utc::now().timestamp_millis() as u64;
    let pub_obj = IdentityKey {
        key_type: "identityKeyPublic".into(),
        key: pub_b64.clone(),
        algorithm: "ML-DSA-65".into(),
        timestamp,
        session_uuid: uuid.into(),
    };
    let priv_obj = IdentityKey {
        key_type: "identityKeyPrivate".into(),
        key: priv_b64.clone(),
        algorithm: "ML-DSA-65".into(),
        timestamp,
        session_uuid: uuid.into(),
    };
    let pub_json = serde_json::to_string(&pub_obj).ok()?;
    let priv_json = serde_json::to_string(&priv_obj).ok()?;
    let mk: crate::r#type::MasterKey = serde_json::from_str(master_public_json).ok()?;
    let mh = key_hash(&mk.key);
    let sign = crate::master_key::sign_master_key(
        master_private_json,
        &pub_json,
        &mh,
    )?;
    Some((pub_json, priv_json, sign))
}

/// 秘密鍵 JSON の妥当性チェック
pub fn is_valid_identity_key_private(key_json: &str) -> bool {
    if let Ok(ik) = serde_json::from_str::<IdentityKey>(key_json) {
        ik.key_type == "identityKeyPrivate"
            && ik.algorithm == "ML-DSA-65"
            && is_valid_uuid_v7(&ik.session_uuid)
    } else { false }
}

/// 公開鍵 JSON の妥当性チェック
pub fn is_valid_identity_key_public(key_json: &str) -> bool {
    if let Ok(ik) = serde_json::from_str::<IdentityKey>(key_json) {
        ik.key_type == "identityKeyPublic"
            && ik.algorithm == "ML-DSA-65"
            && is_valid_uuid_v7(&ik.session_uuid)
    } else { false }
}

/// Sign JSON の妥当性チェック
pub fn is_valid_sign_identity_key(sign_json: &str) -> bool {
    if let Ok(sign) = serde_json::from_str::<crate::r#type::Sign>(sign_json) {
        sign.key_type == "identityKey"
            && sign.algorithm.as_deref() == Some("ML-DSA-65")
    } else { false }
}
