use crate::r#type::{ServerKey, Sign};
use crate::signature::{create_signature_object_mlds65, verify_with_mlds65};
use crate::keyutils::generate_dsa65_key_pair;
use chrono::Utc;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json;

/// 秘密鍵 / 公開鍵生成 (ML‑DSA‑65)
pub fn generate_server_key() -> (String, String) {
    let (pub_b64, priv_b64) = generate_dsa65_key_pair().unwrap();
    let ts = Utc::now().timestamp_millis() as u64;
    let pk = ServerKey { key_type: "serverKeyPublic".into(), key: pub_b64.clone(), timestamp: ts };
    let sk = ServerKey { key_type: "serverKeyPrivate".into(), key: priv_b64.clone(), timestamp: ts };
    (serde_json::to_string(&pk).unwrap(), serde_json::to_string(&sk).unwrap())
}

pub fn is_valid_server_key_public(json: &str) -> bool {
    serde_json::from_str::<ServerKey>(json)
        .map(|k| k.key_type=="serverKeyPublic" && BASE64.decode(&k.key).map_or(false, |b| b.len()==1952))
        .unwrap_or(false)
}
pub fn is_valid_server_key_private(json: &str) -> bool {
    serde_json::from_str::<ServerKey>(json)
        .map(|k| k.key_type=="serverKeyPrivate" && BASE64.decode(&k.key).map_or(false, |b| b.len()==4032))
        .unwrap_or(false)
}

pub fn sign_data_server_key(priv_json: &str, data: &str, key_hash: &str) -> Option<String> {
    let sk: ServerKey = serde_json::from_str(priv_json).ok()?;
    if sk.key_type!="serverKeyPrivate" { return None }
    create_signature_object_mlds65(&sk.key, data.as_bytes(), key_hash, "serverKey").ok()
}
pub fn verify_data_server_key(pub_json: &str, sign_json: &str, data: &str) -> bool {
    let pk = match serde_json::from_str::<ServerKey>(pub_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if pk.key_type != "serverKeyPublic" { return false; }
    let sig_obj = match serde_json::from_str::<Sign>(sign_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if sig_obj.key_type != "serverKey" { return false; }
    crate::signature::verify_with_mlds65(&pk.key, data.as_bytes(), &sig_obj.signature)
}
