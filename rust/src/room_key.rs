use crate::r#type::{RoomKey, EncryptedData};
use crate::core::is_valid_uuid_v7;
use crate::keyutils::generate_symmetric_key;
use crate::crypto::{encrypt_with_symmetric_key, decrypt_with_symmetric_key};
use crate::utils::key_hash;
use chrono::Utc;
use serde_json;

/// RoomKey生成
pub fn generate_room_key(room_uuid: &str) -> Option<String> {
    if !is_valid_uuid_v7(room_uuid) {
        return None;
    }
    let key = generate_symmetric_key();
    let ts = Utc::now().timestamp_millis() as u64;
    let rk = RoomKey { key_type: "roomKey".into(), key: key.clone(), algorithm: "AES-GCM".into(), timestamp: ts, session_uuid: room_uuid.into() };
    serde_json::to_string(&rk).ok()
}

/// RoomKey検証
pub fn is_valid_room_key(key_json: &str) -> bool {
    if let Ok(rk) = serde_json::from_str::<RoomKey>(key_json) {
        rk.key_type == "roomKey" &&
        rk.algorithm == "AES-GCM" &&
        is_valid_uuid_v7(&rk.session_uuid)
    } else {
        false
    }
}

/// RoomKeyを使ったデータ暗号化
pub fn encrypt_data_room_key(key_json: &str, data: &str) -> Option<String> {
    if !is_valid_room_key(key_json) {
        return None;
    }
    let rk = serde_json::from_str::<RoomKey>(key_json).ok()?;
    let enc = encrypt_with_symmetric_key(data, &rk.key);
    let ed = EncryptedData {
        key_type: "roomKey".into(),
        key_hash: key_hash(key_json),
        encrypted_data: enc.encrypted_data,
        iv: enc.iv,
        algorithm: Some(enc.algorithm),
        cipher_text: None,
    };
    serde_json::to_string(&ed).ok()
}

/// RoomKeyを使ったデータ復号
pub fn decrypt_data_room_key(key_json: &str, data_json: &str) -> Option<String> {
    if !is_valid_room_key(key_json) {
        return None;
    }
    let rk = serde_json::from_str::<RoomKey>(key_json).ok()?;
    let ed: EncryptedData = serde_json::from_str(data_json).ok()?;
    Some(decrypt_with_symmetric_key(&ed.encrypted_data, &ed.iv, &rk.key))
}

/// 暗号化RoomKeyデータ検証
pub fn is_valid_encrypted_data_room_key(data: &str) -> bool {
    serde_json::from_str::<EncryptedData>(data)
        .map(|ed| ed.key_type == "roomKey")
        .unwrap_or(false)
}