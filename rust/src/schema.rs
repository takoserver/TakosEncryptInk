use serde_json::Value;
use crate::core::is_valid_uuid_v7;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

fn decode_b64(src: &str) -> Option<Vec<u8>> {
    BASE64.decode(src).ok()
}

/// MasterKeyPrivateSchema に相当
pub fn validate_master_key_private(v: &Value) -> bool {
    v.get("keyType").and_then(Value::as_str) == Some("masterKeyPrivate")
        && v.get("key")
            .and_then(Value::as_str)
            .and_then(decode_b64)
            .map_or(false, |b| b.len() == 4896)
}

/// MasterKeyPublicSchema に相当
pub fn validate_master_key_public(v: &Value) -> bool {
    v.get("keyType").and_then(Value::as_str) == Some("masterKeyPublic")
        && v.get("key")
            .and_then(Value::as_str)
            .and_then(decode_b64)
            .map_or(false, |b| b.len() == 2592)
}

/// SignMasterKeySchema に相当
pub fn validate_sign_master_key(v: &Value) -> bool {
    v.get("keyType").and_then(Value::as_str) == Some("masterKey")
        && v.get("keyHash")
            .and_then(Value::as_str)
            .and_then(decode_b64)
            .map_or(false, |b| b.len() == 32)
        && v.get("signature")
            .and_then(Value::as_str)
            .and_then(decode_b64)
            .is_some()
        && v.get("algorithm").and_then(Value::as_str) == Some("ML-DSA-87")
}

// ...同様に DeviceKeySchema, AccountKeyPublicSchema, AccountKeyPrivateSchema,
//     IdentityKeyPublic/PrivateSchema, MigrateKeySchema, RoomKeySchema,
//     ShareKeySchema, ShareSignKeySchema, EncryptedData各スキーマ を実装...

/// NotEncryptMessageSchema / EncryptedMessageSchema 検証
pub fn validate_message(v: &Value) -> bool {
    let base = |o: &Value| {
        o.get("channel").and_then(Value::as_str).is_some()
            && o.get("timestamp").and_then(Value::as_u64).is_some()
            && o.get("isLarge").and_then(Value::as_bool).is_some()
            && o.get("roomid").and_then(Value::as_str).is_some()
    };
    match v.get("encrypted") {
        Some(Value::Bool(false)) => {
            base(v)
                && v.get("value").and_then(|x| {
                    let t = x.get("type").and_then(Value::as_str)?;
                    ["text","image","video","audio","file","thumbnail"].contains(&t)
                        .then(|| ())
                }).is_some()
        }
        Some(Value::Bool(true)) => base(v) && v.get("value").and_then(Value::as_str).is_some(),
        _ => false,
    }
}
