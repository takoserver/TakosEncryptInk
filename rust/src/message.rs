use crate::r#type::{NotEncryptMessageValue, NotEncryptMessage, EncryptedMessage, TextContent, ImageContent};
use crate::schema::validate_message;
use crate::room_key::{encrypt_data_room_key, decrypt_data_room_key, is_valid_room_key, is_valid_encrypted_data_room_key};
use crate::identity_key::{is_valid_identity_key_private, is_valid_identity_key_public, sign_identity_key, verify_identity_key};
use crate::account_key::encrypt_data_account_key;
use serde_json::{Value, json};

pub fn encrypt_message(
    message_value_json: &str,
    metadata_json: &str,
    room_key_json: &str,
    identity_priv_json: &str,
    identity_pubhash: &str,
    roomid: &str,
) -> Option<String> {
    if !is_valid_room_key(room_key_json) { return None; }
    if !is_valid_identity_key_private(identity_priv_json) { return None; }
    println!("debug1");
    let encrypted_val = encrypt_data_room_key(room_key_json, message_value_json)?;
    let meta: Value = serde_json::from_str(metadata_json).ok()?;
    let channel = meta.get("channel")?.as_str()?.to_string();
    let timestamp = meta.get("timestamp")?.as_u64()?;
    let is_large = meta.get("isLarge")?.as_bool()?;
    let original = meta.get("original").and_then(|v| v.as_str()).map(String::from);
    let msg = EncryptedMessage { encrypted: true, value: encrypted_val.clone(), channel: channel.clone(), original: original.clone(), timestamp, is_large, roomid: roomid.to_string() };
    let msg_str = serde_json::to_string(&msg).ok()?;
    let sign = sign_identity_key(identity_priv_json, &msg_str, identity_pubhash)?;
    let res = json!({"message": msg_str, "sign": sign});
    serde_json::to_string(&res).ok()
}

pub fn decrypt_message(
    message_str: &str,
    sign_str: &str,
    server_timestamp: u64,
    room_key_json: &str,
    identity_pub_json: &str,
    roomid: &str,
) -> Option<String> {
    if !is_valid_identity_key_public(identity_pub_json) { return None; }
    if !verify_identity_key(identity_pub_json, sign_str, message_str) { return None; }
    let v: Value = serde_json::from_str(message_str).ok()?;
    let encrypted = v.get("encrypted")?.as_bool()?;
    let timestamp = v.get("timestamp")?.as_u64()?;
    let channel = v.get("channel")?.as_str()?.to_string();
    let is_large = v.get("isLarge")?.as_bool()?;
    let original = v.get("original").and_then(|v| v.as_str()).map(String::from);
    let rid = v.get("roomid")?.as_str()?;
    if rid != roomid || (timestamp as i64 - server_timestamp as i64).abs() as u64 > 60000 { return None; }
    if !encrypted {
        let val_json = v.get("value")?.clone();
        let res = json!({
            "encrypted": false,
            "value": val_json,
            "channel": channel,
            "original": original,
            "timestamp": timestamp,
            "isLarge": is_large,
            "roomid": roomid
        });
        return serde_json::to_string(&res).ok();
    }
    if !is_valid_room_key(room_key_json) { return None; }
    let enc_val = v.get("value")?.as_str()?;
    if !is_valid_encrypted_data_room_key(enc_val) { return None; }
    let decrypted_str = decrypt_data_room_key(room_key_json, enc_val)?;
    let val_json: Value = serde_json::from_str(&decrypted_str).ok()?;
    // Wrap decrypted content into NotEncryptMessageValue struct
    let content_type = if val_json.get("text").is_some() {
        "text"
    } else if val_json.get("uri").is_some() {
        "image"
    } else {
        "text"
    };
    let value_obj = json!({
        "type": content_type,
        "content": decrypted_str
    });
    let res = json!({
        "encrypted": false,
        "value": value_obj,
        "channel": channel,
        "original": original,
        "timestamp": timestamp,
        "isLarge": is_large,
        "roomid": roomid
    });
    serde_json::to_string(&res).ok()
}

pub fn is_valid_message(message_str: &str) -> bool {
    serde_json::from_str::<Value>(message_str)
        .ok()
        .map_or(false, |v| validate_message(&v))
}

pub fn create_text_content(
    text: &str,
    format: Option<&str>,
    is_thumbnail: Option<bool>,
    thumbnail_of: Option<&str>,
    original_size: Option<u64>,
) -> Option<String> {
    let content = TextContent { text: text.to_string(), format: format.map(String::from), is_thumbnail, thumbnail_of: thumbnail_of.map(String::from), original_size };
    serde_json::to_string(&content).ok()
}

pub fn create_image_content(
    uri: &str,
    filename: &str,
    mime_type: &str,
    is_thumbnail: Option<bool>,
    thumbnail_of: Option<&str>,
    original_size: Option<u64>,
) -> Option<String> {
    let metadata = crate::r#type::MediaMetadata { filename: filename.to_string(), mime_type: mime_type.to_string() };
    let content = ImageContent { uri: uri.to_string(), metadata, is_thumbnail, thumbnail_of: thumbnail_of.map(String::from), original_size };
    serde_json::to_string(&content).ok()
}

pub fn create_video_content(
    uri: &str,
    filename: &str,
    mime_type: &str,
    is_thumbnail: Option<bool>,
    thumbnail_of: Option<&str>,
    original_size: Option<u64>,
) -> Option<String> {
    create_image_content(uri, filename, mime_type, is_thumbnail, thumbnail_of, original_size)
}

pub fn create_audio_content(
    uri: &str,
    filename: &str,
    mime_type: &str,
    is_thumbnail: Option<bool>,
    thumbnail_of: Option<&str>,
    original_size: Option<u64>,
) -> Option<String> {
    create_image_content(uri, filename, mime_type, is_thumbnail, thumbnail_of, original_size)
}

pub fn create_file_content(
    uri: &str,
    filename: &str,
    mime_type: &str,
    is_thumbnail: Option<bool>,
    thumbnail_of: Option<&str>,
    original_size: Option<u64>,
) -> Option<String> {
    create_image_content(uri, filename, mime_type, is_thumbnail, thumbnail_of, original_size)
}

pub fn encrypt_room_key_with_account_keys(
    users_json: &str,
    room_key_json: &str,
) -> Option<String> {
    let users: Vec<Value> = serde_json::from_str(users_json).ok()?;
    let mut res = Vec::new();
    for u in users {
        let account_key = u.get("accountKey")?.as_str()?;
        let user_id = u.get("userId")?.as_str()?;
        if let Some(enc) = encrypt_data_account_key(account_key, room_key_json) {
            res.push(json!({"userId": user_id, "encryptedData": enc}));
        }
    }
    serde_json::to_string(&res).ok()
}