use serde::{Deserialize, Serialize};

/// 基本的な鍵の種類
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKey {
    #[serde(rename = "keyType")]
    pub key_type: String,
    pub key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdentityKey {
    #[serde(rename = "keyType")]
    pub key_type: String,
    pub key: String,
    pub algorithm: String,
    pub timestamp: u64,
    #[serde(rename = "sessionUuid")]
    pub session_uuid: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountKey {
    #[serde(rename = "keyType")]
    pub key_type: String,
    pub key: String,
    pub algorithm: String,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerKey {
    #[serde(rename = "keyType")]
    pub key_type: String,
    pub key: String,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RoomKey {
    #[serde(rename = "keyType")]
    pub key_type: String,
    pub key: String,
    pub algorithm: String,
    pub timestamp: u64,
    #[serde(rename = "sessionUuid")]
    pub session_uuid: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShareKey {
    #[serde(rename = "keyType")]
    pub key_type: String,
    pub key: String,
    pub algorithm: String,
    pub timestamp: u64,
    #[serde(rename = "sessionUuid")]
    pub session_uuid: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShareSignKey {
    #[serde(rename = "keyType")]
    pub key_type: String,
    pub key: String,
    pub algorithm: String,
    pub timestamp: u64,
    #[serde(rename = "sessionUuid")]
    pub session_uuid: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MigrateKey {
    #[serde(rename = "keyType")]
    pub key_type: String,
    pub key: String,
    pub timestamp: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MigrateSignKey {
    #[serde(rename = "keyType")]
    pub key_type: String,
    pub key: String,
    pub timestamp: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceKey {
    #[serde(rename = "keyType")]
    pub key_type: String,
    pub key: String,
}

/// 署名情報
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Sign {
    #[serde(rename = "keyHash")]
    pub key_hash: String,
    pub signature: String,
    #[serde(rename = "keyType")]
    pub key_type: String,
    pub algorithm: Option<String>,
}

/// 暗号化データ
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedData {
    #[serde(rename = "keyType")]
    pub key_type: String,
    #[serde(rename = "keyHash")]
    pub key_hash: String,
    #[serde(rename = "encryptedData")]
    pub encrypted_data: String,
    pub iv: String,
    pub algorithm: Option<String>,
    #[serde(rename = "cipherText")]
    pub cipher_text: Option<String>,
}

pub type UserIdentifier = String;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReplyInfo {
    pub id: String,
}

/// 各種コンテンツ
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TextContent {
    pub text: String,
    pub format: Option<String>,
    #[serde(rename = "isThumbnail")]
    pub is_thumbnail: Option<bool>,
    #[serde(rename = "thumbnailOf")]
    pub thumbnail_of: Option<String>,
    #[serde(rename = "originalSize")]
    pub original_size: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MediaMetadata {
    pub filename: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ImageContent {
    pub uri: String,
    pub metadata: MediaMetadata,
    #[serde(rename = "isThumbnail")]
    pub is_thumbnail: Option<bool>,
    #[serde(rename = "thumbnailOf")]
    pub thumbnail_of: Option<String>,
    #[serde(rename = "originalSize")]
    pub original_size: Option<u64>,
}

pub type VideoContent = ImageContent;
pub type AudioContent = ImageContent;
pub type FileContent = ImageContent;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "originalType")]
pub enum ThumbnailContent {
    #[serde(rename = "text")]
    Text {
        #[serde(rename = "thumbnailText")]
        thumbnail_text: String,
        size: Option<u64>,
    },
    #[serde(rename = "image")]
    Image {
        #[serde(rename = "thumbnailUri")]
        thumbnail_uri: String,
        #[serde(rename = "thumbnailMimeType")]
        thumbnail_mime_type: String,
        size: Option<u64>,
    },
    #[serde(rename = "video")]
    Video {
        #[serde(rename = "thumbnailUri")]
        thumbnail_uri: String,
        #[serde(rename = "thumbnailMimeType")]
        thumbnail_mime_type: String,
        size: Option<u64>,
    },
    #[serde(rename = "file")]
    File {
        #[serde(rename = "thumbnailText")]
        thumbnail_text: String,
        size: Option<u64>,
    },
    #[serde(rename = "audio")]
    Audio {
        #[serde(rename = "thumbnailText")]
        thumbnail_text: String,
        size: Option<u64>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum MessageContent {
    Text(TextContent),
    Image(ImageContent),
    Video(VideoContent),
    Audio(AudioContent),
    File(FileContent),
    Thumbnail(ThumbnailContent),
}

/// メッセージ本体
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NotEncryptMessageValue {
    #[serde(rename = "type")]
    pub _type: String,
    pub content: String,
    pub reply: Option<ReplyInfo>,
    pub mention: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NotEncryptMessage {
    pub encrypted: bool,
    pub value: NotEncryptMessageValue,
    pub channel: String,
    pub original: Option<String>,
    pub timestamp: u64,
    #[serde(rename = "isLarge")]
    pub is_large: bool,
    pub roomid: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedMessage {
    pub encrypted: bool,
    pub value: String,
    pub channel: String,
    pub original: Option<String>,
    pub timestamp: u64,
    #[serde(rename = "isLarge")]
    pub is_large: bool,
    pub roomid: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Message {
    NotEncrypted(NotEncryptMessage),
    Encrypted(EncryptedMessage),
}
