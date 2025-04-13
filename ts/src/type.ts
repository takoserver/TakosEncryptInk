// 基本的な鍵の種類の定義
export interface masterKey {
  keyType: "masterKeyPublic" | "masterKeyPrivate";
  key: string;
}

export interface identityKey {
  keyType: "identityKeyPublic" | "identityKeyPrivate";
  key: string;
  algorithm: string; // 例: "ML-DSA-65"
  timestamp: number;
  sessionUuid: string;
}

export interface accountKey {
  keyType: "accountKeyPublic" | "accountKeyPrivate";
  key: string;
  algorithm: string; // 例: "ML-KEM-768"
  timestamp: number;
}

export interface roomKey {
  keyType: "roomKey";
  key: string;
  algorithm: string; // 例: "AES-256-GCM"
  timestamp: number;
  sessionUuid: string;
}

export interface shareKey {
  keyType: "shareKeyPublic" | "shareKeyPrivate";
  key: string;
  algorithm: string; // 例: "ML-KEM-768"
  timestamp: number;
  sessionUuid: string;
}

export interface shareSignKey {
  keyType: "shareSignKeyPublic" | "shareSignKeyPrivate";
  key: string;
  algorithm: string; // 例: "ML-DSA-65"
  timestamp: number;
  sessionUuid: string;
}

export interface migrateKey {
  keyType: "migrateKeyPublic" | "migrateKeyPrivate";
  key: string;
  // 仕様書に基づきtimestampを追加
  timestamp?: number;
}

export interface migrateSignKey {
  keyType: "migrateSignKeyPublic" | "migrateSignKeyPrivate";
  key: string;
  // 仕様書に基づきtimestampを追加
  timestamp?: number;
}

export interface deviceKey {
  keyType: "deviceKey";
  key: string;
}

// 署名情報の定義
export interface Sign {
  keyHash: string;
  signature: string;
  keyType: string;
  algorithm?: string; // 署名アルゴリズム
}

// 暗号化データの定義
export interface EncryptedData {
  keyType: string;
  keyHash: string;
  encryptedData: string; // 仕様書ではbinaryEncryptedDataだが、コード側に合わせる
  iv: string; // 仕様書ではviだが、標準的な命名規則に合わせる
  algorithm?: string; // 暗号化アルゴリズム
  cipherText?: string;
}

// メッセージ関連の型定義
export type UserIdentifier = string;

export interface ReplyInfo {
  id: string;
}

// 各種コンテンツタイプの定義
export interface TextContent {
  text: string;
  format?: "plain" | "markdown";
  isThumbnail?: boolean;
  thumbnailOf?: string;
  originalSize?: number;
}

export interface ImageContent {
  uri: string;
  metadata: {
    filename: string;
    mimeType: string;
  };
  isThumbnail?: boolean;
  thumbnailOf?: string;
  originalSize?: number;
}

export interface VideoContent {
  uri: string;
  metadata: {
    filename: string;
    mimeType: string;
  };
  isThumbnail?: boolean;
  thumbnailOf?: string;
  originalSize?: number;
}

export interface AudioContent {
  uri: string;
  metadata: {
    filename: string;
    mimeType: string;
  };
  isThumbnail?: boolean;
  thumbnailOf?: string;
  originalSize?: number;
}

export interface FileContent {
  uri: string;
  metadata: {
    filename: string;
    mimeType: string;
  };
  isThumbnail?: boolean;
  thumbnailOf?: string;
  originalSize?: number;
}

// サムネイル関連の型定義
export interface TextThumbnail {
  originalType: "text";
  thumbnailText: string;
  size?: number;
}

export interface MediaThumbnail {
  originalType: "image" | "video";
  thumbnailUri: string;
  thumbnailMimeType: string;
  size?: number;
}

export interface FilesThumbnail {
  originalType: "file" | "audio";
  thumbnailText: string;
  size?: number;
}

export type ThumbnailContent = TextThumbnail | MediaThumbnail | FilesThumbnail;

export type MessageContent = TextContent | ImageContent | VideoContent | 
  AudioContent | FileContent | ThumbnailContent;

// メッセージの型定義（ドキュメントに合わせて更新）
export interface NotEncryptMessageValue {
  type: "text" | "image" | "video" | "audio" | "file" | "thumbnail";
  content: string; // 各タイプに応じたJSON文字列
  reply?: ReplyInfo; // ReplyInfo型を使用
  mention?: string[];
}

export interface NotEncryptMessage {
  encrypted: false;
  value: NotEncryptMessageValue;
  channel: string;
  original?: string;
  timestamp: number;
  isLarge: boolean;
  roomid: string; // roomidを追加
}

export interface EncryptedMessage {
  encrypted: true;
  value: string; // 暗号化されたデータ（EncryptedDataのJSON文字列）
  channel: string;
  original?: string;
  timestamp: number;
  isLarge: boolean;
  roomid: string; // roomidを追加
}

export type Message = NotEncryptMessage | EncryptedMessage;

// 既存の型定義は後方互換性のため残すか、削除するか検討
// export interface MessageContentType { ... }
// export interface MessageMetadataType { ... }
// export interface EncryptedMessageType { ... }
