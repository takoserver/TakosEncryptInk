// TakosEncryptInk - エントリーポイント
// 各モジュールから機能をエクスポートします

// 基本モジュール
export * from "./core.ts";

// マスターキー関連
export * from "./masterKey.ts";

// アイデンティティキー関連
export * from "./identityKey.ts";

// アカウントキー関連（重複関数をリネームしてエクスポート）
export { 
  generateAccountKey,
  isValidAccountKeyPublic,
  isValidAccountKeyPrivate,
  encryptDataAccountKey,
  isValidEncryptedDataAccountKey,
  decryptDataAccountKey,
  isValidEncryptedAccountKey,
  isValidEncryptedDataShareKey as isValidEncryptedDataShareKeyFromAccount
} from "./accountKey.ts";

// ルームキー関連
export * from "./roomKey.ts";

// シェアキー関連（名前衝突を回避）
export {
  generateShareKey,
  isValidShareKeyPublic, 
  isValidShareKeyPrivate,
  encryptDataShareKey,
  decryptDataShareKey,
  isValidEncryptedDataShareKey,
  generateShareSignKey,
  isValidShareSignKeyPublic,
  isValidShareSignKeyPrivate,
  signDataShareSignKey,
  verifyDataShareSignKey,
  isValidSignShareSignKey
} from "./shareKey.ts";

// マイグレーションキー関連
export * from "./migrateKey.ts";

// デバイスキー関連
export * from "./deviceKey.ts";

// サーバーキー関連
export {
  generateServerKey,
  isValidServerKeyPublic,
  isValidServerKeyPrivate,
  signDataWithServerKey,
  signServerKey,
  verifyDataWithServerKey,
  verifyServerKey,
  isValidSignServerKey
} from "./serverKey.ts";

// メッセージ関連
export {
  encryptMessage,
  decryptMessage,
  isValidMessage,
  // メッセージコンテンツヘルパー関数
  createTextContent,
  createImageContent,
  createVideoContent,
  createAudioContent,
  createFileContent,
} from "./message.ts";

// 型定義
export * from "./type.ts";

// ユーティリティ
export {
  keyHash,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  arrayBufferToHex,
  encrypt,
  decrypt,
  isValidkeyPairSign,
  isValidkeyPairEncrypt,
  generateRandomString
} from "./utils.ts";