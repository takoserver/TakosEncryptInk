import { z } from "zod";
import { isValidUUIDv7 } from "./core.ts";
import { base64ToArrayBuffer } from "./utils.ts";

// MasterKey スキーマ
export const MasterKeyPrivateSchema = z.object({
  keyType: z.literal("masterKeyPrivate"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 4896;
    } catch {
      return false;
    }
  }, { message: "Invalid private key binary length" }),
});

export const MasterKeyPublicSchema = z.object({
  keyType: z.literal("masterKeyPublic"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 2592;
    } catch {
      return false;
    }
  }, { message: "Invalid public key binary length" }),
});

export const SignMasterKeySchema = z.object({
  keyType: z.literal("masterKey"),
  keyHash: z.string().refine(hash => {
    try {
      return base64ToArrayBuffer(hash).byteLength === 32;
    } catch {
      return false;
    }
  }, { message: "Invalid key hash length" }),
  signature: z.string().refine(sig => {
    try {
      base64ToArrayBuffer(sig);
      return true;
    } catch {
      return false;
    }
  }, { message: "Invalid signature format" }),
  algorithm: z.literal("ML-DSA-87"),
});

// DeviceKey スキーマ
export const DeviceKeySchema = z.object({
  keyType: z.literal("deviceKey"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 32;
    } catch {
      return false;
    }
  }, { message: "Invalid key binary length" }),
});

// AccountKey スキーマ
export const AccountKeyPublicSchema = z.object({
  keyType: z.literal("accountKeyPublic"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 1184;
    } catch {
      return false;
    }
  }, { message: "Invalid public key binary length" }),
  algorithm: z.literal("ML-KEM-768"),
  timestamp: z.number().int(),
});

export const AccountKeyPrivateSchema = z.object({
  keyType: z.literal("accountKeyPrivate"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 2400;
    } catch {
      return false;
    }
  }, { message: "Invalid private key binary length" }),
  algorithm: z.literal("ML-KEM-768"),
  timestamp: z.number().int(),
});

// IdentityKey スキーマ
export const IdentityKeyPrivateSchema = z.object({
  keyType: z.literal("identityKeyPrivate"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 4032;
    } catch {
      return false;
    }
  }, { message: "Invalid private key binary length" }),
  algorithm: z.literal("ML-DSA-65"),
  timestamp: z.number().int(),
  sessionUuid: z.string().refine(isValidUUIDv7, { message: "Invalid session UUID" }),
});

export const IdentityKeyPublicSchema = z.object({
  keyType: z.literal("identityKeyPublic"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 1952;
    } catch {
      return false;
    }
  }, { message: "Invalid public key binary length" }),
  algorithm: z.literal("ML-DSA-65"),
  timestamp: z.number().int(),
  sessionUuid: z.string().refine(isValidUUIDv7, { message: "Invalid session UUID" }),
});

export const SignIdentityKeySchema = z.object({
  keyType: z.literal("identityKey"),
  keyHash: z.string().refine(hash => {
    try {
      return base64ToArrayBuffer(hash).byteLength === 32;
    } catch {
      return false;
    }
  }, { message: "Invalid key hash length" }),
  signature: z.string().refine(sig => {
    try {
      base64ToArrayBuffer(sig);
      return true;
    } catch {
      return false;
    }
  }, { message: "Invalid signature format" }),
  algorithm: z.literal("ML-DSA-65"),
});

// MigrateKey スキーマ
export const MigrateKeyPrivateSchema = z.object({
  keyType: z.literal("migrateKeyPrivate"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 2400;
    } catch {
      return false;
    }
  }, { message: "Invalid private key binary length" }),
  timestamp: z.number().int().optional(),
});

export const MigrateKeyPublicSchema = z.object({
  keyType: z.literal("migrateKeyPublic"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 1184;
    } catch {
      return false;
    }
  }, { message: "Invalid public key binary length" }),
  timestamp: z.number().int().optional(),
});

export const EncryptedDataMigrateKeySchema = z.object({
  keyType: z.literal("migrateKey"),
  keyHash: z.string().refine(hash => {
    try {
      return base64ToArrayBuffer(hash).byteLength === 32;
    } catch {
      return false;
    }
  }, { message: "Invalid key hash length" }),
  encryptedData: z.string(),
  iv: z.string().refine(iv => {
    try {
      return base64ToArrayBuffer(iv).byteLength === 12;
    } catch {
      return false;
    }
  }, { message: "Invalid IV length" }),
  cipherText: z.string().refine(ct => {
    try {
      return base64ToArrayBuffer(ct).byteLength === 1088;
    } catch {
      return false;
    }
  }, { message: "Invalid cipherText length" }),
  algorithm: z.literal("AES-GCM"),
});

// MigrateSignKey スキーマ
export const MigrateSignKeyPrivateSchema = z.object({
  keyType: z.literal("migrateSignKeyPrivate"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 4032;
    } catch {
      return false;
    }
  }, { message: "Invalid private key binary length" }),
  timestamp: z.number().int().optional(),
});

export const MigrateSignKeyPublicSchema = z.object({
  keyType: z.literal("migrateSignKeyPublic"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 1952;
    } catch {
      return false;
    }
  }, { message: "Invalid public key binary length" }),
  timestamp: z.number().int().optional(),
});

export const SignMigrateSignKeySchema = z.object({
  keyType: z.literal("migrateSignKey"),
  keyHash: z.string().refine(hash => {
    try {
      return base64ToArrayBuffer(hash).byteLength === 32;
    } catch {
      return false;
    }
  }, { message: "Invalid key hash length" }),
  signature: z.string().refine(sig => {
    try {
      base64ToArrayBuffer(sig);
      return true;
    } catch {
      return false;
    }
  }, { message: "Invalid signature format" }),
  algorithm: z.literal("ML-DSA-65"),
});

// RoomKey スキーマ
export const RoomKeySchema = z.object({
  keyType: z.literal("roomKey"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 32;
    } catch {
      return false;
    }
  }, { message: "Invalid key binary length" }),
  algorithm: z.literal("AES-GCM"),
  timestamp: z.number().int(),
  sessionUuid: z.string().refine(isValidUUIDv7, { message: "Invalid session UUID" }),
});

export const EncryptedDataRoomKeySchema = z.object({
  keyType: z.literal("roomKey"),
  keyHash: z.string().refine(hash => {
    try {
      return base64ToArrayBuffer(hash).byteLength === 32;
    } catch {
      return false;
    }
  }, { message: "Invalid key hash length" }),
  encryptedData: z.string(),
  iv: z.string().refine(iv => {
    try {
      return base64ToArrayBuffer(iv).byteLength === 12;
    } catch {
      return false;
    }
  }, { message: "Invalid IV length" }),
  algorithm: z.literal("AES-GCM"),
});

// ServerKey スキーマ
export const ServerKeyPrivateSchema = z.object({
  keyType: z.literal("serverKeyPrivate"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 4032;
    } catch {
      return false;
    }
  }, { message: "Invalid private key binary length" }),
  timestamp: z.number().int(),
});

export const ServerKeyPublicSchema = z.object({
  keyType: z.literal("serverKeyPublic"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 1952;
    } catch {
      return false;
    }
  }, { message: "Invalid public key binary length" }),
  timestamp: z.number().int(),
});

export const SignServerKeySchema = z.object({
  keyType: z.literal("serverKey"),
  keyHash: z.string().refine(hash => {
    try {
      return base64ToArrayBuffer(hash).byteLength === 32;
    } catch {
      return false;
    }
  }, { message: "Invalid key hash length" }),
  signature: z.string().refine(sig => {
    try {
      base64ToArrayBuffer(sig);
      return true;
    } catch {
      return false;
    }
  }, { message: "Invalid signature format" }),
  algorithm: z.literal("ML-DSA-65"),
});

// ShareKey スキーマ
export const ShareKeyPublicSchema = z.object({
  keyType: z.literal("shareKeyPublic"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 1184;
    } catch {
      return false;
    }
  }, { message: "Invalid public key binary length" }),
  algorithm: z.literal("ML-KEM-768"),
  timestamp: z.number().int(),
  sessionUuid: z.string().refine(isValidUUIDv7, { message: "Invalid session UUID" }),
});

export const ShareKeyPrivateSchema = z.object({
  keyType: z.literal("shareKeyPrivate"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 2400;
    } catch {
      return false;
    }
  }, { message: "Invalid private key binary length" }),
  algorithm: z.literal("ML-KEM-768"),
  timestamp: z.number().int(),
  sessionUuid: z.string().refine(isValidUUIDv7, { message: "Invalid session UUID" }),
});

export const ShareSignKeyPublicSchema = z.object({
  keyType: z.literal("shareSignKeyPublic"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 1952;
    } catch {
      return false;
    }
  }, { message: "Invalid public key binary length" }),
  algorithm: z.literal("ML-DSA-65"),
  timestamp: z.number().int(),
  sessionUuid: z.string().refine(isValidUUIDv7, { message: "Invalid session UUID" }),
});

export const ShareSignKeyPrivateSchema = z.object({
  keyType: z.literal("shareSignKeyPrivate"),
  key: z.string().refine((keyBinary) => {
    try {
      return base64ToArrayBuffer(keyBinary).byteLength === 4032;
    } catch {
      return false;
    }
  }, { message: "Invalid private key binary length" }),
  algorithm: z.literal("ML-DSA-65"),
  timestamp: z.number().int(),
  sessionUuid: z.string().refine(isValidUUIDv7, { message: "Invalid session UUID" }),
});

export const SignShareSignKeySchema = z.object({
  keyType: z.literal("shareSignKey"),
  keyHash: z.string().refine(hash => {
    try {
      return base64ToArrayBuffer(hash).byteLength === 32;
    } catch {
      return false;
    }
  }, { message: "Invalid key hash length" }),
  signature: z.string().refine(sig => {
    try {
      base64ToArrayBuffer(sig);
      return true;
    } catch {
      return false;
    }
  }, { message: "Invalid signature format" }),
  algorithm: z.literal("ML-DSA-65").optional(),
});

export const EncryptedDataShareKeySchema = z.object({
  keyType: z.literal("shareKey"),
  keyHash: z.string().refine(hash => {
    try {
      return base64ToArrayBuffer(hash).byteLength === 32;
    } catch {
      return false;
    }
  }, { message: "Invalid key hash length" }),
  encryptedData: z.string(),
  iv: z.string().refine(iv => {
    try {
      return base64ToArrayBuffer(iv).byteLength === 12;
    } catch {
      return false;
    }
  }, { message: "Invalid IV length" }),
  cipherText: z.string().refine(ct => {
    try {
      return base64ToArrayBuffer(ct).byteLength === 1088;
    } catch {
      return false;
    }
  }, { message: "Invalid cipherText length" }),
  algorithm: z.string().optional(),
});

// DeviceKey 暗号化データスキーマ
export const EncryptedDataDeviceKeySchema = z.object({
  keyType: z.literal("deviceKey"),
  keyHash: z.string().refine(hash => {
    try {
      return base64ToArrayBuffer(hash).byteLength === 32;
    } catch {
      return false;
    }
  }, { message: "Invalid key hash length" }),
  encryptedData: z.string(),
  iv: z.string().refine(iv => {
    try {
      return base64ToArrayBuffer(iv).byteLength === 12;
    } catch {
      return false;
    }
  }, { message: "Invalid IV length" }),
  algorithm: z.literal("AES-GCM"),
});

// AccountKey 暗号化データのベーススキーマ
export const EncryptedDataSchemaBase = z.object({
  keyHash: z.string().refine(hash => {
    try {
      return base64ToArrayBuffer(hash).byteLength === 32;
    } catch {
      return false;
    }
  }, { message: "Invalid key hash length" }),
  encryptedData: z.string(),
  iv: z.string().refine(iv => {
    try {
      return base64ToArrayBuffer(iv).byteLength === 12;
    } catch {
      return false;
    }
  }, { message: "Invalid IV length" }),
  algorithm: z.string().optional(),
  cipherText: z.string().optional(),
});

export const EncryptedDataAccountKeySchema = EncryptedDataSchemaBase.extend({
  keyType: z.literal("accountKey"),
  cipherText: z.string().refine(ct => {
    try {
      return base64ToArrayBuffer(ct).byteLength === 1088;
    } catch {
      return false;
    }
  }, { message: "Invalid cipherText length" }),
  algorithm: z.literal("AES-GCM"),
});

// Message スキーマ
export const ReplyInfoSchema = z.object({
  id: z.string(),
});

export const NotEncryptMessageValueSchema = z.object({
  type: z.enum(["text", "image", "video", "audio", "file", "thumbnail"]),
  content: z.string().refine(content => {
    try {
      JSON.parse(content);
      return true;
    } catch {
      return false;
    }
  }, { message: "Content must be a valid JSON string" }),
  reply: ReplyInfoSchema.optional(),
  mention: z.array(z.string()).optional(),
});

export const BaseMessageSchema = z.object({
  channel: z.string().max(100),
  timestamp: z.number().int(),
  isLarge: z.boolean(),
  original: z.string().optional(),
  roomid: z.string(),
});

export const NotEncryptMessageSchema = BaseMessageSchema.extend({
  encrypted: z.literal(false),
  value: NotEncryptMessageValueSchema,
});

export const EncryptedMessageSchema = BaseMessageSchema.extend({
  encrypted: z.literal(true),
  value: z.string(),
});

export const MessageSchema = z.union([NotEncryptMessageSchema, EncryptedMessageSchema]);