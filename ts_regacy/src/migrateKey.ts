import { keyHash } from "./core.ts";
import type { EncryptedData, migrateKey, migrateSignKey, Sign } from "./type.ts";
import { 
  MigrateKeyPrivateSchema, 
  MigrateKeyPublicSchema, 
  EncryptedDataMigrateKeySchema,
  MigrateSignKeyPrivateSchema,
  MigrateSignKeyPublicSchema,
  SignMigrateSignKeySchema
} from "./schema.ts";
import { encrypt, decrypt } from "./crypto.ts";
import { generateKEMKeyPair, generateDSA65KeyPair } from "./keyUtils.ts";
import { createSignatureObjectMLDSA65, verifyWithMLDSA65 } from "./signature.ts";

export function generateMigrateKey(): {
  publicKey: string;
  privateKey: string;
} {
  try {
    const { publicKey, privateKey } = generateKEMKeyPair();
    
    const publicKeyObj: migrateKey = {
      keyType: "migrateKeyPublic",
      key: publicKey,
    };
    
    const privateKeyObj: migrateKey = {
      keyType: "migrateKeyPrivate",
      key: privateKey,
    };
    
    return {
      publicKey: JSON.stringify(publicKeyObj),
      privateKey: JSON.stringify(privateKeyObj),
    };
  } catch (error) {
    console.error("移行キー生成中にエラー:", error);
    throw new Error("移行キーの生成に失敗しました");
  }
}

export function isValidMigrateKeyPrivate(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return MigrateKeyPrivateSchema.safeParse(parsedKey).success;
  } catch {
    return false;
  }
}

export function isValidMigrateKeyPublic(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return MigrateKeyPublicSchema.safeParse(parsedKey).success;
  } catch {
    return false;
  }
}

export async function encryptDataMigrateKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidMigrateKeyPublic(key)) {
    return null;
  }
  
  try {
    const { key: keyBinary } = JSON.parse(key);
    const encryptResult = await encrypt(data, keyBinary);
    
    const result: EncryptedData = {
      keyType: "migrateKey",
      keyHash: await keyHash(key),
      encryptedData: encryptResult.encryptedData,
      iv: encryptResult.iv,
      cipherText: encryptResult.cipherText,
      algorithm: encryptResult.algorithm,
    };
    
    return JSON.stringify(result);
  } catch (error) {
    console.error("移行キーでの暗号化中にエラー:", error);
    return null;
  }
}

export async function decryptDataMigrateKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidMigrateKeyPrivate(key)) {
    return null;
  }
  
  try {
    const { key: keyBinary } = JSON.parse(key);
    const { encryptedData, iv, cipherText } = JSON.parse(data);
    
    if (!cipherText) {
      return null;
    }
    
    return await decrypt(encryptedData, cipherText, iv, keyBinary);
  } catch (error) {
    console.error("移行キーでの復号中にエラー:", error);
    return null;
  }
}

export function isValidEncryptedDataMigrateKey(data: string): boolean {
  try {
    const parsedData = JSON.parse(data);
    return EncryptedDataMigrateKeySchema.safeParse(parsedData).success;
  } catch {
    return false;
  }
}

export function generateMigrateSignKey(): {
  publicKey: string;
  privateKey: string;
} {
  try {
    const { publicKey, privateKey } = generateDSA65KeyPair();
    
    const migrateSignKeyPublic: migrateSignKey = {
      keyType: "migrateSignKeyPublic",
      key: publicKey,
    };
    
    const migrateSignKeyPrivate: migrateSignKey = {
      keyType: "migrateSignKeyPrivate",
      key: privateKey,
    };
    
    return {
      publicKey: JSON.stringify(migrateSignKeyPublic),
      privateKey: JSON.stringify(migrateSignKeyPrivate),
    };
  } catch (error) {
    console.error("移行署名キー生成中にエラー:", error);
    throw new Error("移行署名キーの生成に失敗しました");
  }
}

export function isValidMigrateSignKeyPrivate(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return MigrateSignKeyPrivateSchema.safeParse(parsedKey).success;
  } catch {
    return false;
  }
}

export function isValidMigrateSignKeyPublic(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return MigrateSignKeyPublicSchema.safeParse(parsedKey).success;
  } catch {
    return false;
  }
}

export function signDataMigrateSignKey(
  key: string,
  data: string,
  pubKeyHash: string,
): string | null {
  if (!isValidMigrateSignKeyPrivate(key)) {
    return null;
  }
  
  try {
    const { key: keyBinary } = JSON.parse(key);
    return createSignatureObjectMLDSA65(keyBinary, data, pubKeyHash, "migrateSignKey");
  } catch (error) {
    console.error("移行署名キーでの署名中にエラー:", error);
    return null;
  }
}

export function verifyDataMigrateSignKey(
  key: string,
  sign: string,
  data: string,
): boolean {
  if (!isValidMigrateSignKeyPublic(key)) {
    return false;
  }
  
  try {
    const { key: keyBinary } = JSON.parse(key);
    const signData: Sign = JSON.parse(sign);
    if (signData.keyType !== "migrateSignKey") {
      return false;
    }
    return verifyWithMLDSA65(keyBinary, data, signData.signature);
  } catch (error) {
    console.error("移行署名キーでの検証中にエラー:", error);
    return false;
  }
}

export function isValidSignMigrateSignKey(sign: string): boolean {
  try {
    const parsedSign = JSON.parse(sign);
    return SignMigrateSignKeySchema.safeParse(parsedSign).success;
  } catch {
    return false;
  }
}