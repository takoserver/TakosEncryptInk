import { isValidUUIDv7 } from "./core.ts";
import { keyHash } from "./core.ts";
import { isValidMasterKeyPrivate, signMasterKey } from "./masterKey.ts";
import type { EncryptedData, shareKey, shareSignKey } from "./type.ts";
import { 
  ShareKeyPublicSchema, 
  ShareKeyPrivateSchema, 
  ShareSignKeyPublicSchema,
  ShareSignKeyPrivateSchema,
  SignShareSignKeySchema,
  EncryptedDataShareKeySchema 
} from "./schema.ts";
import { encrypt, decrypt } from "./crypto.ts";
import { createSignatureObjectMLDSA65, verifyWithMLDSA65 } from "./signature.ts";
import { generateKEMKeyPair, generateDSA65KeyPair } from "./keyUtils.ts";

/**
 * 共有キー(ShareKey)を生成する
 * @param masterKey マスターキーの秘密鍵
 * @param sessionUUID セッションUUID
 * @returns 生成された共有キーとその署名、またはエラー時はnull
 */
export async function generateShareKey(
  masterKey: string,
  sessionUUID: string,
): Promise<
  {
    publicKey: string;
    privateKey: string;
    sign: string;
  } | null
> {
  if (!isValidMasterKeyPrivate(masterKey)) {
    return null;
  }
  if (!isValidUUIDv7(sessionUUID)) {
    return null;
  }
  try {
    const { publicKey, privateKey } = generateKEMKeyPair();
    const timestamp = new Date().getTime();
    
    const publicKeyObj: shareKey = {
      keyType: "shareKeyPublic",
      key: publicKey,
      timestamp: timestamp,
      sessionUuid: sessionUUID,
      algorithm: "ML-KEM-768",
    };
    
    const privateKeyObj: shareKey = {
      keyType: "shareKeyPrivate",
      key: privateKey,
      timestamp: timestamp,
      sessionUuid: sessionUUID,
      algorithm: "ML-KEM-768",
    };
    
    const publicKeyStr = JSON.stringify(publicKeyObj);
    const privateKeyStr = JSON.stringify(privateKeyObj);
    
    const sign = await signMasterKey(
      masterKey,
      publicKeyStr,
      await keyHash(masterKey),
    );
    
    if (!sign) {
      return null;
    }
    
    return {
      publicKey: publicKeyStr,
      privateKey: privateKeyStr,
      sign,
    };
  } catch (error) {
    console.error("共有キー生成中にエラー:", error);
    return null;
  }
}

export function isValidShareKeyPublic(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return ShareKeyPublicSchema.safeParse(parsedKey).success;
  } catch (error) {
    console.error("共有キー公開鍵検証中にエラー:", error);
    return false;
  }
}

export function isValidShareKeyPrivate(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return ShareKeyPrivateSchema.safeParse(parsedKey).success;
  } catch (error) {
    console.error("共有キー秘密鍵検証中にエラー:", error);
    return false;
  }
}

/**
 * 共有キーでデータを暗号化する
 * @param key 共有キーの公開鍵
 * @param data 暗号化するデータ
 * @returns 暗号化されたデータのJSON文字列、またはエラー時はnull
 */
export async function encryptDataShareKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidShareKeyPublic(key)) {
    return null;
  }
  try {
    const { key: keyBinary } = JSON.parse(key);
    const encryptResult = await encrypt(data, keyBinary);
    
    const keyHashString = await keyHash(key);
    const result: EncryptedData = {
      keyType: "shareKey",
      keyHash: keyHashString,
      encryptedData: encryptResult.encryptedData,
      iv: encryptResult.iv,
      cipherText: encryptResult.cipherText,
      algorithm: encryptResult.algorithm,
    };
    
    return JSON.stringify(result);
  } catch (error) {
    console.error("共有キーでのデータ暗号化中にエラー:", error);
    return null;
  }
}

/**
 * 共有キーで暗号化されたデータを復号する
 * @param key 共有キーの秘密鍵
 * @param data 復号するデータ
 * @returns 復号されたデータ文字列、またはエラー時はnull
 */
export async function decryptDataShareKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidShareKeyPrivate(key)) {
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
    console.error("共有キーでのデータ復号中にエラー:", error);
    return null;
  }
}

export function isValidEncryptedDataShareKey(data: string): boolean {
  try {
    const parsedData = JSON.parse(data);
    return EncryptedDataShareKeySchema.safeParse(parsedData).success;
  } catch (error) {
    console.error("暗号化共有キーデータ検証中にエラー:", error);
    return false;
  }
}

/**
 * 共有署名キー(ShareSignKey)を生成する
 * @param masterKey マスターキーのオブジェクト
 * @param sessionUUID セッションUUID
 * @returns 生成された共有署名キーとその署名、またはエラー時はnull
 */
export async function generateShareSignKey(
  masterKey: {
    publicKey: string;
    privateKey: string;
  },
  sessionUUID: string,
): Promise<
  { 
    publicKey: string; 
    privateKey: string; 
    sign: string;
  } | null
> {
  if (!isValidMasterKeyPrivate(masterKey.privateKey)) {
    return null;
  }
  if (!isValidUUIDv7(sessionUUID)) {
    return null;
  }
  try {
    const { publicKey, privateKey } = generateDSA65KeyPair();
    const timestamp = new Date().getTime();
    
    const publicKeyObj: shareSignKey = {
      keyType: "shareSignKeyPublic",
      key: publicKey,
      timestamp: timestamp,
      sessionUuid: sessionUUID,
      algorithm: "ML-DSA-65",
    };
    
    const privateKeyObj: shareSignKey = {
      keyType: "shareSignKeyPrivate",
      key: privateKey,
      timestamp: timestamp,
      sessionUuid: sessionUUID,
      algorithm: "ML-DSA-65",
    };
    
    const publicKeyString = JSON.stringify(publicKeyObj);
    const privateKeyString = JSON.stringify(privateKeyObj);
    
    const sign = await signMasterKey(
      masterKey.privateKey,
      publicKeyString,
      await keyHash(masterKey.publicKey),
    );
    
    if (!sign) {
      return null;
    }
    
    return {
      publicKey: publicKeyString,
      privateKey: privateKeyString,
      sign,
    };
  } catch (error) {
    console.error("共有署名キー生成中にエラー:", error);
    return null;
  }
}

export function isValidShareSignKeyPublic(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return ShareSignKeyPublicSchema.safeParse(parsedKey).success;
  } catch (error) {
    console.error("共有署名キー公開鍵検証中にエラー:", error);
    return false;
  }
}

export function isValidShareSignKeyPrivate(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return ShareSignKeyPrivateSchema.safeParse(parsedKey).success;
  } catch (error) {
    console.error("共有署名キー秘密鍵検証中にエラー:", error);
    return false;
  }
}

/**
 * 共有署名キーでデータに署名する
 * @param key 共有署名キーの秘密鍵
 * @param data 署名するデータ
 * @param pubKeyHash 公開鍵のハッシュ
 * @returns 署名オブジェクトのJSON文字列、またはエラー時はnull
 */
export function signDataShareSignKey(
  key: string,
  data: string,
  pubKeyHash: string,
): string | null {
  if (!isValidShareSignKeyPrivate(key)) {
    return null;
  }
  try {
    const { key: keyBinary } = JSON.parse(key);
    return createSignatureObjectMLDSA65(keyBinary, data, pubKeyHash, "shareSignKey");
  } catch (error) {
    console.error("共有署名キーでの署名作成中にエラー:", error);
    return null;
  }
}

/**
 * 共有署名キーで署名を検証する
 * @param key 共有署名キーの公開鍵
 * @param sign 署名オブジェクトのJSON文字列
 * @param data 署名されたデータ
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function verifyDataShareSignKey(
  key: string,
  sign: string,
  data: string,
): boolean {
  if (!isValidShareSignKeyPublic(key)) {
    return false;
  }
  try {
    const { key: keyBinary } = JSON.parse(key);
    const signData = JSON.parse(sign);
    
    if (signData.keyType !== "shareSignKey") {
      return false;
    }
    
    return verifyWithMLDSA65(keyBinary, data, signData.signature);
  } catch (error) {
    console.error("共有署名キーでの署名検証中にエラー:", error);
    return false;
  }
}

export function isValidSignShareSignKey(sign: string): boolean {
  try {
    const parsedSign = JSON.parse(sign);
    return SignShareSignKeySchema.safeParse(parsedSign).success;
  } catch (error) {
    console.error("共有署名キー署名検証中にエラー:", error);
    return false;
  }
}