import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { arrayBufferToBase64, base64ToArrayBuffer, keyHash } from "./utils.ts";
import { isValidUUIDv7 } from "./core.ts";
import { isValidMasterKeyPrivate, signMasterKey } from "./masterKey.ts";
import type { EncryptedData, shareKey, shareSignKey, Sign } from "./type.ts";

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
    const key = ml_kem768.keygen();
    const publicKeyBinary = arrayBufferToBase64(
      key.publicKey as unknown as ArrayBuffer,
    );
    const privateKeyBinary = arrayBufferToBase64(
      key.secretKey as unknown as ArrayBuffer,
    );
    const timestamp = new Date().getTime();
    const publicKeyObj: shareKey = {
      keyType: "shareKeyPublic",
      key: publicKeyBinary,
      timestamp: timestamp,
      sessionUuid: sessionUUID,
      algorithm: "ML-KEM-768",
    };
    const privateKeyObj: shareKey = {
      keyType: "shareKeyPrivate",
      key: privateKeyBinary,
      timestamp: timestamp,
      sessionUuid: sessionUUID,
      algorithm: "ML-KEM-768",
    };
    const publicKey = JSON.stringify(publicKeyObj);
    const privateKey = JSON.stringify(privateKeyObj);
    const sign = await signMasterKey(
      masterKey,
      publicKey,
      await keyHash(masterKey),
    );
    if (!sign) {
      return null;
    }
    return {
      publicKey,
      privateKey,
      sign,
    };
  } catch (error) {
    console.error("共有キー生成中にエラー:", error);
    return null;
  }
}

/**
 * 共有キーの公開鍵が有効かどうかを検証する
 * @param key 検証する共有キーの公開鍵
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidShareKeyPublic(key: string): boolean {
  try {
    if (key.length !== 1696) {
      console.log("共有キー公開鍵の長さが無効:", key.length);
      return false;
    }
    const { key: keyBinary, keyType, sessionUuid } = JSON.parse(key);
    if (keyType !== "shareKeyPublic") {
      return false;
    }
    if (!isValidUUIDv7(sessionUuid)) {
      return false;
    }
    const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
    if (keyBinaryArray.length !== 1184) {
      console.log("共有キー公開鍵のバイナリ長が無効:", keyBinaryArray.length);
      return false;
    }
    return true;
  } catch (error) {
    console.error("共有キー公開鍵検証中にエラー:", error);
    return false;
  }
}

/**
 * 共有キーの秘密鍵が有効かどうかを検証する
 * @param key 検証する共有キーの秘密鍵
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidShareKeyPrivate(key: string): boolean {
  try {
    if (key.length !== 3317) {
      console.log("共有キー秘密鍵の長さが無効:", key.length);
      return false;
    }
    const { key: keyBinary, keyType, sessionUuid } = JSON.parse(key);
    if (keyType !== "shareKeyPrivate") {
      return false;
    }
    if (!isValidUUIDv7(sessionUuid)) {
      return false;
    }
    const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
    if (keyBinaryArray.length !== 2400) {
      console.log("共有キー秘密鍵のバイナリ長が無効:", keyBinaryArray.length);
      return false;
    }
    return true;
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
    const dataArray = new TextEncoder().encode(data);
    const ciphertext = ml_kem768.encapsulate(
      new Uint8Array(base64ToArrayBuffer(keyBinary)),
      new Uint8Array(32),
    );
    const ciphertextString = arrayBufferToBase64(
      ciphertext.cipherText as unknown as ArrayBuffer,
    );
    const keyHashString = await keyHash(key);
    const importedKey = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(ciphertext.sharedSecret),
      "AES-GCM",
      true,
      ["encrypt", "decrypt"],
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      importedKey,
      dataArray,
    );
    const ivString = arrayBufferToBase64(iv as unknown as ArrayBuffer);
    const encryptedDataString = arrayBufferToBase64(encryptedData);
    const result: EncryptedData = {
      keyType: "shareKey",
      keyHash: keyHashString,
      encryptedData: encryptedDataString,
      iv: ivString,
      cipherText: ciphertextString,
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
    const sharedSecret = ml_kem768.decapsulate(
      new Uint8Array(base64ToArrayBuffer(cipherText)),
      new Uint8Array(base64ToArrayBuffer(keyBinary)),
    );
    const importedKey = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(sharedSecret),
      "AES-GCM",
      true,
      ["encrypt", "decrypt"],
    );
    const decryptedData = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(base64ToArrayBuffer(iv)),
      },
      importedKey,
      new Uint8Array(base64ToArrayBuffer(encryptedData)),
    );
    return new TextDecoder().decode(decryptedData);
  } catch (error) {
    console.error("共有キーでのデータ復号中にエラー:", error);
    return null;
  }
}

/**
 * 暗号化された共有キーデータが有効かどうかを検証する
 * @param data 検証する暗号化データ
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidEncryptedDataShareKey(data: string): boolean {
  try {
    const { keyType, keyHash, iv, cipherText } = JSON.parse(data);
    const sha256 = new Uint8Array(base64ToArrayBuffer(keyHash));
    if (keyType !== "shareKey") {
      return false;
    }
    if (sha256.length !== 32) {
      return false;
    }
    if (new Uint8Array(base64ToArrayBuffer(iv)).length !== 12) {
      return false;
    }
    if (new Uint8Array(base64ToArrayBuffer(cipherText)).length !== 1088) {
      return false;
    }
    return true;
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
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const key = ml_dsa65.keygen(seed);
    const publicKeyBinary = arrayBufferToBase64(
      key.publicKey as unknown as ArrayBuffer,
    );
    const privateKeyBinary = arrayBufferToBase64(
      key.secretKey as unknown as ArrayBuffer,
    );
    const timestamp = new Date().getTime();
    const publicKey: shareSignKey = {
      keyType: "shareSignKeyPublic",
      key: publicKeyBinary,
      timestamp: timestamp,
      sessionUuid: sessionUUID,
      algorithm: "ML-DSA-65",
    };
    const privateKey: shareSignKey = {
      keyType: "shareSignKeyPrivate",
      key: privateKeyBinary,
      timestamp: timestamp,
      sessionUuid: sessionUUID,
      algorithm: "ML-DSA-65",
    };
    const publicKeyString = JSON.stringify(publicKey);
    const privateKeyString = JSON.stringify(privateKey);
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

/**
 * 共有署名キーの公開鍵が有効かどうかを検証する
 * @param key 検証する共有署名キーの公開鍵
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidShareSignKeyPublic(key: string): boolean {
  try {
    if (key.length !== 2724) {
      console.log("共有署名キー公開鍵の長さが無効:", key.length);
      return false;
    }
    const { key: keyBinary, keyType, sessionUuid } = JSON.parse(key);
    if (keyType !== "shareSignKeyPublic") {
      return false;
    }
    if (!isValidUUIDv7(sessionUuid)) {
      return false;
    }
    const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
    if (keyBinaryArray.length !== 1952) {
      console.log("共有署名キー公開鍵のバイナリ長が無効:", keyBinaryArray.length);
      return false;
    }
    return true;
  } catch (error) {
    console.error("共有署名キー公開鍵検証中にエラー:", error);
    return false;
  }
}

/**
 * 共有署名キーの秘密鍵が有効かどうかを検証する
 * @param key 検証する共有署名キーの秘密鍵
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidShareSignKeyPrivate(key: string): boolean {
  try {
    if (key.length !== 5497) {
      console.log("共有署名キー秘密鍵の長さが無効:", key.length);
      return false;
    }
    const { key: keyBinary, keyType, sessionUuid } = JSON.parse(key);
    if (keyType !== "shareSignKeyPrivate") {
      return false;
    }
    if (!isValidUUIDv7(sessionUuid)) {
      return false;
    }
    const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
    if (keyBinaryArray.length !== 4032) {
      console.log("共有署名キー秘密鍵のバイナリ長が無効:", keyBinaryArray.length);
      return false;
    }
    return true;
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
    const dataArray = new TextEncoder().encode(data);
    const signature = ml_dsa65.sign(
      new Uint8Array(base64ToArrayBuffer(keyBinary)),
      dataArray,
    );
    const signString = arrayBufferToBase64(signature as unknown as ArrayBuffer);
    const signResult: Sign = {
      signature: signString,
      keyHash: pubKeyHash,
      keyType: "shareSignKey",
    };
    return JSON.stringify(signResult);
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
    const signData: Sign = JSON.parse(sign);
    if (signData.keyType !== "shareSignKey") {
      return false;
    }
    const dataArray = new TextEncoder().encode(data);
    return ml_dsa65.verify(
      new Uint8Array(base64ToArrayBuffer(keyBinary)),
      dataArray,
      new Uint8Array(base64ToArrayBuffer(signData.signature)),
    );
  } catch (error) {
    console.error("共有署名キーでの署名検証中にエラー:", error);
    return false;
  }
}

/**
 * 共有署名キーの署名が有効かどうかを検証する
 * @param sign 検証する署名
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidSignShareSignKey(sign: string): boolean {
  try {
    const { keyHash, signature, keyType } = JSON.parse(sign);
    if (sign.length !== 4510) {
      console.log("共有署名キー署名の長さが無効:", sign.length);
      return false;
    }
    if (keyType !== "shareSignKey") {
      return false;
    }
    if (keyHash.length !== 44) {
      console.log("共有署名キー署名のハッシュ長が無効:", keyHash.length);
      return false;
    }
    if (signature.length !== 4412) {
      console.log("共有署名キー署名の署名長が無効:", signature.length);
      return false;
    }
    return true;
  } catch (error) {
    console.error("共有署名キー署名検証中にエラー:", error);
    return false;
  }
}