import { arrayBufferToBase64, base64ToArrayBuffer, keyHash } from "./utils.ts";
import type { deviceKey, EncryptedData } from "./type.ts";

/**
 * デバイスキーを生成する
 * @returns JSON文字列化されたデバイスキー
 */
export async function generateDeviceKey(): Promise<string> {
  const key = await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );
  const keyBinary = await crypto.subtle.exportKey("raw", key);
  const keyBinaryString = arrayBufferToBase64(keyBinary);
  const deviceKey: deviceKey = {
    keyType: "deviceKey",
    key: keyBinaryString,
  };
  return JSON.stringify(deviceKey);
}

/**
 * デバイスキーが有効かどうかを検証する
 * @param key 検証するデバイスキー
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidDeviceKey(key: string): boolean {
  try {
    if (key.length !== 76) {
      console.log("デバイスキーの長さが無効:", key.length);
      return false;
    }
    const { key: keyBinary, keyType } = JSON.parse(key);
    if (keyType !== "deviceKey") {
      return false;
    }
    const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
    if (keyBinaryArray.length !== 32) {
      console.log("デバイスキーのバイナリ長が無効:", keyBinaryArray.length);
      return false;
    }
    return true;
  } catch (error) {
    console.error("デバイスキー検証中にエラー:", error);
    return false;
  }
}

/**
 * デバイスキーでデータを暗号化する
 * @param key デバイスキー
 * @param data 暗号化するデータ
 * @returns 暗号化されたデータのJSON文字列、またはエラー時はnull
 */
export async function encryptDataDeviceKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidDeviceKey(key)) {
    return null;
  }
  try {
    const { key: keyBinary } = JSON.parse(key);
    const dataArray = new TextEncoder().encode(data);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const importedKey = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(base64ToArrayBuffer(keyBinary)),
      "AES-GCM",
      true,
      ["encrypt", "decrypt"],
    );
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
      keyType: "deviceKey",
      keyHash: await keyHash(key),
      encryptedData: encryptedDataString,
      iv: ivString,
      algorithm: "AES-GCM", // アルゴリズムを追加
    };
    return JSON.stringify(result);
  } catch (error) {
    console.error("デバイスキーでのデータ暗号化中にエラー:", error);
    return null;
  }
}

/**
 * デバイスキーで暗号化されたデータを復号する
 * @param key デバイスキー
 * @param data 復号するデータ
 * @returns 復号されたデータ文字列、またはエラー時はnull
 */
export async function decryptDataDeviceKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidDeviceKey(key)) {
    return null;
  }
  try {
    const { key: keyBinary } = JSON.parse(key);
    const { encryptedData: binaryEncryptedData, iv } = JSON.parse(data);
    const importedKey = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(base64ToArrayBuffer(keyBinary)),
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
      new Uint8Array(base64ToArrayBuffer(binaryEncryptedData)),
    );
    return new TextDecoder().decode(decryptedData);
  } catch (error) {
    console.error("デバイスキーでのデータ復号中にエラー:", error);
    return null;
  }
}

/**
 * 暗号化されたデバイスキーデータが有効かどうかを検証する
 * @param data 検証する暗号化データ
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidEncryptedDataDeviceKey(data: string): boolean {
  try {
    const { keyType, keyHash, iv, algorithm } = JSON.parse(data); // algorithm を追加
    const sha256 = new Uint8Array(base64ToArrayBuffer(keyHash));
    if (keyType !== "deviceKey") {
      return false;
    }
    if (sha256.length !== 32) {
      return false;
    }
    if (new Uint8Array(base64ToArrayBuffer(iv)).length !== 12) {
      return false;
    }
    return true;
  } catch (error) {
    console.error("暗号化デバイスキーデータ検証中にエラー:", error);
    return false;
  }
}