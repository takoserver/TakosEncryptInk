import { keyHash } from "./core.ts";
import type { deviceKey, EncryptedData } from "./type.ts";
import { DeviceKeySchema, EncryptedDataDeviceKeySchema } from "./schema.ts";
import { encryptWithSymmetricKey, decryptWithSymmetricKey } from "./crypto.ts";
import { generateSymmetricKey } from "./keyUtils.ts";

/**
 * デバイスキーを生成する
 * @returns JSON文字列化されたデバイスキー
 */
export async function generateDeviceKey(): Promise<string> {
  const keyBinaryString = await generateSymmetricKey();
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
    const parsedKey = JSON.parse(key);
    return DeviceKeySchema.safeParse(parsedKey).success;
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
    const encryptResult = await encryptWithSymmetricKey(data, keyBinary);
    
    const result: EncryptedData = {
      keyType: "deviceKey",
      keyHash: await keyHash(key),
      encryptedData: encryptResult.encryptedData,
      iv: encryptResult.iv,
      algorithm: encryptResult.algorithm,
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
    const { encryptedData, iv } = JSON.parse(data);
    return await decryptWithSymmetricKey(encryptedData, iv, keyBinary);
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
    const parsedData = JSON.parse(data);
    return EncryptedDataDeviceKeySchema.safeParse(parsedData).success;
  } catch (error) {
    console.error("暗号化デバイスキーデータ検証中にエラー:", error);
    return false;
  }
}