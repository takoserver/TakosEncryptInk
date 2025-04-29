import { keyHash } from "./core.ts";
import { isValidUUIDv7 } from "./core.ts";
import type { EncryptedData, roomKey } from "./type.ts";
import { RoomKeySchema, EncryptedDataRoomKeySchema } from "./schema.ts";
import { encryptWithSymmetricKey, decryptWithSymmetricKey } from "./crypto.ts";
import { generateSymmetricKey } from "./keyUtils.ts";

export async function generateRoomKey(roomUuid: string): Promise<string | null> {
  if (!isValidUUIDv7(roomUuid)) {
    return null;
  }
  try {
    const key = await generateSymmetricKey();
    const timestamp = new Date().getTime();
    
    const roomKey: roomKey = {
      keyType: "roomKey",
      key: key,
      timestamp: timestamp,
      sessionUuid: roomUuid,
      algorithm: "AES-GCM",
    };
    
    return JSON.stringify(roomKey);
  } catch (error) {
    console.error("ルームキー生成中にエラー:", error);
    return null;
  }
}

export function isValidRoomKey(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    const result = RoomKeySchema.safeParse(parsedKey)
    if(!result.success) {
      console.error("ルームキー検証エラー:", result.error.format())

    }
    return result.success
  } catch (error) {
    console.error("ルームキー検証中にエラー:", error);
    return false;
  }
}

export async function encryptDataRoomKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidRoomKey(key)) {
    return null;
  }
  try {
    const { key: keyBinary } = JSON.parse(key);
    const encryptResult = await encryptWithSymmetricKey(data, keyBinary);
    
    const result: EncryptedData = {
      keyType: "roomKey",
      keyHash: await keyHash(key),
      encryptedData: encryptResult.encryptedData,
      iv: encryptResult.iv,
      algorithm: encryptResult.algorithm,
    };
    
    return JSON.stringify(result);
  } catch (error) {
    console.error("ルームキーでのデータ暗号化中にエラー:", error);
    return null;
  }
}

export async function decryptDataRoomKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidRoomKey(key)) {
    return null;
  }
  try {
    const { key: keyBinary } = JSON.parse(key);
    const { encryptedData, iv } = JSON.parse(data);
    return await decryptWithSymmetricKey(encryptedData, iv, keyBinary);
  } catch (error) {
    console.error("ルームキーでのデータ復号中にエラー:", error);
    return null;
  }
}

export function isValidEncryptedDataRoomKey(data: string): boolean {
  try {
    const parsedData = JSON.parse(data);
    return EncryptedDataRoomKeySchema.safeParse(parsedData).success;
  } catch (error) {
    console.error("暗号化ルームキーデータ検証中にエラー:", error);
    return false;
  }
}