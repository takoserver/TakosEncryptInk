import { keyHash } from "./core.ts";
import { isValidMasterKeyPrivate, isValidMasterKeyPublic, signMasterKey } from "./masterKey.ts";
import type { accountKey, EncryptedData } from "./type.ts";
import { 
  AccountKeyPublicSchema, 
  AccountKeyPrivateSchema, 
  EncryptedDataAccountKeySchema, 
  EncryptedDataShareKeySchema 
} from "./schema.ts";
import { encrypt, decrypt } from "./crypto.ts";
import { generateKEMKeyPair } from "./keyUtils.ts";
import { isValidEncryptedDataShareKey } from "./shareKey.ts"

export async function generateAccountKey(masterKey: {
  publicKey: string;
  privateKey: string;
}): Promise<
  {
    publicKey: string;
    privateKey: string;
    sign: string;
  } | null
> {
  if (!isValidMasterKeyPrivate(masterKey.privateKey)) {
    return null;
  }
  if (!isValidMasterKeyPublic(masterKey.publicKey)) {
    return null;
  }

  try {
    const { publicKey, privateKey } = generateKEMKeyPair();
    const timestamp = new Date().getTime();
    
    const publicKeyObj: accountKey = {
      keyType: "accountKeyPublic",
      key: publicKey,
      algorithm: "ML-KEM-768",
      timestamp: timestamp,
    };
    
    const privateKeyObj: accountKey = {
      keyType: "accountKeyPrivate",
      key: privateKey,
      algorithm: "ML-KEM-768",
      timestamp: timestamp,
    };
    
    const publicKeyStr = JSON.stringify(publicKeyObj);
    const privateKeyStr = JSON.stringify(privateKeyObj);
    
    const sign = signMasterKey(
      masterKey.privateKey,
      publicKeyStr,
      await keyHash(masterKey.publicKey),
    );
    
    if (!sign) {
      return null;
    }
    
    return {
      publicKey: publicKeyStr,
      privateKey: privateKeyStr,
      sign: sign,
    };
  } catch (error) {
    console.error("アカウントキー生成中にエラー:", error);
    return null;
  }
}

export function isValidAccountKeyPublic(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return AccountKeyPublicSchema.safeParse(parsedKey).success;
  } catch {
    return false;
  }
}

export function isValidAccountKeyPrivate(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return AccountKeyPrivateSchema.safeParse(parsedKey).success;
  } catch {
    return false;
  }
}

export async function encryptDataAccountKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidAccountKeyPublic(key)) {
    return null;
  }
  
  try {
    const { key: keyBinary } = JSON.parse(key);
    const encryptResult = await encrypt(data, keyBinary);
    
    const result: EncryptedData = {
      encryptedData: encryptResult.encryptedData,
      iv: encryptResult.iv,
      cipherText: encryptResult.cipherText,
      keyType: "accountKey",
      keyHash: await keyHash(key),
      algorithm: encryptResult.algorithm,
    };
    
    return JSON.stringify(result);
  } catch (error) {
    console.error("アカウントキーでの暗号化中にエラー:", error);
    return null;
  }
}

export function isValidEncryptedDataAccountKey(data: string): boolean {
  try {
    const parsedData = JSON.parse(data);
    return EncryptedDataAccountKeySchema.safeParse(parsedData).success;
  } catch {
    return false;
  }
}

export async function decryptDataAccountKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidAccountKeyPrivate(key)) {
    return null;
  }
  if (!isValidEncryptedDataAccountKey(data)) {
    return null;
  }
  
  try {
    const { key: keyBinary } = JSON.parse(key);
    const { encryptedData: binaryEncryptedData, iv, cipherText } = JSON.parse(data);
    
    return await decrypt(binaryEncryptedData, cipherText, iv, keyBinary);
  } catch (error) {
    console.error("アカウントキーでの復号中にエラー:", error);
    return null;
  }
}

export function isValidEncryptedAccountKey(data: string): boolean {
  return isValidEncryptedDataShareKey(data);
}
