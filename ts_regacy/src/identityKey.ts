import { keyHash } from "./core.ts";
import { isValidUUIDv7 } from "./core.ts";
import { isValidMasterKeyPrivate, isValidMasterKeyPublic, signMasterKey } from "./masterKey.ts";
import type { identityKey } from "./type.ts";
import { IdentityKeyPrivateSchema, IdentityKeyPublicSchema, SignIdentityKeySchema } from "./schema.ts";
import { createSignatureObjectMLDSA65, verifyWithMLDSA65 } from "./signature.ts";
import { generateDSA65KeyPair } from "./keyUtils.ts";

export function signIdentityKey(
  key: string,
  data: string,
  pubKeyHash: string,
): string | null {
  if (!isValidIdentityKeyPrivate(key)) {
    return null;
  }
  try {
    const { key: keyBinary } = JSON.parse(key);
    return createSignatureObjectMLDSA65(keyBinary, data, pubKeyHash, "identityKey");
  } catch (error) {
    console.error("署名作成中にエラー:", error);
    return null;
  }
}

export function verifyIdentityKey(
  key: string,
  sign: string,
  data: string,
): boolean {
  if (!isValidIdentityKeyPublic(key)) {
    return false;
  }
  try {
    const { key: keyBinary } = JSON.parse(key);
    const signData = JSON.parse(sign);
    if (signData.keyType !== "identityKey") {
      return false;
    }
    return verifyWithMLDSA65(keyBinary, data, signData.signature);
  } catch (error) {
    console.error("署名検証中にエラー:", error);
    return false;
  }
}

export async function generateIdentityKey(uuid: string, masterKey: {
  publicKey: string;
  privateKey: string;
}): Promise<
  {
    publicKey: string;
    privateKey: string;
    sign: string;
  } | null
> {
  if (!isValidUUIDv7(uuid)) {
    return null;
  }
  if (!isValidMasterKeyPrivate(masterKey.privateKey)) {
    return null;
  }
  if (!isValidMasterKeyPublic(masterKey.publicKey)) {
    return null;
  }

  try {
    const { publicKey, privateKey } = generateDSA65KeyPair();
    const timestamp = new Date().getTime();
    
    const publicKeyObj: identityKey = {
      keyType: "identityKeyPublic",
      key: publicKey,
      algorithm: "ML-DSA-65",
      timestamp: timestamp,
      sessionUuid: uuid,
    };
    
    const privateKeyObj: identityKey = {
      keyType: "identityKeyPrivate",
      key: privateKey,
      algorithm: "ML-DSA-65",
      timestamp: timestamp,
      sessionUuid: uuid,
    };
    
    const publicKeyStr = JSON.stringify(publicKeyObj);
    const privateKeyStr = JSON.stringify(privateKeyObj);
    
    const sign = await signMasterKey(
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
    console.error("アイデンティティキー生成中にエラー:", error);
    return null;
  }
}

export function isValidIdentityKeyPrivate(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return IdentityKeyPrivateSchema.safeParse(parsedKey).success;
  } catch {
    return false;
  }
}

export function isValidIdentityKeyPublic(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return IdentityKeyPublicSchema.safeParse(parsedKey).success;
  } catch {
    return false;
  }
}

export function isValidSignIdentityKey(sign: string): boolean {
  try {
    const parsedSign = JSON.parse(sign);
    return SignIdentityKeySchema.safeParse(parsedSign).success;
  } catch {
    return false;
  }
}