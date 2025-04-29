import type { masterKey } from "./type.ts";
import { MasterKeyPrivateSchema, MasterKeyPublicSchema, SignMasterKeySchema } from "./schema.ts";
import { createSignatureObjectMLDSA87, verifyWithMLDSA87 } from "./signature.ts";
import { generateDSA87KeyPair } from "./keyUtils.ts";

export function signMasterKey(
  key: string,
  data: string,
  pubKeyHash: string,
): string | null {
  if (!isValidMasterKeyPrivate(key)) {
    return null;
  }
  try {
    const { key: keyBinary } = JSON.parse(key);
    return createSignatureObjectMLDSA87(keyBinary, data, pubKeyHash, "masterKey");
  } catch (error) {
    console.error("署名作成中にエラー:", error);
    return null;
  }
}

export function verifyMasterKey(
  key: string,
  sign: string,
  data: string,
): boolean {
  if (!isValidMasterKeyPublic(key)) {
    return false;
  }
  try {
    const { key: keyBinary } = JSON.parse(key);
    const signData = JSON.parse(sign);
    if (signData.keyType !== "masterKey") {
      return false;
    }
    return verifyWithMLDSA87(keyBinary, data, signData.signature);
  } catch (error) {
    console.error("署名検証中にエラー:", error);
    return false;
  }
}

export function generateMasterKey(): {
  publicKey: string;
  privateKey: string;
} {
  try {
    const { publicKey, privateKey } = generateDSA87KeyPair();
    
    const publicKeyObj: masterKey = {
      keyType: "masterKeyPublic",
      key: publicKey,
    };
    
    const privateKeyObj: masterKey = {
      keyType: "masterKeyPrivate",
      key: privateKey,
    };
    
    return {
      publicKey: JSON.stringify(publicKeyObj),
      privateKey: JSON.stringify(privateKeyObj),
    };
  } catch (error) {
    console.error("マスターキー生成中にエラー:", error);
    throw new Error("マスターキーの生成に失敗しました");
  }
}

export function isValidMasterKeyPrivate(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return MasterKeyPrivateSchema.safeParse(parsedKey).success;
  } catch {
    return false;
  }
}

export function isValidMasterKeyPublic(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return MasterKeyPublicSchema.safeParse(parsedKey).success;
  } catch {
    return false;
  }
}

export function isValidSignMasterkey(sign: string): boolean {
  try {
    const parsedSign = JSON.parse(sign);
    return SignMasterKeySchema.safeParse(parsedSign).success;
  } catch {
    return false;
  }
}