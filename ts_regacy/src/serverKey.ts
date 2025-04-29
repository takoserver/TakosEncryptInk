import { keyHash } from "./core.ts";
import type { EncryptedData, serverKey, Sign } from "./type.ts";
import { 
  ServerKeyPublicSchema, 
  ServerKeyPrivateSchema, 
  SignServerKeySchema 
} from "./schema.ts";
import { generateDSA65KeyPair } from "./keyUtils.ts";
import { createSignatureObjectMLDSA65, verifyWithMLDSA65 } from "./signature.ts";

// serverKey生成関数を修正（ML-DSA-65仕様に合わせる）
export function generateServerKey(): {
  publicKey: string;
  privateKey: string;
} {
  try {
    const { publicKey, privateKey } = generateDSA65KeyPair();
    
    const timestamp = Date.now();
    
    const publicKeyObj: serverKey = {
      keyType: "serverKeyPublic",
      key: publicKey,
      timestamp: timestamp,
    };
    
    const privateKeyObj: serverKey = {
      keyType: "serverKeyPrivate",
      key: privateKey,
      timestamp: timestamp,
    };
    
    return {
      publicKey: JSON.stringify(publicKeyObj),
      privateKey: JSON.stringify(privateKeyObj),
    };
  } catch (error) {
    console.error("サーバーキー生成中にエラー:", error);
    throw new Error("サーバーキーの生成に失敗しました");
  }
}

export function isValidServerKeyPrivate(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    return ServerKeyPrivateSchema.safeParse(parsedKey).success;
  } catch {
    return false;
  }
}

export function isValidServerKeyPublic(key: string): boolean {
  try {
    const parsedKey = JSON.parse(key);
    const result = ServerKeyPublicSchema.safeParse(parsedKey)
    if(!result.success) {
      console.error("サーバーキー公開鍵検証エラー:", result.error.format())
      console.log(parsedKey)
    }
    return result.success
  } catch {
    return false;
  }
}

// generateServerSignKey関数を削除（serverKeyは既にML-DSA-65を使用）

export async function signDataServerKey(
  privateKey: string,
  data: string,
  pubKeyHash: string,
): Promise<string | null> {
  if (!isValidServerKeyPrivate(privateKey)) {
    return null;
  }
  try {
    const parsedKey = JSON.parse(privateKey);
    const { key: keyBinary } = parsedKey;
    
    const signObject = createSignatureObjectMLDSA65(keyBinary, data, pubKeyHash, "serverKey");
    if (!signObject) return null;

    // 署名にアルゴリズムを追加
    const signData: Sign = JSON.parse(signObject);
    signData.algorithm = "ML-DSA-65";
    
    return JSON.stringify(signData);
  } catch (error) {
    console.error("サーバーキーでの署名作成中にエラー:", error);
    return null;
  }
}

export function verifyDataServerKey(
  publicKey: string,
  sign: string,
  data: string,
): boolean {
  if (!isValidServerKeyPublic(publicKey) || !isValidSignServerKey(sign)) {
    return false;
  }
  try {
    const parsedKey = JSON.parse(publicKey);
    const { key: keyBinary } = parsedKey;
    const signData = JSON.parse(sign);
    
    if (signData.keyType !== "serverKey") {
      return false;
    }
    
    return verifyWithMLDSA65(keyBinary, data, signData.signature);
  } catch (error) {
    console.error("サーバーキーでの署名検証中にエラー:", error);
    return false;
  }
}

export function isValidSignServerKey(sign: string): boolean {
  try {
    const parsedSign = JSON.parse(sign);
    return SignServerKeySchema.safeParse(parsedSign).success;
  } catch {
    return false;
  }
}

// encryptDataServerKeyとdecryptDataServerKeyを削除（署名用のキーのため不要）
// isValidEncryptedDataServerKeyを削除（署名用のキーのため不要）