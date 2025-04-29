import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { arrayBufferToBase64, base64ToArrayBuffer } from "./utils.ts";
import { z } from "zod";

// --- 鍵生成関数 ---

/**
 * ML-KEM-768鍵ペアを生成する
 * @returns 生成された鍵ペア（publicKey: 公開鍵, privateKey: 秘密鍵）
 */
export function generateKEMKeyPair(): { 
  publicKey: string; 
  privateKey: string;
} {
  try {
    const key = ml_kem768.keygen();
    const publicKeyBinary = arrayBufferToBase64(key.publicKey as unknown as ArrayBuffer);
    const privateKeyBinary = arrayBufferToBase64(key.secretKey as unknown as ArrayBuffer);
    
    return {
      publicKey: publicKeyBinary,
      privateKey: privateKeyBinary,
    };
  } catch (error) {
    console.error("ML-KEM-768鍵ペア生成中にエラー:", error);
    throw new Error("鍵ペアの生成に失敗しました");
  }
}

/**
 * ML-DSA-65鍵ペアを生成する
 * @returns 生成された鍵ペア（publicKey: 公開鍵, privateKey: 秘密鍵）
 */
export function generateDSA65KeyPair(): { 
  publicKey: string; 
  privateKey: string;
} {
  try {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const key = ml_dsa65.keygen(seed);
    const publicKeyBinary = arrayBufferToBase64(key.publicKey as unknown as ArrayBuffer);
    const privateKeyBinary = arrayBufferToBase64(key.secretKey as unknown as ArrayBuffer);
    
    return {
      publicKey: publicKeyBinary,
      privateKey: privateKeyBinary,
    };
  } catch (error) {
    console.error("ML-DSA-65鍵ペア生成中にエラー:", error);
    throw new Error("鍵ペアの生成に失敗しました");
  }
}

/**
 * ML-DSA-87鍵ペアを生成する
 * @returns 生成された鍵ペア（publicKey: 公開鍵, privateKey: 秘密鍵）
 */
export function generateDSA87KeyPair(): { 
  publicKey: string; 
  privateKey: string;
} {
  try {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const key = ml_dsa87.keygen(seed);
    const publicKeyBinary = arrayBufferToBase64(key.publicKey as unknown as ArrayBuffer);
    const privateKeyBinary = arrayBufferToBase64(key.secretKey as unknown as ArrayBuffer);
    
    return {
      publicKey: publicKeyBinary,
      privateKey: privateKeyBinary,
    };
  } catch (error) {
    console.error("ML-DSA-87鍵ペア生成中にエラー:", error);
    throw new Error("鍵ペアの生成に失敗しました");
  }
}

/**
 * AES-GCM用の対称鍵を生成する
 * @returns Base64エンコードされた対称鍵
 */
export async function generateSymmetricKey(): Promise<string> {
  try {
    const key = await crypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"],
    );
    const keyBinary = await crypto.subtle.exportKey("raw", key);
    return arrayBufferToBase64(keyBinary);
  } catch (error) {
    console.error("対称鍵生成中にエラー:", error);
    throw new Error("対称鍵の生成に失敗しました");
  }
}

// --- 鍵検証関数 ---

// Basic schema to check if the input has public and private string properties
const KeyPairSchema = z.object({
  public: z.string(),
  private: z.string(),
});

// Schema for parsed public key structure (basic types)
const ParsedPublicKeySchema = z.object({
  keyType: z.string(), // More specific checks happen below
  key: z.string(),
  // Other fields like algorithm, timestamp, sessionUuid might exist
}).passthrough(); // Allow other fields

// Schema for parsed private key structure (basic types)
const ParsedPrivateKeySchema = z.object({
  keyType: z.string(), // More specific checks happen below
  key: z.string(),
  // Other fields like algorithm, timestamp, sessionUuid might exist
}).passthrough(); // Allow other fields

/**
 * 署名用キーペアが有効かどうかを検証
 * @param keyPair 公開鍵と秘密鍵のペア
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidKeyPairSign(
  keyPair: { public: string; private: string },
): boolean {
  // 1. Validate basic structure
  const pairParseResult = KeyPairSchema.safeParse(keyPair);
  if (!pairParseResult.success) {
    console.error("Invalid key pair structure:", pairParseResult.error);
    return false;
  }

  try {
    // 2. Parse JSON and validate basic parsed structure
    const publicKeyObj = JSON.parse(keyPair.public);
    const privateKeyObj = JSON.parse(keyPair.private);

    const pubParseResult = ParsedPublicKeySchema.safeParse(publicKeyObj);
    const privParseResult = ParsedPrivateKeySchema.safeParse(privateKeyObj);

    if (!pubParseResult.success || !privParseResult.success) {
      console.error("Invalid parsed key structure:", pubParseResult.error, privParseResult.error);
      return false;
    }

    // 3. Perform cryptographic verification based on keyType
    const signText = "test";
    const privateKeyBytes = new Uint8Array(base64ToArrayBuffer(privateKeyObj.key));
    const publicKeyBytes = new Uint8Array(base64ToArrayBuffer(publicKeyObj.key));
    const dataToSign = new TextEncoder().encode(signText);

    let isValidCrypto = false;

    if (publicKeyObj.keyType === "masterKeyPublic" && privateKeyObj.keyType === "masterKeyPrivate") {
      const sign = ml_dsa87.sign(privateKeyBytes, dataToSign);
      isValidCrypto = ml_dsa87.verify(publicKeyBytes, dataToSign, sign);
    } else if (
      (publicKeyObj.keyType === "shareSignKeyPublic" && privateKeyObj.keyType === "shareSignKeyPrivate") ||
      (publicKeyObj.keyType === "identityKeyPublic" && privateKeyObj.keyType === "identityKeyPrivate") ||
      (publicKeyObj.keyType === "migrateSignKeyPublic" && privateKeyObj.keyType === "migrateSignKeyPrivate") ||
      (publicKeyObj.keyType === "serverKeyPublic" && privateKeyObj.keyType === "serverKeyPrivate")
    ) {
      const sign = ml_dsa65.sign(privateKeyBytes, dataToSign);
      isValidCrypto = ml_dsa65.verify(publicKeyBytes, dataToSign, sign);
    } else {
      console.error("Mismatched or unknown key types for signing:", publicKeyObj.keyType, privateKeyObj.keyType);
      return false;
    }

    return isValidCrypto;

  } catch (error) {
    console.error("Key pair sign validation error:", error);
    return false;
  }
}

/**
 * 暗号化用キーペアが有効かどうかを検証
 * @param keyPair 公開鍵と秘密鍵のペア
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidKeyPairEncrypt(
  keyPair: { public: string; private: string },
): boolean {
  // 1. Validate basic structure
  const pairParseResult = KeyPairSchema.safeParse(keyPair);
  if (!pairParseResult.success) {
    console.error("Invalid key pair structure:", pairParseResult.error);
    return false;
  }

  try {
    // 2. Parse JSON and validate basic parsed structure
    const publicKeyObj = JSON.parse(keyPair.public);
    const privateKeyObj = JSON.parse(keyPair.private);

    const pubParseResult = ParsedPublicKeySchema.safeParse(publicKeyObj);
    const privParseResult = ParsedPrivateKeySchema.safeParse(privateKeyObj);

    if (!pubParseResult.success || !privParseResult.success) {
      console.error("Invalid parsed key structure:", pubParseResult.error, privParseResult.error);
      return false;
    }

    // 3. Check for compatible encryption key types
    const validPublicTypes = ["accountKeyPublic", "shareKeyPublic", "migrateKeyPublic"];
    const validPrivateTypes = ["accountKeyPrivate", "shareKeyPrivate", "migrateKeyPrivate"];

    if (!validPublicTypes.includes(publicKeyObj.keyType) || !validPrivateTypes.includes(privateKeyObj.keyType)) {
       console.error("Invalid key types for encryption:", publicKeyObj.keyType, privateKeyObj.keyType);
       return false;
    }
    // Basic check: ensure public and private types correspond (e.g., accountKeyPublic with accountKeyPrivate)
    if (publicKeyObj.keyType.replace('Public', '') !== privateKeyObj.keyType.replace('Private', '')) {
        console.error("Mismatched public/private key types for encryption:", publicKeyObj.keyType, privateKeyObj.keyType);
        return false;
    }

    // 4. Perform cryptographic verification (encapsulate/decapsulate)
    const publicKeyBytes = new Uint8Array(base64ToArrayBuffer(publicKeyObj.key));
    const privateKeyBytes = new Uint8Array(base64ToArrayBuffer(privateKeyObj.key));

    const { cipherText, sharedSecret } = ml_kem768.encapsulate(
      publicKeyBytes,
      new Uint8Array(32), // Seed for encapsulation
    );
    const sharedSecret2 = ml_kem768.decapsulate(
      cipherText,
      privateKeyBytes,
    );

    // Compare the shared secrets
    return arrayBufferToBase64(sharedSecret as unknown as ArrayBuffer) ===
      arrayBufferToBase64(sharedSecret2 as unknown as ArrayBuffer);

  } catch (error) {
    console.error("Key pair encrypt validation error:", error);
    return false;
  }
}

/**
 * ML-DSA-65鍵が有効かどうかをチェックする
 * @param key テストする鍵（Base64エンコード）
 * @param isPublic 公開鍵かどうか（true: 公開鍵, false: 秘密鍵）
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidDSA65Key(key: string, isPublic: boolean): boolean {
  try {
    const keyBytes = new Uint8Array(base64ToArrayBuffer(key));
    
    if (isPublic) {
      // 公開鍵の場合はサイズチェックのみ (1952バイト)
      return keyBytes.length === 1952;
    } else {
      // 秘密鍵の場合は実際に署名を作成して検証する
      const testData = new TextEncoder().encode("test");
      const signature = ml_dsa65.sign(keyBytes, testData);
      
      // 署名が生成できたかどうかで判定
      return signature && signature.length > 0;
    }
  } catch (error) {
    console.error("ML-DSA-65鍵検証中にエラー:", error);
    return false;
  }
}

/**
 * ML-DSA-87鍵が有効かどうかをチェックする
 * @param key テストする鍵（Base64エンコード）
 * @param isPublic 公開鍵かどうか（true: 公開鍵, false: 秘密鍵）
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidDSA87Key(key: string, isPublic: boolean): boolean {
  try {
    const keyBytes = new Uint8Array(base64ToArrayBuffer(key));
    
    if (isPublic) {
      // 公開鍵の場合はサイズチェックのみ (2592バイト)
      return keyBytes.length === 2592;
    } else {
      // 秘密鍵の場合は実際に署名を作成して検証する
      const testData = new TextEncoder().encode("test");
      const signature = ml_dsa87.sign(keyBytes, testData);
      
      // 署名が生成できたかどうかで判定
      return signature && signature.length > 0;
    }
  } catch (error) {
    console.error("ML-DSA-87鍵検証中にエラー:", error);
    return false;
  }
}

/**
 * ML-KEM-768鍵が有効かどうかをチェックする
 * @param key テストする鍵（Base64エンコード）
 * @param isPublic 公開鍵かどうか（true: 公開鍵, false: 秘密鍵）
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidKEMKey(key: string, isPublic: boolean): boolean {
  try {
    const keyBytes = new Uint8Array(base64ToArrayBuffer(key));
    
    if (isPublic) {
      // 公開鍵は1184バイト
      return keyBytes.length === 1184;
    } else {
      // 秘密鍵は2400バイト
      return keyBytes.length === 2400;
    }
  } catch (error) {
    console.error("ML-KEM-768鍵検証中にエラー:", error);
    return false;
  }
}

/**
 * AES-GCM対称鍵が有効かどうかをチェックする
 * @param key テストする鍵（Base64エンコード）
 * @returns 検証結果（true: 有効、false: 無効）
 */
export async function isValidSymmetricKey(key: string): Promise<boolean> {
  try {
    const keyBytes = new Uint8Array(base64ToArrayBuffer(key));
    
    // 鍵長が256ビット(32バイト)かチェック
    if (keyBytes.length !== 32) {
      return false;
    }
    
    // 実際にWebCrypto APIで鍵をインポートしてみる
    await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );
    
    return true;
  } catch (error) {
    console.error("対称鍵検証中にエラー:", error);
    return false;
  }
}

/**
 * ランダムな文字列を生成する
 * @param length 生成する文字列の長さ
 * @returns ランダム文字列
 */
export function generateRandomString(length: number): string {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(randomValues[i] % characters.length);
  }
  return result;
}