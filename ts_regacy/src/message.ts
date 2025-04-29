import { encryptDataRoomKey, decryptDataRoomKey, isValidRoomKey, isValidEncryptedDataRoomKey } from "./roomKey.ts";
import { isValidIdentityKeyPrivate, isValidIdentityKeyPublic, signIdentityKey, verifyIdentityKey } from "./identityKey.ts";
import type {
  Message,
  NotEncryptMessage,
  EncryptedMessage,
  NotEncryptMessageValue,
  TextContent,
  ImageContent,
  VideoContent,
  AudioContent,
  FileContent,
} from "./type.ts";
import { keyHash } from "./utils.ts";
import {
  MessageSchema
} from "./schema.ts";
import { encryptDataAccountKey } from "./accountKey.ts";

/**
 * メッセージを暗号化する
 * @param message メッセージオブジェクト (NotEncryptMessageValue)
 * @param metadata メッセージメタデータ
 * @param roomKey ルームキー
 * @param identityKey アイデンティティキー情報
 * @param roomid ルームID
 * @returns 暗号化されたメッセージと署名、またはエラー時はnull
 */
export async function encryptMessage(
  messageValue: NotEncryptMessageValue,
  metadata: {
    channel: string;
    timestamp: number;
    isLarge: boolean;
    original?: string;
  },
  roomKey: string,
  identityKey: {
    privateKey: string;
    pubKeyHash: string;
  },
  roomid: string,
): Promise<
  {
    message: string;
    sign: string;
  } | null
> {
  if (!isValidRoomKey(roomKey)) {
    console.error("無効なルームキーが指定されました");
    return null;
  }
  if (!isValidIdentityKeyPrivate(identityKey.privateKey)) {
    console.error("無効なアイデンティティキーが指定されました");
    return null;
  }

  try {
    const messageContent = JSON.stringify(messageValue);

    const encryptedValue = await encryptDataRoomKey(roomKey, messageContent);
    if (!encryptedValue) {
      console.error("メッセージコンテンツの暗号化に失敗しました");
      return null;
    }

    const messageObj: EncryptedMessage = {
      encrypted: true,
      value: encryptedValue,
      channel: metadata.channel,
      timestamp: metadata.timestamp,
      isLarge: metadata.isLarge,
      original: metadata.original,
      roomid: roomid,
    };

    const messageString = JSON.stringify(messageObj);

    const sign = signIdentityKey(
      identityKey.privateKey,
      messageString,
      identityKey.pubKeyHash,
    );
    if (!sign) {
      console.error("メッセージの署名に失敗しました");
      return null;
    }

    return {
      message: messageString,
      sign: sign,
    };
  } catch (error) {
    console.error("メッセージ暗号化中にエラー:", error);
    return null;
  }
}

/**
 * 暗号化されたメッセージを復号する
 * @param message 暗号化されたメッセージと署名
 * @param serverData サーバーデータ（タイムスタンプ）
 * @param roomKey ルームキー
 * @param identityKeyPub アイデンティティキーの公開鍵
 * @param roomid ルームID
 * @returns 復号されたメッセージ (Message 型)、またはエラー時はnull
 */
export async function decryptMessage(
message: {
  message: string;
  sign: string;
}, serverData: {
  timestamp: number;
}, roomKey: string, identityKeyPub: string, roomid: string,
): Promise<Message | null> {
  if (!isValidIdentityKeyPublic(identityKeyPub)) {
    console.error("無効なアイデンティティキーが指定されました");
    return null;
  }

  try {
    const { message: messageString, sign: signString } = message;
    const messageObj = JSON.parse(messageString) as Message;

    if (!verifyIdentityKey(identityKeyPub, signString, messageString)) {
      console.error("メッセージの署名検証に失敗しました");
      return null;
    }

    if (!messageObj.encrypted) {
      if (roomid !== messageObj.roomid) {
        console.error("メッセージのルームIDが一致しません");
        return null;
      }
      if (Math.abs(messageObj.timestamp - serverData.timestamp) > 60000) {
        console.error("メッセージのタイムスタンプが無効です");
        return null;
      }
      return messageObj as NotEncryptMessage;
    }

    if (!isValidRoomKey(roomKey)) {
      console.error("無効なルームキーが指定されました (復号時)");
      return null;
    }

    if (Math.abs(messageObj.timestamp - serverData.timestamp) > 60000) {
      console.error("メッセージのタイムスタンプが無効です");
      return null;
    }

    if (roomid !== messageObj.roomid) {
      console.error("メッセージのルームIDが一致しません");
      return null;
    }

    if (!isValidEncryptedDataRoomKey(messageObj.value)) {
      console.error("メッセージ内の暗号化データが無効です");
      return null;
    }

    const decryptedContentString = await decryptDataRoomKey(roomKey, messageObj.value);
    if (!decryptedContentString) {
      console.error("メッセージの復号に失敗しました");
      return null;
    }

    const decryptedValue = JSON.parse(decryptedContentString) as NotEncryptMessageValue;

    const decryptedMessage: NotEncryptMessage = {
      encrypted: false,
      value: decryptedValue,
      channel: messageObj.channel,
      timestamp: messageObj.timestamp,
      isLarge: messageObj.isLarge,
      original: messageObj.original,
      roomid: messageObj.roomid
    };

    return decryptedMessage;

  } catch (error) {
    console.error("メッセージ復号中にエラー:", error);
    return null;
  }
}

/**
 * メッセージが有効かどうかを検証する
 * @param message 検証するメッセージ文字列 (Message 型の JSON 文字列)
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidMessage(message: string): boolean {
  try {
    const messageObj = JSON.parse(message);
    const result = MessageSchema.safeParse(messageObj);
    if (!result.success) {
      // console.error("メッセージ検証エラー:", result.error.errors); // Optional: Log detailed errors
      return false;
    }
    return true;
  } catch (error) {
    // console.error("メッセージ検証中にJSONパースエラー:", error); // Optional: Log parsing errors
    return false;
  }
}

/**
 * テキストコンテンツを作成する
 * @param text テキスト
 * @param format フォーマット（省略時はplain）
 * @param options オプション (isThumbnail, thumbnailOf, originalSize)
 * @returns テキストコンテンツオブジェクトのJSON文字列
 */
export function createTextContent(
  text: string,
  format: "plain" | "markdown" = "plain",
  options: { isThumbnail?: boolean; thumbnailOf?: string; originalSize?: number } = {}
): string {
  const content: TextContent = {
    text,
    format,
    ...options
  };
  return JSON.stringify(content);
}

/**
 * 画像コンテンツを作成する
 * @param uri 画像URI（Base64またはURL）
 * @param filename ファイル名
 * @param mimeType MIMEタイプ
 * @param options オプション (isThumbnail, thumbnailOf, originalSize)
 * @returns 画像コンテンツオブジェクトのJSON文字列
 */
export function createImageContent(
  uri: string,
  filename: string,
  mimeType: string,
  options: { isThumbnail?: boolean; thumbnailOf?: string; originalSize?: number } = {}
): string {
  const content: ImageContent = {
    uri,
    metadata: {
      filename,
      mimeType
    },
    ...options
  };
  return JSON.stringify(content);
}

/**
 * 動画コンテンツを作成する
 * @param uri 動画URI（Base64またはURL）
 * @param filename ファイル名
 * @param mimeType MIMEタイプ
 * @param options オプション (isThumbnail, thumbnailOf, originalSize)
 * @returns 動画コンテンツオブジェクトのJSON文字列
 */
export function createVideoContent(
  uri: string,
  filename: string,
  mimeType: string,
  options: { isThumbnail?: boolean; thumbnailOf?: string; originalSize?: number } = {}
): string {
  const content: VideoContent = {
    uri,
    metadata: {
      filename,
      mimeType
    },
    ...options
  };
  return JSON.stringify(content);
}

/**
 * 音声コンテンツを作成する
 * @param uri 音声URI（Base64またはURL）
 * @param filename ファイル名
 * @param mimeType MIMEタイプ
 * @param options オプション (isThumbnail, thumbnailOf, originalSize)
 * @returns 音声コンテンツオブジェクトのJSON文字列
 */
export function createAudioContent(
  uri: string,
  filename: string,
  mimeType: string,
  options: { isThumbnail?: boolean; thumbnailOf?: string; originalSize?: number } = {}
): string {
  const content: AudioContent = {
    uri,
    metadata: {
      filename,
      mimeType
    },
    ...options
  };
  return JSON.stringify(content);
}

/**
 * ファイルコンテンツを作成する
 * @param uri ファイルURI（Base64またはURL）
 * @param filename ファイル名
 * @param mimeType MIMEタイプ
 * @param options オプション (isThumbnail, thumbnailOf, originalSize)
 * @returns ファイルコンテンツオブジェクトのJSON文字列
 */
export function createFileContent(
  uri: string,
  filename: string,
  mimeType: string,
  options: { isThumbnail?: boolean; thumbnailOf?: string; originalSize?: number } = {}
): string {
  const content: FileContent = {
    uri,
    metadata: {
      filename,
      mimeType
    },
    ...options
  };
  return JSON.stringify(content);
}

export async function encryptRoomKeyWithAccountKeys(
  users: {
    masterKey: string;
    accountKeySign: string;
    accountKey: string;
    userId: string;
  }[],
  roomKey: string,
): Promise<{
  userId: string;
  encryptedData: string;
}[]> {
  const encryptedKeys: {
    userId: string;
    encryptedData: string;
  }[] = [];

  for (const user of users) {
    const { masterKey, accountKeySign, accountKey, userId } = user;
    const encryptedData = await encryptDataAccountKey(accountKey, roomKey);
    if (encryptedData) {
      encryptedKeys.push({
        userId,
        encryptedData,
      });
    }
  }

  return encryptedKeys;
}