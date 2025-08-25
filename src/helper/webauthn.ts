/* eslint-disable @typescript-eslint/no-explicit-any */
/** 部分代码来源于 https://rsolomakhin.github.io/pr/spc/ */

import { sha3_256 } from "@noble/hashes/sha3";
import { p256 } from '@noble/curves/nist.js';
import base64url from "base64url";
import {
  AccountAddress,
} from "@aptos-labs/ts-sdk";
import padString from "./padString";

export const generateTestRawTxn = async () => {
  const privateKey = new Uint8Array(32);
  crypto.getRandomValues(privateKey);
  
  // 创建一个简单的测试挑战
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  
  // 创建一个模拟的交易对象
  const rawTransaction = {
    bcsToBytes: () => challenge
  };
  
  return { challenge: challenge.buffer, rawTransaction };
};

export const p256SignatureFromDER = (derSig: Uint8Array) => {
  let sig = p256.Signature.fromBytes(derSig, 'der');
  
  const rawSig = sig.toBytes('compact');
  return rawSig;
};

export async function isSpcAvailable() {
  try {
    // 检查 PaymentRequest API 是否可用
    if (!window.PaymentRequest) {
      return false;
    }
    
    // 检查浏览器是否支持 SPC - 通过尝试创建 SPC 请求来检测
    const testData = {
      challenge: new Uint8Array([1, 2, 3, 4]),  // 测试挑战
      rpId: "localhost",                          // 依赖方 ID
      credentialIds: [new Uint8Array([1, 2, 3, 4])],  // 测试凭证 ID
      instrument: {
        displayName: "Test",                      // 测试显示名称
        icon: "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEyIDJMMTMuMDkgOC4yNkwxOSA5TDEzLjUgMTQuNzRMMTUgMjFMMTIgMTcuNzdMOSAyMUwxMC41IDE0Ljc0TDUgOUwxMC45MSA4LjI2TDEyIDJaIiBmaWxsPSIjMDA3QUZGIi8+Cjwvc3ZnPgo=",  // 测试图标
      },
      payeeOrigin: "https://localhost",           // 收款方来源
      extensions: {},                             // 扩展
    };
    
    const supportedInstruments = [
      { supportedMethods: "secure-payment-confirmation", data: testData },  // 支持的支付方法
    ];
    
    const details = {
      total: {
        label: "Total",                           // 总计标签
        amount: { currency: "USD", value: "1.00" },  // 金额
      },
    };
    
    // 尝试创建 PaymentRequest 对象来检测 SPC 支持
    new PaymentRequest(supportedInstruments, details);
    return true;
  } catch (error) {
    console.warn("SPC 可用性检查失败:", error);
    return false;
  }
}

export type SPCAuthenticationExtensionsClientInputs =
  AuthenticationExtensionsClientInputs & {
    payment?: {
      isPayment: boolean;
    };
  };

export type SPCAuthenticatorSelectionCriteria =
  AuthenticatorSelectionCriteria & {
    tokenBinding?: string;
  };

export type SPCPublicKeyCredentialCreationOptions = Omit<
  PublicKeyCredentialCreationOptions & {
    extensions: SPCAuthenticationExtensionsClientInputs;
    authenticatorSelection: SPCAuthenticatorSelectionCriteria;
  },
  ""
>;

export const defaultRp: PublicKeyCredentialRpEntity = {
  id: window.location.hostname,  // 依赖方 ID
  name: window.location.origin,  // 依赖方名称
};

export const defaultPubKeyCredParams: PublicKeyCredentialParameters[] = [
  {
    type: "public-key",
    alg: -7, // ECDSA，Windows 不支持
  },
];

export const defaultUser = {
  // 设置一个可理解的用户名，以防 WebAuthn UX 显示它
  // (例如，Chrome MacOS 108+ 上的 Passkeys UX)。这仅用于显示，
  // 对 SPC 的功能没有影响。(例如，它不会在 SPC 交易对话框中显示。)
  name: "Andrew",
  displayName: "",
  // TODO 稍后查看这个
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  id: Uint8Array.from(String(Math.random() * 99999999)),
};

export const defaultResidentKey: ResidentKeyRequirement = spcSupportsPreferred()
  ? "preferred"   // 首选
  : "required";   // 必需

export const defaultAuthenticatorSelection: SPCPublicKeyCredentialCreationOptions["authenticatorSelection"] =
  {
    userVerification: "required",      // 用户验证必需
    residentKey: defaultResidentKey,   // 常驻密钥
    authenticatorAttachment: "platform", // 平台认证器
  };

export const generateDefaultPublicKey =
  async (): Promise<SPCPublicKeyCredentialCreationOptions> => {
    const { challenge } = await generateTestRawTxn();

    return {
      rp: defaultRp,
      user: defaultUser,
      challenge: challenge,
      pubKeyCredParams: defaultPubKeyCredParams,
      authenticatorSelection: defaultAuthenticatorSelection,
      extensions: {},
    };
  };

export const generateDefaultSPCPublicKey =
  async (): Promise<SPCPublicKeyCredentialCreationOptions> => {
    const { challenge } = await generateTestRawTxn();

    return {
      rp: defaultRp,
      user: defaultUser,
      challenge: challenge,
      pubKeyCredParams: defaultPubKeyCredParams,
      authenticatorSelection: defaultAuthenticatorSelection,
      extensions: {
        payment: {
          isPayment: true,
        },
      },
    };
  };

/**
 * 创建一个演示 WebAuthn 凭证，可选择设置 'payment' 扩展
 * 创建的凭证将始终具有名称 'Andrew ···· 1234'，
 * 与认证中使用的演示支付工具匹配
 *
 * @param {SPCPublicKeyCredentialCreationOptions} publicKey
 */
export async function createCredential(
  publicKey?: SPCPublicKeyCredentialCreationOptions
): Promise<Credential | null> {
  const defaultPublicKey = await generateDefaultPublicKey();

  const publicKeyCreationOptions: SPCPublicKeyCredentialCreationOptions = {
    ...defaultPublicKey,
    ...publicKey,
  };

  return await navigator.credentials.create({
    publicKey: publicKeyCreationOptions,
  });
}

export async function createSPCCredential(
  publicKey?: SPCPublicKeyCredentialCreationOptions
): Promise<Credential | null> {
  const defaultPublicKey = await generateDefaultSPCPublicKey();

  const publicKeyCreationOptions: SPCPublicKeyCredentialCreationOptions = {
    ...defaultPublicKey,
    ...publicKey,
  };

  return await navigator.credentials.create({
    publicKey: publicKeyCreationOptions,
  });
}

/**
 * 这是 getCredential 方法的基础实现
 */
export async function getCredential(
  allowCredentials: PublicKeyCredentialDescriptor[]
) {
  const { challenge } = await generateTestRawTxn();

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: challenge as ArrayBuffer,                    // 挑战
    allowCredentials: allowCredentials,  // 允许的凭证
    extensions: {},              // 扩展
  };

  return (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential;
}

/**
 * 返回 SPC 是否支持 residentKey 'preferred'（而不仅仅是 'required'）
 * 不幸的是，没有方法可以检测此功能，所以我们必须进行版本检查
 *
 * @return {boolean} 如果 SPC 支持 residentKey 参数的 'preferred' 则为 true，
 *     否则为 false
 */
export function spcSupportsPreferred() {
  // 这不仅对 Chrome 为 true，对 Edge 等也为 true，但这没关系
  const match = navigator.userAgent.match(/Chrom(e|ium)\/([0-9]+)\./);
  if (!match) return false;

  const version = parseInt(match[2], 10);
  // https://crrev.com/130fada41 在 106.0.5228.0 中落地，但为简单起见，
  // 我们假设任何 106 版本都可以
  return version >= 106;
}

/**
 * @see https://www.w3.org/TR/secure-payment-confirmation/#dictdef-paymentcredentialinstrument
 */
export interface PaymentCredentialInstrument {
  // 必需的 USVString 显示名称
  displayName: string;
  // 必需的 USVString 图标
  icon: string;
  // 布尔值 iconMustBeShown = true
  iconMustBeShown?: boolean;
}

/**
 * @see https://www.w3.org/TR/secure-payment-confirmation/#sctn-securepaymentconfirmationrequest-dictionary
 */
export interface SecurePaymentConfirmationRequest {
  challenge: Uint8Array;
  // 必需的 USVString 依赖方 ID
  rpId: string;
  // 必需的 sequence<BufferSource> 凭证 ID 序列
  credentialIds: Uint8Array[];
  // 必需的 PaymentCredentialInstrument 支付凭证工具
  instrument: PaymentCredentialInstrument;
  // 无符号长整型超时时间
  timeout?: number;
  // USVString 收款方名称
  payeeName?: string;
  // USVString 收款方来源
  payeeOrigin?: string;
  // AuthenticationExtensionsClientInputs 认证扩展客户端输入
  extensions: Record<string, unknown>;
  // sequence<USVString> 语言环境序列
  locale?: string[];
  // 布尔值 显示退出选项
  showOptOut?: boolean;
}

/**
 * 为 SPC 创建 PaymentRequest 对象
 *
 * @param {SecurePaymentConfirmationRequest} spcData - 输入的 SPC 数据。credentialIds 字段
 *     *必须* 设置。此对象中未设置的任何其他 SecurePaymentConfirmationRequest
 *     字段将初始化为默认值。
 * @return {PaymentRequest} 支付请求对象
 */
export function createSPCPaymentRequest(
  spcData: SecurePaymentConfirmationRequest
) {
  if (!window.PaymentRequest) {
    throw new Error("PaymentRequest API is not supported.");
  }
  if (spcData === undefined || spcData.credentialIds === undefined) {
    throw new Error("credentialIds must be set in the input spcData object.");
  }

  // https://w3c.github.io/secure-payment-confirmation/#sctn-securepaymentconfirmationrequest-dictionary
  if (spcData.challenge === undefined)
    spcData.challenge = new TextEncoder().encode("network_data");  // 网络数据
  if (spcData.rpId === undefined) spcData.rpId = window.location.hostname;  // 依赖方 ID
  if (spcData.instrument === undefined)
    spcData.instrument = { displayName: "Andrew ···· 1234", icon: "" };  // 默认支付工具
  if (spcData.instrument.icon === undefined)
    spcData.instrument.icon =
      "https://rsolomakhin.github.io/pr/spc/troy-alt-logo.png";  // 默认图标
  if (spcData.timeout === undefined) spcData.timeout = 60000;  // 默认超时时间
  // 我们只在 *两个* payeeName 和 payeeOrigin 都未设置时才设置默认的 payeeOrigin，
  // 因为规范故意允许其中一个或两个都为 null
  if (!("payeeName" in spcData) && !("payeeOrigin" in spcData))
    spcData.payeeOrigin = window.location.origin;  // 默认收款方来源

  const supportedInstruments = [
    { supportedMethods: "secure-payment-confirmation", data: spcData },
  ];
  const details = {
    total: {
      label: "Total",
      amount: {
        currency: "APT",
        value: "1.01",
      },
    },
  };

  return new PaymentRequest(supportedInstruments, details);
}

/**
 * 将 PaymentResponse 或 PublicKeyCredential 转换为字符串
 */
export function objectToString(input: Record<string, any>) {
  return JSON.stringify(objectToDictionary(input), undefined, 2);
}

export enum Encoding {
  base64 = "base64",
  base64Url = "base64Url",
}

/**
 * 将 PaymentResponse 或 PublicKeyCredential 转换为字典
 * 警告：base64Url 编码不能按预期工作
 *       暂时使用类似 https://www.base64url.com/ 来手动编码
 */
export function objectToDictionary(
  input: Record<string, any>,
  encoding = Encoding.base64
) {
  const output: Record<string, any> = {};
  if (input.requestId) {
    output.requestId = input.requestId;
  }
  if (input.id) {
    output.id = input.id;
  }
  if (input.rawId && input.rawId.constructor === ArrayBuffer) {
    output.rawId = arrayBufferToBase64Url(input.rawId);
  }
  if (
    input.response &&
    (input.response.constructor === AuthenticatorAttestationResponse ||
      input.response.constructor === AuthenticatorAssertionResponse ||
      input.response.constructor === Object)
  ) {
    output.response = objectToDictionary(input.response);
  }
  if (
    input.attestationObject &&
    input.attestationObject.constructor === ArrayBuffer
  ) {
    output.attestationObject =
      encoding === Encoding.base64
        ? arrayBufferToBase64(input.attestationObject)
        : arrayBufferToBase64Url(input.attestationObject);
  }
  if (
    input.authenticatorData &&
    input.authenticatorData.constructor === ArrayBuffer
  ) {
    output.authenticatorData =
      encoding === Encoding.base64
        ? arrayBufferToBase64(input.authenticatorData)
        : arrayBufferToBase64Url(input.authenticatorData);
  }
  if (
    input.authenticatorData &&
    input.authenticatorData.constructor === String
  ) {
    output.authenticatorData =
      encoding === Encoding.base64
        ? input.authenticatorData
        : base64url.fromBase64(input.authenticatorData.toString());
  }
  if (
    input.clientDataJSON &&
    input.clientDataJSON.constructor === ArrayBuffer
  ) {
    const stringifiedClientDataJSON =
      encoding === Encoding.base64
        ? arrayBufferToBase64String(input.clientDataJSON)
        : arrayBufferToBase64Url(input.authenticatorData);

    output.clientDataJSON = stringifiedClientDataJSON;
  }
  if (input.clientDataJSON && input.clientDataJSON.constructor === String) {
    output.clientDataJSON = atob(input.clientDataJSON.toString());
  }
  if (input.info) {
    output.info = objectToDictionary(input.info);
  }
  if (input.signature && input.signature.constructor === ArrayBuffer) {
    output.signature =
      encoding === Encoding.base64
        ? arrayBufferToBase64(input.signature)
        : arrayBufferToBase64Url(input.signature);
  }
  if (input.signature && input.signature.constructor === String) {
    output.signature = input.signature;
  }
  if (input.userHandle && input.userHandle.constructor === ArrayBuffer) {
    output.userHandle =
      encoding === Encoding.base64
        ? arrayBufferToBase64(input.userHandle)
        : arrayBufferToBase64Url(input.userHandle);
  }
  if (input.userHandle && input.userHandle.constructor === String) {
    output.userHandle = input.userHandle;
  }
  if (input.type) {
    output.type = input.type;
  }
  if (input.methodName) {
    output.methodName = input.methodName;
  }
  if (input.details) {
    output.details = objectToDictionary(input.details);
  }
  if (input.appid_extension) {
    output.appid_extension = input.appid_extension;
  }
  if (input.challenge) {
    output.challenge = input.challenge;
  }
  if (input.echo_appid_extension) {
    output.echo_appid_extension = input.echo_appid_extension;
  }
  if (input.echo_prf) {
    output.echo_prf = input.echo_prf;
  }
  if (input.prf_not_evaluated) {
    output.prf_not_evaluated = input.prf_not_evaluated;
  }
  if (input.prf_results) {
    output.prf_results = objectToDictionary(input.prf_results);
  }
  if (input.user_handle) {
    output.user_handle = input.user_handle;
  }
  if (input.authenticator_data) {
    output.authenticator_data = input.authenticator_data;
  }
  if (input.client_data_json) {
    output.client_data_json = atob(input.client_data_json);
  }
  if (input.shippingAddress) {
    output.shippingAddress = input.shippingAddress;
  }
  if (input.shippingOption) {
    output.shippingOption = input.shippingOption;
  }
  if (input.payerName) {
    output.payerName = input.payerName;
  }
  if (input.payerEmail) {
    output.payerEmail = input.payerEmail;
  }
  if (input.payerPhone) {
    output.payerPhone = input.payerPhone;
  }
  return output;
}

/**
 * 将 base64 编码的字符串转换为 Uint8Array
 */
export function base64ToArray(input: string) {
  return Uint8Array.from(atob(input), (c) => c.charCodeAt(0));
}

/**
 * 将 base64Url 编码的字符串转换为 Uint8Array
 */
export function base64UrlToArray(input: string) {
  const base64 = toBase64(input)
  return base64ToArray(base64);
}

export function toBase64(base64url: string): string {
  // 我们需要这是一个字符串，这样我们就可以对它进行 .replace 操作。如果它
  // 已经是一个字符串，这就是一个空操作。
  base64url = base64url.toString();
  return padString(base64url)
      .replace(/-/g, "+")    // 将 - 替换为 +
      .replace(/_/g, "/");   // 将 _ 替换为 /
}

/**
 * 将 ArrayBuffer 转换为 base64 编码的字符串
 */
export function arrayBufferToBase64(input: ArrayBuffer) {
  return btoa(arrayBufferToBase64String(input));
}

export function arrayBufferToBase64Url(input: ArrayBuffer) {
  const base64 = arrayBufferToBase64(input);
  const base64Url = base64url.fromBase64(base64);
  return base64Url;
}

/**
 * 将 ArrayBuffer 转换为 base64 字符串
 */
export function arrayBufferToBase64String(input: ArrayBuffer) {
  return String.fromCharCode(...new Uint8Array(input));
}

/**
 * 将 Uint8Array 转换为十六进制字符串
 */
export function arrayToHex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * 从 WebAuthn 凭证中提取公钥
 */
export function extractPublicKeyFromCredential(credential: PublicKeyCredential): {
  publicKeyBase64: string;
  publicKeyHex: string;
  aptosAddress: string;
} | null {
  try {
    // 获取认证对象
    const attestationResponse = credential.response as AuthenticatorAttestationResponse;
    const attestationObject = attestationResponse.attestationObject;
    
    // 将 ArrayBuffer 转换为 Uint8Array
    const attestationBytes = new Uint8Array(attestationObject);
    
    // 提取公钥（简化版本）
    const publicKeyBytes = attestationBytes.slice(-65); // 通常公钥在末尾
    const publicKeyBase64 = arrayBufferToBase64(publicKeyBytes.buffer);
    const publicKeyHex = arrayToHex(publicKeyBytes);
    
    // 使用 Aptos SDK 计算地址
    const aptosAddress = calculateAptosAddressFromPublicKey(publicKeyBytes);
    
    return {
      publicKeyBase64,
      publicKeyHex,
      aptosAddress
    };
  } catch (error) {
    console.error('提取公钥失败:', error);
    return null;
  }
}

/**
 * 使用 Aptos SDK 从公钥计算地址
 */
export function calculateAptosAddressFromPublicKey(publicKeyBytes: Uint8Array): string {
  try {
    // 移除可能的压缩前缀（0x04 表示未压缩）
    let keyBytes = publicKeyBytes;
    // if (publicKeyBytes[0] === 0x04) {
    //   keyBytes = publicKeyBytes.slice(1);
    // }
    
    // 确保是 64 字节（32 + 32）
    if (keyBytes.length !== 65) {
      throw new Error(`公钥长度不正确: ${keyBytes.length}`);
    }

    // 最后加一个 0x02
    keyBytes = new Uint8Array([...keyBytes, 0x02]);
    
    // 使用 SHA3-256 哈希公钥
    const hashedPublicKey = sha3_256.create().update(keyBytes).digest();
    
    // 转换为 Aptos 地址格式 - 使用正确的 API
    // 将字节数组转换为十六进制字符串，然后使用 fromString
    const hexString = "0x" + arrayToHex(hashedPublicKey);
    const address = AccountAddress.fromString(hexString);
    
    return address.toString();
  } catch (error) {
    console.error('计算 Aptos 地址失败:', error);
    return '计算失败';
  }
}

/**
 * 获取凭证的完整信息
 */
export function getCredentialInfo(credential: PublicKeyCredential): {
  id: string;
  type: string;
  publicKey: {
    base64: string;
    hex: string;
    aptosAddress: string;
  };
  rawData: any;
} | null {
  try {
    const credentialObject = objectToDictionary(credential, Encoding.base64Url);
    const publicKeyInfo = extractPublicKeyFromCredential(credential);
    
    if (!publicKeyInfo) {
      return null;
    }
    
    return {
      id: credentialObject.rawId || '',
      type: credentialObject.type || '',
      publicKey: {
        base64: publicKeyInfo.publicKeyBase64,
        hex: publicKeyInfo.publicKeyHex,
        aptosAddress: publicKeyInfo.aptosAddress
      },
      rawData: credentialObject
    };
  } catch (error) {
    console.error('获取凭证信息失败:', error);
    return null;
  }
}
