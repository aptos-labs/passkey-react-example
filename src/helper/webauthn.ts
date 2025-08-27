/* eslint-disable @typescript-eslint/no-explicit-any */
/** 部分代码来源于 https://rsolomakhin.github.io/pr/spc/ */

import { sha3_256 } from "@noble/hashes/sha3";
import { p256 } from '@noble/curves/nist.js';
import { Buffer } from "buffer";
import {
  AccountAddress,
  AptosConfig,
  Aptos,
  Network,
  Serializer,
  Hex,
  generateSigningMessageForTransaction,
} from "@aptos-labs/ts-sdk";
import { RegistrationResponseJSON} from "@simplewebauthn/server";
import { parseAuthenticatorData, convertCOSEtoPKCS } from "@simplewebauthn/server/helpers";
// Aptos Devnet 配置
const aptosConfig = new AptosConfig({
  network: Network.DEVNET,
});

const aptosClient = new Aptos(aptosConfig);

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
 * 使用 Aptos SDK 从公钥计算地址
 */
export function calculateAptosAddressFromPublicKey(publicKeyBytes: Uint8Array): string {
  try {
    // 验证公钥格式：应该是 65 字节 (0x04 + 32字节x + 32字节y)
    if (publicKeyBytes.length !== 65) {
      throw new Error(`公钥长度不正确: ${publicKeyBytes.length}，应该是 65 字节`);
    }
    
    // 验证公钥格式：第一个字节应该是 0x04 (未压缩的 EC 公钥)
    if (publicKeyBytes[0] !== 0x04) {
      throw new Error(`公钥格式不正确: 第一个字节应该是 0x04，实际是 0x${publicKeyBytes[0].toString(16)}`);
    }

    const serializer = new Serializer();
    serializer.serializeBytes(publicKeyBytes);
    const keyBytes = new Uint8Array(
      [2, ...serializer.toUint8Array(), 2]
    )
    // 使用 SHA3-256 哈希公钥
    const hashedPublicKey = sha3_256.create().update(keyBytes).digest();
    
    // 转换为 Aptos 地址格式
    const hexString = "0x" + Buffer.from(hashedPublicKey).toString("hex");
    const address = AccountAddress.fromString(hexString);

    console.log("address", address.toString());
    
    return address.toString();
  } catch (error) {
    console.error('计算 Aptos 地址失败:', error);
    return '计算失败';
  }
}

export function parsePublicKey(response: RegistrationResponseJSON): Uint8Array {

  console.log("response", response);
  const authData = Buffer.from(response.response.authenticatorData!, "base64");
  console.log("authData", authData);
  const parsedAuthenticatorData = parseAuthenticatorData(authData);
  // Convert from COSE
  const publicKey = convertCOSEtoPKCS(parsedAuthenticatorData.credentialPublicKey!);
  return publicKey;
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
    const publickey = parsePublicKey(credential.toJSON());

    console.log("publickey", new Hex(publickey).toString());
    return {
      id: Buffer.from(credential.rawId).toString("base64"),
      type: credential.type || '',
      publicKey: {
        base64: Buffer.from(publickey).toString("base64"),
        hex: Buffer.from(publickey).toString("hex"),
        aptosAddress: calculateAptosAddressFromPublicKey(publickey)
      },
      rawData: publickey
    };
  } catch (error) {
    console.error('获取凭证信息失败:', error);
    return null;
  }
}

/**
 * 在 Aptos Devnet 上执行模拟转账
 */
export async function simulateDevnetTransfer(
  credentialId?: string
) {

  if (!credentialId) {
    alert("请先创建一个 Passkey 凭证");
    return;
  }
  try {

    // 使用 passkey
    // 读取当前公钥计算地址
    

    // 创建账户
  

    // 获取账户地址
    const savedCredential = window.localStorage.getItem("credentialData");
    
      if (!savedCredential) {
        throw new Error("请先创建一个 Passkey 凭证");
      }
      const credentialData = JSON.parse(savedCredential);
      const senderAddress = credentialData.publicKey.aptosAddress;

    // 创建接收地址（这里使用一个测试地址）
    const receiverAddress = "0x1234567890123456789012345678901234567890123456789012345678901234";
    
    // 转账金额（0.001 APT）
    const amount = 1000; // 最小单位
    
    console.log("=== Devnet 转账模拟 ===");
    console.log("发送方地址:", senderAddress);
    console.log("接收方地址:", receiverAddress);
    console.log("转账金额:", amount, "最小单位");
    

    console.log(aptosClient)
    // build raw transaction

    const rawTxn = await aptosClient.transaction.build.simple({
      sender: senderAddress,
      data: {
        function: "0x1::aptos_account::transfer",
        functionArguments: [
          receiverAddress,
          amount,
        ],
        typeArguments: [],
      }
    });
    console.log("rawTxn", rawTxn);
    
    // 计算 challenge

    const message = generateSigningMessageForTransaction(rawTxn);
    console.log("message", message);

    const challenge = sha3_256(message);
    console.log("challenge", challenge);

    // 签名

    const allowedCredentials: PublicKeyCredentialDescriptor[] = [
      {
        type: "public-key",
        id: Buffer.from(credentialId, "base64"),
      },
    ];

    const publicKey: PublicKeyCredentialRequestOptions = {
      challenge: challenge.buffer,                    // 挑战 - 转换为 ArrayBuffer
      allowCredentials: allowedCredentials,  // 允许的凭证
      extensions: {},              // 扩展
    };
  
    let credential = await navigator.credentials.get({
      publicKey,
    });

    console.log("credential", credential);

    if (!credential) {
      throw new Error("获取凭证失败");
    }

    const { clientDataJSON, authenticatorData, signature } = (credential as PublicKeyCredential).response as AuthenticatorAssertionResponse;

    const signatureCompact = p256SignatureFromDER(new Uint8Array(signature));
    console.log("signatureCompact", signatureCompact);


    // AccountAuthenticatorSingleKey

    // 0x04 +  0x02 + AnyPublickey + AnySignature

    // AnyPublickey serialize 为 0x02 + serializeBytes (publickey bytes)

    // AnySignature serialize 为 0x02 + 0x00 + signature bytes + authenticator Data bytes + clientDataJson Bytes
  
    const serializer = new Serializer();
    serializer.serializeU32AsUleb128(2);
    // AssertionSignatureVariant.Secp256r1 == 0 
    serializer.serializeU32AsUleb128(0);
    serializer.serializeBytes(signatureCompact);
    serializer.serializeBytes(Buffer.from(authenticatorData));
    serializer.serializeBytes(Buffer.from(clientDataJSON));

    const serializedSignature = serializer.toUint8Array();

    console.log("serializedSignature", serializedSignature);

    // sumbit transaction

    const raw_bytes = rawTxn.bcsToHex();
    // 拼接

    const ser = new Serializer();
    ser.serializeU32AsUleb128(2);
    ser.serializeU32AsUleb128(65);
    ser.serializeFixedBytes(Buffer.from(credentialData.publicKey.hex, "hex"));

    const serializedPublickey = ser.toUint8Array();
  
    const ser2 = new Serializer();
    ser2.serializeU32AsUleb128(4);
    ser2.serializeU32AsUleb128(2);
    const bytes = ser2.toUint8Array();
    

    const serializedAuthenticator = new Uint8Array([...bytes, ...serializedPublickey, ...serializedSignature]);
    
    const signed_bytes = new Uint8Array([...raw_bytes.toUint8Array().slice(0, -1),
      ...serializedAuthenticator
    ]);
    
    console.log("signed_bytes", Buffer.from(signed_bytes).toString("hex"));


    console.log("raw_bytes", raw_bytes.toString());

    console.log("faTransfer", await (await fetch(
      "https://fullnode.devnet.aptoslabs.com/v1/transactions",
      {
          method: "POST",
          headers: {
              "Content-Type": "application/x.aptos.signed_transaction+bcs",
          },
          body: signed_bytes
      }
  )).json());
  } catch (error) {
    console.error("转账模拟失败:", error);
    alert(`转账模拟失败: ${error instanceof Error ? error.message : String(error)}`);
    throw error;
  }
}
