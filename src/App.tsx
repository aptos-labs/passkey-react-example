import { useState } from "react";
import reactLogo from "./assets/react.svg";
import viteLogo from "/vite.svg";
import "./App.css";
import {
  createCredential,
  createSPCCredential,
  createSPCPaymentRequest,
  getCredential,
  generateDefaultPublicKey,
  generateTestRawTxn,
  isSpcAvailable,
  objectToDictionary,
  Encoding,
  p256SignatureFromDER,
  base64UrlToArray,
  getCredentialInfo,
  defaultAuthenticatorSelection,
} from "./helper/webauthn";

function App() {
  const [credentialId, setCredentialId] = useState<string | null>(
    window.localStorage.getItem("credentialId")
  );
  const [spcCredentialId, setSpcCredentialId] = useState<string | null>(
    window.localStorage.getItem("spcCredentialId")
  )

  // 通过凭证注册仪式创建 passkey
  const createPasskey = async () => {
    try {
      const credential = (await createCredential()) as PublicKeyCredential;
      
      // 获取完整的凭证信息
      const credentialInfo = getCredentialInfo(credential);
      
      if (credentialInfo) {
        console.log("==== Passkey 创建成功 ===");
        console.log("凭证 ID:", credentialInfo.id);
        console.log("公钥 (Base64):", credentialInfo.publicKey.base64);
        console.log("公钥 (Hex):", credentialInfo.publicKey.hex);
        console.log("Aptos 地址:", credentialInfo.publicKey.aptosAddress);
        console.log("完整凭证数据:", credentialInfo.rawData);
        
        // 保存到本地存储
        window.localStorage.setItem("credentialData", JSON.stringify(credentialInfo));
        
        // 在页面上显示
        alert(`Passkey 创建成功！\n\n` +
              `凭证 ID: ${credentialInfo.id}\n\n` +
              `公钥 (Hex): ${credentialInfo.publicKey.hex}\n\n` +
              `Aptos 地址: ${credentialInfo.publicKey.aptosAddress}\n\n` +
              `详细信息已输出到控制台`);
      } else {
        alert("创建 Passkey 失败：无法提取公钥信息");
      }
      
      setCredentialId(credentialInfo?.id || '');
      window.localStorage.setItem("credentialId", credentialInfo?.id || '');
      
    } catch (error: any) {
      console.error("创建 Passkey 失败:", error);
      alert(`创建 Passkey 失败: ${error.message || error}`);
    }
  };

  // 查看已保存的 Passkey 公钥
  const viewPasskeyPublicKey = async () => {
    try {
      const savedCredential = window.localStorage.getItem("credentialData");
      if (savedCredential) {
        const credentialData = JSON.parse(savedCredential);
        console.log("==== 已保存的 Passkey 公钥信息 ===");
        console.log("凭证 ID:", credentialData.id);
        console.log("公钥 (Base64):", credentialData.publicKey.base64);
        console.log("公钥 (Hex):", credentialData.publicKey.hex);
        console.log("Aptos 地址:", credentialData.publicKey.aptosAddress);
        
        alert(`Passkey 公钥信息：\n\n` +
              `凭证 ID: ${credentialData.id}\n\n` +
              `公钥 (Hex): ${credentialData.publicKey.hex}\n\n` +
              `Aptos 地址: ${credentialData.publicKey.aptosAddress}\n\n` +
              `详细信息已输出到控制台`);
      } else {
        alert("请先创建一个 Passkey 凭证");
      }
    } catch (error: any) {
      console.error("获取公钥失败:", error);
      alert("获取公钥失败，请查看控制台");
    }
  };

  // 通过凭证注册仪式创建 SPC passkey
  const createSPCPasskey = async () => {
    try {
      // 检查 SPC 是否可用
      if (!await isSpcAvailable()) {
        alert("SPC is not available in this browser. Please use Chrome 92+ or Edge 92+");
        return;
      }
      
      const credential = (await createSPCCredential()) as PublicKeyCredential;
      const credentialObject = objectToDictionary(credential, Encoding.base64Url);
      console.log("==== SPC PublicKeyCredential -- Registration Response ===");
      console.log(credentialObject);
      setSpcCredentialId(credentialObject.rawId);
      window.localStorage.setItem("spcCredentialId", credentialObject.rawId);
    } catch (error: any) {
      console.error("Failed to create SPC credential:", error);
      alert(`Failed to create SPC credential: ${error.message || error}`);
    }
  };

  // 通过凭证注册仪式创建带令牌绑定的 passkey
  // @see https://www.w3.org/TR/webauthn-2/#dictdef-tokenbinding
  const createPasskeyWithTokenBinding = async () => {
    const defaultPublicKey = await generateDefaultPublicKey();
    const credential = (await createCredential({ 
      ...defaultPublicKey, 
      authenticatorSelection: {
        ...defaultAuthenticatorSelection,
        tokenBinding: "required",
      } 
    })) as PublicKeyCredential;
    const credentialObject = objectToDictionary(credential, Encoding.base64Url);
    console.log("==== 带令牌绑定的公钥凭证 -- 注册响应 ===");
    console.log(credentialObject);
    setCredentialId(credentialObject.rawId);
    window.localStorage.setItem("credentialId", credentialObject.rawId);
  };

  /**
   * 创建安全支付确认 (SPC)
   * 挑战输入在 spc.ts 文件顶部列出
   */
  const signWithSPCPasskey = async () => {
    try {
      if (!spcCredentialId) {
        alert("没有注册的 SPC 凭证");
        return;
      }

      // 检查 SPC 是否可用
      if (!await isSpcAvailable()) {
        alert("SPC 在此浏览器中不可用。请使用 Chrome 92+ 或 Edge 92+");
        return;
      }

      const realCredentialId: Uint8Array = base64UrlToArray(spcCredentialId);
      const { challenge, rawTransaction } = await generateTestRawTxn();

      const paymentRequest = createSPCPaymentRequest({
        challenge: new Uint8Array(challenge),
        rpId: window.location.hostname,
        credentialIds: [realCredentialId],
        instrument: {
          displayName: "Petra test",
          icon: "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEyIDJMMTMuMDkgOC4yNkwxOSA5TDEzLjUgMTQuNzRMMTUgMjFMMTIgMTcuNzdMOSAyMUwxMC41IDE0Ljc0TDUgOUwxMC45MSA4LjI2TDEyIDJaIiBmaWxsPSIjMDA3QUZGIi8+Cjwvc3ZnPgo=",
        },
        payeeOrigin: `https://localhost:4000`,
        extensions: {},
      });
      
      const paymentResponse = await paymentRequest.show();
      await paymentResponse.complete("success");

      const { clientDataJSON, authenticatorData, signature } = paymentResponse
        .details.response as AuthenticatorAssertionResponse;

      console.log("==== 原始交易 BCS 字节 ===")
      console.log(rawTransaction.bcsToBytes().toString());
      console.log("==== 原始 SPC 支付响应 ===");
      console.log(paymentResponse);
      console.log("==== 原始 SPC 支付响应 - 认证器数据 ===");
      console.log(new Uint8Array(authenticatorData).toString());
      console.log("==== 原始 SPC 支付响应 - 客户端数据 JSON ===");
      console.log(new Uint8Array(clientDataJSON).toString());
      console.log("==== WebAuthn 签名，紧凑格式 ===");
      console.log(p256SignatureFromDER(new Uint8Array(signature)).toString());
      console.log("==== 公钥凭证 -- SPC 认证响应 ===");
      console.log(objectToDictionary(paymentResponse, Encoding.base64Url));
    } catch (error: any) {
      console.error("SPC 支付失败:", error);
      if (error.name === "NotSupportedError") {
        alert("SPC 支付方法不支持。请检查浏览器兼容性并重试。");
      } else {
        alert(`SPC 支付失败: ${error.message || error}`);
      }
    }
  };

  /**
   * 使用用户注册的 passkey 凭证来签名挑战
   * 挑战输入在 spc.ts 文件顶部列出
   */
  const signWithPasskey = async () => {
    if (!credentialId) {
      alert("没有注册的凭证");
      return;
    }

    const allowedCredentials: PublicKeyCredentialDescriptor[] = [
      {
        type: "public-key",
        id: base64UrlToArray(credentialId),
      },
    ];

    const { rawTransaction } = await generateTestRawTxn();
    const authenticationResponse = await getCredential(allowedCredentials);
    if (!authenticationResponse) {
      alert("WebAuthn 获取断言失败");
      return;
    }
    const { clientDataJSON, authenticatorData, signature } =
      authenticationResponse.response as AuthenticatorAssertionResponse;
    console.log("==== 原始交易 BCS 字节 ===")
    console.log(rawTransaction.bcsToBytes().toString());
    console.log("==== WebAuthn 响应 - 认证器数据 ===");
    console.log(new Uint8Array(authenticatorData).toString());
    console.log("==== WebAuthn 响应 - 客户端数据 JSON ===");
    console.log(new Uint8Array(clientDataJSON).toString());
    console.log("==== WebAuthn 签名，紧凑格式 ===");
    console.log(p256SignatureFromDER(new Uint8Array(signature)).toString());
    console.log("==== 公钥凭证 -- 认证响应 ===");
    console.log(objectToDictionary(authenticationResponse, Encoding.base64Url));
  };

  return (
    <>
      <div>
        <a href="https://vitejs.dev" target="_blank">
          <img src={viteLogo} className="logo" alt="Vite logo" />
        </a>
        <a href="https://react.dev" target="_blank">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </div>
      <h1>WebAuthn Demo</h1>
      <div className="card">
        <div className="comfy-row">
          <button
            onClick={async () => {
              const available = await isSpcAvailable();
              if (available) {
                alert("SPC is available in this browser!");
              } else {
                alert("SPC is NOT available. Please use Chrome 92+ or Edge 92+ for SPC functionality.");
              }
            }}
          >
            Check SPC Support
          </button>
          <button onClick={createPasskey}>Create credential</button>
          <button onClick={createSPCPasskey}>Create SPC Credential</button>
          <button onClick={createPasskeyWithTokenBinding}>Create credential + tokenBinding</button>
          <button onClick={signWithPasskey}>Sign with credential</button>
          <button onClick={signWithSPCPasskey}>Sign with SPC credential</button>
          <button onClick={viewPasskeyPublicKey}>查看公钥信息</button>
        </div>
        <p>
          编辑 <code>src/App.tsx</code> 并保存以测试热模块替换 (HMR)
        </p>
        <p>依赖方 ID (rpId): {window.location.hostname}</p>
      </div>
              <p className="read-the-docs">
          点击 Vite 和 React 徽标了解更多信息
        </p>
    </>
  );
}

export default App;
