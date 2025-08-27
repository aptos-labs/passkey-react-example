import { useState } from "react";
import reactLogo from "./assets/react.svg";
import viteLogo from "/vite.svg";
import { Buffer } from "buffer";
import "./App.css";
import {
  createCredential,
  getCredential,
  generateTestRawTxn,
  getCredentialInfo,
  simulateTransfer,
  calculateAptosAddressFromPublicKey,
  p256SignatureFromDER,
  NETWORKS,
  switchNetwork,
  checkTransactionStatusWithTimeout,
} from "./helper/webauthn";
import { Hex } from "@aptos-labs/ts-sdk";

function App() {
  const [credentialId, setCredentialId] = useState<string | null>(
    window.localStorage.getItem("credentialId")
  );
  const [showPublicKeyModal, setShowPublicKeyModal] = useState(false);
  const [publicKeyData, setPublicKeyData] = useState<any>(null);
  const [showTransferModal, setShowTransferModal] = useState(false);
  const [transferData, setTransferData] = useState({
    senderAddress: '',
    receiverAddress: '',
    amount: '0.001'
  });
  const [selectedNetwork, setSelectedNetwork] = useState('DEVNET');
  const [isTransferring, setIsTransferring] = useState(false);
  const [transactionHash, setTransactionHash] = useState<string | null>(null);
  const [transactionStatus, setTransactionStatus] = useState<string>('');

  // 通过凭证注册仪式创建 passkey
  const createPasskey = async () => {
    try {
      const credential = (await createCredential()) as PublicKeyCredential;
      
      console.log("credential", credential);

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
        console.log("公钥 (Uint8Array):", new Hex(credentialData.publicKey.hex).toUint8Array());
        
        console.log("Aptos 地址:", calculateAptosAddressFromPublicKey(Buffer.from(credentialData.publicKey.hex, "hex")));
        
        // 显示弹窗
        setShowPublicKeyModal(true);
        setPublicKeyData(credentialData);
      } else {
        alert("请先创建一个 Passkey 凭证");
      }
    } catch (error: any) {
      console.error("获取公钥失败:", error);
      alert("获取公钥失败，请查看控制台");
    }
  };

  /**
   * 使用用户注册的 passkey 凭证来签名挑战
   */
  const signWithPasskey = async () => {
    if (!credentialId) {
      alert("没有注册的凭证");
      return;
    }

    const allowedCredentials: PublicKeyCredentialDescriptor[] = [
      {
        type: "public-key",
        id: Buffer.from(credentialId, "base64url"),
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
    console.log(authenticationResponse.toJSON());
  };

  // 复制到剪贴板的函数
  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      // alert("已复制到剪贴板！");
    } catch (err) {
      // 如果 navigator.clipboard 不可用，使用传统方法
      const textArea = document.createElement("textarea");
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand("copy");
      document.body.removeChild(textArea);
      // alert("已复制到剪贴板！");
    }
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
          {/* <button
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
          </button> */}
          <button onClick={createPasskey}>Create credential</button>
          <button onClick={signWithPasskey}>Sign with credential</button>
          <button onClick={viewPasskeyPublicKey}>View Public Key</button>
          <button 
            onClick={()=>setShowTransferModal(true)}
            style={{ backgroundColor: '#007AFF', color: 'white', border: 'none' }}
          >
            🚀 Simulate Transfer
          </button>
        </div>
        <p>
          Edit <code>src/App.tsx</code> and save to test Hot Module Replacement (HMR)
        </p>
        <p>Relying Party ID (rpId): {window.location.hostname}</p>
      </div>
      <p className="read-the-docs">
        Click on the Vite and React logos to learn more
      </p>

      {/* 公钥信息弹窗 */}
      {showPublicKeyModal && publicKeyData && (
        <div className="modal-overlay" onClick={() => setShowPublicKeyModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Passkey Public Key Information</h2>
              <button 
                className="modal-close" 
                onClick={() => setShowPublicKeyModal(false)}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="info-section">
                <h3>Credential ID</h3>
                <div className="copy-field">
                  <input 
                    type="text" 
                    value={publicKeyData.id} 
                    readOnly 
                    className="copy-input"
                  />
                  <button 
                    onClick={() => copyToClipboard(publicKeyData.id)}
                    className="copy-button"
                  >
                    Copy
                  </button>
                </div>
              </div>

              <div className="info-section">
                <h3>Public Key (Hex)</h3>
                <div className="copy-field">
                  <input 
                    type="text" 
                    value={publicKeyData.publicKey.hex} 
                    readOnly 
                    className="copy-input"
                  />
                  <button 
                    onClick={() => copyToClipboard(publicKeyData.publicKey.hex)}
                    className="copy-button"
                  >
                    Copy
                  </button>
                </div>
              </div>

              <div className="info-section">
                <h3>Public Key (Base64)</h3>
                <div className="copy-field">
                  <input 
                    type="text" 
                    value={publicKeyData.publicKey.base64} 
                    readOnly 
                    className="copy-input"
                  />
                  <button 
                    onClick={() => copyToClipboard(publicKeyData.publicKey.base64)}
                    className="copy-button"
                  >
                    Copy
                  </button>
                </div>
              </div>

              <div className="info-section">
                <h3>Aptos Address</h3>
                <div className="copy-field">
                  <input 
                    type="text" 
                    value={publicKeyData.publicKey.aptosAddress} 
                    readOnly 
                    className="copy-input"
                  />
                  <button 
                    onClick={() => copyToClipboard(publicKeyData.publicKey.aptosAddress)}
                    className="copy-button"
                  >
                    Copy
                  </button>
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button 
                onClick={() => setShowPublicKeyModal(false)}
                className="modal-close-button"
              >
                关闭
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 转账模拟弹窗 */}
      {showTransferModal && (
        <div className="modal-overlay" onClick={() => setShowTransferModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Transfer Simulation</h2>
              <button 
                className="modal-close" 
                onClick={() => setShowTransferModal(false)}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="info-section">
                <h3>Select Network</h3>
                <select 
                  value={selectedNetwork} 
                  onChange={(e) => {
                    setSelectedNetwork(e.target.value);
                    switchNetwork(e.target.value as keyof typeof NETWORKS);
                  }}
                  className="network-select"
                >
                  {Object.entries(NETWORKS).map(([key, network]) => (
                    <option key={key} value={key}>
                      {network.name}
                    </option>
                  ))}
                </select>
                <p className="network-info">
                  Current Network: {NETWORKS[selectedNetwork as keyof typeof NETWORKS]?.name} 
                  ({NETWORKS[selectedNetwork as keyof typeof NETWORKS]?.fullnodeUrl})
                </p>
              </div>

              <div className="info-section">
                <h3>Receiver Address</h3>
                <div className="input-field">
                  <input 
                    type="text" 
                    value={transferData.receiverAddress} 
                    onChange={(e) => setTransferData(prev => ({...prev, receiverAddress: e.target.value}))}
                    placeholder="0x1234567890123456789012345678901234567890123456789012345678901234"
                    className="transfer-input"
                  />
                </div>
              </div>

              <div className="info-section">
                <h3>Transfer Amount (APT)</h3>
                <div className="input-field">
                  <input 
                    type="text" 
                    value={transferData.amount} 
                    onChange={(e) => setTransferData(prev => ({...prev, amount: e.target.value}))}
                    placeholder="0.001"
                    className="transfer-input"
                  />
                  <p className="amount-info">
                    Smallest Unit: {Math.floor(parseFloat(transferData.amount || '0') * 100000000)}
                  </p>
                </div>
              </div>

              {/* 交易状态显示 */}
              {transactionStatus && (
                <div className="info-section">
                  <h3>Transaction Status</h3>
                  <div className="status-display">
                    <p className={`status-text ${transactionStatus.includes('successfully') || transactionStatus.includes('成功') ? 'success' : transactionStatus.includes('failed') || transactionStatus.includes('失败') || transactionStatus.includes('timeout') || transactionStatus.includes('超时') ? 'error' : 'info'}`}>
                      {transactionStatus}
                    </p>
                    {transactionHash && (
                      <div className="hash-display">
                        <h4>Transaction Hash:</h4>
                        <div className="copy-field">
                          <input 
                            type="text" 
                            value={transactionHash} 
                            readOnly 
                            className="copy-input"
                          />
                          <button 
                            onClick={() => copyToClipboard(transactionHash)}
                            className="copy-button"
                          >
                            Copy
                          </button>
                        </div>
                        {(transactionStatus.includes('successfully') || transactionStatus.includes('成功')) && (
                          <div className="explorer-link">
                            <button 
                              onClick={() => {
                                const networkKey = selectedNetwork.toLowerCase();
                                const explorerUrl = `https://explorer.aptoslabs.com/txn/${transactionHash}?network=${networkKey}`;
                                window.open(explorerUrl, '_blank');
                              }}
                              className="explorer-button"
                            >
                              🔍 View in Aptos Explorer
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button 
                onClick={() => setShowTransferModal(false)}
                className="modal-close-button"
                disabled={isTransferring}
              >
                Cancel
              </button>
              <button 
                onClick={async () => {
                  try {
                    setIsTransferring(true);
                    setTransactionHash(null);
                    setTransactionStatus('Building transaction...');
                    
                    const amountInSmallestUnit = Math.floor(parseFloat(transferData.amount) * 100000000);
                    const hash = await simulateTransfer(
                      credentialId || undefined,
                      undefined,
                      transferData.receiverAddress || undefined,
                      amountInSmallestUnit
                    );
                    
                    if (hash) {
                      setTransactionHash(hash);
                      setTransactionStatus('Transaction submitted, checking status...');
                      
                      // 循环检查交易状态
                      const status = await checkTransactionStatusWithTimeout(hash);
                      setTransactionStatus(status);
                    }
                  } catch (error: any) {
                    setTransactionStatus(`Transfer failed: ${error.message || error}`);
                  } finally {
                    setIsTransferring(false);
                  }
                }}
                className="transfer-button"
                disabled={!transferData.amount || parseFloat(transferData.amount) <= 0 || isTransferring}
              >
                {isTransferring ? (
                  <>
                    <span className="spinner"></span>
                    Processing...
                  </>
                ) : (
                  'Start Transfer Simulation'
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default App;
