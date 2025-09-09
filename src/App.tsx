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
import { Hex } from "@wgb5445/ts-sdk";

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
  const [showSignSuccessModal, setShowSignSuccessModal] = useState(false);
  const [signatureData, setSignatureData] = useState<any>(null);
  const [showCreateSuccessModal, setShowCreateSuccessModal] = useState(false);
  const [createSuccessData, setCreateSuccessData] = useState<any>(null);
  const [showErrorModal, setShowErrorModal] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string>('');

  // Create passkey through credential registration ceremony
  const createPasskey = async () => {
    try {

      const credential = await createCredential();
      
      console.log("credential", credential);

      // Get complete credential information
      const credentialInfo = getCredentialInfo(credential as PublicKeyCredential);
      
      if (credentialInfo) {
        console.log("==== Passkey Created Successfully ===");
        console.log("Credential ID:", credentialInfo.id);
        console.log("Public Key (Base64):", credentialInfo.publicKey.base64);
        console.log("Public Key (Hex):", credentialInfo.publicKey.hex);
        console.log("Aptos Address:", credentialInfo.publicKey.aptosAddress);
        console.log("Complete Credential Data:", credentialInfo.rawData);
        
        // Save to local storage
        window.localStorage.setItem("credentialData", JSON.stringify(credentialInfo));
        
        // Show success modal
        setCreateSuccessData(credentialInfo);
        setShowCreateSuccessModal(true);
      } else {
        showError("Failed to create Passkey: Unable to extract public key information");
      }
      
      setCredentialId(credentialInfo?.id || '');
      window.localStorage.setItem("credentialId", credentialInfo?.id || '');
      
    } catch (error: any) {
      console.error("Failed to create Passkey:", error);
      showError(`Failed to create Passkey: ${error.message || error}`);
    }
  };

  // View saved Passkey public key
  const viewPasskeyPublicKey = async () => {
    try {
      const savedCredential = window.localStorage.getItem("credentialData");
      if (savedCredential) {
        const credentialData = JSON.parse(savedCredential);
        console.log("==== Saved Passkey Public Key Information ===");
        console.log("Credential ID:", credentialData.id);
        console.log("Public Key (Base64):", credentialData.publicKey.base64);
        console.log("Public Key (Hex):", credentialData.publicKey.hex);
        console.log("Public Key (Uint8Array):", new Hex(credentialData.publicKey.hex).toUint8Array());
        
        console.log("Aptos Address:", calculateAptosAddressFromPublicKey(Buffer.from(credentialData.publicKey.hex, "hex")));
        
        // Show modal
        setShowPublicKeyModal(true);
        setPublicKeyData(credentialData);
      } else {
        showError("Please create a Passkey credential first");
      }
    } catch (error: any) {
      console.error("Failed to get public key:", error);
      showError("Failed to get public key, please check console");
    }
  };

  /**
   * Use user-registered passkey credential to sign challenge
   */
  const signWithPasskey = async () => {
    if (!credentialId) {
      showError("No registered credential");
      return;
    }

    try {
      const allowedCredentials: PublicKeyCredentialDescriptor[] = [
        {
          type: "public-key",
          id: Buffer.from(credentialId, "base64"),
        },
      ];

      const { rawTransaction } = await generateTestRawTxn();
      const authenticationResponse = await getCredential(allowedCredentials);
      if (!authenticationResponse) {
        showError("WebAuthn assertion failed");
        return;
      }
      const { clientDataJSON, authenticatorData, signature } =
        authenticationResponse.response as AuthenticatorAssertionResponse;
      
      console.log("==== Raw Transaction BCS Bytes ===")
      console.log(rawTransaction.bcsToBytes().toString());
      console.log("==== WebAuthn Response - Authenticator Data ===");
      console.log(new Uint8Array(authenticatorData).toString());
      console.log("==== WebAuthn Response - Client Data JSON ===");
      console.log(new Uint8Array(clientDataJSON).toString());
      console.log("==== WebAuthn Signature, Compact Format ===");
      console.log(p256SignatureFromDER(new Uint8Array(signature)).toString());

      // Prepare signature data for display
      const signatureInfo = {
        rawTransaction: rawTransaction.bcsToBytes().toString(),
        authenticatorData: new Uint8Array(authenticatorData).toString(),
        clientDataJSON: new Uint8Array(clientDataJSON).toString(),
        signature: p256SignatureFromDER(new Uint8Array(signature)).toString(),
        credentialId: credentialId
      };

      // Show success modal
      setSignatureData(signatureInfo);
      setShowSignSuccessModal(true);
    } catch (error: any) {
      console.error("Signing failed:", error);
      showError(`Signing failed: ${error.message || error}`);
    }
  };

  // Function to show error modal
  const showError = (message: string) => {
    setErrorMessage(message);
    setShowErrorModal(true);
  };

  // Function to copy to clipboard
  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      // Success feedback could be added here if needed
    } catch (err) {
      // If navigator.clipboard is not available, use traditional method
      const textArea = document.createElement("textarea");
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand("copy");
      document.body.removeChild(textArea);
      // Success feedback could be added here if needed
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
      <h1>Aptos Passkey WebAuthn Demo</h1>
      <p className="demo-description">
        Experience secure authentication with passkeys on the Aptos blockchain. 
        Create, manage, and use your passkey for seamless Web3 transactions.
      </p>
      <div className="card">
        <div className="feature-grid">
          <div className="feature-card">
            <div className="feature-icon">🔐</div>
            <h3>Create Passkey</h3>
            <p>Generate a secure passkey credential using WebAuthn. Your biometric data stays on your device.</p>
            <button onClick={createPasskey} className="feature-button">
              Create Passkey
            </button>
          </div>

          <div className="feature-card">
            <div className="feature-icon">✍️</div>
            <h3>Sign Transactions</h3>
            <p>Test your passkey by signing challenge data. Experience secure authentication without passwords.</p>
            <button onClick={signWithPasskey} className="feature-button">
              Sign with Passkey
            </button>
          </div>

          <div className="feature-card">
            <div className="feature-icon">👁️</div>
            <h3>View Credentials</h3>
            <p>See your Aptos address and public key information. Copy credentials for external use.</p>
            <button onClick={viewPasskeyPublicKey} className="feature-button">
              View Address & Keys
            </button>
          </div>

          <div className="feature-card">
            <div className="feature-icon">🚀</div>
            <h3>Simulate Transfer</h3>
            <p>Test a complete transaction flow using your passkey. Experience real Web3 interactions.</p>
            <button 
              onClick={()=>setShowTransferModal(true)}
              className="feature-button transfer-button"
            >
              Simulate Transfer
            </button>
          </div>
        </div>

        <div className="info-section">
          <h3>What is this demo?</h3>
          <p>
            This demo showcases <strong>passkey authentication</strong> on the Aptos blockchain using WebAuthn. 
            Passkeys provide a more secure and user-friendly alternative to traditional passwords by using 
            biometric authentication (fingerprint, face recognition) or device PINs.
          </p>
          
          <div className="benefits-list">
            <h4>Key Benefits:</h4>
            <ul>
              <li>🔒 <strong>Enhanced Security:</strong> No passwords to steal or phish</li>
              <li>⚡ <strong>Faster Authentication:</strong> One-touch biometric verification</li>
              <li>🌐 <strong>Cross-Platform:</strong> Works across devices and browsers</li>
              <li>🔗 <strong>Blockchain Ready:</strong> Seamless Web3 transaction signing</li>
            </ul>
          </div>

          <div className="technical-info">
            <p><strong>Relying Party ID:</strong> <code>{window.location.hostname}</code></p>
            <p><strong>Supported Networks:</strong> Devnet, Testnet, Mainnet</p>
            <p><strong>Browser Support:</strong> Chrome 67+, Firefox 60+, Safari 13+, Edge 79+</p>
          </div>
        </div>
      </div>
      <p className="read-the-docs">
        Click on the Vite and React logos to learn more
      </p>

      {/* Public Key Information Modal */}
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
            </div>
            <div className="modal-footer">
              <button 
                onClick={() => setShowPublicKeyModal(false)}
                className="modal-close-button"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Transfer Simulation Modal */}
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

              {/* Transaction Status Display */}
              {transactionStatus && (
                <div className="info-section">
                  <h3>Transaction Status</h3>
                  <div className="status-display">
                    <p className={`status-text ${transactionStatus.includes('successfully') ? 'success' : transactionStatus.includes('failed') || transactionStatus.includes('timeout') ? 'error' : 'info'}`}>
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
                        {transactionStatus.includes('successfully') && (
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
                      
                      // Loop check transaction status
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

      {/* Signature Success Modal */}
      {showSignSuccessModal && signatureData && (
        <div className="modal-overlay" onClick={() => setShowSignSuccessModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>✅ Signature Successful</h2>
              <button 
                className="modal-close" 
                onClick={() => setShowSignSuccessModal(false)}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="success-message">
                <h3>🎉 Passkey Signature Completed Successfully!</h3>
                <p>
                  Your passkey has successfully signed the challenge data. The signature verifies your identity 
                  and can be used for secure authentication or transaction authorization.
                </p>
              </div>

              <div className="info-section">
                <h3>What was signed:</h3>
                <div className="signature-description">
                  <p><strong>Challenge Data:</strong> A randomly generated 32-byte challenge for authentication</p>
                  <p><strong>Credential ID:</strong> {signatureData.credentialId}</p>
                  <p><strong>Signature Type:</strong> ECDSA P-256 (secp256r1) using WebAuthn</p>
                  <p><strong>Authentication Method:</strong> Passkey biometric authentication</p>
                </div>
              </div>

              <div className="info-section">
                <h3>Signature Details</h3>
                <div className="copy-field">
                  <label>Raw Transaction (BCS):</label>
                  <input 
                    type="text" 
                    value={signatureData.rawTransaction} 
                    readOnly 
                    className="copy-input"
                  />
                  <button 
                    onClick={() => copyToClipboard(signatureData.rawTransaction)}
                    className="copy-button"
                  >
                    Copy
                  </button>
                </div>

                <div className="copy-field">
                  <label>Signature (Compact Format):</label>
                  <input 
                    type="text" 
                    value={signatureData.signature} 
                    readOnly 
                    className="copy-input"
                  />
                  <button 
                    onClick={() => copyToClipboard(signatureData.signature)}
                    className="copy-button"
                  >
                    Copy
                  </button>
                </div>

                <div className="copy-field">
                  <label>Authenticator Data:</label>
                  <input 
                    type="text" 
                    value={signatureData.authenticatorData} 
                    readOnly 
                    className="copy-input"
                  />
                  <button 
                    onClick={() => copyToClipboard(signatureData.authenticatorData)}
                    className="copy-button"
                  >
                    Copy
                  </button>
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button 
                onClick={() => setShowSignSuccessModal(false)}
                className="modal-close-button"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Passkey Creation Success Modal */}
      {showCreateSuccessModal && createSuccessData && (
        <div className="modal-overlay" onClick={() => setShowCreateSuccessModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>🎉 Passkey Created Successfully!</h2>
              <button 
                className="modal-close" 
                onClick={() => setShowCreateSuccessModal(false)}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="success-message">
                <h3>✅ Your Passkey is Ready!</h3>
                <p>
                  Your passkey has been successfully created and is ready to use for secure authentication. 
                  The credential has been saved locally and can be used for signing transactions.
                </p>
              </div>

              <div className="info-section">
                <h3>Credential Information</h3>
                <div className="signature-description">
                  <p><strong>Credential ID:</strong> {createSuccessData.id}</p>
                  <p><strong>Type:</strong> {createSuccessData.type}</p>
                  <p><strong>Authentication Method:</strong> Passkey biometric authentication</p>
                  <p><strong>Status:</strong> Active and ready to use</p>
                </div>
              </div>

              <div className="info-section">
                <h3>Address & Public Key</h3>
                <div className="copy-field">
                  <label>Aptos Address:</label>
                  <input 
                    type="text" 
                    value={createSuccessData.publicKey.aptosAddress} 
                    readOnly 
                    className="copy-input"
                  />
                  <button 
                    onClick={() => copyToClipboard(createSuccessData.publicKey.aptosAddress)}
                    className="copy-button"
                  >
                    Copy
                  </button>
                </div>

                <div className="copy-field">
                  <label>Public Key (Hex):</label>
                  <input 
                    type="text" 
                    value={createSuccessData.publicKey.hex} 
                    readOnly 
                    className="copy-input"
                  />
                  <button 
                    onClick={() => copyToClipboard(createSuccessData.publicKey.hex)}
                    className="copy-button"
                  >
                    Copy
                  </button>
                </div>

                <div className="copy-field">
                  <label>Public Key (Base64):</label>
                  <input 
                    type="text" 
                    value={createSuccessData.publicKey.base64} 
                    readOnly 
                    className="copy-input"
                  />
                  <button 
                    onClick={() => copyToClipboard(createSuccessData.publicKey.base64)}
                    className="copy-button"
                  >
                    Copy
                  </button>
                </div>
              </div>

              <div className="info-section">
                <h3>Next Steps</h3>
                <div className="signature-description">
                  <p>• Use "Sign with credential" to test your passkey</p>
                  <p>• Use "View Address and Public Key" to see your credentials anytime</p>
                  <p>• Use "Simulate Transfer" to test transaction signing</p>
                  <p>• Your passkey is securely stored and ready for use</p>
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button 
                onClick={() => setShowCreateSuccessModal(false)}
                className="modal-close-button"
              >
                Got it!
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Error Modal */}
      {showErrorModal && (
        <div className="modal-overlay" onClick={() => setShowErrorModal(false)}>
          <div className="modal-content error-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>⚠️ Error</h2>
              <button 
                className="modal-close" 
                onClick={() => setShowErrorModal(false)}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="error-message">
                <p>{errorMessage}</p>
              </div>
            </div>
            <div className="modal-footer">
              <button 
                onClick={() => setShowErrorModal(false)}
                className="modal-close-button"
              >
                OK
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default App;
