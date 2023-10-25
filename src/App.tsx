import { useState } from "react";
import reactLogo from "./assets/react.svg";
import viteLogo from "/vite.svg";
import "./App.css";
import {
  Encoding,
  arrayBufferToBase64Url,
  base64ToArray,
  createCredential,
  createSPCPaymentRequest,
  getCredential,
  isSpcAvailable,
  objectToDictionary,
  sha3_256_challenge_bytes,
  defaultPublicKey,
  defaultAuthenticatorSelection,
} from "./helper/webauthn";
import { encodeSignature } from "./helper/encode";

function App() {
  const [credentialId, setCredentialId] = useState<string | null>(
    window.localStorage.getItem("credentialId")
  );

  // Create the passkey via credential registration ceremony
  const createPasskey = async () => {
    const credential = (await createCredential()) as PublicKeyCredential;
    const credentialObject = objectToDictionary(credential, Encoding.base64Url);
    console.log("==== PublicKeyCredential -- Registration Response ===");
    console.log(credentialObject);
    setCredentialId(credentialObject.rawId);
    window.localStorage.setItem("credentialId", credentialObject.rawId);
  };

  // Create the passkey via credential registration ceremony with TokenBinding
  // @see https://www.w3.org/TR/webauthn-2/#dictdef-tokenbinding
  const createPasskeyWithTokenBinding = async () => {
    const credential = (await createCredential({ 
      ...defaultPublicKey, 
      authenticatorSelection: {
        ...defaultAuthenticatorSelection,
        tokenBinding: "required",
      } 
    })) as PublicKeyCredential;
    const credentialObject = objectToDictionary(credential, Encoding.base64Url);
    console.log("==== PublicKeyCredential with Token Binding -- Registration Response ===");
    console.log(credentialObject);
    setCredentialId(credentialObject.rawId);
    window.localStorage.setItem("credentialId", credentialObject.rawId);
  };

  /**
   * Creates a secure payment confirmation (SPC)
   * Challenge input is listed at the top spc.ts
   */
  const createSPC = async () => {
    if (!credentialId) {
      alert("No registered credential");
      return;
    }

    const realCredentialId: Uint8Array = base64ToArray(credentialId);

    const paymentRequest = createSPCPaymentRequest({
      challenge: sha3_256_challenge_bytes,
      rpId: window.location.hostname,
      credentialIds: [realCredentialId],
      instrument: {
        displayName: "Petra test",
        icon: "https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico",
      },
      payeeOrigin: `https://localhost:4000`,
      extensions: {},
    });
    const paymentResponse = await paymentRequest.show();
    await paymentResponse.complete("success");

    const { clientDataJSON, authenticatorData, signature } = paymentResponse
      .details.response as AuthenticatorAssertionResponse;
    const encodedSignature = encodeSignature({
      signature,
      authenticatorData,
      clientDataJSON,
    });

    console.log("==== Raw SPC Payment Response ===");
    console.log(paymentResponse);
    console.log("==== Raw SPC Payment Response - authenticatorData ===");
    console.log(new Uint8Array(paymentResponse.details.response.authenticatorData).toString());
    console.log("==== Raw SPC Payment Response - clientDataJSON ===");
    console.log(new Uint8Array(paymentResponse.details.response.clientDataJSON).toString());
    console.log("==== BCS Encoded WebAuthn Signature ===");
    console.log(encodedSignature);
    console.log("==== BCS Encoded WebAuthn Signature as Base64Url ===");
    console.log(arrayBufferToBase64Url(encodedSignature));
    console.log("==== PublicKeyCredential -- SPC Authentication Response ===");
    console.log(objectToDictionary(paymentResponse, Encoding.base64Url));
  };

  /**
   * Use the passkey credential registered to the user to sign a challenge
   * Challenge input is listed at the top spc.ts
   */
  const signWithPasskey = async () => {
    if (!credentialId) {
      alert("No registered credential");
      return;
    }

    const allowedCredentials: PublicKeyCredentialDescriptor[] = [
      {
        type: "public-key",
        id: base64ToArray(credentialId),
      },
    ];

    const authenticationResponse = await getCredential(allowedCredentials);
    if (!authenticationResponse) {
      alert("Failed webauthn.get assertion");
      return;
    }
    const { clientDataJSON, authenticatorData, signature } =
      authenticationResponse.response as AuthenticatorAssertionResponse;
    const encodedSignature = encodeSignature({
      signature,
      authenticatorData,
      clientDataJSON,
    });
    console.log("==== BCS Encoded WebAuthn Signature ===");
    console.log(encodedSignature);
    console.log("==== Raw SPC Payment Response - authenticatorData ===");
    console.log(new Uint8Array(authenticatorData).toString());
    console.log("==== Raw SPC Payment Response - clientDataJSON ===");
    console.log(new Uint8Array(clientDataJSON).toString());
    console.log("==== BCS Encoded WebAuthn Signature as Base64Url ===");
    console.log(arrayBufferToBase64Url(encodedSignature));
    console.log("==== PublicKeyCredential -- Authentication Response ===");
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
              alert(await isSpcAvailable());
            }}
          >
            isSpcAvailable?
          </button>
          <button onClick={createPasskey}>Create credential</button>
          <button onClick={createPasskeyWithTokenBinding}>Create credential + tokenBinding</button>
          <button onClick={signWithPasskey}>Sign with credential</button>
          <button onClick={createSPC}>Create SPC</button>
        </div>
        <p>
          Edit <code>src/App.tsx</code> and save to test HMR
        </p>
        <p>rpId: {window.location.hostname}</p>
      </div>
      <p className="read-the-docs">
        Click on the Vite and React logos to learn more
      </p>
    </>
  );
}

export default App;
