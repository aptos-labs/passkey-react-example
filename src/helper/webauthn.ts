/* eslint-disable @typescript-eslint/no-explicit-any */
/** Some code sourced from https://rsolomakhin.github.io/pr/spc/ */

import { sha3_256 } from "@noble/hashes/sha3";
import { p256 } from '@noble/curves/nist.js';
import { Buffer } from "buffer";
import {
  AptosConfig,
  Aptos,
  Network,
  Hex,
  generateSigningMessageForTransaction,
  TransactionAuthenticatorSingleSender,
  AccountAuthenticatorSingleKey,
  AnyPublicKey,
  AnySignature,
  WebAuthnSignature,
} from "@wgb5445/ts-sdk";
import { parseAuthenticatorData, convertCOSEtoPKCS } from "@simplewebauthn/server/helpers";
import { Secp256r1PublicKey } from "@wgb5445/ts-sdk";

// Network configuration type
interface NetworkConfig {
  name: string;
  network: Network;
  fullnodeUrl: string;
  faucetUrl: string | null;
  explorerUrl: string;
}
// Network configuration
export const NETWORKS: Record<string, NetworkConfig> = {
  DEVNET: {
    name: "Devnet",
    network: Network.DEVNET,
    fullnodeUrl: "https://fullnode.devnet.aptoslabs.com",
    faucetUrl: "https://faucet.devnet.aptoslabs.com",
    explorerUrl: "https://explorer.aptoslabs.com/account",
  },
  TESTNET: {
    name: "Testnet", 
    network: Network.TESTNET,
    fullnodeUrl: "https://fullnode.testnet.aptoslabs.com",
    faucetUrl: "https://faucet.testnet.aptoslabs.com",
    explorerUrl: "https://explorer.aptoslabs.com/account",
  },
  MAINNET: {
    name: "Mainnet",
    network: Network.MAINNET,
    fullnodeUrl: "https://fullnode.mainnet.aptoslabs.com",
    faucetUrl: null, // Mainnet has no faucet
    explorerUrl: "https://explorer.aptoslabs.com/account",
  }
};

// Default to Devnet
export let currentNetwork = NETWORKS.DEVNET;
export let aptosClient = new Aptos(new AptosConfig({ network: currentNetwork.network }));

// Function to switch networks
export function switchNetwork(networkKey: keyof typeof NETWORKS) {
  currentNetwork = NETWORKS[networkKey];
  aptosClient = new Aptos(new AptosConfig({ network: currentNetwork.network }));
  console.log(`Switched to ${currentNetwork.name} network`);
  return currentNetwork;
}

export const generateTestRawTxn = async () => {
  const privateKey = new Uint8Array(32);
  crypto.getRandomValues(privateKey);
  
  // Create a simple test challenge
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  
  // Create a mock transaction object
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
    // Check if PaymentRequest API is available
    if (!window.PaymentRequest) {
      return false;
    }
    
    // Check if browser supports SPC - detect by trying to create SPC request
    const testData = {
      challenge: new Uint8Array([1, 2, 3, 4]),  // Test challenge
      rpId: "localhost",                          // Relying Party ID
      credentialIds: [new Uint8Array([1, 2, 3, 4])],  // Test credential ID
      instrument: {
        displayName: "Test",                      // Test display name
        icon: "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEyIDJMMTMuMDkgOC4yNkwxOSA5TDEzLjUgMTQuNzRMMTUgMjFMMTIgMTcuNzdMOSAyMUwxMC41IDE0Ljc0TDUgOUwxMC45MSA4LjI2TDEyIDJaIiBmaWxsPSIjMDA3QUZGIi8+Cjwvc3ZnPgo=",  // Test icon
      },
      payeeOrigin: "https://localhost",           // Payee origin
      extensions: {},                             // Extensions
    };
    
    const supportedInstruments = [
      { supportedMethods: "secure-payment-confirmation", data: testData },  // Supported payment methods
    ];
    
    const details = {
      total: {
        label: "Total",                           // Total label
        amount: { currency: "USD", value: "1.00" },  // Amount
      },
    };
    
    // Try to create PaymentRequest object to detect SPC support
    new PaymentRequest(supportedInstruments, details);
    return true;
  } catch (error) {
    console.warn("SPC availability check failed:", error);
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
  id: window.location.hostname,  // Relying Party ID
  name: window.location.origin,  // Relying Party name
};

export const defaultPubKeyCredParams: PublicKeyCredentialParameters[] = [
  {
    type: "public-key",
    alg: -7, // ECDSA, not supported on Windows
  },
];

export const defaultUser = {
  // Set a comprehensible username in case WebAuthn UX displays it
  // (e.g., Passkeys UX on Chrome MacOS 108+). This is for display only,
  // and has no impact on SPC functionality. (e.g., it won't show in SPC transaction dialog.)
  name: "Aptos",
  displayName: "",
  // TODO check this later
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  id: Uint8Array.from(String(Math.random() * 99999999)),
};

export const defaultResidentKey: ResidentKeyRequirement = spcSupportsPreferred()
  ? "preferred"   // Preferred
  : "required";   // Required

export const defaultAuthenticatorSelection: SPCPublicKeyCredentialCreationOptions["authenticatorSelection"] =
  {
    userVerification: "required",      // User verification required
    residentKey: defaultResidentKey,   // Resident key
    authenticatorAttachment: "platform", // Platform authenticator
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
 * Create a demo WebAuthn credential, optionally setting 'payment' extension
 * The created credential will always have the name 'Andrew ···· 1234',
 * matching the demo payment instrument used in authentication
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
 * This is the basic implementation of the getCredential method
 */
export async function getCredential(
  allowCredentials: PublicKeyCredentialDescriptor[]
) {
  const { challenge } = await generateTestRawTxn();

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: challenge as ArrayBuffer,                    // Challenge
    allowCredentials: allowCredentials,  // Allowed credentials
    extensions: {},              // Extensions
  };

  return (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential;
}

/**
 * Returns whether SPC supports residentKey 'preferred' (not just 'required')
 * Unfortunately, there's no way to detect this feature, so we must do version checking
 *
 * @return {boolean} true if SPC supports 'preferred' for residentKey parameter,
 *     false otherwise
 */
export function spcSupportsPreferred() {
  // This is true not only for Chrome but also for Edge, etc., but that's fine
  const match = navigator.userAgent.match(/Chrom(e|ium)\/([0-9]+)\./);
  if (!match) return false;

  const version = parseInt(match[2], 10);
  // https://crrev.com/130fada41 landed in 106.0.5228.0, but for simplicity,
  // we assume any 106 version will work
  return version >= 106;
}

/**
 * @see https://www.w3.org/TR/secure-payment-confirmation/#dictdef-paymentcredentialinstrument
 */
export interface PaymentCredentialInstrument {
  // Required USVString display name
  displayName: string;
  // Required USVString icon
  icon: string;
  // Boolean iconMustBeShown = true
  iconMustBeShown?: boolean;
}

/**
 * @see https://www.w3.org/TR/secure-payment-confirmation/#sctn-securepaymentconfirmationrequest-dictionary
 */
export interface SecurePaymentConfirmationRequest {
  challenge: Uint8Array;
  // Required USVString relying party ID
  rpId: string;
  // Required sequence<BufferSource> credential ID sequence
  credentialIds: Uint8Array[];
  // Required PaymentCredentialInstrument payment credential instrument
  instrument: PaymentCredentialInstrument;
  // Unsigned long timeout
  timeout?: number;
  // USVString payee name
  payeeName?: string;
  // USVString payee origin
  payeeOrigin?: string;
  // AuthenticationExtensionsClientInputs authentication extension client inputs
  extensions: Record<string, unknown>;
  // sequence<USVString> locale sequence
  locale?: string[];
  // Boolean show opt-out option
  showOptOut?: boolean;
}

/**
 * Create PaymentRequest object for SPC
 *
 * @param {SecurePaymentConfirmationRequest} spcData - Input SPC data. credentialIds field
 *     *must* be set. Any other SecurePaymentConfirmationRequest fields not set in this object
 *     will be initialized to default values.
 * @return {PaymentRequest} Payment request object
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
    spcData.challenge = new TextEncoder().encode("network_data");  // Network data
  if (spcData.rpId === undefined) spcData.rpId = window.location.hostname;  // Relying party ID
  if (spcData.instrument === undefined)
    spcData.instrument = { displayName: "Andrew ···· 1234", icon: "" };  // Default payment instrument
  if (spcData.instrument.icon === undefined)
    spcData.instrument.icon =
      "https://rsolomakhin.github.io/pr/spc/troy-alt-logo.png";  // Default icon
  if (spcData.timeout === undefined) spcData.timeout = 60000;  // Default timeout
  // We only set default payeeOrigin when *both* payeeName and payeeOrigin are not set,
  // because the spec intentionally allows either or both to be null
  if (!("payeeName" in spcData) && !("payeeOrigin" in spcData))
    spcData.payeeOrigin = window.location.origin;  // Default payee origin

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
 * Calculate address from public key using Aptos SDK
 */
export function calculateAptosAddressFromPublicKey(publicKeyBytes: Uint8Array): string {
  try {
    // Validate public key format: should be 65 bytes (0x04 + 32 bytes x + 32 bytes y)
    if (publicKeyBytes.length !== 65) {
      throw new Error(`Incorrect public key length: ${publicKeyBytes.length}, should be 65 bytes`);
    }
    
    // Validate public key format: first byte should be 0x04 (uncompressed EC public key)
    if (publicKeyBytes[0] !== 0x04) {
      throw new Error(`Incorrect public key format: first byte should be 0x04, actual is 0x${publicKeyBytes[0].toString(16)}`);
    }

    let publicKey = new Secp256r1PublicKey(publicKeyBytes);
    let authKey = publicKey.authKey();
     
    return authKey.derivedAddress().toString();
  } catch (error) {
    console.error('Failed to calculate Aptos address:', error);
    return 'Calculation failed';
  }
}

export function parsePublicKey(response: PublicKeyCredential): Uint8Array {
  console.log("response", response);
  const authData = Buffer.from((new Uint8Array((response.response as AuthenticatorAttestationResponse).getAuthenticatorData())));
  console.log("authData", authData);
  const parsedAuthenticatorData = parseAuthenticatorData(authData);
  // Convert from COSE
  const publicKey = convertCOSEtoPKCS(parsedAuthenticatorData.credentialPublicKey!);
  return publicKey;
}

/**
 * Get complete credential information
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
    const response = credential;
    console.log("response", response);
    const publickey = parsePublicKey(response);

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
    console.error('Failed to get credential information:', error);
    return null;
  }
}
import type { ECDSASigFormat } from '@noble/curves/abstract/weierstrass';

// ecdsaImpl is the implementation object you get from ecdsa(Point, hash)
export function normalizeS(
  sigBytes: Uint8Array,
  formFormat: ECDSASigFormat = 'compact',
  toFormat: ECDSASigFormat = 'compact'
): Uint8Array {
  const sig = p256.Signature.fromBytes(sigBytes, formFormat);

  // Already low S, return directly
  if (!sig.hasHighS()) return sig.toBytes(toFormat);

  // Normalize: s -> -s mod n (equivalent to n - s)
  const sLow = p256.Point.Fn.neg(sig.s);

  // If it's a recovered signature, need to flip the lowest bit of recovery
  const rec = sig.recovery != null ? (sig.recovery ^ 1) : undefined;

  const normalized = new p256.Signature(sig.r, sLow, rec);
  return normalized.toBytes(toFormat);
}

/**
 * Execute transfer transaction on Aptos network
 */
export async function submitTransfer(
  credentialId?: string,
  senderAddress?: string,
  receiverAddress?: string,
  amount?: number
) {

  if (!credentialId) {
    throw new Error("Please create a Passkey credential first");
  }
  try {

    // Use passkey
    // Read current public key to calculate address
    

    // Create account
  

    // Get account address
    const savedCredential = window.localStorage.getItem("credentialData");
    
    if (!savedCredential) {
      throw new Error("Please create a Passkey credential first");
    }
    const credentialData = JSON.parse(savedCredential);
    
    // Use passed parameters or default values
    const finalSenderAddress = senderAddress || credentialData.publicKey.aptosAddress;
    const finalReceiverAddress = receiverAddress || "0x1234567890123456789012345678901234567890123456789012345678901234";
    const finalAmount = amount || 1000; // Default 0.001 APT (1000 smallest units)
    
    console.log(`=== ${currentNetwork.name} Transfer Transaction ===`);
    console.log("Sender Address:", finalSenderAddress);
    console.log("Receiver Address:", finalReceiverAddress);
    console.log("Transfer Amount:", finalAmount, "smallest units");
    console.log("Network:", currentNetwork.name);
    

    console.log(aptosClient)
    // build raw transaction

    const simpleTxn = await aptosClient.transaction.build.simple({
      sender: finalSenderAddress,
      data: {
        function: "0x1::aptos_account::transfer",
        functionArguments: [
          finalReceiverAddress,
          finalAmount,
        ],
        typeArguments: [],
      },
      options: {
        maxGasAmount: 2000,
        gasUnitPrice: 100
      }
    });
    console.log("rawTxn", simpleTxn.rawTransaction);
    
    // Calculate challenge

    const message = generateSigningMessageForTransaction(simpleTxn);
    console.log("message", message);

    const challenge = sha3_256(message);
    console.log("challenge", challenge);

    // Sign

    const allowedCredentials: PublicKeyCredentialDescriptor[] = [
      {
        type: "public-key",
        id: Buffer.from(credentialId, "base64"),
      },
    ];

    const publicKey: PublicKeyCredentialRequestOptions = {
      challenge: challenge.buffer as ArrayBuffer,                    // Challenge - convert to ArrayBuffer
      allowCredentials: allowedCredentials,  // Allowed credentials
      extensions: {},              // Extensions
    };
  
    let credential = await navigator.credentials.get({
      publicKey,
    });

    console.log("credential", credential);

    if (!credential) {
      throw new Error("Failed to get credential");
    }

    const { clientDataJSON, authenticatorData, signature } = (credential as PublicKeyCredential).response as AuthenticatorAssertionResponse;

    console.log("clientDataJSON", Buffer.from(clientDataJSON).toString("utf-8"));
    console.log("authenticatorData", Buffer.from(authenticatorData).toString("utf-8"));
    console.log("signature", Buffer.from(signature).toString("utf-8"));

    const signatureCompact = normalizeS(new Uint8Array(signature), 'der', 'compact');
    console.log("signatureCompact", signatureCompact);


    const transactionAuthenticator = new TransactionAuthenticatorSingleSender(
      new AccountAuthenticatorSingleKey(new AnyPublicKey(
        new Secp256r1PublicKey(Hex.fromHexInput(credentialData.publicKey.hex).toUint8Array()),
      ),
      new AnySignature(new WebAuthnSignature(signatureCompact, new Uint8Array(authenticatorData), new Uint8Array(clientDataJSON)))
    ),
    );
    console.log("transactionAuthenticator", transactionAuthenticator.bcsToHex().toString());

    // Submit transaction
    
    const result = await aptosClient.transaction.submit.simple({
      transaction: simpleTxn,
      senderAuthenticator: new AccountAuthenticatorSingleKey(new AnyPublicKey(
        new Secp256r1PublicKey(Hex.fromHexInput(credentialData.publicKey.hex).toUint8Array()),
      ),
      new AnySignature(new WebAuthnSignature(signatureCompact, new Uint8Array(authenticatorData), new Uint8Array(clientDataJSON))),
    )});

    

    // Return transaction hash
    if (result.hash) {
      return result.hash;
    } else {
      throw new Error("Failed to get transaction hash");
    }
  } catch (error) {
    console.error("Transfer transaction failed:", error);
    throw error;
  }
}

/**
 * Check transaction status
 */
export async function checkTransactionStatus(transactionHash: string): Promise<string> {
  try {
    const response = await fetch(
      `${currentNetwork.fullnodeUrl}/v1/transactions/by_hash/${transactionHash}`
    );
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const transaction = await response.json();
    console.log("Transaction response:", transaction);
    
    // Aptos transaction status check logic
    if (transaction.success === true) {
      return "Transaction successfully on-chain";
    } else if (transaction.success === false) {
      return `Transaction failed: ${transaction.vm_status || 'Unknown error'}`;
    } else {
      // Check other possible success flags
      if (transaction.vm_status === "Executed successfully") {
        return "Transaction successfully on-chain";
      } else if (transaction.vm_status && transaction.vm_status !== "Executed successfully") {
        return `Transaction failed: ${transaction.vm_status}`;
      } else {
        // If no clear status, check if transaction exists on-chain
        if (transaction.hash) {
          return "Transaction successfully on-chain";
        } else {
          return "Transaction status unknown";
        }
      }
    }
  } catch (error) {
    console.error("Failed to check transaction status:", error);
    throw error;
  }
}

/**
 * Get APT balance for an address
 */
export async function getAptBalance(address: string): Promise<number> {
  try {
    const response = await fetch(`${currentNetwork.fullnodeUrl}/v1/view`, {
      method: "POST",
      headers: {
        "Accept": "application/json, application/x-bcs",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        function: "0x1::coin::balance",
        type_arguments: ["0x1::aptos_coin::AptosCoin"],
        arguments: [address]
      })
    });
    
    if (!response.ok) {
      if (response.status === 404) {
        // Account doesn't exist or has no APT balance
        return 0;
      }
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const data = await response.json();
    const balance = parseInt(data[0]);
    
    // Convert from smallest unit (octas) to APT
    return balance / 100000000;
  } catch (error) {
    console.error("Failed to get APT balance:", error);
    throw error;
  }
}

/**
 * Request APT from faucet (devnet only)
 */
export async function requestFaucet(address: string): Promise<boolean> {
  if (currentNetwork.name !== "Devnet") {
    throw new Error("Faucet is only available on Devnet");
  }
  
  if (!currentNetwork.faucetUrl) {
    throw new Error("Faucet URL not configured for this network");
  }
  
  try {
    // Use POST request with JSON body
    const faucetUrl = `${currentNetwork.faucetUrl}/fund`;
    const response = await fetch(faucetUrl, {
      method: "POST",
      headers: {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        address: address,
        amount: 10000000,
      }),
    });
    
    if (!response.ok) {
      throw new Error(`Faucet request failed: ${response.status} ${response.statusText}`);
    }
    
    const result = await response.json();
    console.log("Faucet response:", result);
    return true;
  } catch (error) {
    console.error("Faucet request failed:", error);
    throw error;
  }
}

/**
 * Transaction status check with timeout loop
 */
export async function checkTransactionStatusWithTimeout(transactionHash: string): Promise<string> {
  const maxAttempts = 10; // 10 second timeout
  const intervalMs = 1000; // Check every 1 second
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      console.log(`Attempt ${attempt} to check transaction status...`);
      
      const response = await fetch(
        `${currentNetwork.fullnodeUrl}/v1/transactions/by_hash/${transactionHash}`
      );
      
      if (!response.ok) {
        if (response.status === 404) {
          // Transaction not yet on-chain, continue waiting
          if (attempt < maxAttempts) {
            await new Promise(resolve => setTimeout(resolve, intervalMs));
            continue;
          } else {
            return "Transaction check timeout: Not on-chain within 10 seconds";
          }
        } else {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
      }
      
      const transaction = await response.json();
      console.log(`Transaction response (attempt ${attempt}):`, transaction);
      
      // Aptos transaction status check logic
      if (transaction.success === true) {
        return "Transaction successfully on-chain";
      } else if (transaction.success === false) {
        return `Transaction failed: ${transaction.vm_status || 'Unknown error'}`;
      } else {
        // Check other possible success flags
        if (transaction.vm_status === "Executed successfully") {
          return "Transaction successfully on-chain";
        } else if (transaction.vm_status && transaction.vm_status !== "Executed successfully") {
          return `Transaction failed: ${transaction.vm_status}`;
        } else {
          // If no clear status, check if transaction exists on-chain
          if (transaction.hash) {
            return "Transaction successfully on-chain";
          } else {
            return "Transaction status unknown";
          }
        }
      }
      
    } catch (error) {
      console.error(`Attempt ${attempt} failed:`, error);
      
      if (attempt < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, intervalMs));
        continue;
      } else {
        return `Transaction check failed: ${error instanceof Error ? error.message : String(error)}`;
      }
    }
  }
  
  return "Transaction check timeout";
}
