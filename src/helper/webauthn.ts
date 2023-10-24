/* eslint-disable @typescript-eslint/no-explicit-any */
/** Some of this code is sourced from https://rsolomakhin.github.io/pr/spc/ */

import { sha3_256 } from "@noble/hashes/sha3";
import base64url from "base64url";

export const base64_url_challenge = "aGVsbG8gd29ybGQ";
export const sha3_256_challenge_bytes = sha3_256
  .create()
  .update(base64ToArray(base64_url_challenge))
  .digest();
export const base64_url_sha3_256_challenge = arrayBufferToBase64(
  sha3_256_challenge_bytes
);

export async function isSpcAvailable() {
  const spcAvailable = Boolean(PaymentRequest);
  return spcAvailable;
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
  id: window.location.hostname,
  name: window.location.origin,
};

export const defaultPubKeyCredParams: PublicKeyCredentialParameters[] = [
  {
    type: "public-key",
    alg: -7, // ECDSA, not supported on Windows.
  },
];

export const defaultUser = {
  // Set an understandable 'username' in case the WebAuthn UX displays it
  // (e.g., the Passkeys UX on Chrome MacOS 108+). This is for display ONLY,
  // and has no bearing on SPC's functionality in general. (For example, it
  // is NOT shown in the SPC transaction dialog.)
  name: "Andrew",
  displayName: "",
  // TODO look at this later
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  id: Uint8Array.from(String(Math.random() * 99999999)),
};

export const defaultResidentKey: ResidentKeyRequirement = spcSupportsPreferred()
  ? "preferred"
  : "required";

export const defaultAuthenticatorSelection: SPCPublicKeyCredentialCreationOptions['authenticatorSelection'] = {
  userVerification: "required",
  residentKey: defaultResidentKey,
  authenticatorAttachment: "platform",
};

export const defaultPublicKey: SPCPublicKeyCredentialCreationOptions = {
  rp: defaultRp,
  user: defaultUser,
  challenge: sha3_256_challenge_bytes,
  pubKeyCredParams: defaultPubKeyCredParams,
  authenticatorSelection: defaultAuthenticatorSelection,
  extensions: {
    payment: {
      isPayment: true,
    },
  },
};

/**
 * Creates a demo WebAuthn credential, optionally setting the 'payment'
 * extension. The created credential will always have the name 'Andrew ····
 * 1234', matching the demo payment instrument used in authentication.
 *
 * @param {SPCPublicKeyCredentialCreationOptions} publicKey
 */
export async function createCredential(
  publicKey: SPCPublicKeyCredentialCreationOptions = defaultPublicKey
): Promise<Credential | null> {
  const publicKeyCreationOptions: SPCPublicKeyCredentialCreationOptions = {
    ...defaultPublicKey,
    ...publicKey,
  };

  return await navigator.credentials.create({
    publicKey: publicKeyCreationOptions,
  });
}

/**
 * This is a barebones implementation of the getCredential method
 */
export async function getCredential(
  allowCredentials: PublicKeyCredentialDescriptor[]
) {
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: sha3_256_challenge_bytes,
    allowCredentials: allowCredentials,
    extensions: {},
  };

  return (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential;
}

/**
 * Returns whether or not SPC supports residentKey 'preferred' (instead of just
 * 'required'). There is unfortunately no way to feature detect this, so we
 * have to do a version check.
 *
 * @return {boolean} true if SPC supports 'preferred' for the residentKey
 *     parameter, false otherwise.
 */
export function spcSupportsPreferred() {
  // This will be true for not just Chrome but also Edge/etc, but that's fine.
  const match = navigator.userAgent.match(/Chrom(e|ium)\/([0-9]+)\./);
  if (!match) return false;

  const version = parseInt(match[2], 10);
  // https://crrev.com/130fada41 landed in 106.0.5228.0, but we assume that any
  // 106 will do for simplicity.
  return version >= 106;
}

/**
 * @see https://www.w3.org/TR/secure-payment-confirmation/#dictdef-paymentcredentialinstrument
 */
export interface PaymentCredentialInstrument {
  // required USVString displayName;
  displayName: string;
  // required USVString icon;
  icon: string;
  // boolean iconMustBeShown = true;
  iconMustBeShown?: boolean;
}

/**
 * @see https://www.w3.org/TR/secure-payment-confirmation/#sctn-securepaymentconfirmationrequest-dictionary
 */
export interface SecurePaymentConfirmationRequest {
  challenge: Uint8Array;
  // required USVString rpId;
  rpId: string;
  // required sequence<BufferSource> credentialIds;
  credentialIds: Uint8Array[];
  // required PaymentCredentialInstrument instrument;
  instrument: PaymentCredentialInstrument;
  // unsigned long timeout;
  timeout?: number;
  // USVString payeeName;
  payeeName?: string;
  // USVString payeeOrigin;
  payeeOrigin?: string;
  // AuthenticationExtensionsClientInputs extensions;
  extensions: Record<string, unknown>;
  // sequence<USVString> locale;
  locale?: string[];
  // boolean showOptOut;
  showOptOut?: boolean;
}

/**
 * Creates a PaymentRequest object for SPC.
 *
 * @param {SecurePaymentConfirmationRequest} spcData - the input SPC data. The
 *     credentialIds field *MUST* be set. Any other SecurePaymentConfirmationRequest
 *     fields not set in this object will be initialized to a default value.
 * @return {PaymentRequest} The payment request object.
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
    spcData.challenge = new TextEncoder().encode("network_data");
  if (spcData.rpId === undefined) spcData.rpId = window.location.hostname;
  if (spcData.instrument === undefined)
    spcData.instrument = { displayName: "Andrew ···· 1234", icon: "" };
  if (spcData.instrument.icon === undefined)
    spcData.instrument.icon =
      "https://rsolomakhin.github.io/pr/spc/troy-alt-logo.png";
  if (spcData.timeout === undefined) spcData.timeout = 60000;
  // We only set a default payeeOrigin if *both* payeeName and payeeOrigin are
  // not set, as the spec deliberately allows either/or to be null.
  if (!("payeeName" in spcData) && !("payeeOrigin" in spcData))
    spcData.payeeOrigin = window.location.origin;

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
 * Converts a PaymentResponse or a PublicKeyCredential into a string.
 */
export function objectToString(input: Record<string, any>) {
  return JSON.stringify(objectToDictionary(input), undefined, 2);
}

export enum Encoding {
  base64 = "base64",
  base64Url = "base64Url",
}

/**
 * Converts a PaymentResponse or a PublicKeyCredential into a dictionary.
 * WARNING: base64Url encoding DOES NOT WORK AS EXPECTED
 *          use something like https://www.base64url.com/ to manually encode
 *          for now
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
 * Converts a base64 encoded string into Unit8Array.
 */
export function base64ToArray(input: string) {
  return Uint8Array.from(atob(input), (c) => c.charCodeAt(0));
}

/**
 * Converts a base64Url encoded string into a Uint8Array.
 */
export function base64UrlToArray(input: string) {
  return base64url.toBuffer(input);
}

/**
 * Converts an ArrayBuffer into a base64 encoded string.
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
 * Converts an ArrayBuffer into a base64 string.
 */
export function arrayBufferToBase64String(input: ArrayBuffer) {
  return String.fromCharCode(...new Uint8Array(input));
}
