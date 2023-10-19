import { BCS } from 'aptos';

export class Base64UrlEncodedBytes {
  /**
   * Constructs a ByteArray instance.
   * @param array
   */
  constructor(public readonly array: Uint8Array) {}

  serialize(serializer: BCS.Serializer): void {
    serializer.serializeBytes(this.array);
  }

  static deserialize(deserializer: BCS.Deserializer): Base64UrlEncodedBytes {
    const array = deserializer.deserializeBytes();
    return new Base64UrlEncodedBytes(array);
  }
}

export interface EncodeSignatureParams {
  // Note: this is the P256 signature from WebAuthn
  signature: ArrayBuffer;
  authenticatorData: ArrayBuffer;
  clientDataJSON: ArrayBuffer
}

// This is what should be included as the transaction signature for a signed WebAuthnP256 transaction
export function encodeSignature({
  signature,
  authenticatorData,
  clientDataJSON
}: EncodeSignatureParams) {
  const serializer = new BCS.Serializer();
  const vector: BCS.Seq<Base64UrlEncodedBytes> = [
    new Base64UrlEncodedBytes(new Uint8Array(signature)),
    new Base64UrlEncodedBytes(new Uint8Array(authenticatorData)),
    new Base64UrlEncodedBytes(new Uint8Array(clientDataJSON)),
  ];
  BCS.serializeVector<Base64UrlEncodedBytes>(vector, serializer);
  const bcsBytes = serializer.getBytes();
  return bcsBytes;
}
