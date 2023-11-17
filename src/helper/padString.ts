export default function padString(input: string): string {
  const segmentLength = 4;
  const stringLength = input.length;
  const diff = stringLength % segmentLength;

  if (!diff) {
      return input;
  }

  let position = stringLength;
  let padLength = segmentLength - diff;
  const paddedStringLength = stringLength + padLength;
  const uint8Array = new Uint8Array(paddedStringLength);

  // Convert the input string to UTF-8 bytes and store them in the Uint8Array
  for (let i = 0; i < stringLength; i++) {
      uint8Array[i] = input.charCodeAt(i);
  }

  // Add padding by setting appropriate UTF-8 bytes
  while (padLength--) {
      uint8Array[position++] = "=".charCodeAt(0);
  }

  // Convert the Uint8Array to a string using TextDecoder
  const textDecoder = new TextDecoder('utf-8');
  const result = textDecoder.decode(uint8Array);

  return result;
}
