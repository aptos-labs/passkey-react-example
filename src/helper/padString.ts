export default function padString(input: string): string {
  const segmentLength = 4;  // 段长度
  const stringLength = input.length;  // 输入字符串长度
  const diff = stringLength % segmentLength;  // 计算余数

  if (!diff) {
      return input;  // 如果没有余数，直接返回原字符串
  }

  let position = stringLength;
  let padLength = segmentLength - diff;  // 需要填充的长度
  const paddedStringLength = stringLength + padLength;  // 填充后的总长度
  const uint8Array = new Uint8Array(paddedStringLength);

  // 将输入字符串转换为 UTF-8 字节并存储在 Uint8Array 中
  for (let i = 0; i < stringLength; i++) {
      uint8Array[i] = input.charCodeAt(i);
  }

  // 通过设置适当的 UTF-8 字节来添加填充
  while (padLength--) {
      uint8Array[position++] = "=".charCodeAt(0);
  }

  // 使用 TextDecoder 将 Uint8Array 转换为字符串
  const textDecoder = new TextDecoder('utf-8');
  const result = textDecoder.decode(uint8Array);

  return result;
}
