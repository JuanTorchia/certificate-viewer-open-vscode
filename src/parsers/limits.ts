export const MAX_INPUT_BYTES = 5 * 1024 * 1024;
export const MAX_PEM_BLOCKS = 100;
export const MAX_PEM_BLOCK_CHARS = 256 * 1024;
export const MAX_CERTIFICATES = 100;
/** Maximum iterations accepted per synchronous PKCS#12 MAC, PBE, or PBKDF2 operation. */
export const MAX_PKCS12_KDF_ITERATIONS = 100_000;

export function assertWithinInputLimit(byteLength: number, label: string): void {
  if (byteLength > MAX_INPUT_BYTES) {
    throw new Error(`${label} is ${byteLength} bytes; CertView refuses to parse files larger than ${MAX_INPUT_BYTES} bytes.`);
  }
}
