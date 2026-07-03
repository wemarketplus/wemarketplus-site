// Alphanumeric alphabet without look-alikes (0/O, 1/l/I) so the temporary
// password survives being read aloud or retyped.
const ALPHABET = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
const TEMP_PASSWORD_LENGTH = 12;

// Convenience generator for the Add User form — comfortably above the
// backend's 8-character minimum. Not a secrets-grade generator; the invited
// user is expected to replace it via the invite flow.
export function generateTempPassword(): string {
  const bytes = new Uint32Array(TEMP_PASSWORD_LENGTH);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]).join('');
}
