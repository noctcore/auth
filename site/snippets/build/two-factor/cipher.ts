import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { SecretCipher } from '@noctcore/auth';

/**
 * AES-256-GCM with the user id as associated data, so a ciphertext copied onto
 * another user's row fails to decrypt. Each ciphertext names its key, so a new
 * key can be added (and made current) without re-encrypting the old rows.
 *
 * keys: key id -> 32 random bytes, from your KMS or secret store, never the repo.
 */
export function aesGcmCipher(keys: ReadonlyMap<string, Uint8Array>, currentKeyId: string): SecretCipher {
  const key = (id: string) => {
    const bytes = keys.get(id);

    if (!bytes || bytes.length !== 32) throw new Error(`No 32-byte key ${id}`);

    return bytes;
  };

  key(currentKeyId);

  return {
    async encrypt(secret, { userId }) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key(currentKeyId), iv);

      cipher.setAAD(Buffer.from(userId, 'utf8'));

      const body = Buffer.concat([cipher.update(secret), cipher.final()]);
      const parts = [iv, body, cipher.getAuthTag()].map((part) => part.toString('base64url'));

      return `${currentKeyId}.${parts.join('.')}`;
    },

    async decrypt(ciphertext, { userId }) {
      const [keyId = '', iv = '', body = '', tag = ''] = ciphertext.split('.');
      const decipher = createDecipheriv('aes-256-gcm', key(keyId), Buffer.from(iv, 'base64url'));

      decipher.setAAD(Buffer.from(userId, 'utf8'));
      decipher.setAuthTag(Buffer.from(tag, 'base64url'));

      return new Uint8Array(Buffer.concat([decipher.update(Buffer.from(body, 'base64url')), decipher.final()]));
    },
  };
}
