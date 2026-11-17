import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { SecretCipher } from '@noctcore/auth';

const IV_BYTES = 12;
const TAG_BYTES = 16;

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
      const iv = randomBytes(IV_BYTES);
      const cipher = createCipheriv('aes-256-gcm', key(currentKeyId), iv, { authTagLength: TAG_BYTES });

      cipher.setAAD(Buffer.from(userId, 'utf8'));

      const body = Buffer.concat([cipher.update(secret), cipher.final()]);
      const parts = [iv, body, cipher.getAuthTag()].map((part) => part.toString('base64url'));

      return `${currentKeyId}.${parts.join('.')}`;
    },

    async decrypt(ciphertext, { userId }) {
      const [keyId = '', ivText = '', body = '', tagText = ''] = ciphertext.split('.');
      const iv = Buffer.from(ivText, 'base64url');
      const tag = Buffer.from(tagText, 'base64url');

      // A short tag would make forgery cheaper: refuse anything but the full 16 bytes.
      if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) throw new Error('Malformed ciphertext');

      const decipher = createDecipheriv('aes-256-gcm', key(keyId), iv, { authTagLength: TAG_BYTES });

      decipher.setAAD(Buffer.from(userId, 'utf8'));
      decipher.setAuthTag(tag);

      return new Uint8Array(Buffer.concat([decipher.update(Buffer.from(body, 'base64url')), decipher.final()]));
    },
  };
}
