// A software passkey for tests: makes registration and sign-in responses the way a real authenticator would
// (attestation "none", user present and verified), so the server's WebAuthn checks run for real.
import { createHash, generateKeyPairSync, sign, randomBytes } from 'node:crypto';

const u8 = (...parts) => Buffer.concat(parts.map((p) => Buffer.from(p)));
const sha = (b) => createHash('sha256').update(b).digest();
// Minimal CBOR: unsigned/negative ints, byte strings, text strings, maps.
function cbor(v) {
  const head = (major, n) => n < 24 ? Buffer.from([major << 5 | n]) : n < 256 ? Buffer.from([major << 5 | 24, n])
    : Buffer.from([major << 5 | 25, n >> 8, n & 255]);
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === 'string') return u8(head(3, Buffer.byteLength(v)), Buffer.from(v));
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return u8(head(2, v.length), v);
  if (v instanceof Map) return u8(head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)]));
  throw new Error('cbor: unsupported');
}

export function softPasskey(origin, rpID) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credId = randomBytes(16);
  const id = credId.toString('base64url');
  let counter = 0;
  const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
  const authData = (attested) => {
    counter++;
    const flags = 0x01 | 0x04 | (attested ? 0x40 : 0); // user present, user verified, attested data
    const c = Buffer.alloc(4); c.writeUInt32BE(counter);
    const base = u8(sha(rpID), [flags], c);
    if (!attested) return base;
    const len = Buffer.from([credId.length >> 8, credId.length & 255]);
    return u8(base, Buffer.alloc(16), len, credId, cose);
  };
  const clientData = (type, challenge, o = origin) => Buffer.from(JSON.stringify({ type, challenge, origin: o, crossOrigin: false }));
  return {
    id,
    register(options) {
      const cd = clientData('webauthn.create', options.challenge);
      const att = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData(true)]]));
      return { id, rawId: id, type: 'public-key', clientExtensionResults: {},
        response: { clientDataJSON: cd.toString('base64url'), attestationObject: att.toString('base64url'), transports: ['internal'] } };
    },
    login(options, { userHandle, asOrigin } = {}) {
      const cd = clientData('webauthn.get', options.challenge, asOrigin);
      const ad = authData(false);
      const sig = sign('sha256', u8(ad, sha(cd)), privateKey);
      return { id, rawId: id, type: 'public-key', clientExtensionResults: {},
        response: { clientDataJSON: cd.toString('base64url'), authenticatorData: ad.toString('base64url'), signature: sig.toString('base64url'),
          ...(userHandle ? { userHandle: Buffer.from(userHandle).toString('base64url') } : {}) } };
    },
  };
}
