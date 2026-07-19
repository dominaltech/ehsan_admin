const { webcrypto } = require('crypto');
const crypto = webcrypto || globalThis.crypto;
const enc = new TextEncoder();

function b64uDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function b64uEncode(buf) {
  const bytes = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer);
  let b = '';
  for (const byte of bytes) b += String.fromCharCode(byte);
  return btoa(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function concat(...bufs) {
  const arrays = bufs.map(b => b instanceof Uint8Array ? b : new Uint8Array(b));
  const total  = arrays.reduce((n, a) => n + a.byteLength, 0);
  const out    = new Uint8Array(total);
  let i = 0;
  for (const a of arrays) { out.set(a, i); i += a.byteLength; }
  return out;
}

function rawP256PrivToPkcs8(rawPriv32) {
  if (rawPriv32.length !== 32) throw new Error(`P-256 private key must be 32 bytes, got ${rawPriv32.length}`);
  return concat(
    new Uint8Array([
      0x30, 0x41,
      0x02, 0x01, 0x00,
      0x30, 0x13,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
      0x04, 0x27,
        0x30, 0x25,
          0x02, 0x01, 0x01,
          0x04, 0x20
    ]),
    rawPriv32
  );
}

async function makeVapidJWT(audience, subject, pubB64u, privB64u) {
  const header  = b64uEncode(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims  = b64uEncode(enc.encode(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 43200,
    sub: subject
  })));
  const signing = `${header}.${claims}`;

  const rawPriv = b64uDecode(privB64u);
  const pkcs8   = rawP256PrivToPkcs8(rawPriv);

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8', pkcs8,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['sign']
  );

  const sigBuf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    cryptoKey,
    enc.encode(signing)
  );

  return `${signing}.${b64uEncode(sigBuf)}`;
}

async function encryptPayload(plaintext, p256dhB64u, authB64u) {
  const clientPubRaw = b64uDecode(p256dhB64u);
  const authSecret   = b64uDecode(authB64u);

  const serverKP     = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const serverPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', serverKP.publicKey));

  const clientPub = await crypto.subtle.importKey('raw', clientPubRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdhBits  = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: clientPub }, serverKP.privateKey, 256));

  const prkKey  = await crypto.subtle.importKey('raw', ecdhBits, 'HKDF', false, ['deriveBits']);
  const keyInfo = concat(enc.encode('WebPush: info\0'), clientPubRaw, serverPubRaw);
  const ikm     = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: authSecret, info: keyInfo }, prkKey, 256
  ));

  const salt   = crypto.getRandomValues(new Uint8Array(16));
  const ikmKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);

  const cekRaw = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('Content-Encoding: aes128gcm\0') }, ikmKey, 128
  ));
  const nonceRaw = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('Content-Encoding: nonce\0') }, ikmKey, 96
  ));

  const cek = await crypto.subtle.importKey('raw', cekRaw, 'AES-GCM', false, ['encrypt']);

  const padded     = concat(enc.encode(plaintext), new Uint8Array([0x02]));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonceRaw }, cek, padded));

  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096, false);

  return concat(salt, rs, new Uint8Array([65]), serverPubRaw, ciphertext);
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const PUB  = process.env.VAPID_PUBLIC_KEY || 'BJ2Mrf8XjtBuAeEWtU6-IHvU3xNGlt_68EXmU7cOid_Pu6_nQY3FPD0S-H0C4j3kBDCvzxq0H2txCywpjYnNukM';
  const PRIV = process.env.VAPID_PRIVATE_KEY;
  const SUBJ = process.env.VAPID_SUBJECT || 'mailto:ehsanproduct1@gmail.com';

  if (!PRIV) {
    return res.status(500).json({ error: 'VAPID_PRIVATE_KEY env var not set in Vercel' });
  }

  const { subscription, title, message, url } = req.body;

  if (!subscription)              return res.status(400).json({ error: 'Missing field: subscription' });
  if (!subscription.endpoint)    return res.status(400).json({ error: 'Missing field: subscription.endpoint' });
  if (!subscription.keys)        return res.status(400).json({ error: 'Missing field: subscription.keys' });
  if (!subscription.keys.p256dh) return res.status(400).json({ error: 'Missing field: subscription.keys.p256dh' });
  if (!subscription.keys.auth)   return res.status(400).json({ error: 'Missing field: subscription.keys.auth' });

  try {
    const endpoint = new URL(subscription.endpoint);
    const audience = `${endpoint.protocol}//${endpoint.host}`;
    const jwt      = await makeVapidJWT(audience, SUBJ, PUB, PRIV);

    const payload = JSON.stringify({
      title: title   || '🛒 Ehsan Admin',
      body:  message || 'New notification',
      url:   url     || '/index.html',
      tag:   'ehsan-order'
    });
    const encBody = await encryptPayload(payload, subscription.keys.p256dh, subscription.keys.auth);

    const pushRes = await fetch(subscription.endpoint, {
      method: 'POST',
      headers: {
        'Authorization':    `vapid t=${jwt},k=${PUB}`,
        'Content-Type':     'application/octet-stream',
        'Content-Encoding': 'aes128gcm',
        'TTL':              '86400'
      },
      body: encBody
    });

    if ([200, 201, 202].includes(pushRes.status)) {
      return res.status(200).json({ success: true, status: pushRes.status });
    }

    const detail = await pushRes.text();
    console.error(`[send-push] Push service returned ${pushRes.status}:`, detail);
    return res.status(502).json({ error: `Push service error ${pushRes.status}`, detail });

  } catch (err) {
    console.error('[send-push] Exception:', err.message, err.stack);
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
};
