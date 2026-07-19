// ─────────────────────────────────────────────────────────────────────────────
//  Netlify Edge Function  →  netlify/edge-functions/send-push.js
//  RFC 8291 aes128gcm Web Push + VAPID (RFC 8292)
// ─────────────────────────────────────────────────────────────────────────────
export const config = { path: '/api/send-push' };

const enc = new TextEncoder();

function b64uDecode(s) {
  // Accept both base64url (- _) and base64 (+ /) and strip padding
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

// ── Build PKCS#8 DER wrapper for a raw 32-byte P-256 private scalar ──
function rawP256PrivToPkcs8(rawPriv32) {
  if (rawPriv32.length !== 32) throw new Error(`P-256 private key must be 32 bytes, got ${rawPriv32.length}`);
  // Minimal PKCS#8 DER for EC private key (ecPrivateKey, namedCurve P-256)
  return concat(
    new Uint8Array([
      // SEQUENCE (total 65 bytes)
      0x30, 0x41,
        // INTEGER 0 (version)
        0x02, 0x01, 0x00,
        // SEQUENCE — AlgorithmIdentifier
        0x30, 0x13,
          0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,  // OID id-ecPublicKey
          0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID P-256
        // OCTET STRING — ECPrivateKey
        0x04, 0x27,
          0x30, 0x25,
            0x02, 0x01, 0x01,  // version = 1
            0x04, 0x20         // OCTET STRING, 32 bytes
    ]),
    rawPriv32
  );
}

// ── VAPID JWT (ES256) ──
async function makeVapidJWT(audience, subject, pubB64u, privB64u) {
  const header  = b64uEncode(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims  = b64uEncode(enc.encode(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 43200,  // 12h
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

// ── RFC 8291 §3 payload encryption (aes128gcm) ──
async function encryptPayload(plaintext, p256dhB64u, authB64u) {
  const clientPubRaw = b64uDecode(p256dhB64u);   // 65 bytes uncompressed P-256 point
  const authSecret   = b64uDecode(authB64u);      // 16 bytes

  // Ephemeral server ECDH key pair
  const serverKP     = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const serverPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', serverKP.publicKey));

  // ECDH shared secret
  const clientPub = await crypto.subtle.importKey('raw', clientPubRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdhBits  = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: clientPub }, serverKP.privateKey, 256));

  // PRK  =  HKDF-SHA-256(salt=authSecret, IKM=ecdhBits, info="WebPush: info\0" || clientPub || serverPub)
  const prkKey  = await crypto.subtle.importKey('raw', ecdhBits, 'HKDF', false, ['deriveBits']);
  const keyInfo = concat(enc.encode('WebPush: info\0'), clientPubRaw, serverPubRaw);
  const ikm     = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: authSecret, info: keyInfo }, prkKey, 256
  ));

  // Random 16-byte salt for this message
  const salt   = crypto.getRandomValues(new Uint8Array(16));
  const ikmKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);

  // CEK  (16 bytes) and Nonce (12 bytes)
  const cekRaw = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('Content-Encoding: aes128gcm\0') }, ikmKey, 128
  ));
  const nonceRaw = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('Content-Encoding: nonce\0') }, ikmKey, 96
  ));

  const cek = await crypto.subtle.importKey('raw', cekRaw, 'AES-GCM', false, ['encrypt']);

  // Pad: plaintext + 0x02 delimiter (§4)
  const padded     = concat(enc.encode(plaintext), new Uint8Array([0x02]));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonceRaw }, cek, padded));

  // RFC 8291 §2 binary header: salt(16) + rs(4 BE=4096) + idlen(1=65) + serverPub(65) + ciphertext
  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096, false);

  return concat(salt, rs, new Uint8Array([65]), serverPubRaw, ciphertext);
}

// ── Main handler ──
export default async (request) => {
  const CORS = {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
  const json = (data, status = 200) =>
    new Response(JSON.stringify(data), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });

  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
  if (request.method !== 'POST')    return json({ error: 'Method not allowed' }, 405);

  // ── Read environment variables ──
  const PUB  = Deno.env.get('VAPID_PUBLIC_KEY') || 'BJ2Mrf8XjtBuAeEWtU6-IHvU3xNGlt_68EXmU7cOid_Pu6_nQY3FPD0S-H0C4j3kBDCvzxq0H2txCywpjYnNukM';
  const PRIV = Deno.env.get('VAPID_PRIVATE_KEY');
  const SUBJ = Deno.env.get('VAPID_SUBJECT') || 'mailto:ehsanproduct1@gmail.com';

  if (!PRIV) return json({ error: 'VAPID_PRIVATE_KEY env var not set in Netlify' }, 500);

  // ── Parse request body ──
  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: 'Invalid JSON body: ' + e.message }, 400); }

  const { subscription, title, message, url } = body;

  // Validate subscription fields explicitly for clear error messages
  if (!subscription)              return json({ error: 'Missing field: subscription' }, 400);
  if (!subscription.endpoint)    return json({ error: 'Missing field: subscription.endpoint' }, 400);
  if (!subscription.keys)        return json({ error: 'Missing field: subscription.keys' }, 400);
  if (!subscription.keys.p256dh) return json({ error: 'Missing field: subscription.keys.p256dh' }, 400);
  if (!subscription.keys.auth)   return json({ error: 'Missing field: subscription.keys.auth' }, 400);

  try {
    // 1. Build VAPID JWT
    const endpoint = new URL(subscription.endpoint);
    const audience = `${endpoint.protocol}//${endpoint.host}`;
    const jwt      = await makeVapidJWT(audience, SUBJ, PUB, PRIV);

    // 2. Encrypt payload
    const payload = JSON.stringify({
      title: title   || '🛒 Ehsan Admin',
      body:  message || 'New notification',
      url:   url     || '/ehan_admin.html',
      tag:   'ehsan-order'
    });
    const encBody = await encryptPayload(payload, subscription.keys.p256dh, subscription.keys.auth);

    // 3. Send to browser push service (FCM/Mozilla/etc)
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

    // 201 = created (Chrome FCM), 200/202 = also success on some services
    if ([200, 201, 202].includes(pushRes.status)) {
      return json({ success: true, status: pushRes.status });
    }

    // Return the push service's actual error body for debugging
    const detail = await pushRes.text();
    console.error(`[send-push] Push service returned ${pushRes.status}:`, detail);
    return json({ error: `Push service error ${pushRes.status}`, detail }, 502);

  } catch (err) {
    console.error('[send-push] Exception:', err.message, err.stack);
    return json({ error: err.message, stack: err.stack }, 500);
  }
};
