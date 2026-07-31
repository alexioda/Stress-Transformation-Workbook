const crypto = require('crypto');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { cipher } = req.body;

  if (!cipher || typeof cipher !== 'string') {
    return res.status(400).json({ success: false });
  }

  const rawInput   = cipher.trim();
  const upperInput = rawInput.toUpperCase();

  const validCiphers = [
    process.env.WORKBOOK_CIPHER_1,
    process.env.WORKBOOK_CIPHER_2,
    process.env.WORKBOOK_CIPHER_3,
  ].filter(Boolean);

  if (validCiphers.length === 0) {
    // Fallback for local dev without env vars set. Restricted to non-production
    // deployments so a forgotten WORKBOOK_CIPHER_* var on Vercel can't silently
    // open a known-password ("DEVMODE") backdoor in production.
    if (process.env.VERCEL_ENV !== 'production' && upperInput === 'DEVMODE') {
      return res.status(200).json({ success: true, token: 'dev' });
    }
  } else if (validCiphers.includes(upperInput)) {
    return res.status(200).json({ success: true, token: generateToken() });
  }

  // Not a manual cipher — check whether it's a real Lemon Squeezy license key
  // (issued automatically on purchase, including $0 orders via a 100%-off
  // discount code, so comped access can flow through Lemon Squeezy too).
  if (await isValidLicenseKey(rawInput)) {
    return res.status(200).json({ success: true, token: generateToken() });
  }

  // Rate limiting note: for production, add IP-based rate limiting here
  // e.g. using Vercel KV or Upstash Redis to track failed attempts.
  return res.status(401).json({ success: false });
}

async function isValidLicenseKey(licenseKey) {
  if (!licenseKey) return false;

  try {
    const params = new URLSearchParams({ license_key: licenseKey });
    const resp = await fetch('https://api.lemonsqueezy.com/v1/licenses/validate', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!resp.ok) return false;
    const data = await resp.json();
    return data.valid === true;
  } catch (e) {
    // Network hiccup or Lemon Squeezy outage — fail closed, not a 500,
    // so this can't be used to crash the endpoint.
    console.warn('Lemon Squeezy license validation error:', e);
    return false;
  }
}

function generateToken() {
  // Signed, timestamped session token verified by api/workbook-content.js —
  // this is what actually gates the workbook content now, not just the lock
  // screen overlay. SETUP: set SESSION_SECRET in Vercel env vars; without it
  // this issues an unsigned token that api/workbook-content.js will reject.
  const issuedAt = Date.now().toString();
  const secret = process.env.SESSION_SECRET;
  if (!secret) {
    console.warn('No SESSION_SECRET set. Issuing unsigned token — /api/workbook-content will reject it until SESSION_SECRET is configured.');
    return `${issuedAt}.unsigned`;
  }
  const signature = crypto.createHmac('sha256', secret).update(issuedAt).digest('hex');
  return `${issuedAt}.${signature}`;
}
