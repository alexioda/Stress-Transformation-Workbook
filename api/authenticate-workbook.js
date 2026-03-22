// api/authenticate-workbook.js
// Vercel serverless function for Stress Transformation Workbook auth.
// Cipher never sent to client.
//
// Set in Vercel dashboard → Settings → Environment Variables:
//   WORKBOOK_CIPHER_1=your_cipher_here
//   WORKBOOK_CIPHER_2=your_second_cipher_here

export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { cipher } = req.body;

  if (!cipher || typeof cipher !== 'string') {
    return res.status(400).json({ success: false });
  }

  const input = cipher.trim().toUpperCase();

  const validCiphers = [
    process.env.WORKBOOK_CIPHER_1,
    process.env.WORKBOOK_CIPHER_2,
    process.env.WORKBOOK_CIPHER_3,
  ].filter(Boolean);

  if (validCiphers.length === 0) {
    // Local dev fallback — remove before production
    console.warn('No WORKBOOK_CIPHER env vars set. Dev fallback active.');
    if (input === 'DEVMODE') {
      return res.status(200).json({ success: true, token: generateToken() });
    }
    return res.status(401).json({ success: false });
  }

  if (validCiphers.includes(input)) {
    return res.status(200).json({ success: true, token: generateToken() });
  }

  return res.status(401).json({ success: false });
}

function generateToken() {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

