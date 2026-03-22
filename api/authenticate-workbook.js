module.exports = function handler(req, res) {
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
    if (input === 'DEVMODE') {
      return res.status(200).json({ success: true, token: 'dev' });
    }
    return res.status(401).json({ success: false });
  }

  if (validCiphers.includes(input)) {
    return res.status(200).json({ success: true, token: Date.now().toString(36) });
  }

  return res.status(401).json({ success: false });
}
