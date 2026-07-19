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

  const SB_URL = process.env.SB_URL;
  const SB_KEY = process.env.SB_SERVICE_ROLE_KEY || 
                 process.env.SUPABASE_SERVICE_ROLE_KEY || 
                 process.env.SUPABASE_SERVICE_KEY || 
                 process.env.SERVICE_ROLE_KEY || 
                 process.env.SB_ANON_KEY;

  const body = req.body;
  const { subscription } = body;
  if (!subscription?.endpoint)    return res.status(400).json({ error: 'Missing subscription.endpoint' });
  if (!subscription?.keys?.p256dh) return res.status(400).json({ error: 'Missing subscription.keys.p256dh' });
  if (!subscription?.keys?.auth)   return res.status(400).json({ error: 'Missing subscription.keys.auth' });

  // DELETE old entries first (keep table clean — only latest subscription)
  await fetch(`${SB_URL}/rest/v1/push_subscriptions?id=gte.0`, {
    method: 'DELETE',
    headers: {
      'apikey':        SB_KEY,
      'Authorization': 'Bearer ' + SB_KEY
    }
  });

  // INSERT fresh subscription
  const sbRes = await fetch(`${SB_URL}/rest/v1/push_subscriptions`, {
    method: 'POST',
    headers: {
      'apikey':        SB_KEY,
      'Authorization': 'Bearer ' + SB_KEY,
      'Content-Type':  'application/json',
      'Prefer':        'return=minimal'
    },
    body: JSON.stringify({
      endpoint:   subscription.endpoint,
      p256dh:     subscription.keys.p256dh,
      auth:       subscription.keys.auth,
      updated_at: new Date().toISOString()
    })
  });

  if (sbRes.ok || sbRes.status === 201) return res.status(200).json({ success: true });

  const errText = await sbRes.text();
  console.error('[save-subscription] Supabase error:', sbRes.status, errText);
  return res.status(502).json({ error: `Supabase ${sbRes.status}: ${errText}` });
};
