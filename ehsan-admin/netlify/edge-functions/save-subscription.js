// ─────────────────────────────────────────────────────────────────────────────
//  Netlify Edge Function  →  save-subscription.js  (ADMIN PANEL)
//  Saves the admin's push subscription to Supabase so the user panel can read it.
//  Uses the anon key — table must allow insert via RLS or have RLS disabled.
// ─────────────────────────────────────────────────────────────────────────────
export const config = { path: '/api/save-subscription' };

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

  const SB_URL = Deno.env.get('SB_URL') || 'https://hsvfhlsfgonmyrnpwfci.supabase.co';
  const SB_KEY = Deno.env.get('SB_SERVICE_ROLE_KEY') || 
                 Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || 
                 Deno.env.get('SUPABASE_SERVICE_KEY') || 
                 Deno.env.get('SERVICE_ROLE_KEY') || 
                 Deno.env.get('SB_ANON_KEY') || 
                 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImhzdmZobHNmZ29ubXlybnB3ZmNpIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODIzNTY4MjcsImV4cCI6MjA5NzkzMjgyN30.GM7hasjxdanObngtWatX4u9y_iw1UTDdoiMS7__tIb4';

  let body;
  try { body = await request.json(); }
  catch (e) { return json({ error: 'Invalid JSON: ' + e.message }, 400); }

  const { subscription } = body;
  if (!subscription?.endpoint)    return json({ error: 'Missing subscription.endpoint' }, 400);
  if (!subscription?.keys?.p256dh) return json({ error: 'Missing subscription.keys.p256dh' }, 400);
  if (!subscription?.keys?.auth)   return json({ error: 'Missing subscription.keys.auth' }, 400);

  // DELETE old entries first (keep table clean — only latest subscription)
  await fetch(`${SB_URL}/rest/v1/push_subscriptions?id=gte.0`, {
    method: 'DELETE',
    headers: {
      'apikey':        SB_KEY,
      'Authorization': 'Bearer ' + SB_KEY
    }
  });

  // INSERT fresh subscription
  const res = await fetch(`${SB_URL}/rest/v1/push_subscriptions`, {
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

  if (res.ok || res.status === 201) return json({ success: true });

  const errText = await res.text();
  console.error('[save-subscription] Supabase error:', res.status, errText);
  return json({ error: `Supabase ${res.status}: ${errText}` }, 502);
};
