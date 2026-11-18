const fetch = global.fetch;

async function test() {
  // Login
  const loginRes = await fetch('http://localhost:3000/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'admin@maildesk.com', password: 'admin123' })
  });
  const loginData = await loginRes.json();
  const token = loginData.token;

  // Test OPTIONS preflight with different origins
  const origins = [
    'http://localhost:3000',
    'http://localhost:3001',
    'null',  // file:// origin
    'http://localhost:3000/api/templates?company_id=1'
  ];

  for (const origin of origins) {
    console.log(`\n--- OPTIONS preflight with Origin: ${origin} ---`);
    const res = await fetch('http://localhost:3000/api/templates?company_id=1', {
      method: 'OPTIONS',
      headers: {
        'Origin': origin,
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'Content-Type, Authorization'
      }
    });
    console.log('Status:', res.status);
    console.log('CORS headers:', {
      'Access-Control-Allow-Origin': res.headers.get('Access-Control-Allow-Origin'),
      'Access-Control-Allow-Methods': res.headers.get('Access-Control-Allow-Methods')
    });
  }

  // Test GET with wrong origin header (simulating different origin)
  console.log('\n--- GET with Origin: http://localhost:3001 (untrusted) ---');
  const res = await fetch('http://localhost:3000/api/templates?company_id=1', {
    headers: { 'Authorization': 'Bearer ' + token, 'Origin': 'http://localhost:3001' }
  });
  console.log('Status:', res.status);
  console.log('Body:', await res.text());
}

test().catch(console.error);