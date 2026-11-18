// Use global fetch (Node 18+)

async function test() {
  // Login
  const loginRes = await fetch('http://localhost:3000/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'admin@maildesk.com', password: 'admin123' })
  });
  const loginData = await loginRes.json();
  console.log('Login status:', loginRes.status);
  console.log('Login data:', JSON.stringify(loginData, null, 2));
  const token = loginData.token;

  // Test /api/templates with company_id=1
  console.log('\n--- Testing /api/templates?company_id=1 ---');
  const t1 = await fetch('http://localhost:3000/api/templates?company_id=1', {
    headers: { 'Authorization': 'Bearer ' + token }
  });
  console.log('Status:', t1.status);
  console.log('Body:', await t1.text());

  // Test /api/templates without company_id
  console.log('\n--- Testing /api/templates (no company_id) ---');
  const t2 = await fetch('http://localhost:3000/api/templates', {
    headers: { 'Authorization': 'Bearer ' + token }
  });
  console.log('Status:', t2.status);
  console.log('Body:', await t2.text());
}

test().catch(console.error);