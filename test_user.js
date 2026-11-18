const fetch = global.fetch;

async function test() {
  // Login as a regular user
  const loginRes = await fetch('http://localhost:3000/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'chamath.kalupahana@greeklanka.com', password: 'admin123' })
  });
  console.log('Login status:', loginRes.status);
  const loginData = await loginRes.json();
  console.log('Login data:', JSON.stringify(loginData, null, 2));
  
  if (loginRes.ok) {
    const token = loginData.token;
    
    // Test /api/templates with company_id=1
    console.log('\n--- Testing /api/templates?company_id=1 ---');
    const t1 = await fetch('http://localhost:3000/api/templates?company_id=1', {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    console.log('Status:', t1.status);
    console.log('Body:', await t1.text());
    
    // Test /api/templates with company_id=2
    console.log('\n--- Testing /api/templates?company_id=2 ---');
    const t2 = await fetch('http://localhost:3000/api/templates?company_id=2', {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    console.log('Status:', t2.status);
    console.log('Body:', await t2.text());
    
    // Test /api/templates with company_id=3
    console.log('\n--- Testing /api/templates?company_id=3 ---');
    const t3 = await fetch('http://localhost:3000/api/templates?company_id=3', {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    console.log('Status:', t3.status);
    console.log('Body:', await t3.text());
  }
}

test().catch(console.error);