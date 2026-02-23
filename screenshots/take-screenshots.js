const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await context.newPage();
  const BASE = 'http://localhost:5232';
  const SHOTS = '/root/BareMetalWeb/screenshots';

  // ── 1. Login (admin already created from prior run) ───────────────
  console.log('1. Logging in...');
  await page.goto(BASE + '/login', { waitUntil: 'networkidle' });
  const title = await page.title();
  if (title.includes('Setup')) {
    await page.locator('#username').fill('admin');
    await page.locator('#email').fill('admin@example.com');
    await page.locator('#password').fill('Password123!');
    await page.locator('button[type="submit"]').click();
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);
  }
  await page.goto(BASE + '/login', { waitUntil: 'networkidle' });
  await page.locator('#email').fill('admin@example.com');
  await page.locator('#password').fill('Password123!');
  await page.locator('button[type="submit"]').click();
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(1000);
  console.log('   Logged in. URL:', page.url());

  // ── 2. Create orders via the classic UI form ──────────────────────
  console.log('2. Creating sample orders...');
  const orders = [
    { num: 'ORD-001', status: 'Open',     date: '2026-02-15', notes: 'First batch of widgets' },
    { num: 'ORD-002', status: 'Approved',  date: '2026-02-16', notes: 'Bulk connectors' },
    { num: 'ORD-003', status: 'Open',      date: '2026-02-18', notes: 'Replacement parts' },
    { num: 'ORD-004', status: 'Cancelled', date: '2026-02-19', notes: 'Wrong specification' },
    { num: 'ORD-005', status: 'Open',      date: '2026-02-20', notes: 'Rush delivery needed' },
  ];

  // Get CSRF token and cookies via meta tag from vnext page
  await page.goto(BASE + '/vnext', { waitUntil: 'networkidle' });
  await page.waitForTimeout(1000);
  const csrfToken = await page.locator('meta[name="csrf-token"]').getAttribute('content');
  console.log('   CSRF token obtained:', csrfToken ? 'yes' : 'no');

  // Get a customer ID for the lookup
  const customersResp = await page.evaluate(() => fetch('/api/customers').then(r => r.json()));
  const customerId = customersResp?.[0]?.Id || customersResp?.[0]?.id || '';
  console.log('   Customer ID for orders:', customerId || '(none)');

  // Get a currency ID
  const currenciesResp = await page.evaluate(() => fetch('/api/currencies').then(r => r.json()));
  const currencyId = currenciesResp?.[0]?.Id || currenciesResp?.[0]?.id || '';
  console.log('   Currency ID for orders:', currencyId || '(none)');

  for (const o of orders) {
    const body = {
      OrderNumber: o.num,
      CustomerId: customerId,
      OrderDate: o.date,
      Status: o.status,
      CurrencyId: currencyId,
      Notes: o.notes,
      IsOpen: o.status === 'Open'
    };
    try {
      await page.evaluate(async ({ body, csrf }) => {
        const r = await fetch('/api/orders', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'BareMetalWeb',
            'X-CSRF-Token': csrf
          },
          body: JSON.stringify(body)
        });
        if (!r.ok) throw new Error(await r.text());
        return r.json();
      }, { body, csrf: csrfToken });
      console.log('   Created', o.num);
    } catch (e) {
      console.log('   Failed to create', o.num, ':', e.message?.substring(0, 80));
    }
  }

  // ── 3. Classic UI screenshots ─────────────────────────────────────
  console.log('\n3. Classic UI — Customers list...');
  await page.goto(BASE + '/admin/data/customers', { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);
  await page.screenshot({ path: SHOTS + '/01-classic-customers-list.png', fullPage: true });

  console.log('4. Classic UI — Orders list...');
  await page.goto(BASE + '/admin/data/orders', { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);
  await page.screenshot({ path: SHOTS + '/02-classic-orders-list.png', fullPage: true });

  console.log('5. Classic UI — Order detail...');
  const orderLink = page.locator('table tbody tr td a').first();
  if (await orderLink.count() > 0) {
    await orderLink.click();
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(500);
    await page.screenshot({ path: SHOTS + '/03-classic-order-detail.png', fullPage: true });
  }

  // ── 4. VNext UI screenshots ───────────────────────────────────────
  console.log('6. VNext — Home...');
  await page.goto(BASE + '/vnext', { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);
  await page.screenshot({ path: SHOTS + '/04-vnext-home.png', fullPage: true });

  console.log('7. VNext — Orders list...');
  await page.goto(BASE + '/vnext/orders', { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);
  await page.screenshot({ path: SHOTS + '/05-vnext-orders-list.png', fullPage: true });

  // View first order
  console.log('8. VNext — Order view...');
  const viewBtn = page.locator('button.btn-outline-primary').first();
  if (await viewBtn.count() > 0) {
    await viewBtn.click();
    await page.waitForTimeout(2000);
    await page.screenshot({ path: SHOTS + '/06-vnext-order-view.png', fullPage: true });

    // Edit
    console.log('9. VNext — Order edit...');
    const editLink = page.locator('a.btn-primary');
    if (await editLink.count() > 0) {
      await editLink.first().click();
      await page.waitForTimeout(2000);
      await page.screenshot({ path: SHOTS + '/07-vnext-order-edit.png', fullPage: true });
    }
  }

  // Create form
  console.log('10. VNext — Create order...');
  await page.goto(BASE + '/vnext/orders/create', { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);
  await page.screenshot({ path: SHOTS + '/08-vnext-order-create.png', fullPage: true });

  // Customers list
  console.log('11. VNext — Customers list...');
  await page.goto(BASE + '/vnext/customers', { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);
  await page.screenshot({ path: SHOTS + '/09-vnext-customers-list.png', fullPage: true });

  await browser.close();
  console.log('\nDone! Screenshots saved to', SHOTS);
})();
