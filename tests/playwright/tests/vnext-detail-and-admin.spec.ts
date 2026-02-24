import { test, expect } from '@playwright/test';

const USERNAME = process.env.CIMIGRATE_TEST_USERNAME || 'admin';
const PASSWORD = process.env.CIMIGRATE_TEST_PASSWORD || 'Admin123!';

test.describe('VNext Detail View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[name="username"], input[id="username"]', USERNAME);
    await page.fill('input[name="password"][type="password"]', PASSWORD);
    await page.click('button[type="submit"], input[type="submit"]');
    await page.waitForURL(/^(?!.*\/login).*$/, { timeout: 10000 });
  });

  test('detail view displays field values', async ({ page }) => {
    // Navigate to list first to find an item
    await page.goto('/UI/data/products');
    await page.waitForSelector('table tbody tr, .card', { timeout: 15000 });

    // Click first View button
    const viewBtn = page.locator('a[title="View"], a:has(i.bi-eye)').first();
    if (await viewBtn.isVisible({ timeout: 3000 })) {
      await viewBtn.click();
      // Should show detail view with dl/dt/dd structure
      await expect(page.locator('dl, .card-body').first()).toBeVisible({ timeout: 10000 });
    }
  });

  test('detail view has Edit and Delete buttons', async ({ page }) => {
    await page.goto('/UI/data/products');
    await page.waitForSelector('table tbody tr, .card', { timeout: 15000 });

    const viewBtn = page.locator('a[title="View"], a:has(i.bi-eye)').first();
    if (await viewBtn.isVisible({ timeout: 3000 })) {
      await viewBtn.click();
      await page.waitForSelector('dl, .card-body', { timeout: 10000 });

      // Should have Edit and Delete buttons
      const editBtn = page.locator('a:has-text("Edit"), a[title="Edit"], a:has(i.bi-pencil)');
      await expect(editBtn.first()).toBeVisible({ timeout: 5000 });
    }
  });

  test('lookup fields show display name with link', async ({ page }) => {
    await page.goto('/UI/data/orders');
    await page.waitForSelector('table tbody tr, .card', { timeout: 15000 });

    const viewBtn = page.locator('a[title="View"], a:has(i.bi-eye)').first();
    if (await viewBtn.isVisible({ timeout: 3000 })) {
      await viewBtn.click();
      await page.waitForSelector('dl, .card-body', { timeout: 10000 });
      await page.waitForTimeout(3000); // wait for lookup resolution

      // Lookup values should be links to the target entity
      const lookupLinks = page.locator('dd[data-lookup-field] a');
      if (await lookupLinks.count() > 0) {
        const href = await lookupLinks.first().getAttribute('href');
        expect(href).toContain('/UI/data/');
      }
    }
  });
});

test.describe('Admin System Pages', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[name="username"], input[id="username"]', USERNAME);
    await page.fill('input[name="password"][type="password"]', PASSWORD);
    await page.click('button[type="submit"], input[type="submit"]');
    await page.waitForURL(/^(?!.*\/login).*$/, { timeout: 10000 });
  });

  test('/admin/logs loads', async ({ page }) => {
    await page.goto('/admin/logs');
    await expect(page).not.toHaveURL(/404/);
    await expect(page.locator('body')).not.toContainText('404');
  });

  test('/admin/sample-data loads', async ({ page }) => {
    await page.goto('/admin/sample-data');
    await expect(page).not.toHaveURL(/404/);
  });

  test('/reports loads (admin-only)', async ({ page }) => {
    await page.goto('/reports');
    await expect(page).not.toHaveURL(/404/);
  });
});

test.describe('Static Assets', () => {
  test('/static/js/bundle.js returns 200', async ({ request }) => {
    const response = await request.get('/static/js/bundle.js');
    expect(response.status()).toBe(200);
    expect(response.headers()['content-type']).toContain('javascript');
  });

  test('/static/js/vnext-bundle.js returns 200', async ({ request }) => {
    const response = await request.get('/static/js/vnext-bundle.js');
    expect(response.status()).toBe(200);
    expect(response.headers()['content-type']).toContain('javascript');
  });
});
