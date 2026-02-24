import { test, expect } from '@playwright/test';

const USERNAME = process.env.CIMIGRATE_TEST_USERNAME || 'admin';
const PASSWORD = process.env.CIMIGRATE_TEST_PASSWORD || 'Admin123!';

test.describe('VNext SPA Navigation & Routing', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[name="username"], input[id="username"]', USERNAME);
    await page.fill('input[name="password"][type="password"]', PASSWORD);
    await page.click('button[type="submit"], input[type="submit"]');
    await page.waitForURL(/^(?!.*\/login).*$/, { timeout: 10000 });
  });

  test('/UI loads VNext SPA shell', async ({ page }) => {
    await page.goto('/UI');
    await expect(page).not.toHaveURL(/404/);
    await expect(page.locator('#vnext-content, [data-vnext-app]')).toBeVisible({ timeout: 10000 });
  });

  test('/UI/data/{entity} loads entity list view', async ({ page }) => {
    await page.goto('/UI/data/customers');
    await expect(page).not.toHaveURL(/404/);
    // Should have a table or card list
    await expect(page.locator('table, .card').first()).toBeVisible({ timeout: 10000 });
  });

  test('/UI/data/{entity}/create loads create form', async ({ page }) => {
    await page.goto('/UI/data/customers/create');
    await expect(page).not.toHaveURL(/404/);
    await expect(page.locator('form, input[name]').first()).toBeVisible({ timeout: 10000 });
  });

  test('sidebar/nav entity links navigate correctly', async ({ page }) => {
    await page.goto('/UI');
    // Find and click a nav link
    const navLink = page.locator('a[href*="/UI/data/"]').first();
    if (await navLink.isVisible({ timeout: 5000 })) {
      await navLink.click();
      await expect(page).not.toHaveURL(/404/);
      await expect(page.locator('table, .card, form').first()).toBeVisible({ timeout: 10000 });
    }
  });

  test('deep-link directly to entity page works', async ({ page }) => {
    await page.goto('/UI/data/products');
    await expect(page).not.toHaveURL(/404/);
    await expect(page.locator('table, .card').first()).toBeVisible({ timeout: 10000 });
  });

  test('browser back/forward navigates SPA history', async ({ page }) => {
    await page.goto('/UI/data/customers');
    await page.waitForSelector('table, .card', { timeout: 10000 });

    // Navigate to another entity
    await page.goto('/UI/data/products');
    await page.waitForSelector('table, .card', { timeout: 10000 });

    // Go back
    await page.goBack();
    await expect(page).toHaveURL(/customers/);
  });
});
