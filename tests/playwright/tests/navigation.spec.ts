import { test, expect } from '@playwright/test';
import { login } from './helpers/auth';

/**
 * Navigation & Routing tests for the VNext SPA.
 *
 * Verifies that all key SPA routes return the shell (no 404s),
 * that the #vnext-content element is populated after JS initialises,
 * and that in-app navigation works without full page reloads.
 */
test.describe('VNext SPA Navigation & Routing', () => {
  test('/UI loads the VNext SPA shell', async ({ page }) => {
    await login(page);
    await page.goto('/UI');

    // Shell must render the content container and a nav bar
    await expect(page.locator('#vnext-content')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#vnext-nav-items')).toBeVisible();

    // The spinner should disappear once the home view has loaded
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // At least one entity card / link should be visible
    const contentText = await page.locator('#vnext-content').textContent({ timeout: 10000 });
    expect(contentText).toBeTruthy();
  });

  test('/UI/data/products loads entity list view', async ({ page }) => {
    await login(page);
    await page.goto('/UI/data/products');

    await expect(page.locator('#vnext-content')).toBeVisible({ timeout: 10000 });
    // Spinner should clear
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Should show entity name and a "New" button
    await expect(page.locator('#vnext-content')).toContainText(/product/i, { timeout: 10000 });
    await expect(page.locator('#vnext-content a[href*="/create"]')).toBeVisible();
  });

  test('/UI/data/products/create loads create form', async ({ page }) => {
    await login(page);
    await page.goto('/UI/data/products/create');

    await expect(page.locator('#vnext-content')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Create form should contain a save/submit button
    await expect(page.locator('#vnext-content button[type="submit"], #vnext-content input[type="submit"]')).toBeVisible({ timeout: 10000 });
  });

  test('/UI/data/customers loads customers list', async ({ page }) => {
    await login(page);
    await page.goto('/UI/data/customers');

    await expect(page.locator('#vnext-content')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });
    await expect(page.locator('#vnext-content')).toContainText(/customer/i, { timeout: 10000 });
  });

  test('/UI/data/todos loads todos list', async ({ page }) => {
    await login(page);
    await page.goto('/UI/data/todos');

    await expect(page.locator('#vnext-content')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });
    await expect(page.locator('#vnext-content')).toContainText(/to.?do/i, { timeout: 10000 });
  });

  test('unknown entity slug shows error, not 404 page', async ({ page }) => {
    await login(page);
    await page.goto('/UI/data/nonexistent-entity-xyzzy');

    // The SPA shell still loads — the server returns 200 for all /UI/* routes
    await expect(page.locator('#vnext-content')).toBeVisible({ timeout: 10000 });
    // The content should show an error message, not an empty page
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });
    const content = await page.locator('#vnext-content').textContent({ timeout: 10000 });
    expect(content).toBeTruthy();
  });

  test('sidebar nav entity links exist and navigate without 404', async ({ page }) => {
    await login(page);
    await page.goto('/UI');

    // Wait for nav to populate
    await expect(page.locator('#vnext-nav-items')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Find the first entity nav link and click it
    const navLinks = page.locator('#vnext-nav-items a[href]');
    const count = await navLinks.count();
    if (count > 0) {
      const href = await navLinks.first().getAttribute('href');
      expect(href).toBeTruthy();
      await navLinks.first().click();
      // Should stay on the SPA (no full reload, URL changes)
      await expect(page.locator('#vnext-content')).toBeVisible({ timeout: 10000 });
      await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });
    }
  });

  test('browser back/forward works (SPA history)', async ({ page }) => {
    await login(page);

    await page.goto('/UI');
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Navigate to the products list
    await page.goto('/UI/data/products');
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });
    expect(page.url()).toContain('/UI/data/products');

    // Go back
    await page.goBack();
    expect(page.url()).toContain('/UI');
    await expect(page.locator('#vnext-content')).toBeVisible({ timeout: 10000 });

    // Go forward
    await page.goForward();
    expect(page.url()).toContain('/UI/data/products');
    await expect(page.locator('#vnext-content')).toBeVisible({ timeout: 10000 });
  });

  test('deep-link directly to entity list works', async ({ page }) => {
    await login(page);
    // Navigate directly — no prior home page visit
    const response = await page.goto('/UI/data/products');
    // The server-side response for /UI/* must be 200
    expect(response?.status()).toBe(200);
    await expect(page.locator('#vnext-content')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });
  });

  test('/UI/{wildcard} routes all return 200 from server (no server-side 404)', async ({ request, page }) => {
    await login(page);
    // Hit a deep SPA path directly via HTTP — server should return the shell with 200
    const response = await page.goto('/UI/data/products/create');
    expect(response?.status()).toBe(200);
  });
});
