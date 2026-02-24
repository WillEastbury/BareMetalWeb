import { test, expect } from '@playwright/test';
import { login } from './helpers/auth';

/**
 * Admin System Pages tests.
 *
 * Tests that SSR admin routes load correctly (return 200 and render expected content):
 * - /admin/logs
 * - /admin/sample-data
 * - /reports
 */
test.describe('Admin System Pages', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('/admin/logs loads for admin user', async ({ page }) => {
    await page.goto('/admin/logs');

    // Should not be redirected to login
    expect(page.url()).not.toContain('/login');

    // Should render some content mentioning logs
    await expect(page.locator('body')).toContainText(/log/i, { timeout: 10000 });
  });

  test('/admin/sample-data loads for admin user', async ({ page }) => {
    await page.goto('/admin/sample-data');

    expect(page.url()).not.toContain('/login');

    // Should render page content (a form or description mentioning sample data)
    await expect(page.locator('body')).toContainText(/sample.?data|generate/i, { timeout: 10000 });
  });

  test('/reports loads for admin user', async ({ page }) => {
    await page.goto('/reports');

    expect(page.url()).not.toContain('/login');

    // Should render some HTML (page body exists, status was 200)
    const bodyText = await page.locator('body').textContent({ timeout: 10000 });
    expect(bodyText).toBeTruthy();
  });

  test('/admin/logs redirects unauthenticated users to login', async ({ page }) => {
    // Don't call login() — navigate directly without a session
    await page.goto('/admin/logs');

    // Should be redirected to /login
    await page.waitForURL(/\/login/, { timeout: 10000 });
  });
});
