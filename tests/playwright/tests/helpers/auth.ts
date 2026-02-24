import { Page } from '@playwright/test';

const USERNAME = process.env.CIMIGRATE_TEST_USERNAME || 'admin';
const PASSWORD = process.env.CIMIGRATE_TEST_PASSWORD || 'Admin123!';

/**
 * Log in with the configured test credentials.
 * Navigates to /login, fills credentials, and waits for the post-login redirect.
 */
export async function login(page: Page): Promise<void> {
  await page.goto('/login');
  await page.waitForSelector('input[name="username"], input[id="username"]', { timeout: 10000 });
  await page.fill('input[name="username"], input[id="username"]', USERNAME);
  await page.fill('input[name="password"][type="password"]', PASSWORD);
  await page.click('button[type="submit"], input[type="submit"]');
  await page.waitForURL(/^(?!.*\/login).*$/, { timeout: 15000 });
}
