import { test, expect } from '@playwright/test';

const USERNAME = process.env.CIMIGRATE_TEST_USERNAME || 'admin';
const PASSWORD = process.env.CIMIGRATE_TEST_PASSWORD || 'Admin123!';

test.describe('VNext Create & Edit Forms', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[name="username"], input[id="username"]', USERNAME);
    await page.fill('input[name="password"][type="password"]', PASSWORD);
    await page.click('button[type="submit"], input[type="submit"]');
    await page.waitForURL(/^(?!.*\/login).*$/, { timeout: 10000 });
  });

  test('create form renders all field types', async ({ page }) => {
    await page.goto('/UI/data/products/create');
    await page.waitForSelector('form, input[name]', { timeout: 10000 });
    // Should have text inputs, selects, etc.
    await expect(page.locator('input, select, textarea').first()).toBeVisible();
  });

  test('required field validation fires on empty submit', async ({ page }) => {
    await page.goto('/UI/data/customers/create');
    await page.waitForSelector('form', { timeout: 10000 });
    // Try to submit empty form
    const submitBtn = page.locator('button[type="submit"], button:has-text("Save"), button:has-text("Create")');
    if (await submitBtn.isVisible({ timeout: 3000 })) {
      await submitBtn.click();
      // Should show validation errors (is-invalid class or native validation)
      await page.waitForTimeout(1000);
      const invalidFields = page.locator('.is-invalid, :invalid');
      expect(await invalidFields.count()).toBeGreaterThan(0);
    }
  });

  test('tag input: add via Enter, remove via × button', async ({ page }) => {
    await page.goto('/UI/data/products/create');
    await page.waitForSelector('form', { timeout: 10000 });

    const tagInput = page.locator('.vnext-tag-input');
    if (await tagInput.isVisible({ timeout: 3000 })) {
      // Add a tag
      await tagInput.fill('test-tag');
      await tagInput.press('Enter');
      // Should create a pill
      await expect(page.locator('.vnext-tag-pill')).toHaveCount(1);

      // Add another via comma
      await tagInput.fill('another-tag,');
      await page.waitForTimeout(500);
      await expect(page.locator('.vnext-tag-pill')).toHaveCount(2);

      // Remove via × button
      await page.locator('.vnext-tag-pill .btn-close').first().click();
      await expect(page.locator('.vnext-tag-pill')).toHaveCount(1);
    }
  });

  test('tag input: remove via Backspace', async ({ page }) => {
    await page.goto('/UI/data/products/create');
    await page.waitForSelector('form', { timeout: 10000 });

    const tagInput = page.locator('.vnext-tag-input');
    if (await tagInput.isVisible({ timeout: 3000 })) {
      // Add a tag first
      await tagInput.fill('remove-me');
      await tagInput.press('Enter');
      await expect(page.locator('.vnext-tag-pill')).toHaveCount(1);

      // Backspace on empty input should remove last tag
      await tagInput.press('Backspace');
      await expect(page.locator('.vnext-tag-pill')).toHaveCount(0);
    }
  });

  test('lookup dropdowns populate with options', async ({ page }) => {
    await page.goto('/UI/data/orders/create');
    await page.waitForSelector('form', { timeout: 10000 });

    // Lookup select should have options loaded
    const lookupSelect = page.locator('select[name="CustomerId"], select[name="customerId"]');
    if (await lookupSelect.isVisible({ timeout: 5000 })) {
      await page.waitForTimeout(3000); // wait for async option loading
      const optionCount = await lookupSelect.locator('option').count();
      // Should have more than just the "Loading..." placeholder
      expect(optionCount).toBeGreaterThan(1);
    }
  });
});
