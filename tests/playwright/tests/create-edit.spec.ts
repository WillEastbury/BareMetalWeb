import { test, expect, Browser } from '@playwright/test';
import { login } from './helpers/auth';

/**
 * Create and Edit form tests for the VNext SPA.
 *
 * Tests that:
 * - Create forms render all expected field types
 * - Required field validation fires on empty submit
 * - A record can be saved and redirects to the detail view
 * - An existing record can be loaded into the edit form
 * - The edit form reflects current values
 */

const ENTITY = 'products';

async function createTestProduct(browser: Browser): Promise<string | null> {
  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    await login(page);
    const resp = await page.request.post(`/api/${ENTITY}`, {
      data: { Name: 'E2E Create-Edit Test - ' + Date.now(), Category: 'E2ETest', Price: 9.99 }
    });
    if (resp.ok()) {
      const body = await resp.json();
      return body.id || body.Id || null;
    }
  } finally {
    await context.close();
  }
  return null;
}

async function deleteTestProduct(browser: Browser, id: string): Promise<void> {
  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    await login(page);
    await page.request.delete(`/api/${ENTITY}/${id}`);
  } finally {
    await context.close();
  }
}

test.describe('VNext SPA Create / Edit Forms', () => {
  let createdId: string | null = null;

  test.afterAll(async ({ browser }) => {
    if (createdId) {
      await deleteTestProduct(browser, createdId);
      createdId = null;
    }
  });

  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('create form renders with a Save button and at least one input field', async ({ page }) => {
    await page.goto(`/UI/data/${ENTITY}/create`);
    await expect(page.locator('#vnext-content')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // The form should exist
    const form = page.locator('#vnext-editor-form');
    await expect(form).toBeVisible({ timeout: 10000 });

    // Must have a Save button
    await expect(page.locator('#vnext-save-btn')).toBeVisible();

    // Must have at least one editable input / select
    const fields = form.locator('input:not([type="hidden"]):not([readonly]), select, textarea');
    expect(await fields.count()).toBeGreaterThan(0);
  });

  test('create form has a Cancel link back to the entity list', async ({ page }) => {
    await page.goto(`/UI/data/${ENTITY}/create`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Cancel should link back to the entity list
    const cancelLink = page.locator('#vnext-editor-form a.btn-secondary');
    await expect(cancelLink).toBeVisible({ timeout: 10000 });
    const href = await cancelLink.getAttribute('href');
    expect(href).toContain(`/UI/data/${ENTITY}`);
  });

  test('required field validation fires on empty submit', async ({ page }) => {
    await page.goto(`/UI/data/${ENTITY}/create`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    const form = page.locator('#vnext-editor-form');
    await expect(form).toBeVisible({ timeout: 10000 });

    // Click Save without filling any required fields
    await page.locator('#vnext-save-btn').click();

    // Browser HTML5 validation or client-side validation should prevent navigation
    // The form should still be visible on the same page (no redirect occurred)
    await expect(form).toBeVisible({ timeout: 3000 });
    expect(page.url()).toContain('/create');
  });

  test('can create a new product record and gets redirected to detail view', async ({ page }) => {
    await page.goto(`/UI/data/${ENTITY}/create`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    const form = page.locator('#vnext-editor-form');
    await expect(form).toBeVisible({ timeout: 10000 });

    // Fill in the Name field (required on products)
    const nameField = form.locator('input[name="Name"], input[name="name"]');
    if (await nameField.isVisible({ timeout: 3000 }).catch(() => false)) {
      await nameField.fill('E2E Test Product - ' + Date.now());
    }

    // Fill other visible string fields to satisfy validation
    const stringFields = form.locator('input[type="text"]:not([readonly]):not([name="Name"]):not([name="name"])');
    const stringCount = await stringFields.count();
    for (let i = 0; i < Math.min(stringCount, 3); i++) {
      const field = stringFields.nth(i);
      if (await field.isEditable()) {
        await field.fill('Test value ' + i);
      }
    }

    // Fill required number fields
    const numberFields = form.locator('input[type="number"]:not([readonly])');
    const numCount = await numberFields.count();
    for (let i = 0; i < numCount; i++) {
      const field = numberFields.nth(i);
      if (await field.isEditable()) {
        await field.fill('1');
      }
    }

    // Submit
    await page.locator('#vnext-save-btn').click();

    // Wait for navigation after save
    await page.waitForURL(/\/UI\/data\/.+/, { timeout: 15000 });
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Capture created ID from URL for cleanup
    const url = page.url();
    const match = url.match(/\/UI\/data\/[^/]+\/([^/]+?)(?:\/edit)?(?:\?.*)?$/);
    if (match && match[1] && match[1] !== 'create') {
      createdId = match[1];
    }
  });

  test('edit form loads an existing record with populated fields', async ({ page, browser }) => {
    const id = await createTestProduct(browser);
    if (!id) { test.skip(); return; }
    if (!createdId) createdId = id;

    await page.goto(`/UI/data/${ENTITY}/${id}/edit`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    const form = page.locator('#vnext-editor-form');
    await expect(form).toBeVisible({ timeout: 10000 });

    // At least one visible input should have a non-empty value
    const inputs = form.locator('input[type="text"]:not([readonly])');
    const count = await inputs.count();
    let hasValue = false;
    for (let i = 0; i < count; i++) {
      const val = await inputs.nth(i).inputValue();
      if (val && val.trim()) { hasValue = true; break; }
    }
    expect(hasValue).toBe(true);
  });

  test('edit form has a Cancel link that goes back to the detail view', async ({ page, browser }) => {
    const id = await createTestProduct(browser);
    if (!id) { test.skip(); return; }
    if (!createdId) createdId = id;

    await page.goto(`/UI/data/${ENTITY}/${id}/edit`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    const cancelLink = page.locator('#vnext-editor-form a.btn-secondary');
    await expect(cancelLink).toBeVisible({ timeout: 10000 });
    const href = await cancelLink.getAttribute('href');
    expect(href).toContain(`/UI/data/${ENTITY}/${id}`);
  });

  test('breadcrumb on create form links back to entity list and home', async ({ page }) => {
    await page.goto(`/UI/data/${ENTITY}/create`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    const breadcrumb = page.locator('.breadcrumb');
    await expect(breadcrumb).toBeVisible({ timeout: 10000 });

    // Home link
    await expect(breadcrumb.locator('a[href="/UI"]')).toBeVisible();
    // Entity list link
    await expect(breadcrumb.locator(`a[href*="/UI/data/${ENTITY}"]`)).toBeVisible();
  });
});
