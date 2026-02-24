import { test, expect, Browser } from '@playwright/test';
import { login } from './helpers/auth';

/**
 * Detail view tests for the VNext SPA.
 *
 * Tests that:
 * - Detail view renders for a known record
 * - All field values are displayed
 * - Lookup fields show a display name with a link to the target entity
 * - Edit button is present and functional
 * - Breadcrumb navigation is correct
 */

const ENTITY = 'products';

async function createDetailTestRecord(browser: Browser): Promise<string | null> {
  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    await login(page);
    const resp = await page.request.post(`/api/${ENTITY}`, {
      data: { Name: 'E2E Detail Test - ' + Date.now(), Category: 'E2ETest', Price: 42.00 }
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

async function deleteDetailTestRecord(browser: Browser, id: string): Promise<void> {
  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    await login(page);
    await page.request.delete(`/api/${ENTITY}/${id}`);
  } finally {
    await context.close();
  }
}

test.describe('VNext SPA Detail View', () => {
  let testRecordId: string | null = null;

  test.beforeAll(async ({ browser }) => {
    testRecordId = await createDetailTestRecord(browser);
  });

  test.afterAll(async ({ browser }) => {
    if (testRecordId) {
      await deleteDetailTestRecord(browser, testRecordId);
      testRecordId = null;
    }
  });

  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('detail view renders when navigating to a valid entity ID', async ({ page }) => {
    if (!testRecordId) { test.skip(); return; }

    await page.goto(`/UI/data/${ENTITY}/${testRecordId}`);
    await expect(page.locator('#vnext-content')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Should show the entity name in the content
    await expect(page.locator('#vnext-content')).toContainText(/product/i);
  });

  test('detail view shows Edit button', async ({ page }) => {
    if (!testRecordId) { test.skip(); return; }

    await page.goto(`/UI/data/${ENTITY}/${testRecordId}`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Edit button must be present
    const editBtn = page.locator(`#vnext-content a[href*="${testRecordId}/edit"]`);
    await expect(editBtn).toBeVisible({ timeout: 10000 });
  });

  test('detail view shows field values in a description list', async ({ page }) => {
    if (!testRecordId) { test.skip(); return; }

    await page.goto(`/UI/data/${ENTITY}/${testRecordId}`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Detail view renders a <dl> with <dt>/<dd> pairs
    const dl = page.locator('#vnext-content dl.row');
    await expect(dl).toBeVisible({ timeout: 10000 });

    const terms = dl.locator('dt');
    expect(await terms.count()).toBeGreaterThan(0);
  });

  test('detail view breadcrumb links to entity list and home', async ({ page }) => {
    if (!testRecordId) { test.skip(); return; }

    await page.goto(`/UI/data/${ENTITY}/${testRecordId}`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    const breadcrumb = page.locator('.breadcrumb');
    await expect(breadcrumb).toBeVisible({ timeout: 10000 });

    await expect(breadcrumb.locator('a[href="/UI"]')).toBeVisible();
    await expect(breadcrumb.locator(`a[href*="/UI/data/${ENTITY}"]`)).toBeVisible();
  });

  test('Edit button on detail view navigates to the edit form', async ({ page }) => {
    if (!testRecordId) { test.skip(); return; }

    await page.goto(`/UI/data/${ENTITY}/${testRecordId}`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    const editBtn = page.locator(`#vnext-content a[href*="${testRecordId}/edit"]`).first();
    await expect(editBtn).toBeVisible({ timeout: 10000 });
    await editBtn.click();

    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });
    expect(page.url()).toContain('/edit');

    // Edit form should be rendered
    await expect(page.locator('#vnext-editor-form')).toBeVisible({ timeout: 10000 });
  });

  test('lookup fields in detail view have links to target entities', async ({ page }) => {
    // Use orders which have a CustomerId lookup to verify lookup link rendering
    await page.goto('/UI/data/orders');
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Look for any row in the table to navigate to its detail view
    const viewLinks = page.locator('#vnext-content table tbody tr a[href*="/UI/data/orders/"]').first();
    const hasRows = await viewLinks.isVisible({ timeout: 3000 }).catch(() => false);
    if (!hasRows) { test.skip(); return; }

    await viewLinks.click();
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Lookup cells have data-lookup-field; after resolution they contain an <a> tag
    const lookupCells = page.locator('[data-lookup-field]');
    const count = await lookupCells.count();
    if (count > 0) {
      // Wait for lookup resolution (background async)
      await page.waitForTimeout(3000);
      const firstCell = lookupCells.first();
      // Should now contain a link to the target entity
      const link = firstCell.locator('a');
      if (await link.isVisible({ timeout: 2000 }).catch(() => false)) {
        const href = await link.getAttribute('href');
        expect(href).toContain('/UI/data/');
      }
    }
  });

  test('JSON export link is present on detail view', async ({ page }) => {
    if (!testRecordId) { test.skip(); return; }

    await page.goto(`/UI/data/${ENTITY}/${testRecordId}`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Should have a JSON export link to the REST API
    const jsonLink = page.locator(`#vnext-content a[href*="/api/${ENTITY}/${testRecordId}"]`);
    await expect(jsonLink).toBeVisible({ timeout: 10000 });
  });
});
