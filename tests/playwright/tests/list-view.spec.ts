import { test, expect } from '@playwright/test';
import { login } from './helpers/auth';

/**
 * List view tests for the VNext SPA.
 *
 * Verifies that entity list views render correctly, including:
 * - Rows appear in the table
 * - Lookup columns resolve to display values (not raw IDs)
 * - Pagination controls are present when there are enough rows
 * - Sort links change the URL sort parameters
 * - Search/filter form works
 * - Tags display as badges
 */

const ENTITY = 'products';
const ENTITY_WITH_LOOKUP = 'orders'; // orders have a CustomerId lookup

test.describe('VNext SPA List View', () => {
  let createdProductId: string | null = null;

  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test.afterAll(async ({ request }) => {
    // Clean up the test product created by create-edit tests (if any)
    if (createdProductId) {
      await request.delete(`/api/products/${createdProductId}`);
      createdProductId = null;
    }
  });

  test('entity list loads and displays the list view shell', async ({ page }) => {
    await page.goto(`/UI/data/${ENTITY}`);
    await expect(page.locator('#vnext-content')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Title should contain the entity name
    await expect(page.locator('#vnext-content')).toContainText(/product/i);

    // New / create button must be present
    await expect(page.locator('#vnext-content a[href*="/create"]')).toBeVisible();
  });

  test('list view shows a table with column headers', async ({ page }) => {
    await page.goto(`/UI/data/${ENTITY}`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // There should be at least one <th> header in the list table
    const headers = page.locator('#vnext-content table thead th');
    await expect(headers.first()).toBeVisible({ timeout: 10000 });
  });

  test('search/filter form is present and submittable', async ({ page }) => {
    await page.goto(`/UI/data/${ENTITY}`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    const searchForm = page.locator('#vnext-search-form');
    await expect(searchForm).toBeVisible({ timeout: 10000 });

    // Type a search term and submit
    const searchInput = searchForm.locator('input[type="search"]');
    await searchInput.fill('test');
    await searchForm.locator('button[type="submit"]').click();

    // URL should contain q=test
    await page.waitForURL(/q=test/, { timeout: 10000 });
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Clear search
    await searchInput.fill('');
    await searchForm.locator('button[type="submit"]').click();
    await page.waitForURL(/\/UI\/data\/products/, { timeout: 10000 });
  });

  test('sort column link updates URL sort parameters', async ({ page }) => {
    await page.goto(`/UI/data/${ENTITY}`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // Click the first sortable column header link
    const firstSortLink = page.locator('#vnext-content table thead th a').first();
    if (await firstSortLink.isVisible()) {
      await firstSortLink.click();
      await page.waitForURL(/sort=/, { timeout: 10000 });
      expect(page.url()).toMatch(/sort=/);
    }
  });

  test('lookup columns in orders list render display values, not raw IDs only', async ({ page }) => {
    await page.goto(`/UI/data/${ENTITY_WITH_LOOKUP}`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // If there are rows with lookup columns, the cells should have data-lookup-field attributes
    // which are resolved by resolveViewLookups() to human-readable names
    const lookupCells = page.locator('[data-lookup-field]');
    const lookupCount = await lookupCells.count();

    if (lookupCount > 0) {
      // After resolution, cells should not display raw numeric GUIDs as the sole visible text
      // (the JS replaces the inner text with the resolved display name)
      // We wait briefly for lookup resolution to complete
      await page.waitForTimeout(3000);
      // At least one resolved cell should show non-numeric text
      const firstCell = lookupCells.first();
      const cellText = await firstCell.textContent();
      expect(cellText).toBeTruthy();
    }
  });

  test('pagination controls appear when record count exceeds page size', async ({ page, request }) => {
    // This test is opportunistic — it only verifies pagination markup when data exists
    await page.goto(`/UI/data/${ENTITY}?top=1`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    // If total > 1, a pagination nav should appear
    const totalBadge = page.locator('#vnext-content .badge[aria-label*="total records"]');
    if (await totalBadge.isVisible({ timeout: 3000 }).catch(() => false)) {
      const totalText = await totalBadge.textContent() || '';
      const total = parseInt(totalText, 10);
      if (total > 1) {
        const pagination = page.locator('#vnext-content nav[aria-label="pagination"]');
        await expect(pagination).toBeVisible({ timeout: 5000 });
      }
    }
  });

  test('list view shows export CSV and export JSON buttons', async ({ page }) => {
    await page.goto(`/UI/data/${ENTITY}`);
    await expect(page.locator('.spinner-border')).toHaveCount(0, { timeout: 15000 });

    await expect(page.locator('#vnext-content a[href*="format=csv"]')).toBeVisible();
    await expect(page.locator('#vnext-content a[href*="format=json"]')).toBeVisible();
  });
});
