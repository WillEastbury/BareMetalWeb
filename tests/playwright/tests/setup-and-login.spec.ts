import { test, expect } from '@playwright/test';

test.describe('Initial Setup and Login Flow', () => {
  test('should complete initial setup and login successfully', async ({ page }) => {
    // Navigate to home page - should redirect to setup if no users exist
    await page.goto('/');
    
    // Wait for setup page to load
    await page.waitForURL(/\/setup/, { timeout: 10000 });
    
    // Verify setup page elements
    await expect(page.locator('h1, h2, h3').filter({ hasText: /setup/i }).first()).toBeVisible();
    
    // Fill out setup form
    const username = 'admin';
    const displayName = 'Admin User';
    const password = 'Admin123!';
    
    // Find and fill username field
    await page.fill('input[name="username"], input[id="username"]', username);
    
    // Find and fill display name field
    await page.fill('input[name="displayname"], input[name="displayName"], input[id="displayname"], input[id="displayName"]', displayName);
    
    // Fill password fields
    await page.fill('input[name="password"][type="password"]', password);
    await page.fill('input[name="confirmpassword"], input[name="confirmPassword"], input[name="confirm_password"]', password);
    
    // Submit the form
    await page.click('button[type="submit"], input[type="submit"]');
    
    // Wait for redirect after successful setup
    await page.waitForURL(/^(?!.*\/setup).*$/, { timeout: 10000 });
    
    // Verify we're logged in - check for account or logout link
    const accountLink = page.locator('a[href="/account"], a[href="/logout"]');
    await expect(accountLink.first()).toBeVisible({ timeout: 5000 });
    
    console.log('✓ Setup completed successfully');
  });

  test('should login with created account', async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
    
    // Verify login page loaded
    await expect(page.locator('h1, h2, h3').filter({ hasText: /login/i }).first()).toBeVisible();
    
    // Fill login form
    const username = 'admin';
    const password = 'Admin123!';
    
    await page.fill('input[name="username"], input[id="username"]', username);
    await page.fill('input[name="password"][type="password"]', password);
    
    // Submit login form
    await page.click('button[type="submit"], input[type="submit"]');
    
    // Wait for redirect after successful login
    await page.waitForURL(/^(?!.*\/login).*$/, { timeout: 10000 });
    
    // Verify we're logged in
    const accountLink = page.locator('a[href="/account"], a[href="/logout"]');
    await expect(accountLink.first()).toBeVisible({ timeout: 5000 });
    
    console.log('✓ Login successful');
  });

  test('should logout successfully', async ({ page }) => {
    // First login
    await page.goto('/login');
    await page.fill('input[name="username"], input[id="username"]', 'admin');
    await page.fill('input[name="password"][type="password"]', 'Admin123!');
    await page.click('button[type="submit"], input[type="submit"]');
    await page.waitForURL(/^(?!.*\/login).*$/, { timeout: 10000 });
    
    // Navigate to logout
    await page.goto('/logout');
    
    // If there's a logout confirmation, click it
    const logoutButton = page.locator('button[type="submit"], input[type="submit"]');
    if (await logoutButton.isVisible({ timeout: 2000 })) {
      await logoutButton.click();
    }
    
    // Wait a moment for logout to complete
    await page.waitForTimeout(1000);
    
    // Navigate to home and verify we're logged out
    await page.goto('/');
    
    // Should see login link when logged out
    const loginLink = page.locator('a[href="/login"]');
    await expect(loginLink).toBeVisible({ timeout: 5000 });
    
    console.log('✓ Logout successful');
  });

  test('should prevent access to protected pages when not logged in', async ({ page }) => {
    // Try to access account page without logging in
    await page.goto('/account');
    
    // Should be redirected to login page
    await page.waitForURL(/\/login/, { timeout: 10000 });
    
    console.log('✓ Protected page access correctly blocked');
  });
});
