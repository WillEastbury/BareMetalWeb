import { test, expect } from '@playwright/test';

/**
 * Static asset availability tests.
 * These tests verify that key static files are served with HTTP 200 and correct content types.
 * They do NOT require authentication.
 */
test.describe('Static Assets', () => {
  test('/static/css/site.css returns 200', async ({ request }) => {
    const response = await request.get('/static/css/site.css');
    expect(response.status()).toBe(200);
    const contentType = response.headers()['content-type'] || '';
    expect(contentType).toContain('text/css');
  });

  test('/static/js/vnext-app.js returns 200', async ({ request }) => {
    const response = await request.get('/static/js/vnext-app.js');
    expect(response.status()).toBe(200);
    const contentType = response.headers()['content-type'] || '';
    expect(contentType).toContain('javascript');
  });

  test('/static/js/BareMetalRouting.js returns 200', async ({ request }) => {
    const response = await request.get('/static/js/BareMetalRouting.js');
    expect(response.status()).toBe(200);
  });

  test('/static/js/BareMetalRest.js returns 200', async ({ request }) => {
    const response = await request.get('/static/js/BareMetalRest.js');
    expect(response.status()).toBe(200);
  });

  test('/static/css/bootstrap.min.css returns 200', async ({ request }) => {
    const response = await request.get('/static/css/bootstrap.min.css');
    expect(response.status()).toBe(200);
    const contentType = response.headers()['content-type'] || '';
    expect(contentType).toContain('text/css');
  });
});
