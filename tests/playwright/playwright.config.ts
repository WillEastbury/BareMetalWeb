import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report' }],
    ['json', { outputFile: 'test-results.json' }]
  ],
  use: {
    baseURL: process.env.BASE_URL || 'https://baremetalweb-cireset.azurewebsites.net',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    // Setup project: runs first to create the initial admin account on a fresh CI-reset site.
    {
      name: 'setup',
      testMatch: '**/setup-and-login.spec.ts',
    },
    // Main test project: depends on setup completing first.
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['setup'],
      testIgnore: '**/setup-and-login.spec.ts',
    },
  ],
  timeout: 60000,
  expect: {
    timeout: 10000,
  },
});
