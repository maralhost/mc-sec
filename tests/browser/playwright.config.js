// Development-only. The pages come from the local preview (tests/tools/preview.php): demo data, a fixed clock,
// Http and DNS mocked. No real scan, no credits, no outside request.
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: '.',
  timeout: 60000,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:8796',
    viewport: { width: 1280, height: 900 },
    browserName: 'chromium',
    // MCSEC_CHROME: path of a Chromium already on this machine, when `npx playwright install chromium` cannot download one
    launchOptions: process.env.MCSEC_CHROME ? { executablePath: process.env.MCSEC_CHROME } : {},
  },
  webServer: {
    command: 'php -S 127.0.0.1:8796 tests/tools/preview.php',
    cwd: '../..',
    url: 'http://127.0.0.1:8796/index.php?m=mcsec',
    reuseExistingServer: true,
    timeout: 30000,
  },
});
