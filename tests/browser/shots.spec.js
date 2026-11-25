// Full-page pictures of the main screens, in Persian and English, light and dark, wide and narrow.
// SHOTS=before|after chooses the folder (tests/browser/shots/<name>/, not in git), so two runs can be compared.
const { test } = require('@playwright/test');
const path = require('path');
const { client, admin, url } = require('./pages');

const out = path.join(__dirname, 'shots', process.env.SHOTS || 'current');

for (const [name, p] of client) {
  for (const lang of ['fa', 'en']) {
    for (const dark of [false, true]) {
      test(`${name} ${lang} ${dark ? 'dark' : 'light'}`, async ({ page }) => {
        await page.goto(url(p, lang, dark));
        await page.screenshot({ path: path.join(out, `${name}-${lang}-${dark ? 'dark' : 'light'}.png`), fullPage: true });
      });
    }
  }
  test(`${name} fa narrow`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(url(p, 'fa', false));
    await page.screenshot({ path: path.join(out, `${name}-fa-narrow.png`), fullPage: true });
  });
}
for (const [name, p] of admin) {
  test(`${name}`, async ({ page }) => {
    await page.goto(p);
    await page.screenshot({ path: path.join(out, `${name}.png`), fullPage: true });
  });
}
