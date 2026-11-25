// What must keep working whatever the styling: the pages without JavaScript, the keyboard, direction of technical
// values, no request to any outside host, and no page wider than a narrow screen.
const { test, expect } = require('@playwright/test');
const { client, url } = require('./pages');

test.describe('without JavaScript', () => {
  test.use({ javaScriptEnabled: false });
  for (const [name, p] of client) {
    test(`${name} renders and its main content is there`, async ({ page }) => {
      await page.goto(url(p, 'fa', false));
      await expect(page.locator('.mcs .mcs-view')).toBeVisible();
      expect((await page.locator('.mcs .mcs-view').innerText()).length).toBeGreaterThan(80);
    });
  }
  test('findings: the filter is a plain GET form and the pager is plain links', async ({ page }) => {
    await page.goto(url('/index.php?m=mcsec&p=findings', 'fa', false));
    await expect(page.locator('.mcs form.mcs-filters[method="get"]')).toHaveCount(1);
    await page.locator('.mcs form.mcs-filters button[type="submit"]').click();
    await expect(page).toHaveURL(/p=findings/);
  });
  test('a drawer opens without script', async ({ page }) => {
    await page.goto('/catalog.php?x=1');
    const d = page.locator('.mcs details').first();
    await d.locator('summary').click();
    await expect(d).toHaveAttribute('open', '');
  });
});

test('no request leaves the page for another host', async ({ page }) => {
  const outside = [];
  page.on('request', (r) => { if (!r.url().startsWith('http://127.0.0.1:8796') && !r.url().startsWith('data:')) outside.push(r.url()); });
  for (const [, p] of client) {
    await page.goto(url(p, 'fa', false));
  }
  expect(outside).toEqual([]);
});

test('keyboard: focus moves through the findings page and is visible', async ({ page }) => {
  await page.goto(url('/index.php?m=mcsec&p=findings', 'fa', false));
  const seen = new Set();
  for (let i = 0; i < 25; i++) {
    await page.keyboard.press('Tab');
    const info = await page.evaluate(() => {
      const e = document.activeElement;
      if (!e || e === document.body || !e.closest('.mcs')) return null;
      const s = getComputedStyle(e);
      return { tag: e.tagName, ring: s.outlineStyle !== 'none' || s.boxShadow !== 'none' };
    });
    if (info) seen.add(info.tag + (info.ring ? '+' : '-'));
  }
  expect([...seen].some((x) => x.endsWith('+'))).toBeTruthy();
  expect([...seen].filter((x) => x.endsWith('-'))).toEqual([]);
});

test('technical values keep their own direction in a right-to-left page', async ({ page }) => {
  await page.goto(url('/index.php?m=mcsec&p=findings', 'fa', false));
  const dirs = await page.locator('.mcs bdi[dir="ltr"], .mcs [dir="ltr"]').evaluateAll((els) => els.slice(0, 40).map((e) => getComputedStyle(e).direction));
  expect(dirs.length).toBeGreaterThan(0);
  expect(dirs.every((d) => d === 'ltr')).toBeTruthy();
});

for (const [name, p] of client) {
  test(`${name} fits a narrow screen without sideways scrolling`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(url(p, 'fa', false));
    const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(over).toBeLessThanOrEqual(1);
  });
}
