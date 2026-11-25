// Automated accessibility checks (axe-core, WCAG 2.0/2.1/2.2 A and AA rules) of the module's own markup: the scan is
// limited to .mcs (customer panel) and .mcsa (admin panel), because the page around them is the preview's stand-in
// for the host theme, not ours. An automated pass finds only part of the problems; the manual review is separate.
// A11Y_REPORT=1 lists the violations without failing (to take stock); otherwise any violation fails the test.
const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const { client, admin, url } = require('./pages');

const tags = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
const report = process.env.A11Y_REPORT === '1';

async function scan(page, root, name) {
  const r = await new AxeBuilder({ page }).include(root).withTags(tags).analyze();
  const found = r.violations.map((v) => `${v.id} (${v.impact}) x${v.nodes.length}: ${v.nodes[0].target.join(" ")}` + (report && v.nodes[0].any[0] && v.nodes[0].any[0].data && v.nodes[0].any[0].data.contrastRatio ? ` [${v.nodes[0].any[0].data.fgColor} on ${v.nodes[0].any[0].data.bgColor} = ${v.nodes[0].any[0].data.contrastRatio}]` : ""));
  if (report) {
    console.log(`A11Y ${name}: ${found.length ? found.join(' | ') : 'none'}`);
    return;
  }
  expect(found, name).toEqual([]);
}

for (const [name, p] of client.concat([['catalog', '/catalog.php?x=1']])) {
  for (const lang of ['fa', 'en']) {
    for (const dark of [false, true]) {
      test(`a11y ${name} ${lang} ${dark ? 'dark' : 'light'}`, async ({ page }) => {
        await page.goto(url(p, lang, dark));
        await scan(page, '.mcs', `${name} ${lang} ${dark ? 'dark' : 'light'}`);
      });
    }
  }
}
for (const [name, p] of admin) {
  test(`a11y ${name}`, async ({ page }) => {
    await page.goto(p);
    await scan(page, '.mcsa', name);
  });
}
