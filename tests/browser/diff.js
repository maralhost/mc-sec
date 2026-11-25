// Development helper: where do two folders of pictures (made by shots.spec.js) differ?  node diff.js before after [name.png]
// Prints, per picture, how many pixels differ and the box that holds them. Uses the test browser's own canvas.
const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');
(async () => {
  const [a, b, only] = process.argv.slice(2);
  const dir = (n) => path.join(__dirname, 'shots', n);
  const browser = await chromium.launch(process.env.MCSEC_CHROME ? { executablePath: process.env.MCSEC_CHROME } : {});
  const page = await browser.newPage();
  let same = 0;
  for (const f of fs.readdirSync(dir(a)).filter((x) => x.endsWith('.png') && (!only || x === only))) {
    if (!fs.existsSync(path.join(dir(b), f))) { console.log('missing   ' + f); continue; }
    const [x, y] = [a, b].map((n) => 'data:image/png;base64,' + fs.readFileSync(path.join(dir(n), f)).toString('base64'));
    const r = await page.evaluate(async ([x, y]) => {
      const load = (s) => new Promise((ok) => { const i = new Image(); i.onload = () => ok(i); i.src = s; });
      const [p, q] = [await load(x), await load(y)];
      if (p.width !== q.width || p.height !== q.height) return { size: [p.width, p.height, q.width, q.height] };
      const data = (i) => { const c = new OffscreenCanvas(i.width, i.height); const g = c.getContext('2d'); g.drawImage(i, 0, 0); return g.getImageData(0, 0, i.width, i.height).data; };
      const [d, e] = [data(p), data(q)];
      let n = 0, x0 = 1e9, y0 = 1e9, x1 = -1, y1 = -1;
      for (let i = 0; i < d.length; i += 4) {
        if (Math.abs(d[i] - e[i]) + Math.abs(d[i + 1] - e[i + 1]) + Math.abs(d[i + 2] - e[i + 2]) > 6) {
          n++; const px = (i / 4) % p.width, py = Math.floor(i / 4 / p.width);
          x0 = Math.min(x0, px); y0 = Math.min(y0, py); x1 = Math.max(x1, px); y1 = Math.max(y1, py);
        }
      }
      return { n, box: n ? [x0, y0, x1, y1] : null };
    }, [x, y]);
    if (r.size) console.log('size      ' + f + '  ' + r.size.join(' '));
    else if (r.n) console.log('differs   ' + f + '  ' + r.n + ' px in box ' + r.box.join(','));
    else same++;
  }
  console.log(same + ' identical');
  await browser.close();
})();
