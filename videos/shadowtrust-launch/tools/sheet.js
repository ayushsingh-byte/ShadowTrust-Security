// usage: node sheet.js <out.png> <cols> <cellWidth> <img...>   Contact sheet of images with their names.
const puppeteer = require('puppeteer-core'); const path = require('path');
(async () => {
  const [out, cols, w, ...imgs] = process.argv.slice(2);
  const b = await puppeteer.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true, args: ['--allow-file-access-from-files'] });
  const p = await b.newPage();
  const html = `<body style="margin:0;background:#555;font:12px sans-serif;color:#fff;display:grid;gap:6px;padding:6px;grid-template-columns:repeat(${cols},${w}px)">` + imgs.map(i => `<div><img style="display:block;width:${w}px" src="file://${path.resolve(i)}"><div style="padding:2px 0">${path.basename(i)}</div></div>`).join('') + '</body>';
  await p.setViewport({ width: cols * (+w + 6) + 6, height: 600 });
  const tmp = path.resolve(out) + '.html'; require('fs').writeFileSync(tmp, html);
  await p.goto('file://' + tmp, { waitUntil: 'load' }); await new Promise(r => setTimeout(r, 400)); require('fs').unlinkSync(tmp);
  await p.screenshot({ path: out, fullPage: true }); await b.close(); console.log(out);
})();
