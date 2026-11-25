// The screens the browser checks look at. `client` pages take lang (fa|en) and theme; the admin panel is Persian only.
const client = [
  ['home', '/index.php?m=mcsec&p=home'],
  ['findings', '/index.php?m=mcsec&p=findings'],
  ['findings-by-fix', '/index.php?m=mcsec&p=findings&group=1'],
  ['assets', '/index.php?m=mcsec&p=assets'],
  ['scans', '/index.php?m=mcsec&p=scans'],
  ['reports', '/index.php?m=mcsec&p=reports'],
];
const admin = [
  ['admin-overview', '/addonmodules.php?module=mcsec'],
  ['admin-settings', '/addonmodules.php?module=mcsec&mcsa=settings'],
  ['admin-scans', '/addonmodules.php?module=mcsec&mcsa=scans'],
  ['admin-revenue', '/addonmodules.php?module=mcsec&mcsa=revenue'],
];
const url = (path, lang, dark) => path + (path.includes('index.php') ? '&lang=' + lang : '') + (dark ? '&dark=1' : '');

module.exports = { client, admin, url };
