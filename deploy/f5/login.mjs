// F5 lab login smoke test (Playwright, runs on the developer machine inside the lab tailnet).
// Logs one test user in at https://tagcess.<domain>/ through Zitadel and prints where it lands.
// Credentials come from F5_USERS_FILE (tab-separated "user<TAB>password" lines, kept OUTSIDE the repo).
//   npm i playwright && F5_USERS_FILE=~/f5-lab-users.txt node deploy/f5/login.mjs devops@tagcess.test
//   F5_DOMAIN default lab.example.com
import { chromium } from 'playwright';
import fs from 'fs';

const who = process.argv[2] || 'devops@';
const file = process.env.F5_USERS_FILE;
if (!file) throw new Error('F5_USERS_FILE is required');
const line = fs.readFileSync(file, 'utf8').split('\n').find(l => l.startsWith(who));
if (!line) throw new Error(`no user starting with ${who} in F5_USERS_FILE`);
const [user, pass] = line.split('\t');
const host = `tagcess.${process.env.F5_DOMAIN || 'lab.example.com'}`;

const b = await chromium.launch({ headless: true });
const p = await (await b.newContext()).newPage();
p.setDefaultTimeout(60000);
await p.goto(`https://${host}/`, { waitUntil: 'domcontentloaded' });
const login = p.locator('input[name="loginName"], input#loginName').first();
await login.fill(user);
await p.getByRole('button', { name: /continue/i }).click();
await p.locator('input[type="password"]').first().fill(pass);
await p.getByRole('button', { name: /continue/i }).click();
await p.waitForURL(new RegExp(`${host.replace(/\./g, '\\.')}/(?!oauth2)`), { timeout: 90000 })
  .catch(e => console.log('wait:', e.message.split('\n')[0]));
console.log(user, '->', p.url(), '|', await p.title());
await b.close();
