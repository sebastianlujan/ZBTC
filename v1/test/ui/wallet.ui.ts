// The demo wallet end to end, through the real page: clicks, wheel and typing are real
// input, so an element covering a control fails the test (Playwright checks which element
// receives each click). The tests share one network and run in order.
import { expect, test, type Locator, type Page } from '@playwright/test';

test.describe.configure({ mode: 'serial' });

let page: Page;

test.beforeAll(async ({ browser }) => {
  page = await browser.newPage();
  await page.goto('/');
});

test.afterAll(async () => {
  await page.close();
});

const balance = () => page.locator('.balance .amount');
const sheet = () => page.locator('#sheet-layer');
const height = async () => Number((await page.locator('#chain-pill').textContent())?.match(/\d+/)?.[0]);
const activityRow = (title: string) => page.locator('.row', { hasText: title }).first();
const command = (line: string) => page.locator('.tcmd', { hasText: line });

/** Waits until no action runs and no command is still streaming into the terminal. */
async function settled(): Promise<void> {
  await expect(page.locator('#panel-toggle')).not.toHaveClass(/is-busy/);
  await expect(page.locator('.tentry.running')).toHaveCount(0);
}

async function openSend(): Promise<Locator> {
  await page.getByRole('button', { name: 'Enviar', exact: true }).click();
  await expect(sheet()).toBeVisible();
  return page.getByLabel('Monto');
}

/** Types into the amount field the way a person does: select all, then key by key. */
async function typeAmount(text: string): Promise<void> {
  const amount = page.getByLabel('Monto');
  await amount.click();
  await amount.press('ControlOrMeta+a');
  await amount.pressSequentially(text);
}

async function showAccount(name: 'Alice' | 'Bob'): Promise<void> {
  await page.locator('#accounts').getByRole('radio', { name }).click();
  await expect(page.locator('.app-head .who')).toHaveText(new RegExp(name));
}

test('creates a fresh network from the wallet', async () => {
  await page.getByRole('button', { name: 'Crear red de prueba' }).click();
  await settled();
  await expect(balance()).toHaveText('100');
  await expect(page.locator('.hero-sub')).toHaveText('Todo disponible para enviar');
  await expect(activityRow('Saldo inicial')).toContainText('+100 ZBTC');
});

test('sends a typed amount privately', async () => {
  await openSend();
  await typeAmount('23');
  await expect(page.locator('#send-submit')).toHaveText('Enviar 23 ZBTC en privado');
  await expect(page.locator('#send-submit')).toBeEnabled();
  await page.locator('#send-submit').click();
  await expect(page.locator('.result h3')).toHaveText('Enviado');
  await expect(command('zbtc send alice bob 23')).toHaveCount(1);
  await page.getByRole('button', { name: 'Listo' }).click();
  await expect(sheet()).toBeHidden();
  await settled();
  await expect(activityRow('Enviado a Bob')).toContainText('−23 ZBTC');
  await expect(activityRow('Enviado a Bob')).toContainText('Pendiente');
  // The spent note is locked until a block confirms the transfer; the change is on its way.
  await expect(balance()).toHaveText('77');
  await expect(page.locator('.hero-sub')).toContainText('0 ZBTC disponibles ahora');
});

test('mines exactly one block per click and confirms the transfer', async () => {
  const before = await height();
  await page.locator('#mine').click();
  // A second click while the first one mines must do nothing.
  await page.locator('#mine').click({ force: true, timeout: 2_000 });
  await settled();
  expect(await height()).toBe(before + 1);
  await expect(activityRow('Enviado a Bob')).toContainText('Confirmada');
  await expect(page.locator('.hero-sub')).toHaveText('Todo disponible para enviar');
  await expect(page.locator('.banner')).toHaveCount(0);
});

test("shows the payment in Bob's wallet, without the sender", async () => {
  await showAccount('Bob');
  await expect(balance()).toHaveText('23');
  await expect(activityRow('Recibido')).toContainText('+23 ZBTC');
  await expect(activityRow('Recibido')).toContainText('remitente oculto');
});

test('rejects amounts the wallet cannot send', async () => {
  await openSend();
  await typeAmount('24');
  await expect(page.locator('#send-hint')).toHaveText('Disponible: 23 ZBTC.');
  await expect(page.locator('#send-hint')).toHaveClass(/bad/);
  await expect(page.locator('#send-submit')).toBeDisabled();
  await typeAmount('2.5');
  await expect(page.locator('#send-hint')).toHaveText('El monto debe ser un número entero de ZBTC.');
  await expect(page.locator('#send-submit')).toBeDisabled();
  await page.getByRole('radio', { name: /Público/ }).click();
  await typeAmount('0,95');
  await expect(page.locator('#send-hint')).toHaveClass(/bad/);
  await expect(page.locator('#send-submit')).toBeDisabled();
  await page.getByRole('button', { name: 'Cancelar' }).click();
  await expect(sheet()).toBeHidden();
});

test('sends BTC publicly and opens it in the explorer', async () => {
  await openSend();
  await page.getByRole('radio', { name: /Público/ }).click();
  await typeAmount('0,25');
  await expect(page.locator('#send-submit')).toHaveText('Enviar 0,25 BTC en público');
  await page.locator('#send-submit').click();
  await expect(page.locator('.result h3')).toHaveText('Enviado');
  await page.getByRole('button', { name: 'Ver en el explorer' }).click();
  await expect(page.locator('#tab-explorer')).toBeVisible();
  await settled();
  await expect(page.locator('#tab-explorer')).toContainText('tipo: transparente');
  await expect(page.locator('#tab-explorer')).toContainText('estado: en la mempool');
  await expect(page.locator('#tab-explorer')).toContainText('remitente: visible');
});

test('decrypts the shielded transfer only with the right key', async () => {
  await activityRow('Recibido').filter({ hasText: 'ZBTC' }).click();
  await settled();
  const explorer = page.locator('#tab-explorer');
  await expect(explorer).toContainText('tipo: zbtc · protegida (shielded)');
  await expect(explorer).toContainText('destinatario: oculto');
  const inner = page.locator('[data-chart="inner"]');
  await explorer.getByRole('button', { name: 'bob', exact: true }).click();
  await settled();
  await expect(inner).toHaveAttribute('aria-label', /nota para Bob: 23 ZBTC/);
  await explorer.getByRole('button', { name: 'alice', exact: true }).click();
  await settled();
  // Alice's key opens only her change, never Bob's note.
  await expect(inner).toHaveAttribute('aria-label', /nota para Alice: 77 ZBTC/);
  await expect(inner).not.toHaveAttribute('aria-label', /Bob/);
});

test('debug shows the envelope and finds no leak', async () => {
  await page.getByRole('tab', { name: 'debug' }).click();
  await settled();
  const debug = page.locator('#tab-debug');
  await expect(debug).toContainText('monto: no');
  await expect(debug).toContainText('clave de dueño del destinatario: no');
  await expect(debug).toContainText('clave de cifrado del destinatario: no');
  await expect(debug.locator('.bytemap span')).toHaveCount(8);
  await expect(debug).toContainText('replay: 1 aceptadas · 0 rechazadas');
});

test('picking the shown transaction in debug brings its envelope into view', async () => {
  const debug = page.locator('#tab-debug');
  // The only transfer is already picked and decoded, so the click changes no data.
  await debug.locator('.tbtn[aria-pressed="true"]').click();
  const section = debug.locator('#debug-tx');
  await expect(section).toHaveClass(/flash/);
  await expect(section.getByText('búsqueda de fugas')).toBeInViewport();
});

test('receive shows a shielded and a transparent address', async () => {
  await page.getByRole('button', { name: 'Recibir', exact: true }).click();
  // A shielded address is "zbtcrt" followed by the hex of the owner and encryption keys.
  await expect(page.locator('.address code')).toHaveText(/^zbtcrt[0-9a-f]{128}$/);
  await page.getByRole('radio', { name: /Pública/ }).click();
  await expect(page.locator('.address code')).toHaveText(/^bcrt1/);
  await page.keyboard.press('Escape');
  await expect(sheet()).toBeHidden();
});

test('scrolls inside the phone with the mouse wheel', async () => {
  const app = page.locator('.app');
  await app.hover();
  await page.mouse.wheel(0, 500);
  await expect.poll(() => app.evaluate((el) => el.scrollTop)).toBeGreaterThan(0);
});

test('resizes the side panel on the x axis only', async () => {
  const panel = page.locator('#panel');
  const before = await panel.boundingBox();
  const edge = await page.locator('#panel-resizer').boundingBox();
  if (!before || !edge) throw new Error('panel not visible');
  await page.mouse.move(edge.x + 3, edge.y + 300);
  await page.mouse.down();
  await page.mouse.move(edge.x - 200, edge.y + 380, { steps: 8 });
  await page.mouse.up();
  const after = await panel.boundingBox();
  expect(Math.round(after!.width - before.width)).toBe(203);
  expect(after!.height).toBe(before.height);
  await page.locator('#panel-resizer').dblclick();
});

test('resets the network from debug after confirming', async () => {
  await page.getByRole('tab', { name: 'debug' }).click();
  await page.getByRole('button', { name: 'reiniciar red' }).click();
  await page.getByRole('button', { name: 'sí, reiniciar' }).click();
  await settled();
  await showAccount('Alice');
  await expect(balance()).toHaveText('100');
  await expect(page.locator('.row')).toHaveCount(1);
});
