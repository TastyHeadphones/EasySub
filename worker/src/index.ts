import { randomChallenge } from './base64';
import {
  verifyRegistration,
  verifyAssertion,
  RegistrationCredentialPayload,
  AssertionCredentialPayload,
} from './webauthn';

interface Env {
  DO_ADMIN: DurableObjectNamespace;
  DO_CREDS: DurableObjectNamespace;
  DO_CHALLENGES: DurableObjectNamespace;
  DO_SESSIONS: DurableObjectNamespace;
  DO_SUBS: DurableObjectNamespace;
  DO_LINKS: DurableObjectNamespace;
  DO_OUTBOX: DurableObjectNamespace;
  ASSETS: Fetcher;
  EMAIL_API_URL?: string;
  EMAIL_API_KEY?: string;
  EMAIL_FROM?: string;
}

interface AdminStatus {
  registered: boolean;
  email?: string;
}

interface StoredCredential {
  id: string;
  publicKeyJwk: JsonWebKey;
  counter: number;
  transports?: string[];
  createdAt: number;
}

interface SessionRecord {
  token: string;
  subject: string;
  expiresAt: number;
  createdAt: number;
}

interface SubscriptionRecord {
  id: string;
  name: string;
  linkUrl: string;
  intervalDays?: number;
  invokeAt?: number;
  createdAt: number;
  expiresAt: number;
  status: 'active' | 'expired';
}

interface SubscriptionInput {
  name: string;
  linkUrl: string;
  intervalDays?: number;
  invokeAt?: number;
  expiresAt: number;
}

interface ShareLinkRecord {
  slug: string;
  subscriptionId: string;
  createdAt: number;
  expiresAt: number;
  lastAccessedAt?: number;
  active: boolean;
}

interface OutboxMessage {
  id: string;
  to: string;
  subject: string;
  body: string;
  createdAt: number;
  lastTriedAt?: number;
  error?: string;
  status: 'pending' | 'sent' | 'failed';
}

const SESSION_COOKIE = 'sb_session';
const SESSION_TTL_SECONDS = 60 * 60;
const CHALLENGE_TTL_SECONDS = 5 * 60;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(),
      });
    }
    if (url.pathname.startsWith('/api/')) {
      return handleApi(request, env);
    }
    if (url.pathname.startsWith('/s/')) {
      return handlePublicLink(request, env);
    }
    if (url.pathname === '/dev/emails') {
      return handleDevEmails(env);
    }
    return serveAssetOrSpa(request, env, ctx);
  },
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runCron(env));
  },
};

function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET,POST,DELETE,OPTIONS',
    'access-control-allow-headers': 'content-type',
  };
}

async function handleApi(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api/, '');
  try {
    if (request.method === 'GET' && path === '/admin/status') {
      const status = await getAdminStatus(env);
      return json(status);
    }
    if (request.method === 'POST' && path === '/admin/register/start') {
      let body: any = {};
      try {
        body = await request.json();
      } catch {
        body = {};
      }
      return json(await startRegistration(body, request, env));
    }
    if (request.method === 'POST' && path === '/admin/register/finish') {
      const body = await request.json();
      const result = await finishRegistration(body, request, env);
      return json(result);
    }
    if (request.method === 'POST' && path === '/admin/login/start') {
      let body: any = {};
      try {
        body = await request.json();
      } catch {
        body = {};
      }
      return json(await startLogin(body, request, env));
    }
    if (request.method === 'POST' && path === '/admin/login/finish') {
      const body = await request.json();
      const { response, cookie } = await finishLogin(body, request, env);
      return json(response, cookie ? { 'set-cookie': cookie } : undefined);
    }
    if (request.method === 'POST' && path === '/admin/logout') {
      const token = getSessionToken(request);
      if (token) {
        await sessionRequest(env, 'delete', { token });
      }
      return json({ ok: true }, `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
    }

    const session = await requireSession(request, env);
    if (!session) {
      return json({ error: 'Unauthorized' }, undefined, 401);
    }

    if (request.method === 'GET' && path === '/subscriptions') {
      const subs = await subsRequest<SubscriptionRecord[]>(env, 'list');
      return json({ items: subs });
    }
    if (request.method === 'POST' && path === '/subscriptions') {
      const payload = await request.json();
      const normalized = prepareSubscriptionPayload(payload);
      const created = await subsRequest<SubscriptionRecord>(env, 'create', normalized);
      return json(created, undefined, 201);
    }
    if (request.method === 'DELETE' && path.startsWith('/subscriptions/')) {
      const id = path.split('/')[2];
      await subsRequest(env, 'delete', { id });
      return json({ ok: true });
    }
    if (request.method === 'POST' && path.startsWith('/subscriptions/') && path.endsWith('/share')) {
      const id = path.split('/')[2];
      const subscription = await subsRequest<SubscriptionRecord | null>(env, 'get', { id });
      if (!subscription) {
        throw new Error('Subscription not found');
      }
      const share = await linkRequest<ShareLinkRecord>(env, 'create', { subscriptionId: id, expiresAt: subscription.expiresAt });
      return json(share, undefined, 201);
    }
    return json({ error: 'Not found' }, undefined, 404);
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : 'Unexpected error' }, undefined, 400);
  }
}

async function startRegistration(body: any, request: Request, env: Env) {
  const status = await getAdminStatus(env);
  if (status.registered) {
    throw new Error('Admin already registered');
  }
  const url = new URL(request.url);
  const rpId = url.hostname;
  const origin = url.origin;
  const suffix = crypto.randomUUID().split('-')[0];
  const derivedEmail = `admin+${suffix}@${rpId}`;
  const fallbackName = `Owner ${suffix}`;
  const email =
    typeof body?.email === 'string' && body.email.trim().length > 0 ? body.email.trim().toLowerCase() : derivedEmail;
  const displayName =
    typeof body?.displayName === 'string' && body.displayName.trim().length > 0
      ? body.displayName.trim()
      : fallbackName;
  const challenge = randomChallenge();
  const userId = randomChallenge(32);
  await challengeRequest(env, 'create', {
    challenge,
    purpose: 'register',
    context: { email, displayName },
    ttlSeconds: CHALLENGE_TTL_SECONDS,
  });
  return {
    challenge,
    publicKey: {
      rp: { name: 'EasySub', id: rpId },
      user: {
        id: userId,
        name: email,
        displayName,
      },
      challenge,
      timeout: 60000,
      pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
      attestation: 'none',
      authenticatorSelection: { userVerification: 'preferred', residentKey: 'preferred' },
    },
    origin,
  };
}

async function finishRegistration(body: any, request: Request, env: Env) {
  const { credential, challenge } = body as {
    credential: RegistrationCredentialPayload;
    challenge: string;
  };
  if (!credential || !challenge) {
    throw new Error('Missing credential payload');
  }
  const origin = new URL(request.url).origin;
  const rpId = new URL(request.url).hostname;
  const record = await challengeRequest<ChallengeRecord>(env, 'consume', {
    challenge,
    purpose: 'register',
  });
  const verification = await verifyRegistration({
    credential,
    expectedChallenge: challenge,
    expectedOrigin: origin,
    rpId,
  });
  const stored: StoredCredential = {
    id: verification.credentialId,
    publicKeyJwk: verification.publicKeyJwk,
    counter: verification.counter,
    transports: verification.transports,
    createdAt: Date.now(),
  };
  await credsRequest<StoredCredential>(env, 'put', { credential: stored });
  const email = (record?.context as { email?: string })?.email ?? 'admin@local';
  await adminRequest(env, 'initialize', { email });
  return { registered: true };
}

async function startLogin(body: any, request: Request, env: Env) {
  const status = await getAdminStatus(env);
  if (!status.registered) {
    throw new Error('Admin not registered');
  }
  const credentials = await credsRequest<StoredCredential[]>(env, 'list');
  if (!credentials.length) {
    throw new Error('No credentials');
  }
  const challenge = randomChallenge();
  await challengeRequest(env, 'create', {
    purpose: 'login',
    challenge,
    ttlSeconds: CHALLENGE_TTL_SECONDS,
  });
  return {
    challenge,
    publicKey: {
      challenge,
      allowCredentials: credentials.map((cred: StoredCredential) => ({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports ?? [],
      })),
      timeout: 60000,
      rpId: new URL(request.url).hostname,
      userVerification: 'preferred',
    },
  };
}

async function finishLogin(body: any, request: Request, env: Env) {
  const { credential, challenge } = body as {
    credential: AssertionCredentialPayload;
    challenge: string;
  };
  if (!credential || !challenge) {
    throw new Error('Missing credential payload');
  }
  const creds = await credsRequest<StoredCredential[]>(env, 'list');
  const found = creds.find((c: StoredCredential) => c.id === credential.id);
  if (!found) {
    throw new Error('Credential not recognized');
  }
  await challengeRequest(env, 'consume', { challenge, purpose: 'login' });
  const origin = new URL(request.url).origin;
  const rpId = new URL(request.url).hostname;
  const verification = await verifyAssertion({
    credential,
    expectedChallenge: challenge,
    expectedOrigin: origin,
    rpId,
    publicKeyJwk: found.publicKeyJwk,
    prevCounter: found.counter,
  });
  await credsRequest<StoredCredential>(env, 'updateCounter', { id: found.id, counter: verification.newCounter });
  const session = await sessionRequest<SessionRecord>(env, 'create', { subject: 'admin', ttlSeconds: SESSION_TTL_SECONDS });
  const cookie = `${SESSION_COOKIE}=${session.token}; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=${new Date(
    session.expiresAt,
  ).toUTCString()}`;
  return {
    response: { ok: true },
    cookie,
  };
}

async function requireSession(request: Request, env: Env) {
  const token = getSessionToken(request);
  if (!token) return null;
  const result = await sessionRequest<{ valid: boolean; session?: SessionRecord }>(env, 'validate', { token });
  if (!result.valid) {
    return null;
  }
  return result.session as SessionRecord;
}

function getSessionToken(request: Request) {
  const cookie = request.headers.get('cookie');
  if (!cookie) return null;
  const match = cookie.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`));
  return match ? match[1] : null;
}

function prepareSubscriptionPayload(body: any): SubscriptionInput {
  const name = String(body?.name ?? '').trim();
  const rawLink = String(body?.linkUrl ?? '').trim();
  if (!name || !rawLink) {
    throw new Error('Name and link are required');
  }
  let linkUrl: string;
  try {
    const parsed = new URL(rawLink);
    linkUrl = parsed.toString();
  } catch {
    throw new Error('Link must be a valid URL');
  }
  const intervalDaysValue = body?.intervalDays;
  const hasInterval = intervalDaysValue !== undefined && intervalDaysValue !== null && intervalDaysValue !== '';
  let intervalDays: number | undefined;
  if (hasInterval) {
    const parsedInterval = Number(intervalDaysValue);
    if (!Number.isFinite(parsedInterval) || parsedInterval <= 0) {
      throw new Error('Interval days must be a positive number');
    }
    intervalDays = Math.round(parsedInterval);
  }
  if (hasInterval && intervalDays === undefined) {
    throw new Error('Interval days must be a positive number');
  }
  const invokeInput = body?.invokeAt ?? body?.invokeDate;
  let invokeAt: number | undefined;
  if (invokeInput) {
    const parsed = new Date(invokeInput);
    const timestamp = parsed.getTime();
    if (Number.isNaN(timestamp)) {
      throw new Error('Invoke date is invalid');
    }
    invokeAt = timestamp;
  }
  let expiresAt: number | undefined;
  if (typeof body?.expiresAt === 'number') {
    expiresAt = body.expiresAt;
  } else if (invokeAt) {
    expiresAt = invokeAt;
  } else if (intervalDays) {
    expiresAt = Date.now() + intervalDays * 24 * 60 * 60 * 1000;
  }
  if (!expiresAt) {
    throw new Error('Provide either interval days or an invoke date');
  }
  return {
    name,
    linkUrl,
    intervalDays: intervalDays ?? undefined,
    invokeAt,
    expiresAt,
  };
}

async function runCron(env: Env) {
  await Promise.all([
    subsRequest(env, 'expire', { now: Date.now() }),
    linkRequest(env, 'prune', { now: Date.now() }),
    flushOutbox(env),
  ]);
}

async function flushOutbox(env: Env) {
  const pending = await outboxRequest<OutboxMessage[]>(env, 'pending');
  for (const message of pending as OutboxMessage[]) {
    const sent = await deliverEmail(message, env);
    if (sent) {
      await outboxRequest<OutboxMessage | null>(env, 'markSent', { id: message.id });
    } else {
      await outboxRequest<OutboxMessage | null>(env, 'recordError', { id: message.id, error: 'Missing EMAIL_* secrets' });
    }
  }
}

async function deliverEmail(message: OutboxMessage, env: Env): Promise<boolean> {
  if (!env.EMAIL_API_URL || !env.EMAIL_API_KEY) {
    return false;
  }
  try {
    const response = await fetch(env.EMAIL_API_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${env.EMAIL_API_KEY}`,
      },
      body: JSON.stringify({
        to: message.to,
        from: env.EMAIL_FROM ?? 'no-reply@easysub.app',
        subject: message.subject,
        text: message.body,
      }),
    });
    return response.ok;
  } catch (error) {
    console.error('Email delivery failed', error);
    return false;
  }
}

async function handlePublicLink(request: Request, env: Env) {
  const url = new URL(request.url);
  const segments = url.pathname.split('/');
  const slug = segments[2];
  if (!slug) {
    return new Response('Link not found', { status: 404 });
  }
  const link = await linkRequest<ShareLinkRecord | null>(env, 'get', { slug });
  if (!link || !link.active) {
    return new Response('Link not found or expired', { status: 404 });
  }
  const subscription = await subsRequest<SubscriptionRecord | null>(env, 'get', { id: link.subscriptionId });
  if (!subscription) {
    return new Response('Subscription missing', { status: 404 });
  }
  let fetchedText = '';
  let fetchError = '';
  try {
    const response = await fetch(subscription.linkUrl, { method: 'GET' });
    if (!response.ok) {
      throw new Error(`Remote link returned ${response.status}`);
    }
    const text = await response.text();
    fetchedText = text.slice(0, 5000);
  } catch (error) {
    fetchError = `Unable to load linked content: ${
      error instanceof Error ? error.message : 'Unknown error'
    }`;
  }
  const scheduleParts: string[] = [];
  if (subscription.intervalDays) {
    scheduleParts.push(`Interval: every ${subscription.intervalDays} day${subscription.intervalDays === 1 ? '' : 's'}`);
  }
  if (subscription.invokeAt) {
    scheduleParts.push(`Invokes on ${new Date(subscription.invokeAt).toLocaleString('en-US')}`);
  }
  scheduleParts.push(`Valid until ${new Date(subscription.expiresAt).toLocaleString('en-US')}`);
  const safeName = escapeHtml(subscription.name);
  const safeLink = escapeHtml(subscription.linkUrl);
  const safeBody = escapeHtml(fetchedText || fetchError || 'No content available');
  const metaHtml = scheduleParts.map((line) => `<p class="meta">${escapeHtml(line)}</p>`).join('');
  const html = `<!doctype html>
  <html>
    <head>
      <meta charset="utf-8" />
      <title>${safeName} · EasySub</title>
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <style>
        body { font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 32px; background: #f6f6f9; }
        .card { max-width: 640px; margin: 0 auto; background: #fff; border-radius: 16px; padding: 32px; box-shadow: 0 10px 30px rgba(15,23,42,0.1); }
        h1 { margin-top: 0; font-size: 1.8rem; }
        .meta { color: #475569; margin-top: 8px; }
        pre { background: #f8fafc; padding: 16px; border-radius: 12px; white-space: pre-wrap; word-break: break-word; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace; }
        a { color: #2563eb; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>${safeName}</h1>
        <p class="meta"><a href="${safeLink}" target="_blank" rel="noreferrer">Source link</a></p>
        ${metaHtml}
        <pre>${safeBody}</pre>
      </div>
    </body>
  </html>`;
  return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
}

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      case "'":
        return '&#39;';
      default:
        return char;
    }
  });
}

async function handleDevEmails(env: Env) {
  const emails = await outboxRequest<OutboxMessage[]>(env, 'list');
  const rows = (emails as OutboxMessage[]).map(
    (email) => `<tr><td>${email.to}</td><td>${email.subject}</td><td>${email.status}</td><td>${
      email.error ?? ''
    }</td><td>${new Date(email.createdAt).toLocaleString('en-US')}</td></tr>`,
  );
  const html = `<!doctype html><html><head><meta charset="utf-8"/><title>Dev Outbox</title>
  <style>body{font-family:system-ui;padding:32px;background:#0f172a;color:#e2e8f0}table{width:100%;border-collapse:collapse;}th,td{padding:8px;border-bottom:1px solid rgba(226,232,240,0.2);}th{text-align:left;color:#38bdf8}</style>
  </head><body><h1>Outbox</h1><table><thead><tr><th>To</th><th>Subject</th><th>Status</th><th>Error</th><th>Created</th></tr></thead><tbody>${rows.join(
    '',
  )}</tbody></table></body></html>`;
  return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
}

async function serveAssetOrSpa(request: Request, env: Env, ctx: ExecutionContext) {
  const assetResponse = await env.ASSETS.fetch(request);
  if (assetResponse.status !== 404) {
    return assetResponse;
  }
  const url = new URL(request.url);
  const fallbackHeaders = new Headers(request.headers);
  const fallback = new Request(`${url.origin}/index.html`, {
    method: 'GET',
    headers: fallbackHeaders,
  });
  return env.ASSETS.fetch(fallback);
}

function json(body: unknown, extraHeader?: Record<string, string> | string, status = 200) {
  const headers = { 'content-type': 'application/json', ...corsHeaders() } as Record<string, string>;
  if (typeof extraHeader === 'string') {
    headers['set-cookie'] = extraHeader;
  } else if (extraHeader) {
    Object.assign(headers, extraHeader);
  }
  return new Response(JSON.stringify(body ?? {}), { status, headers });
}

type DoMessage<T = unknown> = {
  action: string;
  data?: T;
};

async function getAdminStatus(env: Env): Promise<AdminStatus> {
  return adminRequest<AdminStatus>(env, 'status');
}

function singletonStub(namespace: DurableObjectNamespace, name: string) {
  const id = namespace.idFromName(name);
  return namespace.get(id);
}

async function adminRequest<T>(env: Env, action: string, data?: unknown) {
  const stub = singletonStub(env.DO_ADMIN, 'admin');
  return doRequest<T>(stub, action, data);
}

async function credsRequest<T>(env: Env, action: string, data?: unknown) {
  const stub = singletonStub(env.DO_CREDS, 'credentials');
  return doRequest<T>(stub, action, data);
}

async function challengeRequest<T>(env: Env, action: string, data?: unknown) {
  const stub = singletonStub(env.DO_CHALLENGES, 'challenges');
  return doRequest<T>(stub, action, data);
}

async function sessionRequest<T>(env: Env, action: string, data?: unknown) {
  const stub = singletonStub(env.DO_SESSIONS, 'sessions');
  return doRequest<T>(stub, action, data);
}

async function subsRequest<T>(env: Env, action: string, data?: unknown) {
  const stub = singletonStub(env.DO_SUBS, 'subscriptions');
  return doRequest<T>(stub, action, data);
}

async function linkRequest<T>(env: Env, action: string, data?: unknown) {
  const stub = singletonStub(env.DO_LINKS, 'links');
  return doRequest<T>(stub, action, data);
}

async function outboxRequest<T>(env: Env, action: string, data?: unknown) {
  const stub = singletonStub(env.DO_OUTBOX, 'outbox');
  return doRequest<T>(stub, action, data);
}

async function doRequest<T>(stub: DurableObjectStub, action: string, data?: unknown): Promise<T> {
  const response = await stub.fetch('https://do.internal', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ action, data }),
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  if (response.headers.get('content-type')?.includes('application/json')) {
    return response.json<T>();
  }
  return undefined as T;
}

class BaseStore<T> {
  protected state: DurableObjectState;
  protected storageKey = 'state';
  protected data!: T;
  protected ready: Promise<void>;

  constructor(state: DurableObjectState, seed: T) {
    this.state = state;
    this.ready = this.state.blockConcurrencyWhile(async () => {
      const stored = await this.state.storage.get<T>(this.storageKey);
      this.data = stored ?? seed;
      if (!stored) {
        await this.state.storage.put(this.storageKey, this.data);
      }
    });
  }

  protected async persist() {
    await this.state.storage.put(this.storageKey, this.data);
  }
}

interface AdminState {
  registered: boolean;
  email?: string;
  createdAt?: number;
}

export class AdminStore extends BaseStore<AdminState> implements DurableObject {
  constructor(state: DurableObjectState) {
    super(state, { registered: false });
  }

  async fetch(request: Request): Promise<Response> {
    await this.ready;
    const { action, data } = (await request.json()) as DoMessage<{ email?: string }>;
    const payload = data ?? {};
    if (action === 'status') {
      return Response.json(this.data);
    }
    if (action === 'initialize') {
      if (this.data.registered) {
        return new Response('Already initialized', { status: 400 });
      }
      this.data = { registered: true, email: payload.email, createdAt: Date.now() };
      await this.persist();
      return Response.json(this.data);
    }
    return new Response('Unknown action', { status: 400 });
  }
}

interface CredentialState {
  items: Record<string, StoredCredential>;
}

export class CredentialStore extends BaseStore<CredentialState> implements DurableObject {
  constructor(state: DurableObjectState) {
    super(state, { items: {} });
  }

  async fetch(request: Request) {
    await this.ready;
    const { action, data } = (await request.json()) as DoMessage<{
      credential?: StoredCredential;
      id?: string;
      counter?: number;
    }>;
    const payload = data ?? {};
    if (action === 'list') {
      return Response.json(Object.values(this.data.items));
    }
    if (action === 'put') {
      const credential = payload.credential;
      if (!credential) {
        return new Response('Missing credential', { status: 400 });
      }
      this.data.items[credential.id] = credential;
      await this.persist();
      return Response.json(credential);
    }
    if (action === 'updateCounter') {
      const { id, counter } = payload;
      if (!id || typeof counter !== 'number') {
        return new Response('Invalid counter update', { status: 400 });
      }
      const existing = this.data.items[id];
      if (existing) {
        existing.counter = counter;
        await this.persist();
        return Response.json(existing);
      }
      return new Response('Unknown credential', { status: 404 });
    }
    return new Response('Unknown action', { status: 400 });
  }
}

interface ChallengeRecord {
  challenge: string;
  purpose: 'register' | 'login';
  context?: unknown;
  expiresAt: number;
}

interface ChallengeState {
  records: Record<string, ChallengeRecord>;
}

export class ChallengeStore extends BaseStore<ChallengeState> implements DurableObject {
  constructor(state: DurableObjectState) {
    super(state, { records: {} });
  }

  async fetch(request: Request) {
    await this.ready;
    await this.cleanup();
    type ChallengePayload = {
      challenge?: string;
      purpose?: ChallengeRecord['purpose'];
      context?: unknown;
      ttlSeconds?: number;
    };
    const { action, data } = (await request.json()) as DoMessage<ChallengePayload>;
    const payload: ChallengePayload = data ?? {};
    if (action === 'create') {
      if (!payload.challenge || !payload.purpose) {
        return new Response('Invalid challenge payload', { status: 400 });
      }
      const record: ChallengeRecord = {
        challenge: payload.challenge,
        purpose: payload.purpose,
        context: payload.context,
        expiresAt: Date.now() + (payload.ttlSeconds ?? CHALLENGE_TTL_SECONDS) * 1000,
      };
      this.data.records[record.challenge] = record;
      await this.persist();
      return Response.json(record);
    }
    if (action === 'consume') {
      const { challenge, purpose } = payload;
      if (!challenge || !purpose) {
        return new Response('Invalid challenge', { status: 400 });
      }
      const record = this.data.records[challenge];
      if (!record || record.purpose !== purpose || record.expiresAt < Date.now()) {
        return new Response('Invalid challenge', { status: 400 });
      }
      delete this.data.records[challenge];
      await this.persist();
      return Response.json(record);
    }
    return new Response('Unknown action', { status: 400 });
  }

  private async cleanup() {
    const now = Date.now();
    let removed = false;
    Object.keys(this.data.records).forEach((key) => {
      if (this.data.records[key]?.expiresAt < now) {
        delete this.data.records[key];
        removed = true;
      }
    });
    if (removed) {
      await this.persist();
    }
  }
}

interface SessionState {
  sessions: Record<string, SessionRecord>;
}

export class SessionStore extends BaseStore<SessionState> implements DurableObject {
  constructor(state: DurableObjectState) {
    super(state, { sessions: {} });
  }

  async fetch(request: Request) {
    await this.ready;
    type SessionPayload = {
      subject?: string;
      ttlSeconds?: number;
      token?: string;
    };
    const { action, data } = (await request.json()) as DoMessage<SessionPayload>;
    const payload: SessionPayload = data ?? {};
    if (action === 'create') {
      const token = crypto.randomUUID().replace(/-/g, '');
      const session: SessionRecord = {
        token,
        subject: payload.subject ?? 'admin',
        createdAt: Date.now(),
        expiresAt: Date.now() + (payload.ttlSeconds ?? SESSION_TTL_SECONDS) * 1000,
      };
      this.data.sessions[token] = session;
      await this.persist();
      return Response.json(session);
    }
    if (action === 'validate') {
      const token = payload.token;
      if (!token) {
        return Response.json({ valid: false });
      }
      const session = this.data.sessions[token];
      if (!session || session.expiresAt < Date.now()) {
        if (session) {
          delete this.data.sessions[token];
          await this.persist();
        }
        return Response.json({ valid: false });
      }
      return Response.json({ valid: true, session });
    }
    if (action === 'delete') {
      if (payload.token) {
        delete this.data.sessions[payload.token];
        await this.persist();
      }
      return Response.json({ ok: true });
    }
    return new Response('Unknown action', { status: 400 });
  }
}

interface SubscriptionState {
  items: Record<string, SubscriptionRecord>;
}

export class SubscriptionStore extends BaseStore<SubscriptionState> implements DurableObject {
  constructor(state: DurableObjectState) {
    super(state, { items: {} });
  }

  async fetch(request: Request) {
    await this.ready;
    const { action, data } = (await request.json()) as DoMessage<
      Partial<SubscriptionInput> & { id?: string; now?: number }
    >;
    const payload = data ?? {};
    if (action === 'list') {
      return Response.json(Object.values(this.data.items));
    }
    if (action === 'create') {
      const id = crypto.randomUUID();
      const record: SubscriptionRecord = {
        id,
        name: payload.name ?? '',
        linkUrl: payload.linkUrl ?? '',
        intervalDays: payload.intervalDays,
        invokeAt: payload.invokeAt,
        createdAt: Date.now(),
        expiresAt: payload.expiresAt ?? payload.invokeAt ?? Date.now(),
        status: 'active',
      };
      this.data.items[id] = record;
      await this.persist();
      return Response.json(record);
    }
    if (action === 'delete') {
      if (payload.id) {
        delete this.data.items[payload.id];
        await this.persist();
      }
      return Response.json({ ok: true });
    }
    if (action === 'get') {
      return Response.json((payload.id ? this.data.items[payload.id] : null) ?? null);
    }
    if (action === 'expire') {
      const now = payload.now ?? Date.now();
      let changed = false;
      Object.values(this.data.items).forEach((item) => {
        if (item.status === 'active' && item.expiresAt <= now) {
          item.status = 'expired';
          changed = true;
        }
      });
      if (changed) await this.persist();
      return Response.json({ ok: true });
    }
    return new Response('Unknown action', { status: 400 });
  }
}

interface LinkState {
  items: Record<string, ShareLinkRecord>;
}

export class LinkStore extends BaseStore<LinkState> implements DurableObject {
  constructor(state: DurableObjectState) {
    super(state, { items: {} });
  }

  async fetch(request: Request) {
    await this.ready;
    const { action, data } = (await request.json()) as DoMessage<{
      subscriptionId?: string;
      expiresAt?: number;
      slug?: string;
      now?: number;
    }>;
    const payload = data ?? {};
    if (action === 'create') {
      if (!payload.subscriptionId) {
        return new Response('subscriptionId is required', { status: 400 });
      }
      const slug = crypto.randomUUID().split('-')[0];
      const record: ShareLinkRecord = {
        slug,
        subscriptionId: payload.subscriptionId,
        createdAt: Date.now(),
        expiresAt: payload.expiresAt ?? Date.now() + 7 * 24 * 60 * 60 * 1000,
        active: true,
      };
      this.data.items[slug] = record;
      await this.persist();
      return Response.json(record);
    }
    if (action === 'get') {
      const record = payload.slug ? this.data.items[payload.slug] : undefined;
      if (record) {
        record.lastAccessedAt = Date.now();
        await this.persist();
      }
      return Response.json(record ?? null);
    }
    if (action === 'prune') {
      const now = payload.now ?? Date.now();
      Object.keys(this.data.items).forEach((slug) => {
        const record = this.data.items[slug];
        if (!record) return;
        if (record.expiresAt <= now) {
          delete this.data.items[slug];
        }
      });
      await this.persist();
      return Response.json({ ok: true });
    }
    return new Response('Unknown action', { status: 400 });
  }
}

interface OutboxState {
  items: Record<string, OutboxMessage>;
}

export class OutboxStore extends BaseStore<OutboxState> implements DurableObject {
  constructor(state: DurableObjectState) {
    super(state, { items: {} });
  }

  async fetch(request: Request) {
    await this.ready;
    const { action, data } = (await request.json()) as DoMessage<{
      message?: OutboxMessage;
      id?: string;
      error?: string;
    }>;
    const payload = data ?? {};
    if (action === 'enqueue') {
      const message = payload.message;
      if (!message) {
        return new Response('Missing message', { status: 400 });
      }
      message.status = message.status ?? 'pending';
      message.createdAt = message.createdAt ?? Date.now();
      this.data.items[message.id] = message;
      await this.persist();
      return Response.json(message);
    }
    if (action === 'list') {
      return Response.json(Object.values(this.data.items));
    }
    if (action === 'pending') {
      return Response.json(Object.values(this.data.items).filter((msg) => msg.status === 'pending'));
    }
    if (action === 'markSent') {
      const item = payload.id ? this.data.items[payload.id] : undefined;
      if (item) {
        item.status = 'sent';
        item.lastTriedAt = Date.now();
        await this.persist();
      }
      return Response.json(item ?? null);
    }
    if (action === 'recordError') {
      const item = payload.id ? this.data.items[payload.id] : undefined;
      if (item) {
        item.error = payload.error;
        item.lastTriedAt = Date.now();
        await this.persist();
      }
      return Response.json(item ?? null);
    }
    return new Response('Unknown action', { status: 400 });
  }
}
