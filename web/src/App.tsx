import { useEffect, useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import type { CreationOptionsJSON, RequestOptionsJSON } from './lib/webauthn';
import { inflateCreationOptions, inflateRequestOptions, serializeCredential } from './lib/webauthn';

interface AdminStatus {
  registered: boolean;
}

interface SubscriptionRecord {
  id: string;
  name: string;
  subscriberEmail: string;
  amountCents: number;
  currency: string;
  intervalDays: number;
  createdAt: number;
  expiresAt: number;
  notes?: string;
  status: 'active' | 'expired';
}

type Phase = 'loading' | 'register' | 'login' | 'dashboard';

type ShareLookup = Record<string, string>;

const FORM_DEFAULT = {
  name: '',
  email: '',
  amount: '9.99',
  currency: 'USD',
  intervalDays: 30,
  notes: '',
};

const App = () => {
  const [phase, setPhase] = useState<Phase>('loading');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [subs, setSubs] = useState<SubscriptionRecord[]>([]);
  const [shares, setShares] = useState<ShareLookup>({});
  const [form, setForm] = useState({ ...FORM_DEFAULT });
  const passkeySupported = useMemo(() => typeof window !== 'undefined' && 'PublicKeyCredential' in window, []);

  useEffect(() => {
    refreshStatus();
  }, []);

  const refreshStatus = async () => {
    try {
      const next = await apiFetch<AdminStatus>('/api/admin/status');
      setPhase(next.registered ? 'login' : 'register');
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const refreshSubs = async () => {
    try {
      const data = await apiFetch<{ items: SubscriptionRecord[] }>('/api/subscriptions');
      setSubs(data.items);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleRegister = async () => {
    if (!passkeySupported) {
      setError('Passkeys are not supported in this browser.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const start = await apiFetch<{ challenge: string; publicKey: CreationOptionsJSON }>('/api/admin/register/start', {
        method: 'POST',
        body: JSON.stringify({}),
      });
      const options = inflateCreationOptions(start.publicKey);
      const credential = (await navigator.credentials.create({ publicKey: options })) as PublicKeyCredential | null;
      if (!credential) {
        throw new Error('Credential creation was cancelled');
      }
      const payload = serializeCredential(credential);
      await apiFetch('/api/admin/register/finish', {
        method: 'POST',
        body: JSON.stringify({ credential: payload, challenge: start.challenge }),
      });
      await refreshStatus();
      setPhase('login');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const handleLogin = async () => {
    if (!passkeySupported) {
      setError('Passkeys are not supported in this browser.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const start = await apiFetch<{ challenge: string; publicKey: RequestOptionsJSON }>('/api/admin/login/start', {
        method: 'POST',
      });
      const options = inflateRequestOptions(start.publicKey);
      const credential = (await navigator.credentials.get({ publicKey: options, mediation: 'optional' })) as PublicKeyCredential | null;
      if (!credential) {
        throw new Error('Credential request was cancelled');
      }
      const payload = serializeCredential(credential);
      await apiFetch('/api/admin/login/finish', {
        method: 'POST',
        body: JSON.stringify({ credential: payload, challenge: start.challenge }),
      });
      setPhase('dashboard');
      await refreshSubs();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const handleLogout = async () => {
    await apiFetch('/api/admin/logout', { method: 'POST' });
    setPhase('login');
    setSubs([]);
  };

  const handleCreateSub = async (evt: FormEvent<HTMLFormElement>) => {
    evt.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const amountNumber = Number(form.amount);
      const amountCents = Math.round(amountNumber * 100);
      if (!Number.isFinite(amountCents) || amountCents <= 0) {
        throw new Error('Enter a valid amount');
      }
      await apiFetch('/api/subscriptions', {
        method: 'POST',
        body: JSON.stringify({
          name: form.name,
          subscriberEmail: form.email,
          amountCents,
          currency: form.currency,
          intervalDays: Number(form.intervalDays),
          notes: form.notes,
        }),
      });
      setForm({ ...FORM_DEFAULT });
      await refreshSubs();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const handleShare = async (id: string) => {
    try {
      const result = await apiFetch<{ slug: string }>(`/api/subscriptions/${id}/share`, { method: 'POST' });
      setShares((prev) => ({ ...prev, [id]: `${window.location.origin}/s/${result.slug}` }));
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this subscription?')) return;
    await apiFetch(`/api/subscriptions/${id}`, { method: 'DELETE' });
    await refreshSubs();
  };

  const renderContent = () => {
    if (phase === 'loading') {
      return <p>Loading…</p>;
    }
    if (phase === 'register') {
      return (
        <section className="panel">
          <h2>Register Passkey</h2>
          <p className="muted">
            One click creates the admin identity with an auto-generated email, then stores your passkey.
          </p>
          <button type="button" onClick={handleRegister} disabled={busy}>
            Create Admin Passkey
          </button>
        </section>
      );
    }
    if (phase === 'login') {
      return (
        <section className="panel">
          <h2>Admin Login</h2>
          <p className="muted">Use your passkey to unlock the dashboard.</p>
          <button onClick={handleLogin} disabled={busy} className="primary">
            Sign in with Passkey
          </button>
        </section>
      );
    }
    return (
      <section className="panel">
        <header className="panel__header">
          <div>
            <h2>Subscriptions</h2>
            <p className="muted">Create plans, share public links, and monitor expiry.</p>
          </div>
          <div className="panel__actions">
            <a href="/dev/emails" target="_blank" rel="noreferrer">
              View dev emails
            </a>
            <button onClick={handleLogout} className="ghost">
              Logout
            </button>
          </div>
        </header>
        <div className="grid">
          <form onSubmit={handleCreateSub} className="card stack">
            <h3>New subscription</h3>
            <label>
              Name
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </label>
            <label>
              Subscriber email
              <input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required />
            </label>
            <div className="row">
              <label>
                Amount
                <input type="number" min="0" step="0.01" value={form.amount} onChange={(e) => setForm({ ...form, amount: e.target.value })} required />
              </label>
              <label>
                Currency
                <input value={form.currency} onChange={(e) => setForm({ ...form, currency: e.target.value.toUpperCase() })} required />
              </label>
            </div>
            <label>
              Interval (days)
              <input type="number" min="1" value={form.intervalDays} onChange={(e) => setForm({ ...form, intervalDays: Number(e.target.value) })} required />
            </label>
            <label>
              Notes
              <textarea value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} rows={3} />
            </label>
            <button type="submit" disabled={busy}>Create subscription</button>
          </form>
          <div className="card">
            {subs.length === 0 ? (
              <p className="muted">No subscriptions yet.</p>
            ) : (
              <ul className="list">
                {subs.map((sub) => (
                  <li key={sub.id} className="list__item">
                    <div>
                      <h4>{sub.name}</h4>
                      <p className="muted">
                        {(sub.amountCents / 100).toFixed(2)} {sub.currency} · every {sub.intervalDays} days
                      </p>
                      <p className="muted">Subscriber: {sub.subscriberEmail}</p>
                      <p className="muted">Expires: {new Date(sub.expiresAt).toLocaleString()}</p>
                      {shares[sub.id] && (
                        <p className="share">Share link: <a href={shares[sub.id]} target="_blank" rel="noreferrer">{shares[sub.id]}</a></p>
                      )}
                    </div>
                    <div className="actions">
                      <button type="button" onClick={() => handleShare(sub.id)}>
                        Create link
                      </button>
                      <button type="button" className="ghost" onClick={() => handleDelete(sub.id)}>
                        Delete
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </section>
    );
  };

  return (
    <main>
      <div className="layout">
        <header>
          <h1>EasySub</h1>
          <p className="muted">Passwordless subscription manager deployable in one command.</p>
        </header>
        {!passkeySupported && (
          <div className="warning">This browser does not support WebAuthn / passkeys.</div>
        )}
        {error && <div className="error">{error}</div>}
        {renderContent()}
      </div>
    </main>
  );
};

async function apiFetch<T>(input: RequestInfo, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    accept: 'application/json',
    ...(init?.headers as Record<string, string>),
  };
  if (init?.body && !headers['content-type']) {
    headers['content-type'] = 'application/json';
  }
  const response = await fetch(input, {
    ...init,
    headers,
    credentials: 'include',
  });
  if (!response.ok) {
    let message = 'Request failed';
    try {
      const data = await response.json();
      if (typeof data?.error === 'string') {
        message = data.error;
      }
    } catch {
      // ignore
    }
    throw new Error(message);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json();
}

export default App;
