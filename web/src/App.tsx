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
  linkUrl: string;
  intervalDays?: number;
  invokeAt?: number;
  createdAt: number;
  expiresAt: number;
  status: 'active' | 'expired';
}

type Phase = 'loading' | 'register' | 'login' | 'dashboard';

type ShareLookup = Record<string, string>;

type ScheduleMode = 'interval' | 'invoke';

interface EditState {
  linkUrl: string;
  scheduleMode: ScheduleMode;
  intervalDays: string;
  invokeDate: string;
}

const FORM_DEFAULT = {
  name: '',
  linkUrl: '',
  intervalDays: '30',
  scheduleMode: 'interval' as ScheduleMode,
  invokeDate: '',
};

type FormState = typeof FORM_DEFAULT;

const toLocalInputValue = (timestamp: number) => {
  const date = new Date(timestamp);
  const offset = date.getTimezoneOffset();
  const local = new Date(date.getTime() - offset * 60 * 1000);
  return local.toISOString().slice(0, 16);
};

const deriveEditState = (sub: SubscriptionRecord): EditState => ({
  linkUrl: sub.linkUrl,
  scheduleMode: sub.invokeAt ? 'invoke' : 'interval',
  intervalDays: sub.intervalDays ? String(sub.intervalDays) : '',
  invokeDate: sub.invokeAt ? toLocalInputValue(sub.invokeAt) : '',
});

const App = () => {
  const [phase, setPhase] = useState<Phase>('loading');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [subs, setSubs] = useState<SubscriptionRecord[]>([]);
  const [shares, setShares] = useState<ShareLookup>({});
  const [form, setForm] = useState<FormState>({ ...FORM_DEFAULT });
  const [edits, setEdits] = useState<Record<string, EditState>>({});
  const [bulkLink, setBulkLink] = useState('');
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [bulkUpdating, setBulkUpdating] = useState(false);
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

  useEffect(() => {
    const next: Record<string, EditState> = {};
    subs.forEach((sub) => {
      next[sub.id] = deriveEditState(sub);
    });
    setEdits(next);
  }, [subs]);

  const updateEditState = (id: string, patch: Partial<EditState>) => {
    setEdits((prev) => {
      const source = subs.find((s) => s.id === id);
      const fallback: EditState = source
        ? deriveEditState(source)
        : { linkUrl: '', scheduleMode: 'interval', intervalDays: '', invokeDate: '' };
      const base = prev[id] ?? fallback;
      return {
        ...prev,
        [id]: { ...base, ...patch },
      };
    });
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
      const payload: Record<string, unknown> = {
        name: form.name.trim(),
        linkUrl: form.linkUrl.trim(),
      };
      if (!payload.name || !payload.linkUrl) {
        throw new Error('Name and link are required');
      }
      if (form.scheduleMode === 'interval') {
        const days = Number(form.intervalDays);
        if (!Number.isFinite(days) || days <= 0) {
          throw new Error('Enter a valid interval');
        }
        payload.intervalDays = Math.round(days);
      } else {
        if (!form.invokeDate) {
          throw new Error('Pick an invoke date');
        }
        const timestamp = new Date(form.invokeDate).getTime();
        if (Number.isNaN(timestamp)) {
          throw new Error('Invoke date is invalid');
        }
        payload.invokeAt = timestamp;
      }
      await apiFetch('/api/subscriptions', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      setForm({ ...FORM_DEFAULT });
      await refreshSubs();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const handleUpdateSub = async (id: string) => {
    const source = subs.find((sub) => sub.id === id);
    const state = edits[id] ?? (source ? deriveEditState(source) : null);
    if (!state) return;
    setUpdatingId(id);
    setError(null);
    try {
      const payload: Record<string, unknown> = {
        linkUrl: state.linkUrl.trim(),
        scheduleMode: state.scheduleMode,
      };
      if (!payload.linkUrl) {
        throw new Error('Link is required');
      }
      if (state.scheduleMode === 'interval') {
        const days = Number(state.intervalDays);
        if (!Number.isFinite(days) || days <= 0) {
          throw new Error('Enter a valid interval');
        }
        payload.intervalDays = Math.round(days);
      } else {
        if (!state.invokeDate) {
          throw new Error('Pick an invoke date');
        }
        const timestamp = new Date(state.invokeDate).getTime();
        if (Number.isNaN(timestamp)) {
          throw new Error('Invoke date is invalid');
        }
        payload.invokeAt = timestamp;
      }
      await apiFetch(`/api/subscriptions/${id}`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      });
      await refreshSubs();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUpdatingId(null);
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

  const handleBulkLinkUpdate = async (evt: FormEvent<HTMLFormElement>) => {
    evt.preventDefault();
    if (!bulkLink.trim()) {
      setError('Enter a link to apply');
      return;
    }
    setBulkUpdating(true);
    setError(null);
    try {
      await apiFetch('/api/subscriptions/bulk/link', {
        method: 'POST',
        body: JSON.stringify({ linkUrl: bulkLink.trim() }),
      });
      setBulkLink('');
      await refreshSubs();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBulkUpdating(false);
    }
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
        <form className="panel__bulk" onSubmit={handleBulkLinkUpdate}>
          <label>
            Apply link to all subscriptions
            <input
              type="url"
              placeholder="https://example.com/broadcast.txt"
              value={bulkLink}
              onChange={(e) => setBulkLink(e.target.value)}
              required
            />
          </label>
          <button type="submit" disabled={bulkUpdating || !bulkLink.trim()}>
            {bulkUpdating ? 'Updating…' : 'Update all links'}
          </button>
        </form>
        <div className="grid">
          <form onSubmit={handleCreateSub} className="card stack">
            <h3>New subscription</h3>
            <label>
              Name
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </label>
            <label>
              Source link
              <input
                type="url"
                placeholder="https://example.com/content.txt"
                value={form.linkUrl}
                onChange={(e) => setForm({ ...form, linkUrl: e.target.value })}
                required
              />
            </label>
            <div className="schedule stack">
              <span className="muted">Schedule</span>
              <div className="schedule__option">
                <label>
                  <input
                    type="radio"
                    name="schedule"
                    value="interval"
                    checked={form.scheduleMode === 'interval'}
                    onChange={() => setForm((prev) => ({ ...prev, scheduleMode: 'interval' }))}
                  />
                  <span>Interval (days)</span>
                </label>
                {form.scheduleMode === 'interval' && (
                  <input
                    type="number"
                    min="1"
                    value={form.intervalDays}
                    onChange={(e) => setForm({ ...form, intervalDays: e.target.value })}
                    required
                  />
                )}
              </div>
              <div className="schedule__option">
                <label>
                  <input
                    type="radio"
                    name="schedule"
                    value="invoke"
                    checked={form.scheduleMode === 'invoke'}
                    onChange={() => setForm((prev) => ({ ...prev, scheduleMode: 'invoke' }))}
                  />
                  <span>Invoke on date</span>
                </label>
                {form.scheduleMode === 'invoke' && (
                  <input
                    type="datetime-local"
                    value={form.invokeDate}
                    onChange={(e) => setForm({ ...form, invokeDate: e.target.value })}
                    required
                  />
                )}
              </div>
            </div>
            <button type="submit" disabled={busy}>Create subscription</button>
          </form>
          <div className="card">
            {subs.length === 0 ? (
              <p className="muted">No subscriptions yet.</p>
            ) : (
              <ul className="list">
                {subs.map((sub) => (
                  <li key={sub.id} className="list__item">
                    <div className="list__body">
                      <div>
                        <h4>{sub.name}</h4>
                        <p className="muted">
                          {sub.invokeAt
                            ? `Invokes on ${new Date(sub.invokeAt).toLocaleString()}`
                            : sub.intervalDays
                              ? `Interval: every ${sub.intervalDays} day${sub.intervalDays === 1 ? '' : 's'}`
                              : 'Custom schedule'}
                        </p>
                        <p className="muted">
                          Link: <a href={sub.linkUrl} target="_blank" rel="noreferrer">{sub.linkUrl}</a>
                        </p>
                        <p className="muted">Expires: {new Date(sub.expiresAt).toLocaleString()}</p>
                        {shares[sub.id] && (
                          <p className="share">Share link: <a href={shares[sub.id]} target="_blank" rel="noreferrer">{shares[sub.id]}</a></p>
                        )}
                      </div>
                      <div className="edit">
                        <label>
                          Link
                          <input
                            type="url"
                            value={edits[sub.id]?.linkUrl ?? sub.linkUrl}
                            onChange={(e) => updateEditState(sub.id, { linkUrl: e.target.value })}
                            required
                          />
                        </label>
                        <div className="schedule stack">
                          <span className="muted">Schedule</span>
                          <div className="schedule__option">
                            <label>
                              <input
                                type="radio"
                                name={`schedule-${sub.id}`}
                                value="interval"
                                checked={(edits[sub.id]?.scheduleMode ?? 'interval') === 'interval'}
                                onChange={() => updateEditState(sub.id, { scheduleMode: 'interval' })}
                              />
                              <span>Interval (days)</span>
                            </label>
                            {(edits[sub.id]?.scheduleMode ?? 'interval') === 'interval' && (
                              <input
                                type="number"
                                min="1"
                                value={edits[sub.id]?.intervalDays ?? ''}
                                onChange={(e) => updateEditState(sub.id, { intervalDays: e.target.value })}
                                required
                              />
                            )}
                          </div>
                          <div className="schedule__option">
                            <label>
                              <input
                                type="radio"
                                name={`schedule-${sub.id}`}
                                value="invoke"
                                checked={edits[sub.id]?.scheduleMode === 'invoke'}
                                onChange={() => updateEditState(sub.id, { scheduleMode: 'invoke' })}
                              />
                              <span>Invoke on date</span>
                            </label>
                            {edits[sub.id]?.scheduleMode === 'invoke' && (
                              <input
                                type="datetime-local"
                                value={edits[sub.id]?.invokeDate ?? ''}
                                onChange={(e) => updateEditState(sub.id, { invokeDate: e.target.value })}
                                required
                              />
                            )}
                          </div>
                        </div>
                        <div className="edit__actions">
                          <button type="button" onClick={() => handleUpdateSub(sub.id)} disabled={updatingId === sub.id}>
                            {updatingId === sub.id ? 'Saving…' : 'Save changes'}
                          </button>
                        </div>
                      </div>
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
