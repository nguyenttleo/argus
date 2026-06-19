'use client';

import { useEffect, useState } from 'react';
import { scanFile, scanUrl } from '@/lib/api';
import type { Report } from '@/lib/types';
import Dropzone from './Dropzone';

// EICAR carried as base64 so the literal signature is not in the source bundle.
const EICAR_B64 = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=';
const PHASES = ['lexical', 'signatures', 'yara', 'reputation', 'scoring'];

export default function Scanner({ onResult, onBusy }: { onResult: (r: Report) => void; onBusy: (b: boolean) => void }) {
  const [tab, setTab] = useState<'url' | 'file'>('url');
  const [url, setUrl] = useState('');
  const [deepFetch, setDeepFetch] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState(0);

  useEffect(() => {
    if (!loading) return;
    const id = setInterval(() => setPhase((p) => (p + 1) % PHASES.length), 650);
    return () => clearInterval(id);
  }, [loading]);

  async function run(p: Promise<Report>) {
    setLoading(true);
    setError(null);
    onBusy(true);
    try {
      onResult(await p);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
      onBusy(false);
    }
  }

  function submitUrl(value: string) {
    const v = value.trim();
    if (!v) return setError('Enter a URL.');
    setTab('url');
    setUrl(v);
    void run(scanUrl(v, { fetch: deepFetch, reputation: true }));
  }

  function submitFile(file: File) {
    setTab('file');
    void run(scanFile(file));
  }

  function demoEicar() {
    const bytes = Uint8Array.from(atob(EICAR_B64), (c) => c.charCodeAt(0));
    submitFile(new File([bytes], 'eicar.com', { type: 'application/octet-stream' }));
  }

  return (
    <div className="text-[13px]">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="segmented" role="tablist" aria-label="scan type">
          <button type="button" role="tab" aria-selected={tab === 'url'} onClick={() => setTab('url')} className="segmented-item">
            URL
          </button>
          <button type="button" role="tab" aria-selected={tab === 'file'} onClick={() => setTab('file')} className="segmented-item">
            File
          </button>
        </div>
        <button
          type="button"
          aria-pressed={deepFetch}
          onClick={() => setDeepFetch((d) => !d)}
          disabled={loading || tab !== 'url'}
          className="toggle"
        >
          <span className="toggle-box">{deepFetch ? 'x' : ' '}</span>
          deep fetch
        </button>
      </div>

      {tab === 'url' ? (
        <form
          className="scan-form"
          onSubmit={(e) => {
            e.preventDefault();
            submitUrl(url);
          }}
        >
          <label className="sr-only" htmlFor="url-input">
            URL
          </label>
          <span className="prompt" aria-hidden>
            &gt;
          </span>
          <input
            id="url-input"
            data-testid="url-input"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/login"
            spellCheck={false}
            autoComplete="off"
            autoFocus
            disabled={loading}
            className="scan-input"
          />
          <button data-testid="scan-url" disabled={loading} className="btn btn-primary shrink-0">
            scan
          </button>
        </form>
      ) : (
        <Dropzone onFile={submitFile} disabled={loading} />
      )}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="text-muted">samples</span>
        <button type="button" onClick={() => submitUrl('https://www.google.com/')} disabled={loading} data-testid="demo-benign" className="btn">
          google.com
        </button>
        <button
          type="button"
          onClick={() => submitUrl('http://paypal.com@secure-paypa1-login.tk/webscr?cmd=verify')}
          disabled={loading}
          data-testid="demo-phishing"
          className="btn"
        >
          phishing URL
        </button>
        <button type="button" onClick={demoEicar} disabled={loading} data-testid="demo-eicar" className="btn">
          eicar
        </button>
      </div>

      {loading && (
        <div className="mt-4 text-muted" role="status">
          <span className="prompt">&gt;</span> scanning: <span className="text-fg">{PHASES[phase]}</span>
          <span className="caret" />
        </div>
      )}
      {error && (
        <div className="mt-4" role="alert" style={{ color: '#f92672' }}>
          x {error}
        </div>
      )}
    </div>
  );
}
