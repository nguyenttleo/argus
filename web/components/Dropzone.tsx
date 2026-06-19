'use client';

import { useRef, useState } from 'react';

const MAX_BYTES = 32 * 1024 * 1024;

export default function Dropzone({ onFile, disabled }: { onFile: (f: File) => void; disabled?: boolean }) {
  const [over, setOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  function handle(file: File | undefined) {
    setError(null);
    if (!file) return;
    if (file.size > MAX_BYTES) return setError(`Too large: ${(file.size / 1024 / 1024).toFixed(1)} MB (limit 32 MB).`);
    if (file.size === 0) return setError('Empty file.');
    onFile(file);
  }

  return (
    <div className="text-[13px]">
      <div
        role="button"
        tabIndex={0}
        aria-disabled={disabled}
        onClick={() => !disabled && inputRef.current?.click()}
        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && !disabled && inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          if (!disabled) setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          if (!disabled) handle(e.dataTransfer.files?.[0]);
        }}
        className={`dropzone ${over ? 'dropzone-active' : ''} ${disabled ? 'pointer-events-none opacity-50' : ''}`}
      >
        <div className="text-fg">
          <span className="prompt">&gt;</span> drop file or browse
        </div>
        <div className="mt-1.5 text-muted">hash, signature, YARA, static analysis / 32 MB max</div>
        <input ref={inputRef} type="file" className="hidden" onChange={(e) => handle(e.target.files?.[0])} />
      </div>
      {error && (
        <div className="mt-2" role="alert" style={{ color: '#f92672' }}>
          x {error}
        </div>
      )}
    </div>
  );
}
