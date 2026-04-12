import { useId, useState } from 'react';

interface KeyImporterProps {
  label: string;
  accept: string;
  onKeyLoaded: (data: Uint8Array) => void;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  return `${(bytes / 1024).toFixed(1)} Ko`;
}

function keyTypeLabel(filename: string): string {
  if (filename.endsWith('.mlapriv')) return 'Clé privée';
  if (filename.endsWith('.mlapub')) return 'Clé publique';
  return 'Clé';
}

export default function KeyImporter({ label, accept, onKeyLoaded }: KeyImporterProps) {
  const inputId = useId();
  const [loaded, setLoaded] = useState<{ name: string; size: number } | null>(null);

  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const buffer = await file.arrayBuffer();
    onKeyLoaded(new Uint8Array(buffer));
    setLoaded({ name: file.name, size: file.size });
    e.target.value = '';
  };

  return (
    <div className="space-y-2">
      <span className="text-sm" style={{ color: 'var(--text-2)' }}>{label}</span>

      {loaded ? (
        <div
          className="flex items-center justify-between gap-3 px-3 py-2.5 rounded-lg border"
          style={{ background: 'var(--success-bg)', borderColor: 'rgba(26,110,60,0.3)' }}
        >
          <div className="flex items-center gap-2 min-w-0">
            <svg
              aria-hidden="true"
              className="w-4 h-4 flex-shrink-0"
              style={{ color: 'var(--success)' }}
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
              />
            </svg>
            <div className="min-w-0">
              <p className="text-sm font-medium truncate" style={{ color: 'var(--success)' }}>{loaded.name}</p>
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                {keyTypeLabel(loaded.name)} · {formatSize(loaded.size)}
              </p>
            </div>
          </div>

          <label
            htmlFor={inputId}
            className="flex-shrink-0 text-xs cursor-pointer underline underline-offset-2 transition-colors"
            style={{ color: 'var(--text-3)' }}
            onMouseOver={(e) => (e.currentTarget.style.color = 'var(--text-2)')}
            onMouseOut={(e) => (e.currentTarget.style.color = 'var(--text-3)')}
          >
            Changer
          </label>
          <input
            id={inputId}
            type="file"
            accept={accept}
            onChange={handleFile}
            className="hidden"
          />
        </div>
      ) : (
        <label
          htmlFor={inputId}
          className="flex items-center gap-3 px-3 py-2.5 rounded-lg border cursor-pointer transition-colors"
          style={{ borderColor: 'var(--border-hi)', background: 'var(--bg-surface)' }}
          onMouseOver={(e) => (e.currentTarget.style.borderColor = 'var(--accent)')}
          onMouseOut={(e) => (e.currentTarget.style.borderColor = 'var(--border-hi)')}
        >
          <svg
            aria-hidden="true"
            className="w-4 h-4 flex-shrink-0"
            style={{ color: 'var(--text-3)' }}
            fill="none"
            stroke="currentColor"
            strokeWidth={1.5}
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"
            />
          </svg>
          <span className="text-sm" style={{ color: 'var(--text-3)' }}>Choisir un fichier {accept}</span>
          <input
            id={inputId}
            type="file"
            accept={accept}
            onChange={handleFile}
            className="hidden"
          />
        </label>
      )}
    </div>
  );
}
