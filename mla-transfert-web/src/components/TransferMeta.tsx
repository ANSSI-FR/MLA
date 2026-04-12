import { useEffect, useState } from 'react';
import { getTransferInfo, type TransferInfo } from '../lib/api';

interface TransferMetaProps {
  transferId: string;
  onExpired?: () => void;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
}

function formatExpiry(seconds: number): string {
  if (seconds < 60) return "moins d'une minute";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h`;
  const days = Math.floor(hours / 24);
  return `${days} jour${days > 1 ? 's' : ''}`;
}

export default function TransferMeta({ transferId, onExpired }: TransferMetaProps) {
  const [info, setInfo] = useState<TransferInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    getTransferInfo(transferId)
      .then(setInfo)
      .catch((err: Error) => {
        if (err.message.includes('expire')) {
          setExpired(true);
          onExpired?.();
        }
      })
      .finally(() => setLoading(false));
  }, [transferId]);

  if (loading) {
    return (
      <div
        className="flex gap-6 justify-center text-sm animate-pulse"
        style={{ color: 'var(--text-3)' }}
        aria-busy="true"
        aria-label="Chargement des informations du transfert"
      >
        <span className="rounded h-4 w-24 inline-block" style={{ background: 'var(--bg-surface)' }} />
        <span className="rounded h-4 w-32 inline-block" style={{ background: 'var(--bg-surface)' }} />
      </div>
    );
  }

  if (expired) {
    return (
      <div
        role="alert"
        className="text-center px-4 py-3 rounded-lg text-sm border"
        style={{
          background: 'rgba(247,108,108,0.08)',
          borderColor: 'rgba(247,108,108,0.3)',
          color: 'var(--coral)',
        }}
      >
        Ce transfert a expiré ou n'existe pas.
      </div>
    );
  }

  if (!info) return null;

  return (
    <dl className="flex gap-6 justify-center text-sm" style={{ color: 'var(--text-2)' }}>
      <div className="flex items-center gap-2">
        <svg
          aria-hidden="true"
          className="w-4 h-4"
          style={{ color: 'var(--text-3)' }}
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5M10 11.25h4M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125z"
          />
        </svg>
        <dt className="sr-only">Taille</dt>
        <dd>{formatSize(info.size)}</dd>
      </div>

      <div className="flex items-center gap-2">
        <svg
          aria-hidden="true"
          className="w-4 h-4"
          style={{ color: 'var(--text-3)' }}
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        <dt className="sr-only">Expire dans</dt>
        <dd>Expire dans {formatExpiry(info.expires_in_seconds)}</dd>
      </div>
    </dl>
  );
}
