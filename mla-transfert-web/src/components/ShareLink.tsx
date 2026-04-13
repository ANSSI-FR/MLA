import { useEffect, useState } from 'react';

interface ShareLinkProps {
  link: string;
  autoCopied?: boolean;
}

export default function ShareLink({ link, autoCopied = false }: ShareLinkProps) {
  const [copied, setCopied] = useState(autoCopied);

  useEffect(() => {
    if (autoCopied) {
      const t = setTimeout(() => setCopied(false), 3000);
      return () => clearTimeout(t);
    }
  }, [autoCopied]);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(link);
    setCopied(true);
    setTimeout(() => setCopied(false), 3000);
  };

  return (
    <div className="space-y-2">
      <div
        className="rounded-lg p-4 flex items-center gap-3"
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-hi)' }}
      >
        <input
          type="text"
          value={link}
          readOnly
          aria-label="Lien de partage"
          className="flex-1 bg-transparent text-sm font-mono focus:outline-none min-w-0"
          style={{ color: 'var(--text-1)' }}
          onFocus={(e) => e.currentTarget.select()}
        />
        <button
          onClick={handleCopy}
          aria-label={copied ? 'Lien copié' : 'Copier le lien'}
          className="flex-shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-white text-sm font-medium transition-all focus-visible:outline focus-visible:outline-2"
          style={{ background: 'var(--accent-dark)' }}
          onMouseOver={(e) => (e.currentTarget.style.background = 'var(--accent)')}
          onMouseOut={(e) => (e.currentTarget.style.background = 'var(--accent-dark)')}
        >
          {copied ? (
            <>
              <svg aria-hidden="true" className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
              </svg>
              Copié !
            </>
          ) : (
            <>
              <svg aria-hidden="true" className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184" />
              </svg>
              Copier
            </>
          )}
        </button>
      </div>

      <p
        aria-live="polite"
        className={`text-xs text-center transition-opacity duration-300 ${copied ? 'opacity-100' : 'opacity-0'}`}
        style={{ color: 'var(--success)' }}
      >
        Lien copié dans le presse-papier
      </p>
    </div>
  );
}
