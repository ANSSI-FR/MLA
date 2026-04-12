import { useState } from 'react';
import { generateKeypair } from '../lib/mla';

export default function KeyGenerator() {
  const [generated, setGenerated] = useState(false);

  const handleGenerate = async () => {
    const { privateKey, publicKey } = await generateKeypair();

    const privBlob = new Blob([privateKey], { type: 'application/octet-stream' });
    const privUrl = URL.createObjectURL(privBlob);
    const privLink = document.createElement('a');
    privLink.href = privUrl;
    privLink.download = 'my-key.mlapriv';
    privLink.click();
    URL.revokeObjectURL(privUrl);

    const pubBlob = new Blob([publicKey], { type: 'application/octet-stream' });
    const pubUrl = URL.createObjectURL(pubBlob);
    const pubLink = document.createElement('a');
    pubLink.href = pubUrl;
    pubLink.download = 'my-key.mlapub';
    pubLink.click();
    URL.revokeObjectURL(pubUrl);

    setGenerated(true);
  };

  return (
    <div
      className="rounded-lg p-4 space-y-3"
      style={{ border: '1px solid var(--border)', background: 'var(--bg-surface)' }}
    >
      <p className="text-sm" style={{ color: 'var(--text-2)' }}>
        Pas encore de clés ? Générez une paire de clés MLA.
      </p>
      <button
        type="button"
        onClick={handleGenerate}
        className="btn-secondary"
        style={{ width: 'auto', padding: '8px 16px', fontSize: '0.875rem' }}
      >
        Générer mes clés
      </button>
      {generated && (
        <p className="text-xs flex items-center gap-1.5 animate-fade-in" style={{ color: 'var(--success)' }}>
          <svg aria-hidden="true" className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
          </svg>
          Clés générées et téléchargées. Gardez votre .mlapriv en lieu sûr !
        </p>
      )}
    </div>
  );
}
