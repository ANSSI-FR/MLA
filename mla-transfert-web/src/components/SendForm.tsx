import { useEffect, useState } from 'react';
import FileDropZone from './FileDropZone';
import ModeSelector from './ModeSelector';
import PasswordInput from './PasswordInput';
import KeyImporter from './KeyImporter';
import KeyGenerator from './KeyGenerator';
import TransferProgress from './TransferProgress';
import ShareLink from './ShareLink';
import {
  encryptWithPassword,
  encryptWithKeys,
  type FileEntry,
} from '../lib/mla';
import { uploadFile } from '../lib/api';

export default function SendForm() {
  const [files, setFiles] = useState<File[]>([]);
  const [mode, setMode] = useState<'simple' | 'advanced'>('simple');
  const [password, setPassword] = useState('');
  const [senderPrivKey, setSenderPrivKey] = useState<Uint8Array | null>(null);
  const [receiverPubKey, setReceiverPubKey] = useState<Uint8Array | null>(null);
  const [expiresHours, setExpiresHours] = useState(24);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState<'idle' | 'encrypting' | 'uploading' | 'done' | 'error'>('idle');
  const [shareLink, setShareLink] = useState('');
  const [error, setError] = useState('');

  const canSubmit =
    files.length > 0 &&
    ((mode === 'simple' && password.length >= 12) ||
      (mode === 'advanced' && senderPrivKey !== null && receiverPubKey !== null));

  // Auto-copie le lien dès qu'il est disponible
  useEffect(() => {
    if (status === 'done' && shareLink) {
      navigator.clipboard.writeText(shareLink).catch(() => {
        // Silencieux : l'utilisateur peut copier manuellement
      });
    }
  }, [status, shareLink]);

  const handleReset = () => {
    setFiles([]);
    setPassword('');
    setSenderPrivKey(null);
    setReceiverPubKey(null);
    setProgress(0);
    setStatus('idle');
    setShareLink('');
    setError('');
  };

  const MAX_FILE_SIZE = 100 * 1024 * 1024;

  const handleSubmit = async () => {
    const oversized = files.find((f) => f.size > MAX_FILE_SIZE);
    if (oversized) {
      setError(`"${oversized.name}" dépasse la limite de 100 Mo`);
      return;
    }

    try {
      setStatus('encrypting');
      setProgress(10);
      setError('');

      const fileEntries: FileEntry[] = await Promise.all(
        files.map(async (f) => ({
          name: f.name,
          data: new Uint8Array(await f.arrayBuffer()),
        })),
      );

      setProgress(30);

      let encrypted: Uint8Array;
      if (mode === 'simple') {
        encrypted = await encryptWithPassword(fileEntries, password);
      } else {
        encrypted = await encryptWithKeys(fileEntries, senderPrivKey!, receiverPubKey!);
      }

      setProgress(70);
      setStatus('uploading');

      const result = await uploadFile(encrypted, expiresHours);

      setProgress(100);
      setStatus('done');
      const base = (import.meta.env.PUBLIC_BASE_URL as string | undefined)
        ?.replace(/\/$/, '') ?? window.location.origin;
      setShareLink(`${base}/receive/${result.id}?rt=${encodeURIComponent(result.room_token)}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erreur inconnue');
      setStatus('error');
    }
  };

  return (
    <div className="space-y-6 max-w-xl mx-auto">
      <FileDropZone files={files} onFilesSelected={setFiles} maxSizeBytes={100 * 1024 * 1024} />

      <ModeSelector mode={mode} onModeChange={setMode} />

      {mode === 'simple' ? (
        <PasswordInput
          value={password}
          onChange={setPassword}
          placeholder="Mot de passe (min. 12 caractères)"
        />
      ) : (
        <div className="space-y-4">
          <KeyImporter
            label="Votre cle privee (.mlapriv) pour signer"
            accept=".mlapriv"
            onKeyLoaded={setSenderPrivKey}
          />
          <KeyImporter
            label="Cle publique du destinataire (.mlapub)"
            accept=".mlapub"
            onKeyLoaded={setReceiverPubKey}
          />
          <KeyGenerator />
        </div>
      )}

      <div>
        <label className="section-label block mb-2">Expiration</label>
        <select
          value={expiresHours}
          onChange={(e) => setExpiresHours(Number(e.target.value))}
          className="input-field text-sm"
        >
          <option value={1}>1 heure</option>
          <option value={24}>24 heures</option>
          <option value={168}>7 jours</option>
        </select>
      </div>

      {status !== 'idle' && status !== 'done' && status !== 'error' && (
        <TransferProgress
          progress={progress}
          label={status === 'encrypting' ? 'Chiffrement...' : 'Upload...'}
        />
      )}

      {error && (
        <p className="text-sm flex items-center gap-2 animate-fade-in" style={{ color: 'var(--coral)' }} role="alert">
          <svg aria-hidden="true" className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
          </svg>
          {error}
        </p>
      )}

      {status === 'done' && shareLink && (
        <>
          <ShareLink link={shareLink} autoCopied />
          <button onClick={handleReset} className="btn-secondary">
            Nouveau transfert
          </button>
        </>
      )}

      {status === 'error' && (
        <button onClick={handleReset} className="btn-secondary">
          Recommencer
        </button>
      )}

      {status !== 'done' && status !== 'error' && (
        <button
          onClick={handleSubmit}
          disabled={!canSubmit || status === 'encrypting' || status === 'uploading'}
          className="btn-primary"
        >
          {status === 'encrypting' ? 'Chiffrement…' : status === 'uploading' ? 'Envoi…' : 'Chiffrer et envoyer'}
        </button>
      )}
    </div>
  );
}
