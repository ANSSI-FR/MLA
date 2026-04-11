import { useRef, useState } from 'react';
import ModeSelector from './ModeSelector';
import PasswordInput from './PasswordInput';
import KeyImporter from './KeyImporter';
import TransferProgress from './TransferProgress';
import {
  decryptWithPassword,
  decryptWithKeys,
  type FileEntry,
} from '../lib/mla';
import { downloadFile } from '../lib/api';

interface ReceiveFormProps {
  transferId: string;
}

export default function ReceiveForm({ transferId }: ReceiveFormProps) {
  const [mode, setMode] = useState<'simple' | 'advanced'>('simple');
  const [password, setPassword] = useState('');
  const [receiverPrivKey, setReceiverPrivKey] = useState<Uint8Array | null>(null);
  const [senderPubKey, setSenderPubKey] = useState<Uint8Array | null>(null);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState<'idle' | 'downloading' | 'decrypting' | 'done' | 'error'>('idle');
  const decryptTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [error, setError] = useState('');
  const [decryptedFiles, setDecryptedFiles] = useState<FileEntry[]>([]);

  const canSubmit =
    (mode === 'simple' && password.length >= 12) ||
    (mode === 'advanced' && receiverPrivKey !== null && senderPubKey !== null);

  const handleDecrypt = async () => {
    try {
      setError('');
      setStatus('downloading');
      setProgress(20);

      const mlaData = await downloadFile(transferId);

      setProgress(50);
      setStatus('decrypting');

      // Animation fluide pendant le déchiffrement (opération synchrone WASM)
      decryptTimerRef.current = setInterval(() => {
        setProgress((prev) => (prev < 90 ? prev + 2 : prev));
      }, 80);

      let files: FileEntry[];
      if (mode === 'simple') {
        files = await decryptWithPassword(mlaData, password);
      } else {
        files = await decryptWithKeys(mlaData, receiverPrivKey!, senderPubKey!);
      }

      if (decryptTimerRef.current) clearInterval(decryptTimerRef.current);

      setDecryptedFiles(files);
      setProgress(100);
      setStatus('done');
    } catch (err) {
      if (decryptTimerRef.current) clearInterval(decryptTimerRef.current);
      setError(err instanceof Error ? err.message : 'Erreur de dechiffrement');
      setStatus('error');
    }
  };

  const downloadDecryptedFile = (file: FileEntry) => {
    const blob = new Blob([file.data]);
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = file.name;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-xl mx-auto">
      <ModeSelector mode={mode} onModeChange={setMode} />

      {mode === 'simple' ? (
        <PasswordInput
          value={password}
          onChange={setPassword}
          placeholder="Mot de passe fourni par l'expediteur"
        />
      ) : (
        <div className="space-y-4">
          <KeyImporter
            label="Votre cle privee (.mlapriv) pour dechiffrer"
            accept=".mlapriv"
            onKeyLoaded={setReceiverPrivKey}
          />
          <KeyImporter
            label="Cle publique de l'expediteur (.mlapub) pour verifier"
            accept=".mlapub"
            onKeyLoaded={setSenderPubKey}
          />
        </div>
      )}

      {status !== 'idle' && status !== 'done' && status !== 'error' && (
        <TransferProgress
          progress={progress}
          label={status === 'downloading' ? 'Telechargement...' : 'Dechiffrement...'}
        />
      )}

      {error && (
        <p className="text-red-400 text-sm flex items-center gap-2 animate-fade-in" role="alert">
          <svg aria-hidden="true" className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
          </svg>
          {error}
        </p>
      )}

      {status === 'done' && (
        <div className="space-y-3 animate-slide-up">
          <p className="text-green-400 text-sm font-medium flex items-center gap-2">
            <svg aria-hidden="true" className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Déchiffrement réussi
          </p>
          {decryptedFiles.map((file, i) => (
            <button
              key={i}
              onClick={() => downloadDecryptedFile(file)}
              className="card-hover w-full text-left px-4 py-3 flex items-center justify-between gap-3"
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <svg aria-hidden="true" className="w-4 h-4 text-cyber-500 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
                </svg>
                <span className="text-gray-200 text-sm truncate">{file.name}</span>
              </div>
              <span className="text-xs text-gray-500 font-mono flex-shrink-0">
                {(file.data.length / 1024).toFixed(1)} Ko
              </span>
            </button>
          ))}
        </div>
      )}

      {status !== 'done' && (
        <button
          onClick={handleDecrypt}
          disabled={!canSubmit || status === 'downloading' || status === 'decrypting'}
          className="btn-primary"
        >
          {status === 'downloading' ? 'Téléchargement…' : status === 'decrypting' ? 'Déchiffrement…' : 'Déchiffrer et télécharger'}
        </button>
      )}
    </div>
  );
}
