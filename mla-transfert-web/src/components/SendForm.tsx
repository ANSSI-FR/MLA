import { useState } from 'react';
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

type TransferMode = 'relay' | 'p2p';

export default function SendForm() {
  const [files, setFiles] = useState<File[]>([]);
  const [mode, setMode] = useState<'simple' | 'advanced'>('simple');
  const [transferMode, setTransferMode] = useState<TransferMode>('relay');
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
    ((mode === 'simple' && password.length >= 8) ||
      (mode === 'advanced' && senderPrivKey !== null && receiverPubKey !== null));

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

  const handleSubmit = async () => {
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
      setShareLink(`${window.location.origin}/receive/${result.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erreur inconnue');
      setStatus('error');
    }
  };

  return (
    <div className="space-y-6 max-w-xl mx-auto">
      <FileDropZone files={files} onFilesSelected={setFiles} />

      <ModeSelector mode={mode} onModeChange={setMode} />

      {mode === 'simple' ? (
        <PasswordInput
          value={password}
          onChange={setPassword}
          placeholder="Mot de passe (min. 8 caracteres)"
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

      <div className="flex gap-4">
        <select
          value={expiresHours}
          onChange={(e) => setExpiresHours(Number(e.target.value))}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-100 text-sm"
        >
          <option value={1}>1 heure</option>
          <option value={24}>24 heures</option>
          <option value={168}>7 jours</option>
        </select>

        <select
          value={transferMode}
          onChange={(e) => setTransferMode(e.target.value as TransferMode)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-100 text-sm"
        >
          <option value="relay">Relais serveur</option>
          <option value="p2p">P2P (WebRTC)</option>
        </select>
      </div>

      {status !== 'idle' && status !== 'done' && status !== 'error' && (
        <TransferProgress
          progress={progress}
          label={status === 'encrypting' ? 'Chiffrement...' : 'Upload...'}
        />
      )}

      {error && (
        <p className="text-red-500 text-sm">{error}</p>
      )}

      {status === 'done' && shareLink && (
        <>
          <ShareLink link={shareLink} />
          <button
            onClick={handleReset}
            className="w-full py-3 rounded-lg font-medium transition-colors bg-gray-800 text-gray-200 hover:bg-gray-700"
          >
            Nouveau transfert
          </button>
        </>
      )}

      {status === 'error' && (
        <button
          onClick={handleReset}
          className="w-full py-3 rounded-lg font-medium transition-colors bg-gray-800 text-gray-200 hover:bg-gray-700"
        >
          Recommencer
        </button>
      )}

      {status !== 'done' && status !== 'error' && (
        <button
          onClick={handleSubmit}
          disabled={!canSubmit || status === 'encrypting' || status === 'uploading'}
          className="w-full py-3 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed bg-cyber-700 text-white hover:bg-cyber-500"
        >
          Chiffrer et envoyer
        </button>
      )}
    </div>
  );
}
