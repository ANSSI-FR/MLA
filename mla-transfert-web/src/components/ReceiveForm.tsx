import { useState } from 'react';
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
  const [error, setError] = useState('');
  const [decryptedFiles, setDecryptedFiles] = useState<FileEntry[]>([]);

  const canSubmit =
    (mode === 'simple' && password.length >= 8) ||
    (mode === 'advanced' && receiverPrivKey !== null && senderPubKey !== null);

  const handleDecrypt = async () => {
    try {
      setError('');
      setStatus('downloading');
      setProgress(20);

      const mlaData = await downloadFile(transferId);

      setProgress(50);
      setStatus('decrypting');

      let files: FileEntry[];
      if (mode === 'simple') {
        files = await decryptWithPassword(mlaData, password);
      } else {
        files = await decryptWithKeys(mlaData, receiverPrivKey!, senderPubKey!);
      }

      setDecryptedFiles(files);
      setProgress(100);
      setStatus('done');
    } catch (err) {
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

      {error && <p className="text-red-500 text-sm">{error}</p>}

      {status === 'done' && (
        <div className="space-y-2">
          <p className="text-green-500 text-sm font-medium">Dechiffrement reussi !</p>
          {decryptedFiles.map((file, i) => (
            <button
              key={i}
              onClick={() => downloadDecryptedFile(file)}
              className="w-full text-left px-4 py-3 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors"
            >
              <span className="text-gray-200">{file.name}</span>
              <span className="text-gray-500 text-sm ml-2">
                ({(file.data.length / 1024).toFixed(1)} Ko)
              </span>
            </button>
          ))}
        </div>
      )}

      {status !== 'done' && (
        <button
          onClick={handleDecrypt}
          disabled={!canSubmit || status === 'downloading' || status === 'decrypting'}
          className="w-full py-3 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed bg-cyber-700 text-white hover:bg-cyber-500"
        >
          Dechiffrer et telecharger
        </button>
      )}
    </div>
  );
}
