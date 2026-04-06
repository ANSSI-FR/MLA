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
    <div className="border border-gray-700 rounded-lg p-4">
      <p className="text-sm text-gray-400 mb-3">
        Pas encore de cles ? Generez une paire de cles MLA.
      </p>
      <button
        onClick={handleGenerate}
        className="px-4 py-2 rounded-lg bg-gray-800 text-gray-200 hover:bg-gray-700 transition-colors text-sm"
      >
        Generer mes cles
      </button>
      {generated && (
        <p className="text-xs text-green-500 mt-2">
          Cles generees et telechargees. Gardez votre .mlapriv en lieu sur !
        </p>
      )}
    </div>
  );
}
