import { useState } from 'react';
import TransferMeta from './TransferMeta';
import ReceiveForm from './ReceiveForm';

interface ReceiveSectionProps {
  transferId: string;
}

export default function ReceiveSection({ transferId }: ReceiveSectionProps) {
  const [expired, setExpired] = useState(false);

  return (
    <div className="animate-slide-up space-y-8">
      <div className="text-center space-y-3">
        <h2 className="text-4xl font-bold tracking-tight">
          Fichier <span className="text-gradient">sécurisé</span> reçu
        </h2>
        <p className="max-w-sm mx-auto leading-relaxed" style={{ color: 'var(--text-2)' }}>
          Entrez le mot de passe ou importez vos clés pour déchiffrer.
        </p>
        <TransferMeta transferId={transferId} onExpired={() => setExpired(true)} />
      </div>

      {!expired && (
        <div className="card p-8">
          <ReceiveForm transferId={transferId} />
        </div>
      )}
    </div>
  );
}
