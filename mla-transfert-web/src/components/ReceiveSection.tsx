import { useState } from 'react';
import TransferMeta from './TransferMeta';
import ReceiveForm from './ReceiveForm';

interface ReceiveSectionProps {
  transferId: string;
}

export default function ReceiveSection({ transferId }: ReceiveSectionProps) {
  const [expired, setExpired] = useState(false);

  return (
    <>
      <div className="text-center mb-8">
        <h2 className="text-3xl font-bold mb-3">Vous avez reçu un fichier sécurisé</h2>
        <p className="text-gray-400 mb-4">
          Entrez le mot de passe ou importez vos clés pour déchiffrer.
        </p>
        <TransferMeta transferId={transferId} onExpired={() => setExpired(true)} />
      </div>
      {!expired && <ReceiveForm transferId={transferId} />}
    </>
  );
}
