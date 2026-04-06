import { useState } from 'react';

interface ShareLinkProps {
  link: string;
}

export default function ShareLink({ link }: ShareLinkProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(link);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-gray-800 rounded-lg p-4 flex items-center gap-3">
      <input
        type="text"
        value={link}
        readOnly
        className="flex-1 bg-transparent text-gray-100 text-sm font-mono focus:outline-none"
      />
      <button
        onClick={handleCopy}
        className="px-3 py-1 rounded bg-cyber-700 text-white text-sm hover:bg-cyber-500 transition-colors"
      >
        {copied ? 'Copie !' : 'Copier'}
      </button>
    </div>
  );
}
