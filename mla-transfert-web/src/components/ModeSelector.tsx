interface ModeSelectorProps {
  mode: 'simple' | 'advanced';
  onModeChange: (mode: 'simple' | 'advanced') => void;
}

export default function ModeSelector({ mode, onModeChange }: ModeSelectorProps) {
  return (
    <div className="flex rounded-lg overflow-hidden border border-gray-700">
      <button
        onClick={() => onModeChange('simple')}
        className={`flex-1 px-4 py-2 text-sm font-medium transition-colors ${
          mode === 'simple'
            ? 'bg-cyber-700 text-white'
            : 'bg-gray-800 text-gray-400 hover:text-gray-200'
        }`}
      >
        Mot de passe
      </button>
      <button
        onClick={() => onModeChange('advanced')}
        className={`flex-1 px-4 py-2 text-sm font-medium transition-colors ${
          mode === 'advanced'
            ? 'bg-cyber-700 text-white'
            : 'bg-gray-800 text-gray-400 hover:text-gray-200'
        }`}
      >
        Cles MLA
      </button>
    </div>
  );
}
