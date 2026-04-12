interface ModeSelectorProps {
  mode: 'simple' | 'advanced';
  onModeChange: (mode: 'simple' | 'advanced') => void;
}

export default function ModeSelector({ mode, onModeChange }: ModeSelectorProps) {
  return (
    <div className="mode-toggle" role="group" aria-label="Mode de chiffrement">
      <button
        type="button"
        onClick={() => onModeChange('simple')}
        className={`mode-toggle-btn ${mode === 'simple' ? 'mode-toggle-btn-active' : 'mode-toggle-btn-inactive'}`}
        aria-pressed={mode === 'simple'}
      >
        Mot de passe
      </button>
      <button
        type="button"
        onClick={() => onModeChange('advanced')}
        className={`mode-toggle-btn ${mode === 'advanced' ? 'mode-toggle-btn-active' : 'mode-toggle-btn-inactive'}`}
        aria-pressed={mode === 'advanced'}
      >
        Clés MLA
      </button>
    </div>
  );
}
