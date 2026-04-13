import { useMemo, useState } from 'react';

interface PasswordInputProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}

// Génère un mot de passe cryptographiquement sûr
// Source d'aléa : crypto.getRandomValues() (CSPRNG navigateur — jamais Math.random())
// Entropie : ~119 bits pour 20 chars sur un alphabet de 74 symboles

// Uniform random integer in [0, max) using rejection sampling.
// Discards values in the incomplete last group so every output has equal
// probability — eliminates modulo bias regardless of alphabet size.
function randBelow(max: number): number {
  // Values ≥ threshold are in a complete group of `max`; reject the rest.
  const threshold = (0x100000000 % max) >>> 0;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if ((buf[0] >>> 0) >= threshold) return (buf[0] >>> 0) % max;
  }
}

function generatePassword(length = 20): string {
  const upper   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower   = 'abcdefghijklmnopqrstuvwxyz';
  const digits  = '0123456789';
  const special = '!@#$%^&*-_=+?';
  const all = upper + lower + digits + special;

  // Guarantee one character from each category, then fill the rest.
  const chars: string[] = [
    upper[randBelow(upper.length)],
    lower[randBelow(lower.length)],
    digits[randBelow(digits.length)],
    special[randBelow(special.length)],
    ...Array.from({ length: length - 4 }, () => all[randBelow(all.length)]),
  ];

  // Fisher-Yates shuffle — each swap index drawn with rejection sampling.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randBelow(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join('');
}

function getStrength(password: string): {
  label: string;
  barColor: string;
  barWidth: string;
  textColor: string;
} {
  const len = password.length;
  if (len === 0)  return { label: '',          barColor: 'var(--border)',  barWidth: '0%',   textColor: 'var(--text-3)' };
  if (len < 8)    return { label: 'Faible',    barColor: 'var(--coral)',   barWidth: '25%',  textColor: 'var(--coral)' };
  if (len < 12)   return { label: 'Moyen',     barColor: 'var(--warn-bar)',  barWidth: '50%',  textColor: 'var(--warn)' };
  if (len < 16)   return { label: 'Fort',      barColor: '#4ade80',          barWidth: '75%',  textColor: 'var(--success)' };
  return           { label: 'Excellent',  barColor: 'var(--accent)',  barWidth: '100%', textColor: 'var(--accent)' };
}

export default function PasswordInput({ value, onChange, placeholder }: PasswordInputProps) {
  const strength = useMemo(() => getStrength(value), [value]);
  const [show, setShow] = useState(false);
  const [genCopied, setGenCopied] = useState(false);

  const handleGenerate = () => {
    const pwd = generatePassword(20);
    onChange(pwd);
    setShow(true); // montre le mot de passe généré
    navigator.clipboard.writeText(pwd).then(() => {
      setGenCopied(true);
      setTimeout(() => setGenCopied(false), 2500);
    });
  };

  return (
    <div className="space-y-2">
      <div className="relative">
        <input
          type={show ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder ?? 'Mot de passe'}
          className="input-field"
          style={{ paddingRight: '5rem' }}
          autoComplete="new-password"
        />

        {/* Bouton générer */}
        <button
          type="button"
          onClick={handleGenerate}
          title="Générer un mot de passe fort"
          className="absolute top-1/2 -translate-y-1/2 flex items-center justify-center rounded-md transition-all"
          style={{
            right: '2.5rem',
            width: '28px',
            height: '28px',
            color: 'var(--text-3)',
          }}
          onMouseOver={(e) => (e.currentTarget.style.color = 'var(--accent)')}
          onMouseOut={(e) => (e.currentTarget.style.color = 'var(--text-3)')}
          aria-label="Générer un mot de passe fort"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.75}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
          </svg>
        </button>

        {/* Bouton afficher/masquer */}
        <button
          type="button"
          onClick={() => setShow((s) => !s)}
          className="absolute right-3 top-1/2 -translate-y-1/2 p-1 transition-colors"
          style={{ color: 'var(--text-3)' }}
          onMouseOver={(e) => (e.currentTarget.style.color = 'var(--text-1)')}
          onMouseOut={(e) => (e.currentTarget.style.color = 'var(--text-3)')}
          aria-label={show ? 'Masquer le mot de passe' : 'Afficher le mot de passe'}
        >
          {show ? (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" />
            </svg>
          ) : (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          )}
        </button>
      </div>

      {/* Barre de force */}
      {value.length > 0 && (
        <div className="animate-fade-in space-y-1">
          <div
            className="h-1 rounded-full overflow-hidden"
            style={{ background: 'var(--bg-surface)' }}
          >
            <div
              className="h-full rounded-full transition-all duration-300"
              style={{ width: strength.barWidth, background: strength.barColor }}
            />
          </div>
          <p className="text-xs" style={{ color: strength.textColor }}>{strength.label}</p>
        </div>
      )}

      {/* Feedback génération */}
      {genCopied && (
        <p className="text-xs flex items-center gap-1.5 animate-fade-in" style={{ color: 'var(--success)' }} aria-live="polite">
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
          </svg>
          Mot de passe généré et copié dans le presse-papier
        </p>
      )}
    </div>
  );
}
