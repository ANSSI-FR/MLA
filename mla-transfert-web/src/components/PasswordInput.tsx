import { useMemo, useState } from 'react';

interface PasswordInputProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}

function getStrength(password: string): {
  label: string;
  color: string;
  width: string;
  textColor: string;
} {
  const len = password.length;
  if (len === 0)  return { label: '',         color: 'bg-gray-700',   width: 'w-0',    textColor: 'text-gray-600' };
  if (len < 8)    return { label: 'Faible',   color: 'bg-red-500',    width: 'w-1/4',  textColor: 'text-red-400' };
  if (len < 12)   return { label: 'Moyen',    color: 'bg-yellow-500', width: 'w-2/4',  textColor: 'text-yellow-400' };
  if (len < 16)   return { label: 'Fort',     color: 'bg-green-500',  width: 'w-3/4',  textColor: 'text-green-400' };
  return           { label: 'Excellent', color: 'bg-cyber-500',  width: 'w-full', textColor: 'text-cyber-400' };
}

export default function PasswordInput({ value, onChange, placeholder }: PasswordInputProps) {
  const strength = useMemo(() => getStrength(value), [value]);
  const [show, setShow] = useState(false);

  return (
    <div className="space-y-2">
      <div className="relative">
        <input
          type={show ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder ?? 'Mot de passe'}
          className="input-field pr-11"
          autoComplete="current-password"
        />
        <button
          type="button"
          onClick={() => setShow((s) => !s)}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors p-1"
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

      {value.length > 0 && (
        <div className="animate-fade-in space-y-1">
          <div className="h-1 bg-gray-800 rounded-full overflow-hidden">
            <div className={`h-full ${strength.color} ${strength.width} transition-all duration-400 rounded-full`} />
          </div>
          <p className={`text-xs ${strength.textColor}`}>{strength.label}</p>
        </div>
      )}
    </div>
  );
}
