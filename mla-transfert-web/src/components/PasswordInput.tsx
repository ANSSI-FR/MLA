import { useMemo } from 'react';

interface PasswordInputProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}

function getStrength(password: string): { label: string; color: string; width: string } {
  const len = password.length;
  if (len === 0) return { label: '', color: 'bg-gray-700', width: 'w-0' };
  if (len < 8) return { label: 'Faible', color: 'bg-red-500', width: 'w-1/4' };
  if (len < 12) return { label: 'Moyen', color: 'bg-yellow-500', width: 'w-2/4' };
  if (len < 16) return { label: 'Fort', color: 'bg-green-500', width: 'w-3/4' };
  return { label: 'Excellent', color: 'bg-cyber-500', width: 'w-full' };
}

export default function PasswordInput({ value, onChange, placeholder }: PasswordInputProps) {
  const strength = useMemo(() => getStrength(value), [value]);

  return (
    <div>
      <input
        type="password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder ?? 'Mot de passe'}
        className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-100 focus:border-cyber-500 focus:outline-none"
      />
      {value.length > 0 && (
        <div className="mt-2">
          <div className="h-1 bg-gray-800 rounded-full overflow-hidden">
            <div className={`h-full ${strength.color} ${strength.width} transition-all`} />
          </div>
          <p className="text-xs text-gray-500 mt-1">{strength.label}</p>
        </div>
      )}
    </div>
  );
}
