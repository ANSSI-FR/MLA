interface TransferProgressProps {
  progress: number;
  label: string;
}

export default function TransferProgress({ progress, label }: TransferProgressProps) {
  return (
    <div className="space-y-2 animate-fade-in">
      <div className="flex justify-between items-center">
        <span className="text-sm flex items-center gap-2" style={{ color: 'var(--text-2)' }}>
          <span
            className="inline-block w-1.5 h-1.5 rounded-full animate-pulse"
            style={{ background: 'var(--accent)' }}
          />
          {label}
        </span>
        <span className="text-sm font-mono tabular-nums" style={{ color: 'var(--accent)' }}>
          {Math.round(progress)}%
        </span>
      </div>
      <div className="progress-track">
        <div
          className="progress-fill"
          style={{ width: `${progress}%` }}
          role="progressbar"
          aria-valuenow={Math.round(progress)}
          aria-valuemin={0}
          aria-valuemax={100}
        />
      </div>
    </div>
  );
}
