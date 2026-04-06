interface TransferProgressProps {
  progress: number;
  label: string;
}

export default function TransferProgress({ progress, label }: TransferProgressProps) {
  return (
    <div>
      <div className="flex justify-between text-sm text-gray-400 mb-1">
        <span>{label}</span>
        <span>{Math.round(progress)}%</span>
      </div>
      <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
        <div
          className="h-full bg-cyber-500 transition-all duration-300"
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  );
}
