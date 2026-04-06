import { useState, useCallback, type DragEvent } from 'react';

interface FileDropZoneProps {
  onFilesSelected: (files: File[]) => void;
  files: File[];
}

export default function FileDropZone({ onFilesSelected, files }: FileDropZoneProps) {
  const [isDragging, setIsDragging] = useState(false);

  const handleDrop = useCallback(
    (e: DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setIsDragging(false);
      const dropped = Array.from(e.dataTransfer.files);
      onFilesSelected([...files, ...dropped]);
    },
    [files, onFilesSelected],
  );

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      if (e.target.files) {
        const selected = Array.from(e.target.files);
        onFilesSelected([...files, ...selected]);
      }
    },
    [files, onFilesSelected],
  );

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      className={`border-2 border-dashed rounded-xl p-8 text-center transition-colors cursor-pointer ${
        isDragging ? 'border-cyber-500 bg-cyber-950/30' : 'border-gray-700 hover:border-gray-500'
      }`}
    >
      <input type="file" multiple onChange={handleFileInput} className="hidden" id="file-input" />
      <label htmlFor="file-input" className="cursor-pointer">
        <p className="text-lg mb-2">Glissez vos fichiers ici</p>
        <p className="text-sm text-gray-500">ou cliquez pour parcourir</p>
      </label>
      {files.length > 0 && (
        <ul className="mt-4 text-left text-sm text-gray-400">
          {files.map((f, i) => (
            <li key={i} className="py-1">{f.name} ({(f.size / 1024).toFixed(1)} Ko)</li>
          ))}
        </ul>
      )}
    </div>
  );
}
