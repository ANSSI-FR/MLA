import { useState, useCallback, useEffect, type DragEvent } from 'react';

interface FileDropZoneProps {
  onFilesSelected: (files: File[]) => void;
  files: File[];
  maxSizeBytes?: number;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} Go`;
}

export default function FileDropZone({ onFilesSelected, files, maxSizeBytes = 100 * 1024 * 1024 }: FileDropZoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [sizeError, setSizeError] = useState<string | null>(null);

  useEffect(() => {
    if (!sizeError) return;
    const timer = setTimeout(() => setSizeError(null), 4000);
    return () => clearTimeout(timer);
  }, [sizeError]);

  const filterFiles = useCallback(
    (incoming: File[]): File[] => {
      const valid: File[] = [];
      let errorMsg: string | null = null;

      for (const f of incoming) {
        if (f.size > maxSizeBytes) {
          errorMsg = `"${f.name}" dépasse la limite de ${formatSize(maxSizeBytes)}`;
        } else {
          valid.push(f);
        }
      }

      if (errorMsg) {
        setSizeError(errorMsg);
      }

      return valid;
    },
    [maxSizeBytes],
  );

  const handleDrop = useCallback(
    (e: DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setIsDragging(false);
      const dropped = Array.from(e.dataTransfer.files);
      const valid = filterFiles(dropped);
      if (valid.length > 0) {
        setSizeError(null);
        onFilesSelected([...files, ...valid]);
      }
    },
    [files, onFilesSelected, filterFiles],
  );

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      if (e.target.files) {
        const selected = Array.from(e.target.files);
        const valid = filterFiles(selected);
        if (valid.length > 0) {
          setSizeError(null);
          onFilesSelected([...files, ...valid]);
        }
        // Reset pour permettre de re-sélectionner le même fichier
        e.target.value = '';
      }
    },
    [files, onFilesSelected, filterFiles],
  );

  const removeFile = (index: number) => {
    onFilesSelected(files.filter((_, i) => i !== index));
  };

  const totalSize = files.reduce((acc, f) => acc + f.size, 0);

  return (
    <div>
      <div
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`border-2 border-dashed rounded-xl p-8 text-center transition-colors ${
          isDragging ? 'border-cyber-500 bg-cyber-950/30' : 'border-gray-700 hover:border-gray-500'
        }`}
      >
        {files.length === 0 ? (
          <>
            <input
              type="file"
              multiple
              onChange={handleFileInput}
              className="hidden"
              id="file-input"
            />
            <label htmlFor="file-input" className="cursor-pointer block">
              {/* Upload icon */}
              <svg
                aria-hidden="true"
                className="w-10 h-10 mx-auto mb-3 text-gray-600"
                fill="none"
                stroke="currentColor"
                strokeWidth={1.5}
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"
                />
              </svg>
              <p className="text-lg mb-1">Glissez vos fichiers ici</p>
              <p className="text-sm text-gray-500">ou cliquez pour parcourir</p>
            </label>
          </>
        ) : (
          <div className="text-left">
            <ul className="space-y-2 mb-3">
              {files.map((f, i) => (
                <li key={i} className="flex items-center justify-between gap-3 py-1.5 px-3 bg-gray-800/60 rounded-lg">
                  <div className="flex items-center gap-2 min-w-0">
                    {/* File icon */}
                    <svg
                      aria-hidden="true"
                      className="w-4 h-4 flex-shrink-0 text-gray-500"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth={1.5}
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"
                      />
                    </svg>
                    <span className="text-sm text-gray-200 truncate">{f.name}</span>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0">
                    <span className="text-xs text-gray-500">{formatSize(f.size)}</span>
                    <button
                      type="button"
                      onClick={() => removeFile(i)}
                      aria-label={`Retirer ${f.name}`}
                      className="text-gray-600 hover:text-red-400 transition-colors"
                    >
                      <svg
                        aria-hidden="true"
                        className="w-4 h-4"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth={2}
                        viewBox="0 0 24 24"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                </li>
              ))}
            </ul>

            <div className="flex items-center justify-between text-xs text-gray-500 pt-2 border-t border-gray-700/50">
              <span>{files.length} fichier{files.length > 1 ? 's' : ''}</span>
              <span>Total : {formatSize(totalSize)}</span>
            </div>

            {/* Ajouter d'autres fichiers */}
            <label
              htmlFor="file-input-more"
              className="mt-3 inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 cursor-pointer transition-colors"
            >
              <svg aria-hidden="true" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
              </svg>
              Ajouter des fichiers
            </label>
            <input
              type="file"
              multiple
              onChange={handleFileInput}
              className="hidden"
              id="file-input-more"
            />
          </div>
        )}
      </div>

      {sizeError && (
        <p className="mt-2 text-sm text-red-500" role="alert">{sizeError}</p>
      )}
    </div>
  );
}
