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

export default function FileDropZone({
  onFilesSelected,
  files,
  maxSizeBytes = 100 * 1024 * 1024,
}: FileDropZoneProps) {
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
      if (errorMsg) setSizeError(errorMsg);
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
    <div className="space-y-2">
      <div
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`drop-zone p-6 text-center ${isDragging ? 'drop-zone-active' : ''}`}
      >
        {files.length === 0 ? (
          <>
            <input type="file" multiple onChange={handleFileInput} className="hidden" id="file-input" />
            <label htmlFor="file-input" className="cursor-pointer block">
              <div
                className="w-12 h-12 mx-auto mb-4 rounded-xl flex items-center justify-center transition-all duration-200"
                style={{
                  background: isDragging ? 'rgba(0,86,135,0.12)' : 'var(--bg-surface)',
                  color: isDragging ? 'var(--accent)' : 'var(--text-3)',
                  border: '1px solid var(--border)',
                }}
              >
                <svg aria-hidden="true" className="w-6 h-6" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                </svg>
              </div>
              <p className="text-base font-medium mb-1" style={{ color: 'var(--text-1)' }}>
                {isDragging ? 'Relâchez pour ajouter' : 'Glissez vos fichiers ici'}
              </p>
              <p className="text-sm" style={{ color: 'var(--text-3)' }}>
                ou{' '}
                <span style={{ color: 'var(--accent)' }}>parcourir</span>
                {' '}· max {formatSize(maxSizeBytes)}
              </p>
            </label>
          </>
        ) : (
          <div className="text-left animate-slide-up">
            <ul className="space-y-2 mb-4">
              {files.map((f, i) => (
                <li
                  key={i}
                  className="flex items-center justify-between gap-3 py-2 px-3 rounded-xl"
                  style={{
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border)',
                  }}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
                      style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}
                    >
                      <svg aria-hidden="true" className="w-3.5 h-3.5" style={{ color: 'var(--text-2)' }} fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                      </svg>
                    </div>
                    <span className="text-sm truncate" style={{ color: 'var(--text-1)' }}>{f.name}</span>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0">
                    <span className="text-xs font-mono" style={{ color: 'var(--text-3)' }}>{formatSize(f.size)}</span>
                    <button
                      type="button"
                      onClick={() => removeFile(i)}
                      aria-label={`Retirer ${f.name}`}
                      className="w-6 h-6 rounded-lg flex items-center justify-center transition-all duration-150"
                      style={{ color: 'var(--text-3)' }}
                      onMouseOver={(e) => {
                        e.currentTarget.style.color = 'var(--coral)';
                        e.currentTarget.style.background = 'rgba(247,108,108,0.10)';
                      }}
                      onMouseOut={(e) => {
                        e.currentTarget.style.color = 'var(--text-3)';
                        e.currentTarget.style.background = 'transparent';
                      }}
                    >
                      <svg aria-hidden="true" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                </li>
              ))}
            </ul>

            <div
              className="flex items-center justify-between pt-3"
              style={{ borderTop: '1px solid var(--border)' }}
            >
              <div className="flex items-center gap-3">
                <span className="section-label">{files.length} fichier{files.length > 1 ? 's' : ''}</span>
                <span className="text-xs font-mono" style={{ color: 'var(--text-3)' }}>{formatSize(totalSize)}</span>
              </div>
              <label
                htmlFor="file-input-more"
                className="inline-flex items-center gap-1.5 text-xs cursor-pointer transition-colors duration-150"
                style={{ color: 'var(--text-3)' }}
                onMouseOver={(e) => (e.currentTarget.style.color = 'var(--accent)')}
                onMouseOut={(e) => (e.currentTarget.style.color = 'var(--text-3)')}
              >
                <svg aria-hidden="true" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
                </svg>
                Ajouter
              </label>
              <input type="file" multiple onChange={handleFileInput} className="hidden" id="file-input-more" />
            </div>
          </div>
        )}
      </div>

      {sizeError && (
        <p className="text-sm flex items-center gap-2 animate-fade-in" role="alert" style={{ color: 'var(--coral)' }}>
          <svg aria-hidden="true" className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
          </svg>
          {sizeError}
        </p>
      )}
    </div>
  );
}
