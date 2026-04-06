interface KeyImporterProps {
  label: string;
  accept: string;
  onKeyLoaded: (data: Uint8Array) => void;
}

export default function KeyImporter({ label, accept, onKeyLoaded }: KeyImporterProps) {
  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const buffer = await file.arrayBuffer();
    onKeyLoaded(new Uint8Array(buffer));
  };

  return (
    <label className="block cursor-pointer">
      <span className="text-sm text-gray-400">{label}</span>
      <input
        type="file"
        accept={accept}
        onChange={handleFile}
        className="mt-1 block w-full text-sm text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-gray-800 file:text-gray-300 hover:file:bg-gray-700"
      />
    </label>
  );
}
