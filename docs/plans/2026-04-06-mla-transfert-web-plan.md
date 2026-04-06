# MLA-Transfert Web Frontend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a user-friendly web interface for MLA-Transfert using Astro + React + TailwindCSS, integrating the mla-wasm module for client-side encryption and the Axum backend for file relay and P2P signaling.

**Architecture:** Astro static site with React islands for interactive components. WASM module loaded at init for all crypto operations. Two modes: simple (password) and advanced (MLA keys). Two transfer modes: relay (server) and P2P (WebRTC). All crypto happens in the browser -- zero-knowledge.

**Tech Stack:** Astro, React 19, TypeScript, TailwindCSS, mla-wasm (WASM), WebRTC API

---

## File Structure

```
mla-transfert-web/
├── package.json
├── astro.config.mjs
├── tailwind.config.mjs
├── tsconfig.json
├── public/
│   └── favicon.svg
├── src/
│   ├── layouts/
│   │   └── Layout.astro          # Base HTML layout with head, dark theme
│   ├── pages/
│   │   ├── index.astro           # Landing page with send form
│   │   └── receive/[id].astro    # Download page for a transfer
│   ├── components/
│   │   ├── SendForm.tsx          # Main send form (drag&drop, mode selector, submit)
│   │   ├── ReceiveForm.tsx       # Download form (password/key input, decrypt)
│   │   ├── FileDropZone.tsx      # Drag & drop area for files
│   │   ├── ModeSelector.tsx      # Toggle simple/advanced mode
│   │   ├── PasswordInput.tsx     # Password field with strength indicator
│   │   ├── KeyImporter.tsx       # Import .mlapriv/.mlapub files
│   │   ├── KeyGenerator.tsx      # Generate + download MLA keypair
│   │   ├── TransferProgress.tsx  # Upload/download progress bar
│   │   └── ShareLink.tsx         # Display + copy share link
│   ├── lib/
│   │   ├── mla.ts               # WASM init + typed wrappers around mla-wasm functions
│   │   ├── api.ts               # HTTP client for backend API (upload, download, info)
│   │   └── webrtc.ts            # WebRTC P2P file transfer logic
│   └── styles/
│       └── global.css            # Tailwind directives + custom styles
```

---

### Task 1: Scaffold Astro project with Tailwind

**Files:**
- Create: `mla-transfert-web/package.json`
- Create: `mla-transfert-web/astro.config.mjs`
- Create: `mla-transfert-web/tailwind.config.mjs`
- Create: `mla-transfert-web/tsconfig.json`
- Create: `mla-transfert-web/src/layouts/Layout.astro`
- Create: `mla-transfert-web/src/pages/index.astro`
- Create: `mla-transfert-web/src/styles/global.css`

- [ ] **Step 1: Create package.json**

```json
{
  "name": "mla-transfert-web",
  "type": "module",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "dev": "astro dev",
    "build": "astro build",
    "preview": "astro preview"
  },
  "dependencies": {
    "astro": "^5.0.0",
    "@astrojs/react": "^4.0.0",
    "@astrojs/tailwind": "^6.0.0",
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0",
    "tailwindcss": "^4.0.0"
  }
}
```

- [ ] **Step 2: Create astro.config.mjs**

```javascript
import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  integrations: [react(), tailwind()],
  vite: {
    optimizeDeps: {
      exclude: ['mla-wasm'],
    },
  },
});
```

- [ ] **Step 3: Create tailwind.config.mjs**

```javascript
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          50: '#f0f9ff',
          500: '#0ea5e9',
          700: '#0369a1',
          900: '#0c4a6e',
          950: '#082f49',
        },
      },
    },
  },
  plugins: [],
};
```

- [ ] **Step 4: Create tsconfig.json**

```json
{
  "extends": "astro/tsconfigs/strict",
  "compilerOptions": {
    "jsx": "react-jsx"
  }
}
```

- [ ] **Step 5: Create Layout.astro**

```astro
---
interface Props {
  title: string;
}

const { title } = Astro.props;
---

<!doctype html>
<html lang="fr" class="dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="description" content="Transfert de fichiers securise avec chiffrement post-quantique MLA" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <title>{title}</title>
  </head>
  <body class="min-h-screen bg-gray-950 text-gray-100">
    <header class="border-b border-gray-800 px-6 py-4">
      <div class="mx-auto max-w-4xl flex items-center gap-3">
        <h1 class="text-xl font-bold text-cyber-500">MLA-Transfert</h1>
        <span class="text-xs text-gray-500">Chiffrement post-quantique, zero-knowledge</span>
      </div>
    </header>
    <main class="mx-auto max-w-4xl px-6 py-10">
      <slot />
    </main>
  </body>
</html>
```

- [ ] **Step 6: Create global.css**

```css
@tailwind base;
@tailwind components;
@tailwind utilities;
```

- [ ] **Step 7: Create index.astro (placeholder)**

```astro
---
import Layout from '../layouts/Layout.astro';
---

<Layout title="MLA-Transfert">
  <div class="text-center">
    <h2 class="text-3xl font-bold mb-4">Envoyez vos fichiers en toute securite</h2>
    <p class="text-gray-400 mb-8">Chiffrement post-quantique MLA, directement dans votre navigateur.</p>
    <div id="send-form">
      <!-- React component will mount here -->
    </div>
  </div>
</Layout>
```

- [ ] **Step 8: Install dependencies and verify**

```bash
cd mla-transfert-web && npm install && npm run build
```

Expected: build OK

- [ ] **Step 9: Commit**

```bash
git add mla-transfert-web/
git commit -m "feat(web): scaffold Astro project with React and TailwindCSS"
```

---

### Task 2: WASM integration layer

**Files:**
- Create: `mla-transfert-web/src/lib/mla.ts`

- [ ] **Step 1: Copy WASM package**

The WASM package needs to be accessible. Link or copy from mla-wasm/pkg:

```bash
cd mla-transfert-web && npm install ../mla-wasm/pkg
```

- [ ] **Step 2: Create mla.ts typed wrapper**

```typescript
import init, {
  generate_keypair,
  encrypt_with_password,
  decrypt_with_password,
  encrypt_with_keys,
  decrypt_with_keys,
  type MlaKeypair,
} from 'mla-wasm';

let initialized = false;

export async function initMla(): Promise<void> {
  if (!initialized) {
    await init();
    initialized = true;
  }
}

export interface FileEntry {
  name: string;
  data: Uint8Array;
}

export async function generateKeypair(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
  await initMla();
  const kp = generate_keypair();
  return {
    privateKey: kp.private_key,
    publicKey: kp.public_key,
  };
}

export async function encryptWithPassword(
  files: FileEntry[],
  password: string,
): Promise<Uint8Array> {
  await initMla();
  const names = files.map((f) => f.name);
  const contents = files.map((f) => f.data);
  return encrypt_with_password(names, contents, password);
}

export async function decryptWithPassword(
  mlaData: Uint8Array,
  password: string,
): Promise<FileEntry[]> {
  await initMla();
  const entries: [string, Uint8Array][] = decrypt_with_password(mlaData, password);
  return entries.map(([name, data]) => ({ name, data }));
}

export async function encryptWithKeys(
  files: FileEntry[],
  senderPrivateKey: Uint8Array,
  receiverPublicKey: Uint8Array,
): Promise<Uint8Array> {
  await initMla();
  const names = files.map((f) => f.name);
  const contents = files.map((f) => f.data);
  return encrypt_with_keys(names, contents, senderPrivateKey, receiverPublicKey);
}

export async function decryptWithKeys(
  mlaData: Uint8Array,
  receiverPrivateKey: Uint8Array,
  senderPublicKey: Uint8Array,
): Promise<FileEntry[]> {
  await initMla();
  const entries: [string, Uint8Array][] = decrypt_with_keys(
    mlaData,
    receiverPrivateKey,
    senderPublicKey,
  );
  return entries.map(([name, data]) => ({ name, data }));
}
```

- [ ] **Step 3: Verify TypeScript compiles**

Run: `cd mla-transfert-web && npx astro check`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add mla-transfert-web/src/lib/mla.ts mla-transfert-web/package.json
git commit -m "feat(web): add WASM integration layer with typed wrappers"
```

---

### Task 3: API client for backend

**Files:**
- Create: `mla-transfert-web/src/lib/api.ts`

- [ ] **Step 1: Create api.ts**

```typescript
const API_BASE = import.meta.env.PUBLIC_API_URL ?? 'http://localhost:3001';

export interface UploadResponse {
  id: string;
  expires_in_hours: number;
}

export interface TransferInfo {
  id: string;
  size: number;
  expires_in_seconds: number;
}

export async function uploadFile(
  encryptedData: Uint8Array,
  expiresHours: number = 24,
): Promise<UploadResponse> {
  const formData = new FormData();
  formData.append('file', new Blob([encryptedData]), 'transfer.mla');
  formData.append('expires_hours', String(expiresHours));

  const response = await fetch(`${API_BASE}/api/upload`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.error ?? 'Upload failed');
  }

  return response.json();
}

export async function downloadFile(id: string): Promise<Uint8Array> {
  const response = await fetch(`${API_BASE}/api/download/${id}`);

  if (response.status === 410) {
    throw new Error('Ce transfert a expire');
  }
  if (!response.ok) {
    throw new Error('Transfert introuvable');
  }

  const buffer = await response.arrayBuffer();
  return new Uint8Array(buffer);
}

export async function getTransferInfo(id: string): Promise<TransferInfo> {
  const response = await fetch(`${API_BASE}/api/info/${id}`);

  if (response.status === 410) {
    throw new Error('Ce transfert a expire');
  }
  if (!response.ok) {
    throw new Error('Transfert introuvable');
  }

  return response.json();
}
```

- [ ] **Step 2: Commit**

```bash
git add mla-transfert-web/src/lib/api.ts
git commit -m "feat(web): add API client for backend communication"
```

---

### Task 4: Core UI components (FileDropZone, PasswordInput, ModeSelector)

**Files:**
- Create: `mla-transfert-web/src/components/FileDropZone.tsx`
- Create: `mla-transfert-web/src/components/PasswordInput.tsx`
- Create: `mla-transfert-web/src/components/ModeSelector.tsx`
- Create: `mla-transfert-web/src/components/ShareLink.tsx`
- Create: `mla-transfert-web/src/components/TransferProgress.tsx`

- [ ] **Step 1: Create FileDropZone.tsx**

```tsx
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
      <input
        type="file"
        multiple
        onChange={handleFileInput}
        className="hidden"
        id="file-input"
      />
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
```

- [ ] **Step 2: Create PasswordInput.tsx**

```tsx
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
```

- [ ] **Step 3: Create ModeSelector.tsx**

```tsx
interface ModeSelectorProps {
  mode: 'simple' | 'advanced';
  onModeChange: (mode: 'simple' | 'advanced') => void;
}

export default function ModeSelector({ mode, onModeChange }: ModeSelectorProps) {
  return (
    <div className="flex rounded-lg overflow-hidden border border-gray-700">
      <button
        onClick={() => onModeChange('simple')}
        className={`flex-1 px-4 py-2 text-sm font-medium transition-colors ${
          mode === 'simple'
            ? 'bg-cyber-700 text-white'
            : 'bg-gray-800 text-gray-400 hover:text-gray-200'
        }`}
      >
        Mot de passe
      </button>
      <button
        onClick={() => onModeChange('advanced')}
        className={`flex-1 px-4 py-2 text-sm font-medium transition-colors ${
          mode === 'advanced'
            ? 'bg-cyber-700 text-white'
            : 'bg-gray-800 text-gray-400 hover:text-gray-200'
        }`}
      >
        Cles MLA
      </button>
    </div>
  );
}
```

- [ ] **Step 4: Create ShareLink.tsx**

```tsx
import { useState } from 'react';

interface ShareLinkProps {
  link: string;
}

export default function ShareLink({ link }: ShareLinkProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(link);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-gray-800 rounded-lg p-4 flex items-center gap-3">
      <input
        type="text"
        value={link}
        readOnly
        className="flex-1 bg-transparent text-gray-100 text-sm font-mono focus:outline-none"
      />
      <button
        onClick={handleCopy}
        className="px-3 py-1 rounded bg-cyber-700 text-white text-sm hover:bg-cyber-500 transition-colors"
      >
        {copied ? 'Copie !' : 'Copier'}
      </button>
    </div>
  );
}
```

- [ ] **Step 5: Create TransferProgress.tsx**

```tsx
interface TransferProgressProps {
  progress: number; // 0-100
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
```

- [ ] **Step 6: Commit**

```bash
git add mla-transfert-web/src/components/
git commit -m "feat(web): add core UI components (drop zone, password, mode selector, share link, progress)"
```

---

### Task 5: Key management components

**Files:**
- Create: `mla-transfert-web/src/components/KeyImporter.tsx`
- Create: `mla-transfert-web/src/components/KeyGenerator.tsx`

- [ ] **Step 1: Create KeyImporter.tsx**

```tsx
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
```

- [ ] **Step 2: Create KeyGenerator.tsx**

```tsx
import { useState } from 'react';
import { generateKeypair } from '../lib/mla';

export default function KeyGenerator() {
  const [generated, setGenerated] = useState(false);

  const handleGenerate = async () => {
    const { privateKey, publicKey } = await generateKeypair();

    // Download private key
    const privBlob = new Blob([privateKey], { type: 'application/octet-stream' });
    const privUrl = URL.createObjectURL(privBlob);
    const privLink = document.createElement('a');
    privLink.href = privUrl;
    privLink.download = 'my-key.mlapriv';
    privLink.click();
    URL.revokeObjectURL(privUrl);

    // Download public key
    const pubBlob = new Blob([publicKey], { type: 'application/octet-stream' });
    const pubUrl = URL.createObjectURL(pubBlob);
    const pubLink = document.createElement('a');
    pubLink.href = pubUrl;
    pubLink.download = 'my-key.mlapub';
    pubLink.click();
    URL.revokeObjectURL(pubUrl);

    setGenerated(true);
  };

  return (
    <div className="border border-gray-700 rounded-lg p-4">
      <p className="text-sm text-gray-400 mb-3">
        Pas encore de cles ? Generez une paire de cles MLA.
      </p>
      <button
        onClick={handleGenerate}
        className="px-4 py-2 rounded-lg bg-gray-800 text-gray-200 hover:bg-gray-700 transition-colors text-sm"
      >
        Generer mes cles
      </button>
      {generated && (
        <p className="text-xs text-green-500 mt-2">
          Cles generees et telechargees. Gardez votre .mlapriv en lieu sur !
        </p>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Commit**

```bash
git add mla-transfert-web/src/components/KeyImporter.tsx mla-transfert-web/src/components/KeyGenerator.tsx
git commit -m "feat(web): add key import and generation components"
```

---

### Task 6: SendForm -- main send page component

**Files:**
- Create: `mla-transfert-web/src/components/SendForm.tsx`
- Modify: `mla-transfert-web/src/pages/index.astro`

- [ ] **Step 1: Create SendForm.tsx**

```tsx
import { useState } from 'react';
import FileDropZone from './FileDropZone';
import ModeSelector from './ModeSelector';
import PasswordInput from './PasswordInput';
import KeyImporter from './KeyImporter';
import KeyGenerator from './KeyGenerator';
import TransferProgress from './TransferProgress';
import ShareLink from './ShareLink';
import {
  encryptWithPassword,
  encryptWithKeys,
  type FileEntry,
} from '../lib/mla';
import { uploadFile } from '../lib/api';

type TransferMode = 'relay' | 'p2p';

export default function SendForm() {
  const [files, setFiles] = useState<File[]>([]);
  const [mode, setMode] = useState<'simple' | 'advanced'>('simple');
  const [transferMode, setTransferMode] = useState<TransferMode>('relay');
  const [password, setPassword] = useState('');
  const [senderPrivKey, setSenderPrivKey] = useState<Uint8Array | null>(null);
  const [receiverPubKey, setReceiverPubKey] = useState<Uint8Array | null>(null);
  const [expiresHours, setExpiresHours] = useState(24);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState<'idle' | 'encrypting' | 'uploading' | 'done' | 'error'>('idle');
  const [shareLink, setShareLink] = useState('');
  const [error, setError] = useState('');

  const canSubmit =
    files.length > 0 &&
    ((mode === 'simple' && password.length >= 8) ||
      (mode === 'advanced' && senderPrivKey !== null && receiverPubKey !== null));

  const handleSubmit = async () => {
    try {
      setStatus('encrypting');
      setProgress(10);
      setError('');

      const fileEntries: FileEntry[] = await Promise.all(
        files.map(async (f) => ({
          name: f.name,
          data: new Uint8Array(await f.arrayBuffer()),
        })),
      );

      setProgress(30);

      let encrypted: Uint8Array;
      if (mode === 'simple') {
        encrypted = await encryptWithPassword(fileEntries, password);
      } else {
        encrypted = await encryptWithKeys(fileEntries, senderPrivKey!, receiverPubKey!);
      }

      setProgress(70);
      setStatus('uploading');

      const result = await uploadFile(encrypted, expiresHours);

      setProgress(100);
      setStatus('done');
      setShareLink(`${window.location.origin}/receive/${result.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erreur inconnue');
      setStatus('error');
    }
  };

  return (
    <div className="space-y-6 max-w-xl mx-auto">
      <FileDropZone files={files} onFilesSelected={setFiles} />

      <ModeSelector mode={mode} onModeChange={setMode} />

      {mode === 'simple' ? (
        <PasswordInput
          value={password}
          onChange={setPassword}
          placeholder="Mot de passe (min. 8 caracteres)"
        />
      ) : (
        <div className="space-y-4">
          <KeyImporter
            label="Votre cle privee (.mlapriv) pour signer"
            accept=".mlapriv"
            onKeyLoaded={setSenderPrivKey}
          />
          <KeyImporter
            label="Cle publique du destinataire (.mlapub)"
            accept=".mlapub"
            onKeyLoaded={setReceiverPubKey}
          />
          <KeyGenerator />
        </div>
      )}

      <div className="flex gap-4">
        <select
          value={expiresHours}
          onChange={(e) => setExpiresHours(Number(e.target.value))}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-100 text-sm"
        >
          <option value={1}>1 heure</option>
          <option value={24}>24 heures</option>
          <option value={168}>7 jours</option>
        </select>

        <select
          value={transferMode}
          onChange={(e) => setTransferMode(e.target.value as TransferMode)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-100 text-sm"
        >
          <option value="relay">Relais serveur</option>
          <option value="p2p">P2P (WebRTC)</option>
        </select>
      </div>

      {status !== 'idle' && status !== 'done' && status !== 'error' && (
        <TransferProgress
          progress={progress}
          label={status === 'encrypting' ? 'Chiffrement...' : 'Upload...'}
        />
      )}

      {error && (
        <p className="text-red-500 text-sm">{error}</p>
      )}

      {status === 'done' && shareLink && (
        <ShareLink link={shareLink} />
      )}

      {status !== 'done' && (
        <button
          onClick={handleSubmit}
          disabled={!canSubmit || status === 'encrypting' || status === 'uploading'}
          className="w-full py-3 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed bg-cyber-700 text-white hover:bg-cyber-500"
        >
          Chiffrer et envoyer
        </button>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Update index.astro**

```astro
---
import Layout from '../layouts/Layout.astro';
import SendForm from '../components/SendForm';
---

<Layout title="MLA-Transfert - Envoi securise">
  <div class="text-center mb-10">
    <h2 class="text-3xl font-bold mb-4">Envoyez vos fichiers en toute securite</h2>
    <p class="text-gray-400">Chiffrement post-quantique MLA, directement dans votre navigateur.</p>
  </div>
  <SendForm client:load />
</Layout>
```

- [ ] **Step 3: Verify build**

Run: `cd mla-transfert-web && npm run build`
Expected: build OK

- [ ] **Step 4: Commit**

```bash
git add mla-transfert-web/src/
git commit -m "feat(web): add SendForm with file encryption and upload workflow"
```

---

### Task 7: ReceiveForm -- download page

**Files:**
- Create: `mla-transfert-web/src/components/ReceiveForm.tsx`
- Create: `mla-transfert-web/src/pages/receive/[id].astro`

- [ ] **Step 1: Create ReceiveForm.tsx**

```tsx
import { useState } from 'react';
import ModeSelector from './ModeSelector';
import PasswordInput from './PasswordInput';
import KeyImporter from './KeyImporter';
import TransferProgress from './TransferProgress';
import {
  decryptWithPassword,
  decryptWithKeys,
  type FileEntry,
} from '../lib/mla';
import { downloadFile, getTransferInfo } from '../lib/api';

interface ReceiveFormProps {
  transferId: string;
}

export default function ReceiveForm({ transferId }: ReceiveFormProps) {
  const [mode, setMode] = useState<'simple' | 'advanced'>('simple');
  const [password, setPassword] = useState('');
  const [receiverPrivKey, setReceiverPrivKey] = useState<Uint8Array | null>(null);
  const [senderPubKey, setSenderPubKey] = useState<Uint8Array | null>(null);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState<'idle' | 'downloading' | 'decrypting' | 'done' | 'error'>('idle');
  const [error, setError] = useState('');
  const [decryptedFiles, setDecryptedFiles] = useState<FileEntry[]>([]);

  const canSubmit =
    (mode === 'simple' && password.length >= 8) ||
    (mode === 'advanced' && receiverPrivKey !== null && senderPubKey !== null);

  const handleDecrypt = async () => {
    try {
      setError('');
      setStatus('downloading');
      setProgress(20);

      const mlaData = await downloadFile(transferId);

      setProgress(50);
      setStatus('decrypting');

      let files: FileEntry[];
      if (mode === 'simple') {
        files = await decryptWithPassword(mlaData, password);
      } else {
        files = await decryptWithKeys(mlaData, receiverPrivKey!, senderPubKey!);
      }

      setDecryptedFiles(files);
      setProgress(100);
      setStatus('done');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erreur de dechiffrement');
      setStatus('error');
    }
  };

  const downloadDecryptedFile = (file: FileEntry) => {
    const blob = new Blob([file.data]);
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = file.name;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-xl mx-auto">
      <ModeSelector mode={mode} onModeChange={setMode} />

      {mode === 'simple' ? (
        <PasswordInput
          value={password}
          onChange={setPassword}
          placeholder="Mot de passe fourni par l'expediteur"
        />
      ) : (
        <div className="space-y-4">
          <KeyImporter
            label="Votre cle privee (.mlapriv) pour dechiffrer"
            accept=".mlapriv"
            onKeyLoaded={setReceiverPrivKey}
          />
          <KeyImporter
            label="Cle publique de l'expediteur (.mlapub) pour verifier"
            accept=".mlapub"
            onKeyLoaded={setSenderPubKey}
          />
        </div>
      )}

      {status !== 'idle' && status !== 'done' && status !== 'error' && (
        <TransferProgress
          progress={progress}
          label={status === 'downloading' ? 'Telechargement...' : 'Dechiffrement...'}
        />
      )}

      {error && <p className="text-red-500 text-sm">{error}</p>}

      {status === 'done' && (
        <div className="space-y-2">
          <p className="text-green-500 text-sm font-medium">Dechiffrement reussi !</p>
          {decryptedFiles.map((file, i) => (
            <button
              key={i}
              onClick={() => downloadDecryptedFile(file)}
              className="w-full text-left px-4 py-3 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors"
            >
              <span className="text-gray-200">{file.name}</span>
              <span className="text-gray-500 text-sm ml-2">
                ({(file.data.length / 1024).toFixed(1)} Ko)
              </span>
            </button>
          ))}
        </div>
      )}

      {status !== 'done' && (
        <button
          onClick={handleDecrypt}
          disabled={!canSubmit || status === 'downloading' || status === 'decrypting'}
          className="w-full py-3 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed bg-cyber-700 text-white hover:bg-cyber-500"
        >
          Dechiffrer et telecharger
        </button>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Create receive/[id].astro**

```astro
---
import Layout from '../../layouts/Layout.astro';
import ReceiveForm from '../../components/ReceiveForm';

const { id } = Astro.params;
---

<Layout title="MLA-Transfert - Reception">
  <div class="text-center mb-10">
    <h2 class="text-3xl font-bold mb-4">Vous avez recu un fichier securise</h2>
    <p class="text-gray-400">Entrez le mot de passe ou importez vos cles pour dechiffrer.</p>
  </div>
  <ReceiveForm client:load transferId={id!} />
</Layout>
```

- [ ] **Step 3: Verify build**

Run: `cd mla-transfert-web && npm run build`
Expected: build OK

- [ ] **Step 4: Commit**

```bash
git add mla-transfert-web/src/
git commit -m "feat(web): add ReceiveForm with download and decryption workflow"
```

---

### Task 8: WebRTC P2P transfer

**Files:**
- Create: `mla-transfert-web/src/lib/webrtc.ts`

- [ ] **Step 1: Create webrtc.ts**

```typescript
const SIGNAL_BASE = import.meta.env.PUBLIC_API_URL ?? 'http://localhost:3001';

function getSignalUrl(room: string): string {
  const base = SIGNAL_BASE.replace(/^http/, 'ws');
  return `${base}/api/signal/${room}`;
}

interface PeerMessage {
  type: 'offer' | 'answer' | 'candidate';
  data: RTCSessionDescriptionInit | RTCIceCandidateInit;
}

export async function sendViaPeer(
  room: string,
  encryptedData: Uint8Array,
  onProgress: (pct: number) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(getSignalUrl(room));
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
    });

    const channel = pc.createDataChannel('transfer', { ordered: true });
    const CHUNK_SIZE = 16384;

    channel.onopen = () => {
      let offset = 0;
      const total = encryptedData.byteLength;

      const sendChunk = () => {
        while (offset < total) {
          if (channel.bufferedAmount > CHUNK_SIZE * 8) {
            setTimeout(sendChunk, 50);
            return;
          }
          const end = Math.min(offset + CHUNK_SIZE, total);
          channel.send(encryptedData.slice(offset, end));
          offset = end;
          onProgress((offset / total) * 100);
        }
        channel.send('__DONE__');
        resolve();
      };

      sendChunk();
    };

    pc.onicecandidate = (e) => {
      if (e.candidate) {
        ws.send(JSON.stringify({ type: 'candidate', data: e.candidate.toJSON() }));
      }
    };

    ws.onmessage = async (event) => {
      const msg: PeerMessage = JSON.parse(event.data);
      if (msg.type === 'answer') {
        await pc.setRemoteDescription(msg.data as RTCSessionDescriptionInit);
      } else if (msg.type === 'candidate') {
        await pc.addIceCandidate(msg.data as RTCIceCandidateInit);
      }
    };

    ws.onopen = async () => {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      ws.send(JSON.stringify({ type: 'offer', data: offer }));
    };

    ws.onerror = () => reject(new Error('WebSocket signaling error'));
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'failed') reject(new Error('P2P connection failed'));
    };
  });
}

export async function receiveViaPeer(
  room: string,
  onProgress: (pct: number) => void,
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(getSignalUrl(room));
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
    });

    const chunks: Uint8Array[] = [];

    pc.ondatachannel = (event) => {
      const channel = event.channel;
      channel.binaryType = 'arraybuffer';

      channel.onmessage = (msg) => {
        if (typeof msg.data === 'string' && msg.data === '__DONE__') {
          const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
          const result = new Uint8Array(total);
          let offset = 0;
          for (const chunk of chunks) {
            result.set(chunk, offset);
            offset += chunk.byteLength;
          }
          resolve(result);
        } else {
          chunks.push(new Uint8Array(msg.data as ArrayBuffer));
          onProgress(chunks.length); // approximate
        }
      };
    };

    pc.onicecandidate = (e) => {
      if (e.candidate) {
        ws.send(JSON.stringify({ type: 'candidate', data: e.candidate.toJSON() }));
      }
    };

    ws.onmessage = async (event) => {
      const msg: PeerMessage = JSON.parse(event.data);
      if (msg.type === 'offer') {
        await pc.setRemoteDescription(msg.data as RTCSessionDescriptionInit);
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        ws.send(JSON.stringify({ type: 'answer', data: answer }));
      } else if (msg.type === 'candidate') {
        await pc.addIceCandidate(msg.data as RTCIceCandidateInit);
      }
    };

    ws.onerror = () => reject(new Error('WebSocket signaling error'));
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'failed') reject(new Error('P2P connection failed'));
    };
  });
}
```

- [ ] **Step 2: Commit**

```bash
git add mla-transfert-web/src/lib/webrtc.ts
git commit -m "feat(web): add WebRTC P2P file transfer logic"
```

---

## Pages summary

| Route | Description |
|-------|-------------|
| `/` | Send form -- drag & drop, encrypt, upload/P2P, get share link |
| `/receive/:id` | Receive form -- enter password/keys, download, decrypt |
