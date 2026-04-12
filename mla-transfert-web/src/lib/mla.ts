import init, {
  generate_keypair,
  encrypt_with_password,
  decrypt_with_password,
  encrypt_with_keys,
  decrypt_with_keys,
} from 'mla-wasm';

let initialized = false;

export async function initMla(): Promise<void> {
  if (!initialized) {
    await init({ module_or_path: '/mla_wasm_bg.wasm' });
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
  // serde_wasm_bindgen sérialise Vec<u8> en Array<number> JS, pas en Uint8Array.
  // La conversion explicite est obligatoire sinon new Blob([data]) corrompt le fichier
  // en stringifiant l'array ("72,101,108,...").
  const entries = decrypt_with_password(mlaData, password) as [string, number[]][];
  return entries.map(([name, data]) => ({ name, data: new Uint8Array(data) }));
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
  const entries = decrypt_with_keys(
    mlaData,
    receiverPrivateKey,
    senderPublicKey,
  ) as [string, number[]][];
  return entries.map(([name, data]) => ({ name, data: new Uint8Array(data) }));
}
