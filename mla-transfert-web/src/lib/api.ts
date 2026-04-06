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
