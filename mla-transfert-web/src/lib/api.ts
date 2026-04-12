const API_BASE = import.meta.env.PUBLIC_API_URL ?? 'http://localhost:3001';

async function extractError(response: Response, fallback: string): Promise<string> {
  const text = await response.text();
  try {
    const json = JSON.parse(text);
    return json.error ?? fallback;
  } catch {
    return text || fallback;
  }
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error('La requête a expiré. Vérifiez votre connexion.');
    }
    throw new Error('Impossible de joindre le serveur. Vérifiez votre connexion.');
  } finally {
    clearTimeout(id);
  }
}

async function withRetry<T>(
  fn: () => Promise<T>,
  maxRetries: number = 2,
): Promise<T> {
  let lastError: Error | undefined;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      // Ne pas retry sur les erreurs "métier" (expiration, mot de passe incorrect…)
      const msg = lastError.message.toLowerCase();
      if (
        msg.includes('expire') ||
        msg.includes('introuvable') ||
        msg.includes('invalide') ||
        msg.includes('trop volumineux') ||
        attempt === maxRetries
      ) {
        break;
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  throw lastError;
}

export interface UploadResponse {
  id: string;
  expires_in_hours: number;
  room_token: string;
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
  return withRetry(async () => {
    const formData = new FormData();
    formData.append('file', new Blob([encryptedData]), 'transfer.mla');
    formData.append('expires_hours', String(expiresHours));

    const response = await fetchWithTimeout(
      `${API_BASE}/api/upload`,
      { method: 'POST', body: formData },
      30_000,
    );

    if (response.status >= 400 && response.status < 500) {
      throw new Error(await extractError(response, 'Upload échoué'));
    }
    if (!response.ok) {
      throw new Error(await extractError(response, 'Erreur serveur lors de l\'upload'));
    }

    return response.json();
  });
}

export async function downloadFile(id: string): Promise<Uint8Array> {
  return withRetry(async () => {
    const response = await fetchWithTimeout(
      `${API_BASE}/api/download/${id}`,
      {},
      30_000,
    );

    if (response.status === 410) {
      throw new Error('Ce transfert a expire');
    }
    if (response.status >= 400 && response.status < 500) {
      throw new Error('Transfert introuvable');
    }
    if (!response.ok) {
      throw new Error('Erreur serveur lors du téléchargement');
    }

    const buffer = await response.arrayBuffer();
    return new Uint8Array(buffer);
  });
}

export async function getTransferInfo(id: string): Promise<TransferInfo> {
  const response = await fetchWithTimeout(
    `${API_BASE}/api/info/${id}`,
    {},
    5_000,
  );

  if (response.status === 410) {
    throw new Error('Ce transfert a expire');
  }
  if (!response.ok) {
    throw new Error('Transfert introuvable');
  }

  return response.json();
}
