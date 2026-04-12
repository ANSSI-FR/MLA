const SIGNAL_BASE = import.meta.env.PUBLIC_API_URL ?? 'http://localhost:3001';
const STUN_URL = (import.meta.env.PUBLIC_STUN_URL as string | undefined) ?? 'stun:stun.nextcloud.com:443';

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
      iceServers: [{ urls: STUN_URL }],
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
      let msg: PeerMessage;
      try { msg = JSON.parse(event.data as string); } catch { return; }
      if (!msg?.type || !msg?.data) return;
      if (msg.type === 'answer' && typeof (msg.data as RTCSessionDescriptionInit).type === 'string') {
        await pc.setRemoteDescription(new RTCSessionDescription(msg.data as RTCSessionDescriptionInit));
      } else if (msg.type === 'candidate') {
        await pc.addIceCandidate(new RTCIceCandidate(msg.data as RTCIceCandidateInit));
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
      iceServers: [{ urls: STUN_URL }],
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
          onProgress(chunks.length);
        }
      };
    };

    pc.onicecandidate = (e) => {
      if (e.candidate) {
        ws.send(JSON.stringify({ type: 'candidate', data: e.candidate.toJSON() }));
      }
    };

    ws.onmessage = async (event) => {
      let msg: PeerMessage;
      try { msg = JSON.parse(event.data as string); } catch { return; }
      if (!msg?.type || !msg?.data) return;
      if (msg.type === 'offer' && typeof (msg.data as RTCSessionDescriptionInit).type === 'string') {
        await pc.setRemoteDescription(new RTCSessionDescription(msg.data as RTCSessionDescriptionInit));
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        ws.send(JSON.stringify({ type: 'answer', data: answer }));
      } else if (msg.type === 'candidate') {
        await pc.addIceCandidate(new RTCIceCandidate(msg.data as RTCIceCandidateInit));
      }
    };

    ws.onerror = () => reject(new Error('WebSocket signaling error'));
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'failed') reject(new Error('P2P connection failed'));
    };
  });
}
