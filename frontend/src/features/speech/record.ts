export const MAX_RECORD_MS = 30_000;

const EMPTY_WAV_BYTES = 8_000;

export const voiceCapture = {
  record: captureUtterance,
};

export function microphoneMessage(error: unknown): string {
  const name =
    typeof error === "object" && error !== null && "name" in error ? String(error.name) : "";

  if (
    name === "NotAllowedError" ||
    name === "NotFoundError" ||
    name === "SecurityError" ||
    name === "NotReadableError"
  ) {
    return "Microphone permission was denied or no microphone is available. Type the request instead.";
  }

  return "The microphone could not be used. Type the request instead.";
}

export function recordingIsEmpty(blob: Blob): boolean {
  return blob.size < EMPTY_WAV_BYTES;
}

export async function captureUtterance(signal: AbortSignal): Promise<Blob> {
  if (!navigator.mediaDevices?.getUserMedia) {
    throw Object.assign(new Error("no-microphone"), { name: "NotFoundError" });
  }

  const stream = await navigator.mediaDevices.getUserMedia({
    audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true },
  });

  try {
    return await recordWav(stream, signal);
  } finally {
    for (const track of stream.getTracks()) track.stop();
  }
}

async function recordWav(stream: MediaStream, signal: AbortSignal): Promise<Blob> {
  const context = new AudioContext();
  const rate = context.sampleRate;
  const chunks: Float32Array[] = [];

  try {
    await context.audioWorklet.addModule(`${import.meta.env.BASE_URL}recorder-worklet.js`);
    const source = context.createMediaStreamSource(stream);
    const node = new AudioWorkletNode(context, "investigation-recorder");
    const sink = context.createGain();
    sink.gain.value = 0;
    node.port.onmessage = (event: MessageEvent<Float32Array>) => {
      if (event.data?.length) chunks.push(new Float32Array(event.data));
    };
    source.connect(node);
    node.connect(sink);
    sink.connect(context.destination);

    await new Promise<void>((resolve) => {
      const timer = window.setTimeout(resolve, MAX_RECORD_MS);

      const finish = () => {
        window.clearTimeout(timer);
        resolve();
      };

      if (signal.aborted) finish();
      else signal.addEventListener("abort", finish, { once: true });
    });

    node.port.onmessage = null;
    node.disconnect();
    source.disconnect();
    sink.disconnect();
  } finally {
    await context.close();
  }

  if (signal.aborted && signal.reason === "leave") {
    throw Object.assign(new Error("left"), { name: "AbortError" });
  }

  return encodeWav(concat(chunks), rate);
}

function concat(chunks: Float32Array[]): Float32Array {
  const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const merged = new Float32Array(length);
  let offset = 0;

  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }

  return merged;
}

function encodeWav(samples: Float32Array, sampleRate: number): Blob {
  const buffer = new ArrayBuffer(44 + samples.length * 2);
  const view = new DataView(buffer);

  const write = (offset: number, text: string) => {
    for (let index = 0; index < text.length; index += 1) {
      view.setUint8(offset + index, text.charCodeAt(index));
    }
  };

  write(0, "RIFF");
  view.setUint32(4, 36 + samples.length * 2, true);
  write(8, "WAVE");
  write(12, "fmt ");
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  write(36, "data");
  view.setUint32(40, samples.length * 2, true);

  for (let index = 0; index < samples.length; index += 1) {
    const sample = Math.max(-1, Math.min(1, samples[index] ?? 0));
    view.setInt16(44 + index * 2, sample < 0 ? sample * 0x8000 : sample * 0x7fff, true);
  }

  return new Blob([buffer], { type: "audio/wav" });
}
