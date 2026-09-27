/** UI adapter for the existing local API. No wallet, RPC, or engine changes. */
export type JsonRecord = Record<string, unknown>;
export const isRecord = (value: unknown): value is JsonRecord =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
export const text = (value: unknown, fallback = 'Not returned'): string =>
  typeof value === 'string' && value.trim() ? value :
  typeof value === 'number' && Number.isFinite(value) ? String(value) : fallback;

export async function requestJson(
  url: string, signal: AbortSignal, body?: JsonRecord,
): Promise<JsonRecord> {
  const response = await fetch(url, {
    method: body ? 'POST' : 'GET', signal,
    headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  // Some static hosts return index.html with HTTP 200 for missing /api routes.
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.toLowerCase().includes('application/json')) {
    throw new Error(`HTTP ${response.status}: expected a JSON engine response. No live result was accepted.`);
  }
  const data: unknown = await response.json();
  if (!isRecord(data)) throw new Error('Malformed engine response: expected a JSON object.');
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${text(data.reason, text(data.message, text(data.error, 'Engine request failed.')))}`);
  }
  return data;
}

const ANALYSIS_STATUSES = new Set([
  'FOUND_LOSS', 'NO_MODELED_LOSS', 'UNMODELED', 'INVALID_CAPABILITY', 'PROSPECTIVE_RISK',
]);
export function validateAnalysis(data: JsonRecord): JsonRecord {
  if (typeof data.status !== 'string' || !ANALYSIS_STATUSES.has(data.status)) {
    throw new Error('Unrecognized analysis status. No fixture result has been substituted.');
  }
  if (data.status === 'FOUND_LOSS') {
    const ce = data.counterexample;
    if (typeof data.runId !== 'string' || !data.runId.trim() || !isRecord(ce) ||
        !Array.isArray(ce.trace) || ce.trace.length === 0 || !ce.trace.every(isRecord) ||
        !isRecord(ce.loss) || typeof ce.loss.formatted !== 'string' ||
        typeof ce.loss.symbol !== 'string' || typeof ce.depth !== 'number' ||
        !Number.isInteger(ce.depth) || ce.depth < 1 || ce.depth !== ce.trace.length) {
      throw new Error('Incomplete loss-witness response. Live metrics and recovery remain unavailable.');
    }
  }
  return data;
}

export function validateRecovery(data: JsonRecord, runId: string): JsonRecord {
  if (data.runId !== runId) throw new Error('Recovery response does not match the selected analysis session.');
  if (data.status !== 'CONFIRMED') {
    throw new Error(text(data.reason, text(data.message, `Recovery not confirmed (${text(data.status)}).`)));
  }
  return data;
}

export function validateReplay(data: JsonRecord, runId: string): JsonRecord {
  if (data.runId !== runId || typeof data.mitigated !== 'boolean') {
    throw new Error('Incomplete or mismatched replay response. The outcome is not verified.');
  }
  if (typeof data.assetsLost !== 'string' || !/^\d+$/.test(data.assetsLost) ||
      typeof data.finalVictimBalance !== 'string' || !data.finalVictimBalance.trim()) {
    throw new Error('Replay response is missing measured balance or loss evidence.');
  }
  if (data.mitigated !== (BigInt(data.assetsLost) === 0n)) {
    throw new Error('Replay status contradicts reported loss. No success result was accepted.');
  }
  return data;
}
