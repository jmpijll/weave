export type LogValue = string | number | boolean | null;

export interface LogFields {
  [key: string]: LogValue;
}

/**
 * Safe structured log line. Only stable codes, IDs, timings and statuses are
 * emitted as values; never auth headers, signatures, secret material, raw SQL
 * values, or resource names that could leak private ancestry.
 */
export function logEvent(event: string, fields: LogFields = {}): void {
  const entry = {
    ts: new Date().toISOString(),
    event,
    ...fields,
  };
  console.log(JSON.stringify(entry));
}
