/**
 * Weave M3.2 I4.1 — shared bounded strict JSON body helper for `/v1` routes.
 *
 * Owns only transport-neutral parsing mechanics: POST/media check is the
 * caller's, this helper owns the 8-KiB raw limit, effective boundary
 * deadline, fatal UTF-8, body abort handling, flush-drop signalling, JSON
 * parsing, and a syntax-aware top-level duplicate-key guard.
 *
 * The guard decodes JSON key escapes before comparison and rejects a
 * duplicate of any required member. It does not use a regex or `JSON.parse`
 * alone, because `JSON.parse` silently overwrites duplicate members.
 */
import type { IncomingMessage } from "node:http";
import type { V1Operation } from "./boundary.ts";

export const JSON_BODY_MAX_BYTES = 8 * 1024;

export type JsonBodyResult =
  | { ok: true; value: unknown }
  | { ok: false; outcome: "bad_request" | "deadline" | "aborted" | "oversize" };

export function readJsonString(text: string, start: number): { value: string; next: number } | null {
  // text[start] === '"'
  let i = start + 1;
  let out = "";
  for (;;) {
    if (i >= text.length) return null;
    const ch = text[i]!;
    if (ch === '"') return { value: out, next: i + 1 };
    if (ch === "\\") {
      i++;
      if (i >= text.length) return null;
      const esc = text[i]!;
      if (esc === '"' || esc === "\\" || esc === "/") {
        out += esc;
        i++;
      } else if (esc === "b") {
        out += "\b";
        i++;
      } else if (esc === "f") {
        out += "\f";
        i++;
      } else if (esc === "n") {
        out += "\n";
        i++;
      } else if (esc === "r") {
        out += "\r";
        i++;
      } else if (esc === "t") {
        out += "\t";
        i++;
      } else if (esc === "u") {
        const hex = text.slice(i + 1, i + 5);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) return null;
        out += String.fromCharCode(parseInt(hex, 16));
        i += 5;
      } else {
        return null;
      }
    } else {
      const code = ch.charCodeAt(0);
      if (code < 0x20) return null;
      out += ch;
      i++;
    }
  }
}

/** Skip one JSON value starting at `start` (after leading whitespace). Returns the end offset, or -1. */
function skipJsonValue(text: string, start: number): number {
  let i = start;
  while (i < text.length && " \t\n\r".includes(text[i]!)) i++;
  const ch = text[i];
  if (ch === undefined) return -1;
  if (ch === '"') {
    const s = readJsonString(text, i);
    if (s === null) return -1;
    return s.next;
  }
  if (ch === "{" || ch === "[") {
    i++;
    let depth = 1;
    let inStr = false;
    while (i < text.length) {
      const c = text[i]!;
      if (inStr) {
        if (c === "\\") {
          i += 2;
          continue;
        }
        if (c === '"') inStr = false;
        i++;
        continue;
      }
      if (c === '"') {
        inStr = true;
        i++;
        continue;
      }
      if (c === "{" || c === "[") depth++;
      else if (c === "}" || c === "]") {
        depth--;
        if (depth === 0) {
          // Bracket-kind balance is validated by JSON.parse afterwards; the
          // scanner only needs the value extent for duplicate-key detection.
          return i + 1;
        }
      }
      i++;
    }
    return -1;
  }
  // literals: true, false, null, numbers — consume to delimiter.
  const rest = text.slice(i);
  const m = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(rest);
  if (!m) return -1;
  return i + m[0].length;
}

/** Read a bounded raw body, distinguishing deadline expiry from client abort. */
export function readBoundedBody(
  request: IncomingMessage,
  max: number,
  deadlineMs: number,
): Promise<Buffer | "oversize" | "timeout" | "aborted"> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const cleanup = (): void => {
      if (timer) clearTimeout(timer);
      request.removeListener("data", onData);
      request.removeListener("end", onEnd);
      request.removeListener("error", onError);
      request.removeListener("aborted", onAborted);
    };
    const finish = (value: Buffer | "oversize" | "timeout" | "aborted"): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(value);
    };
    const onData = (chunk: Buffer | string): void => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
      total += buffer.length;
      if (total > max) {
        finish("oversize");
        return;
      }
      chunks.push(buffer);
    };
    const onEnd = (): void => finish(Buffer.concat(chunks));
    const onError = (): void => finish("aborted");
    const onAborted = (): void => finish("aborted");
    timer = setTimeout(() => finish("timeout"), deadlineMs);
    request.on("data", onData);
    request.on("end", onEnd);
    request.on("error", onError);
    request.on("aborted", onAborted);
  });
}

export interface StrictJsonOptions {
  maxBytes?: number;
  requiredKeys?: readonly string[];
}

/**
 * Read, UTF-8-decode, JSON-parse, and duplicate-guard one request body.
 * Returns `aborted` only when the client went away (caller must return
 * without writing); `oversize` maps to `bad_request` with a flush-drop;
 * `deadline` maps to transport-503.
 */
export async function readStrictJsonBody(
  request: IncomingMessage,
  operation: V1Operation,
  options: StrictJsonOptions = {},
): Promise<JsonBodyResult> {
  const max = options.maxBytes ?? JSON_BODY_MAX_BYTES;
  const raw = await readBoundedBody(request, max, operation.admission.bodyDeadlineMs);
  if (raw === "oversize") return { ok: false, outcome: "oversize" };
  if (raw === "timeout") return { ok: false, outcome: "deadline" };
  if (raw === "aborted") return { ok: false, outcome: "aborted" };
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  } catch {
    return { ok: false, outcome: "bad_request" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, outcome: "bad_request" };
  }
  if (options.requiredKeys && options.requiredKeys.length > 0) {
    if (hasDuplicateRequiredKey(text, options.requiredKeys)) {
      return { ok: false, outcome: "bad_request" };
    }
  }
  return { ok: true, value: parsed };
}

/**
 * Detect a top-level duplicate among required keys. Returns true when the raw
 * text contains a duplicate of any required member ( escapes decoded ).
 */
export function hasDuplicateRequiredKey(text: string, requiredKeys: readonly string[]): boolean {
  const required = new Set(requiredKeys);
  let i = 0;
  const skipWs = (): void => {
    while (i < text.length && " \t\n\r".includes(text[i]!)) i++;
  };
  skipWs();
  if (text[i] !== "{") return false;
  i++;
  const seen = new Set<string>();
  skipWs();
  if (text[i] === "}") return false;
  for (;;) {
    skipWs();
    if (text[i] !== '"') return false;
    const key = readJsonString(text, i);
    if (key === null) return false;
    i = key.next;
    if (required.has(key.value)) {
      if (seen.has(key.value)) return true;
      seen.add(key.value);
    }
    skipWs();
    if (text[i] !== ":") return false;
    i++;
    const end = skipJsonValue(text, i);
    if (end < 0) return false;
    i = end;
    skipWs();
    if (text[i] === ",") {
      i++;
      continue;
    }
    return false;
  }
}
