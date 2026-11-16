import type { IncomingMessage, ServerResponse } from 'node:http';
import { serializeCookie, toPublicError, type AuthFailure, type CookieSpec } from '@noctcore/auth';

// Every code the flows can return maps to a status. Anything else is a 400.
const STATUS: Partial<Record<string, number>> = {
  invalid_credentials: 401,
  session_expired: 401,
  rate_limited: 429,
  fresh_auth_required: 403,
  forbidden: 403,
  captcha_unavailable: 503,
};

export function send(
  res: ServerResponse,
  status: number,
  body: unknown,
  cookies: readonly CookieSpec[] = [],
  headers: Record<string, string> = {},
): void {
  res.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    // Reset and verification links carry their token in the URL.
    'referrer-policy': 'no-referrer',
    ...headers,
    ...(cookies.length > 0 ? { 'set-cookie': cookies.map(serializeCookie) } : {}),
  });

  res.end(JSON.stringify(body));
}

/** Sends only the public part of a refusal; `reason` stays on the server. */
export function failure(res: ServerResponse, result: AuthFailure): void {
  const error = toPublicError(result);
  const headers: Record<string, string> = error.retryAfterSeconds
    ? { 'retry-after': String(error.retryAfterSeconds) }
    : {};

  send(res, STATUS[error.code] ?? 400, { error }, [], headers);
}

export function header(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];

  return Array.isArray(value) ? value[0] : value;
}

/** A JSON object body of at most 16 KiB, else an empty object. */
export async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  if (header(req, 'content-type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json')
    return {};

  const chunks: Buffer[] = [];
  let size = 0;

  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;

    if (size > 16_384) return {};

    chunks.push(chunk);
  }

  try {
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));

    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

export function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}
