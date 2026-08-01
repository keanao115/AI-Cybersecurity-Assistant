// Security & Data Hygiene Utilities for Enterprise SOC Data Ingestion

/**
 * Strips CRLF characters (\r, \n) and dangerous control characters from raw logs
 * to prevent Log Injection / Log Forgery attacks (CWE-117).
 */
export function sanitizeRawLog(rawInput: string, maxLen: number = 65536): string {
  if (!rawInput) return '';

  // Enforce maximum length to prevent DoS via huge payload strings
  const truncated = rawInput.length > maxLen ? rawInput.substring(0, maxLen) : rawInput;

  // Replace CRLF and NULL bytes with space/literal escape
  return truncated
    .replace(/\r\n/g, ' \\n ')
    .replace(/[\r\n]/g, ' \\n ')
    .replace(/\0/g, '')
    // Remove non-printable control characters except standard tabs
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

/**
 * HTML Escaping utility to prevent Stored XSS in SOC dashboard tables.
 */
export function escapeHtml(text: string): string {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ─── PII & Credential Masking Patterns ────────────────────────────────────────
const CREDIT_CARD_REGEX = /\b(?:\d[ -]*?){13,16}\b/g;
const PASSWORD_KV_REGEX = /(?:password|passwd|pwd|pass|secret|token|api_key|apikey)=([^\s&"'`]+)/gi;
const BEARER_TOKEN_REGEX = /Bearer\s+([a-zA-Z0-9\-\._~\+\/]+=*)/gi;

/**
 * Masks sensitive PII, credit cards, passwords, and bearer tokens in raw log text
 * before database persistence or WebSocket stream broadcast.
 */
export function maskSensitivePii(text: string): { maskedText: string; hasPiiMasked: boolean } {
  if (!text) return { maskedText: '', hasPiiMasked: false };

  let hasPii = false;
  let masked = text;

  if (CREDIT_CARD_REGEX.test(masked)) {
    hasPii = true;
    masked = masked.replace(CREDIT_CARD_REGEX, '****-****-****-****');
  }

  if (PASSWORD_KV_REGEX.test(masked)) {
    hasPii = true;
    masked = masked.replace(PASSWORD_KV_REGEX, (match, val) => match.replace(val, '[MASKED_CREDENTIAL]'));
  }

  if (BEARER_TOKEN_REGEX.test(masked)) {
    hasPii = true;
    masked = masked.replace(BEARER_TOKEN_REGEX, 'Bearer [MASKED_TOKEN]');
  }

  return { maskedText: masked, hasPiiMasked: hasPii };
}
