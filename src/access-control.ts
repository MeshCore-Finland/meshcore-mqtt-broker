import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { getAirportInfo } from 'airport-utils';
import { parse } from 'yaml';

export interface AccessControlSnapshot {
  acceptedIatas: Set<string>;
  blockedObservers: Set<string>;
}

function isKnownIata(code: string): boolean {
  if (code === 'TEST') return true;

  try {
    getAirportInfo(code);
    return true;
  } catch {
    return false;
  }
}

function parseAccessControl(contents: string): AccessControlSnapshot {
  const document: unknown = parse(contents);
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error('ACL must be a YAML object');
  }

  const value = document as Record<string, unknown>;
  const unknownKeys = Object.keys(value).filter(
    key => key !== 'acceptedIatas' && key !== 'blockedObservers',
  );
  if (unknownKeys.length > 0) {
    throw new Error(`Unknown ACL field(s): ${unknownKeys.join(', ')}`);
  }

  if (!Array.isArray(value.acceptedIatas)) {
    throw new Error('acceptedIatas must be a YAML list');
  }
  if (value.blockedObservers !== undefined && !Array.isArray(value.blockedObservers)) {
    throw new Error('blockedObservers must be a YAML list');
  }

  const acceptedIatas = new Set<string>();
  for (const item of value.acceptedIatas) {
    if (typeof item !== 'string') {
      throw new Error('Every acceptedIatas entry must be a string');
    }
    const code = item.trim().toUpperCase();
    if (!/^[A-Z]{3}$/.test(code) || !isKnownIata(code)) {
      throw new Error(`Invalid IATA in acceptedIatas: ${item}`);
    }
    acceptedIatas.add(code);
  }

  const blockedObservers = new Set<string>();
  for (const item of (value.blockedObservers || []) as unknown[]) {
    if (typeof item !== 'string') {
      throw new Error('Every blockedObservers entry must be a string');
    }
    const publicKey = item.trim().toUpperCase();
    if (!/^[0-9A-F]{64}$/.test(publicKey)) {
      throw new Error(`Invalid observer public key in blockedObservers: ${item}`);
    }
    blockedObservers.add(publicKey);
  }

  return { acceptedIatas, blockedObservers };
}

function contentHash(contents: string): string {
  return createHash('sha256').update(contents).digest('hex');
}

export class AccessControl {
  private snapshot: AccessControlSnapshot;
  private appliedHash: string;
  private rejectedHash = '';
  private lastReadError = '';

  constructor(private readonly filePath: string) {
    const contents = readFileSync(filePath, 'utf8');
    this.snapshot = parseAccessControl(contents);
    this.appliedHash = contentHash(contents);
    console.log(
      `[ACL] Loaded ${this.snapshot.acceptedIatas.size} accepted IATA(s) and ` +
      `${this.snapshot.blockedObservers.size} blocked observer(s) from ${filePath}`,
    );
  }

  acceptsIata(code: string): boolean {
    return this.snapshot.acceptedIatas.has(code.toUpperCase());
  }

  isObserverBlocked(publicKey: string): boolean {
    return this.snapshot.blockedObservers.has(publicKey.toUpperCase());
  }

  reload(): string[] {
    let contents: string;
    try {
      contents = readFileSync(this.filePath, 'utf8');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message !== this.lastReadError) {
        console.error(`[ACL] Cannot read ${this.filePath}; retaining last valid ACL: ${message}`);
        this.lastReadError = message;
      }
      return [];
    }

    const hash = contentHash(contents);
    if (hash === this.appliedHash) {
      this.lastReadError = '';
      this.rejectedHash = '';
      return [];
    }
    if (hash === this.rejectedHash) return [];

    let next: AccessControlSnapshot;
    try {
      next = parseAccessControl(contents);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[ACL] Rejected invalid update to ${this.filePath}; retaining last valid ACL: ${message}`);
      this.rejectedHash = hash;
      return [];
    }

    const newlyBlocked = [...next.blockedObservers].filter(
      publicKey => !this.snapshot.blockedObservers.has(publicKey),
    );
    this.snapshot = next;
    this.appliedHash = hash;
    this.rejectedHash = '';
    this.lastReadError = '';
    console.log(
      `[ACL] Reloaded ${next.acceptedIatas.size} accepted IATA(s) and ` +
      `${next.blockedObservers.size} blocked observer(s)`,
    );
    return newlyBlocked;
  }
}
