import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { getAirportInfo } from 'airport-utils';
import { parse } from 'yaml';

export interface AccessControlSnapshot {
  acceptedIatas: Set<string>;
  observers: Map<string, ObserverOptions>;
}

export interface ObserverOptions {
  blacklist: boolean;
  override_iata?: string;
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
    key => key !== 'version' && key !== 'accepted_iatas' && key !== 'observers',
  );
  if (unknownKeys.length > 0) {
    throw new Error(`Unknown ACL field(s): ${unknownKeys.join(', ')}`);
  }

  if (value.version !== 1) {
    throw new Error('ACL version must be 1');
  }
  if (!Array.isArray(value.accepted_iatas)) {
    throw new Error('accepted_iatas must be a YAML list');
  }
  if (value.observers !== undefined &&
      (value.observers === null || typeof value.observers !== 'object' || Array.isArray(value.observers))) {
    throw new Error('observers must be a YAML mapping');
  }

  const acceptedIatas = new Set<string>();
  for (const item of value.accepted_iatas) {
    if (typeof item !== 'string') {
      throw new Error('Every accepted_iatas entry must be a string');
    }
    const code = item.trim().toUpperCase();
    if (!/^[A-Z]{3}$/.test(code) || !isKnownIata(code)) {
      throw new Error(`Invalid IATA in accepted_iatas: ${item}`);
    }
    acceptedIatas.add(code);
  }

  const observers = new Map<string, ObserverOptions>();
  const observerConfiguration = value.observers as Record<string, unknown> | undefined;
  for (const [rawPublicKey, rawOptions] of Object.entries(observerConfiguration || {})) {
    const publicKey = rawPublicKey.trim().toUpperCase();
    if (!/^[0-9A-F]{64}$/.test(publicKey)) {
      throw new Error(`Invalid observer public key: ${rawPublicKey}`);
    }
    if (observers.has(publicKey)) {
      throw new Error(`Duplicate observer public key: ${publicKey.substring(0, 8)}`);
    }

    if (!rawOptions || typeof rawOptions !== 'object' || Array.isArray(rawOptions)) {
      throw new Error(`Options for observer ${publicKey.substring(0, 8)} must be a YAML mapping`);
    }

    const options = rawOptions as Record<string, unknown>;
    const unknownOptions = Object.keys(options).filter(
      key => key !== 'blacklist' && key !== 'override_iata',
    );
    if (unknownOptions.length > 0) {
      throw new Error(`Unknown option(s) for observer ${publicKey.substring(0, 8)}: ${unknownOptions.join(', ')}`);
    }

    if (options.blacklist !== undefined && typeof options.blacklist !== 'boolean') {
      throw new Error(`blacklist for observer ${publicKey.substring(0, 8)} must be true or false`);
    }

    let overrideIata: string | undefined;
    if (options.override_iata !== undefined) {
      if (typeof options.override_iata !== 'string') {
        throw new Error(`override_iata for observer ${publicKey.substring(0, 8)} must be an IATA string`);
      }
      overrideIata = options.override_iata.trim().toUpperCase();
      if (!/^[A-Z]{3}$/.test(overrideIata) || !isKnownIata(overrideIata)) {
        throw new Error(`Invalid override_iata for observer ${publicKey.substring(0, 8)}: ${options.override_iata}`);
      }
      if (!acceptedIatas.has(overrideIata)) {
        throw new Error(`override_iata ${overrideIata} for observer ${publicKey.substring(0, 8)} is not in accepted_iatas`);
      }
    }

    observers.set(publicKey, {
      blacklist: options.blacklist === true,
      ...(overrideIata ? { override_iata: overrideIata } : {}),
    });
  }

  return { acceptedIatas, observers };
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
    const blockedCount = [...this.snapshot.observers.values()].filter(observer => observer.blacklist).length;
    console.log(
      `[ACL] Loaded ${this.snapshot.acceptedIatas.size} accepted IATA(s) and ` +
      `${blockedCount} blocked observer(s) from ${filePath}`,
    );
  }

  acceptsIata(code: string): boolean {
    return this.snapshot.acceptedIatas.has(code.toUpperCase());
  }

  isObserverBlocked(publicKey: string): boolean {
    return this.snapshot.observers.get(publicKey.toUpperCase())?.blacklist === true;
  }

  getIataOverride(publicKey: string): string | undefined {
    return this.snapshot.observers.get(publicKey.toUpperCase())?.override_iata;
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

    const newlyBlocked = [...next.observers.entries()]
      .filter(([publicKey, options]) =>
        options.blacklist && this.snapshot.observers.get(publicKey)?.blacklist !== true,
      )
      .map(([publicKey]) => publicKey);
    const blockedCount = [...next.observers.values()].filter(observer => observer.blacklist).length;
    this.snapshot = next;
    this.appliedHash = hash;
    this.rejectedHash = '';
    this.lastReadError = '';
    console.log(
      `[ACL] Reloaded ${next.acceptedIatas.size} accepted IATA(s) and ` +
      `${blockedCount} blocked observer(s)`,
    );
    return newlyBlocked;
  }
}
