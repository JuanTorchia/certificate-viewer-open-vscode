import { ParsedDocument } from "../models/parsedDocument";
import { parseDocument } from "./documentParser";

export interface ParsedDocumentStat {
  size: number;
  mtime: number;
}

export interface ParsedDocumentCacheDependencies {
  stat(uri: string): Promise<ParsedDocumentStat>;
  readFile(uri: string): Promise<Uint8Array>;
  parse?: (raw: Uint8Array, filename: string) => ParsedDocument | Promise<ParsedDocument>;
}

interface CacheEntry {
  stat: ParsedDocumentStat;
  parsed: ParsedDocument;
}

export interface ParsedDocumentCacheOptions {
  maxEntries?: number;
}

export class ParsedDocumentCache {
  private readonly entries = new Map<string, CacheEntry>();
  private readonly inFlight = new Map<string, number>();
  private readonly generations = new Map<string, number>();
  private readonly maxEntries: number;
  private epoch = 0;

  constructor(
    private readonly deps: ParsedDocumentCacheDependencies,
    options: ParsedDocumentCacheOptions = {}
  ) {
    this.maxEntries = Math.max(1, options.maxEntries ?? 200);
  }

  async get(uri: string, filename: string): Promise<ParsedDocument> {
    this.inFlight.set(uri, (this.inFlight.get(uri) ?? 0) + 1);
    try {
      return await this.parseWithRetry(uri, filename, 0);
    } finally {
      const count = (this.inFlight.get(uri) ?? 1) - 1;
      if (count > 0) this.inFlight.set(uri, count);
      else {
        this.inFlight.delete(uri);
        this.generations.delete(uri);
      }
    }
  }

  private async parseWithRetry(uri: string, filename: string, retry: number): Promise<ParsedDocument> {
    const epoch = this.epoch;
    const generation = this.generations.get(uri) ?? 0;
    const stat = await this.deps.stat(uri);
    if (!this.isCurrent(uri, epoch, generation)) return this.retryOrError(uri, filename, retry);
    const cached = this.entries.get(uri);
    if (cached && cached.stat.size === stat.size && cached.stat.mtime === stat.mtime) {
      this.entries.delete(uri);
      this.entries.set(uri, cached);
      return cached.parsed;
    }

    const raw = await this.deps.readFile(uri);
    const parsed = await (this.deps.parse ?? parseDocument)(raw, filename);
    const currentStat = await this.deps.stat(uri);
    if (!this.isCurrent(uri, epoch, generation) || currentStat.size !== stat.size || currentStat.mtime !== stat.mtime) {
      return this.retryOrError(uri, filename, retry);
    }
    this.entries.delete(uri);
    this.entries.set(uri, { stat: currentStat, parsed });
    this.evictOldestEntries();
    return parsed;
  }

  invalidate(uri: string): void {
    this.entries.delete(uri);
    if (this.inFlight.has(uri)) this.generations.set(uri, (this.generations.get(uri) ?? 0) + 1);
  }

  clear(): void {
    this.entries.clear();
    this.generations.clear();
    this.epoch++;
  }

  private isCurrent(uri: string, epoch: number, generation: number): boolean {
    return epoch === this.epoch && generation === (this.generations.get(uri) ?? 0);
  }

  private retryOrError(uri: string, filename: string, retry: number): Promise<ParsedDocument> | ParsedDocument {
    if (retry === 0) return this.parseWithRetry(uri, filename, 1);
    return {
      type: "error",
      message: `Failed to parse ${filename}`,
      detail: "The file changed repeatedly while CertView was parsing it. Reopen the file to retry.",
    };
  }

  private evictOldestEntries(): void {
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (!oldest) return;
      this.entries.delete(oldest);
    }
  }
}
