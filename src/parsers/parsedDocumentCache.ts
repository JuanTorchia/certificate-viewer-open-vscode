import { ParsedDocument } from "../models/parsedDocument";
import { parseDocument } from "./documentParser";

export interface ParsedDocumentStat {
  size: number;
  mtime: number;
}

export interface ParsedDocumentCacheDependencies {
  stat(uri: string): Promise<ParsedDocumentStat>;
  readFile(uri: string): Promise<Uint8Array>;
  parse?: (raw: Uint8Array, filename: string) => ParsedDocument;
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
  private readonly maxEntries: number;

  constructor(
    private readonly deps: ParsedDocumentCacheDependencies,
    options: ParsedDocumentCacheOptions = {}
  ) {
    this.maxEntries = Math.max(1, options.maxEntries ?? 200);
  }

  async get(uri: string, filename: string): Promise<ParsedDocument> {
    const stat = await this.deps.stat(uri);
    const cached = this.entries.get(uri);
    if (cached && cached.stat.size === stat.size && cached.stat.mtime === stat.mtime) {
      this.entries.delete(uri);
      this.entries.set(uri, cached);
      return cached.parsed;
    }

    const raw = await this.deps.readFile(uri);
    const parsed = (this.deps.parse ?? parseDocument)(raw, filename);
    this.entries.delete(uri);
    this.entries.set(uri, { stat, parsed });
    this.evictOldestEntries();
    return parsed;
  }

  invalidate(uri: string): void {
    this.entries.delete(uri);
  }

  clear(): void {
    this.entries.clear();
  }

  private evictOldestEntries(): void {
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (!oldest) return;
      this.entries.delete(oldest);
    }
  }
}
