import * as assert from "assert";
import { ParsedDocument } from "../../models/parsedDocument";
import { ParsedDocumentCache, ParsedDocumentStat } from "../../parsers/parsedDocumentCache";

suite("ParsedDocumentCache", () => {
  const parsed: ParsedDocument = { type: "keys", items: [] };

  test("reuses a parsed document while uri, size, and mtime match", async () => {
    let readCount = 0;
    let parseCount = 0;
    const cache = new ParsedDocumentCache({
      stat: async (): Promise<ParsedDocumentStat> => ({ size: 12, mtime: 100 }),
      readFile: async (): Promise<Uint8Array> => {
        readCount += 1;
        return Buffer.from("certificate");
      },
      parse: (): ParsedDocument => {
        parseCount += 1;
        return parsed;
      },
    });

    const first = await cache.get("file:///cert.pem", "cert.pem");
    const second = await cache.get("file:///cert.pem", "cert.pem");

    assert.strictEqual(first, parsed);
    assert.strictEqual(second, parsed);
    assert.strictEqual(readCount, 1);
    assert.strictEqual(parseCount, 1);
  });

  test("reparses when the file mtime changes", async () => {
    let mtime = 100;
    let parseCount = 0;
    const cache = new ParsedDocumentCache({
      stat: async (): Promise<ParsedDocumentStat> => ({ size: 12, mtime }),
      readFile: async (): Promise<Uint8Array> => Buffer.from("certificate"),
      parse: (): ParsedDocument => {
        parseCount += 1;
        return { type: "keys", items: [] };
      },
    });

    const first = await cache.get("file:///cert.pem", "cert.pem");
    mtime = 200;
    const second = await cache.get("file:///cert.pem", "cert.pem");

    assert.notStrictEqual(first, second);
    assert.strictEqual(parseCount, 2);
  });

  test("can invalidate one uri without clearing the whole cache", async () => {
    let parseCount = 0;
    const cache = new ParsedDocumentCache({
      stat: async (uri: string): Promise<ParsedDocumentStat> => ({ size: uri.endsWith("a.pem") ? 10 : 20, mtime: 100 }),
      readFile: async (uri: string): Promise<Uint8Array> => Buffer.from(uri),
      parse: (): ParsedDocument => {
        parseCount += 1;
        return { type: "keys", items: [] };
      },
    });

    await cache.get("file:///a.pem", "a.pem");
    await cache.get("file:///b.pem", "b.pem");
    cache.invalidate("file:///a.pem");
    await cache.get("file:///a.pem", "a.pem");
    await cache.get("file:///b.pem", "b.pem");

    assert.strictEqual(parseCount, 3);
  });

  test("evicts the oldest entry when maxEntries is reached", async () => {
    let parseCount = 0;
    const cache = new ParsedDocumentCache({
      stat: async (): Promise<ParsedDocumentStat> => ({ size: 12, mtime: 100 }),
      readFile: async (uri: string): Promise<Uint8Array> => Buffer.from(uri),
      parse: (): ParsedDocument => {
        parseCount += 1;
        return { type: "keys", items: [] };
      },
    }, { maxEntries: 2 });

    await cache.get("file:///a.pem", "a.pem");
    await cache.get("file:///b.pem", "b.pem");
    await cache.get("file:///c.pem", "c.pem");
    await cache.get("file:///a.pem", "a.pem");
    await cache.get("file:///b.pem", "b.pem");

    assert.strictEqual(parseCount, 5);
  });
});
