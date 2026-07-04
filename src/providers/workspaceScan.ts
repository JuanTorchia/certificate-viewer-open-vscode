export const DEFAULT_WORKSPACE_SCAN_MAX_FILES = 200;
export const DEFAULT_WORKSPACE_EXCLUDE_GLOBS = ["**/node_modules/**"];
export const SUPPORTED_WORKSPACE_FILE_GLOB = "**/*.{pem,cer,crt,der,p7b,p7c,p7,crl,csr,p12,pfx,key,pub,jwk}";
export const DEFAULT_WORKSPACE_AUTO_REFRESH = true;

export interface RawWorkspaceScanSettings {
  maxFiles?: unknown;
  excludeGlobs?: unknown;
  autoRefresh?: unknown;
}

export interface WorkspaceScanSettings {
  maxFiles: number;
  excludeGlobs: string[];
  autoRefresh: boolean;
}

export interface LimitedWorkspaceScanResult<T> {
  files: T[];
  limitReached: boolean;
}

export function normalizeWorkspaceScanSettings(raw: RawWorkspaceScanSettings): WorkspaceScanSettings {
  return {
    maxFiles: normalizeMaxFiles(raw.maxFiles),
    excludeGlobs: normalizeExcludeGlobs(raw.excludeGlobs),
    autoRefresh: normalizeAutoRefresh(raw.autoRefresh),
  };
}

export function buildWorkspaceExcludeGlob(excludeGlobs: string[]): string {
  const globs = [...DEFAULT_WORKSPACE_EXCLUDE_GLOBS, ...excludeGlobs];
  return globs.length === 1 ? globs[0] : `{${globs.join(",")}}`;
}

export function limitWorkspaceScanResults<T>(results: T[], maxFiles: number): LimitedWorkspaceScanResult<T> {
  if (results.length > maxFiles) {
    return { files: results.slice(0, maxFiles), limitReached: true };
  }
  return { files: results, limitReached: false };
}

export function shouldRefreshWorkspaceUri(fsPath: string, excludeGlobs: string[]): boolean {
  const normalizedPath = fsPath.replace(/\\/g, "/");
  return ![...DEFAULT_WORKSPACE_EXCLUDE_GLOBS, ...excludeGlobs].some(glob => matchesWorkspaceExclude(normalizedPath, glob));
}

function normalizeMaxFiles(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? Math.floor(value)
    : DEFAULT_WORKSPACE_SCAN_MAX_FILES;
}

function normalizeExcludeGlobs(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === "string")
    .map(item => item.trim())
    .filter(Boolean);
}

function normalizeAutoRefresh(value: unknown): boolean {
  return typeof value === "boolean" ? value : DEFAULT_WORKSPACE_AUTO_REFRESH;
}

function matchesWorkspaceExclude(fsPath: string, glob: string): boolean {
  const normalizedGlob = glob.replace(/\\/g, "/");
  if (normalizedGlob.startsWith("**/") && normalizedGlob.endsWith("/**")) {
    const directory = normalizedGlob.slice(3, -3);
    return fsPath.includes(`/${directory}/`) || fsPath.startsWith(`${directory}/`);
  }
  if (normalizedGlob.endsWith("/**")) {
    const prefix = normalizedGlob.slice(0, -3);
    return fsPath === prefix || fsPath.startsWith(`${prefix}/`);
  }
  if (normalizedGlob.startsWith("**/")) {
    const suffix = normalizedGlob.slice(3);
    return fsPath.endsWith(`/${suffix}`) || fsPath === suffix;
  }
  return fsPath === normalizedGlob || fsPath.startsWith(`${normalizedGlob}/`);
}
