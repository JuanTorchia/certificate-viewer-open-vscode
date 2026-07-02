export const DEFAULT_WORKSPACE_SCAN_MAX_FILES = 200;
export const DEFAULT_WORKSPACE_EXCLUDE_GLOBS = ["**/node_modules/**"];

export interface RawWorkspaceScanSettings {
  maxFiles?: unknown;
  excludeGlobs?: unknown;
}

export interface WorkspaceScanSettings {
  maxFiles: number;
  excludeGlobs: string[];
}

export interface LimitedWorkspaceScanResult<T> {
  files: T[];
  limitReached: boolean;
}

export function normalizeWorkspaceScanSettings(raw: RawWorkspaceScanSettings): WorkspaceScanSettings {
  return {
    maxFiles: normalizeMaxFiles(raw.maxFiles),
    excludeGlobs: normalizeExcludeGlobs(raw.excludeGlobs),
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
