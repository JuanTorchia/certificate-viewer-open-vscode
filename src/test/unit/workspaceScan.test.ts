import * as assert from "assert";
import { buildWorkspaceExcludeGlob, limitWorkspaceScanResults, normalizeWorkspaceScanSettings, shouldRefreshWorkspaceUri } from "../../providers/workspaceScan";

suite("workspaceScan", (): void => {
  test("combines default and user exclude globs for VS Code findFiles", (): void => {
    const exclude = buildWorkspaceExcludeGlob(["**/dist/**", "build/**"]);

    assert.strictEqual(exclude, "{**/node_modules/**,**/dist/**,build/**}");
  });

  test("keeps the default node_modules exclude when user excludes are empty", (): void => {
    const exclude = buildWorkspaceExcludeGlob([]);

    assert.strictEqual(exclude, "**/node_modules/**");
  });

  test("normalizes invalid maxFiles and exclude values", (): void => {
    const settings = normalizeWorkspaceScanSettings({
      maxFiles: -1,
      excludeGlobs: [" **/dist/** ", "", 42, "**/build/**"],
      autoRefresh: "yes",
    });

    assert.deepStrictEqual(settings, {
      maxFiles: 200,
      excludeGlobs: ["**/dist/**", "**/build/**"],
      autoRefresh: true,
    });
  });

  test("normalizes auto refresh when explicitly disabled", (): void => {
    const settings = normalizeWorkspaceScanSettings({
      autoRefresh: false,
    });

    assert.strictEqual(settings.autoRefresh, false);
  });

  test("returns all files when the scan stays below the configured limit", (): void => {
    const result = limitWorkspaceScanResults(["a.pem", "b.pem"], 3);

    assert.deepStrictEqual(result.files, ["a.pem", "b.pem"]);
    assert.strictEqual(result.limitReached, false);
  });

  test("drops the sentinel result and marks the scan as limited", (): void => {
    const result = limitWorkspaceScanResults(["a.pem", "b.pem", "c.pem"], 2);

    assert.deepStrictEqual(result.files, ["a.pem", "b.pem"]);
    assert.strictEqual(result.limitReached, true);
  });

  test("skips watcher refreshes for default and user excluded paths", (): void => {
    assert.strictEqual(shouldRefreshWorkspaceUri("repo/node_modules/certs/dev.pem", []), false);
    assert.strictEqual(shouldRefreshWorkspaceUri("repo/dist/certs/dev.pem", ["**/dist/**"]), false);
    assert.strictEqual(shouldRefreshWorkspaceUri("build/certs/dev.pem", ["build/**"]), false);
    assert.strictEqual(shouldRefreshWorkspaceUri("repo/certs/dev.pem", ["**/dist/**"]), true);
  });
});
