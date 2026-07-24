# Working Agreements

- Respond in Spanish by default, with a direct technical tone.
- Do not agree by default. If an idea is unclear, risky, incomplete, or technically weak, say so and explain why.
- Prefer concise answers that go straight to the decision, trade-off, command, file, or next action.
- Challenge assumptions before implementing infrastructure, security, production, deployment, database, or credential changes.
- When there are multiple viable paths, give the recommended option first, then briefly compare alternatives.
- Ask for clarification only when the missing detail changes the technical decision or creates operational risk.
- For production or security-sensitive work, favor explicit validation, dry-runs, least privilege, auditability, and rollback paths.
- Do not optimize for being agreeable. Optimize for useful technical judgment, clear execution, and safe outcomes.

<!-- codebase-memory-mcp:start -->
# Codebase Knowledge Graph (codebase-memory-mcp)

This project uses codebase-memory-mcp to maintain a knowledge graph of the codebase.
Project name: `certview-vscode`.
ALWAYS prefer MCP graph tools over grep/glob/file-search for code discovery.
Before relying on graph results, call `index_status(project="certview-vscode")`.
If the index is unavailable, stale, or does not cover recent edits, reindex with `index_repository(repo_path="C:\\Users\\jstor\\develop\\certview-vscode", mode="fast")` for routine freshness checks, or fall back to direct file reads for the affected files.
Use `mode="moderate"` or `mode="full"` only when semantic or similarity search is needed.
When reviewing or editing recently changed files, prefer direct file reads for those files even if graph discovery was used to find related symbols.

## Priority Order

1. `search_graph` — find functions, classes, routes, variables by pattern
2. `trace_path` — trace who calls a function or what it calls
3. `get_code_snippet` — read specific function/class source code
4. `query_graph` — run Cypher queries for complex patterns
5. `get_architecture` — high-level project summary

## When to fall back to grep/glob

- Searching for string literals, error messages, config values
- Searching non-code files (Dockerfiles, shell scripts, configs)
- When MCP tools return insufficient results

## Examples

- Find a handler: `search_graph(project="certview-vscode", name_pattern=".*OrderHandler.*")`
- Who calls it: `trace_path(project="certview-vscode", function_name="OrderHandler", direction="inbound")`
- Read source: `get_code_snippet(project="certview-vscode", qualified_name="pkg/orders.OrderHandler")`
<!-- codebase-memory-mcp:end -->

## Commands

- Install dependencies: `pnpm install`
- Compile: `pnpm compile`
- Bundle extension: `pnpm bundle`
- Lint: `pnpm lint`
- Unit tests: `pnpm test:unit`
- VS Code integration tests: `pnpm test`
- Package readiness: `pnpm package:ci`
