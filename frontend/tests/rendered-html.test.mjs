import assert from "node:assert/strict";
import test from "node:test";

test("frontend source documents the complete ShieldScore graph", async () => {
  const source = await (await import("node:fs/promises")).readFile(
    new URL("../app/components/audit-dashboard.tsx", import.meta.url),
    "utf8",
  );
  const graph = await (await import("node:fs/promises")).readFile(
    new URL("../app/lib/audit.ts", import.meta.url),
    "utf8",
  );

  assert.match(source, /ShieldScore/);
  assert.match(graph, /scan_data_classification/);
  assert.match(graph, /compliance_mapper/);
  assert.match(graph, /report_generator/);
  assert.match(source, /api\/audit\/start/);
  assert.match(source, /api\/audit\/upload/);
  assert.match(source, /Upload ZIP/);
  assert.match(source, /X-API-Key/);
});
