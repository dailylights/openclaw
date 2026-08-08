import type { DatabaseSync } from "node:sqlite";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "openclaw/plugin-sdk/sqlite-runtime";
import type { ScopedMemoryDatabase } from "./scoped-memory-db.js";

/** Tombstone every catalog descendant before a source artifact can disappear. */
export const tombstoneRevisionLineage = (params: {
  database: DatabaseSync;
  revisionId: string;
  nowMs: number;
}): readonly string[] => {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const descendantIds = new Set([params.revisionId]);
  let frontier = [params.revisionId];
  while (frontier.length > 0) {
    const children = executeSqliteQuerySync(
      params.database,
      db
        .selectFrom("memory_lineage_edges")
        .select("child_revision_id")
        .where("parent_revision_id", "in", frontier)
        .orderBy("child_revision_id"),
    ).rows;
    frontier = children.flatMap((child) => {
      if (descendantIds.has(child.child_revision_id)) {
        return [];
      }
      descendantIds.add(child.child_revision_id);
      return [child.child_revision_id];
    });
  }
  const invalidatedIds = [...descendantIds];
  executeSqliteQuerySync(
    params.database,
    db.deleteFrom("memory_scoped_chunks").where("revision_id", "in", invalidatedIds),
  );
  executeSqliteQuerySync(
    params.database,
    db
      .updateTable("memory_resource_revisions")
      .set({ lifecycle_state: "tombstoned", retired_at: params.nowMs })
      .where("revision_id", "in", invalidatedIds)
      .where("lifecycle_state", "in", ["pending", "active", "quarantined"]),
  );
  executeSqliteQuerySync(
    params.database,
    db
      .updateTable("memory_write_intents")
      .set({ state: "quarantined", updated_at: params.nowMs })
      .where("pending_revision_id", "in", invalidatedIds)
      .where("state", "in", ["pending", "renamed"]),
  );
  return Object.freeze(invalidatedIds);
};
