import { executeSqliteQueryTakeFirstSync, getNodeSqliteKysely } from "../infra/kysely-sync.js";
import type { DB as OpenClawAgentDatabaseSchema } from "../state/openclaw-agent-db.generated.js";
import { openOpenClawAgentDatabase } from "../state/openclaw-agent-db.js";
import { ensureOpenClawAgentScopedMemorySchema } from "../state/openclaw-agent-scoped-memory-schema.js";

type MemoryCutoverDatabase = Pick<OpenClawAgentDatabaseSchema, "memory_migrations">;

// Cutover is process-stable. Doctor/configuration changes require a restart, so
// request-time code never polls the database for a fresher migration phase.
const cutoverByAgentId = new Map<string, boolean>();

/** True once any verified migration has moved this agent onto scoped memory. */
export function isMemoryIsolationCutoverAgent(agentIdInput: string): boolean {
  const agentId = agentIdInput.trim();
  if (!agentId) {
    return true;
  }
  const cached = cutoverByAgentId.get(agentId);
  if (cached !== undefined) {
    return cached;
  }
  try {
    const database = openOpenClawAgentDatabase({ agentId });
    ensureOpenClawAgentScopedMemorySchema(database.db);
    const row = executeSqliteQueryTakeFirstSync(
      database.db,
      getNodeSqliteKysely<MemoryCutoverDatabase>(database.db)
        .selectFrom("memory_migrations")
        .select("migration_id")
        .where("phase", "=", "cutover")
        .limit(1),
    );
    const cutover = row !== undefined;
    cutoverByAgentId.set(agentId, cutover);
    return cutover;
  } catch {
    // An unreadable authority store cannot safely re-enable legacy filesystem reads.
    cutoverByAgentId.set(agentId, true);
    return true;
  }
}
