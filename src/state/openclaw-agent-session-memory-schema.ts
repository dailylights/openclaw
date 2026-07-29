import { OPENCLAW_AGENT_SCHEMA_SQL } from "./openclaw-agent-schema.js";

const SESSION_MEMORY_SCHEMA_START = "CREATE TABLE IF NOT EXISTS session_memory_subjects (";
const SESSION_MEMORY_SCHEMA_END = "CREATE TABLE IF NOT EXISTS session_suggestions (";

function extractSessionMemorySchema(): string {
  const start = OPENCLAW_AGENT_SCHEMA_SQL.indexOf(SESSION_MEMORY_SCHEMA_START);
  const end = OPENCLAW_AGENT_SCHEMA_SQL.indexOf(SESSION_MEMORY_SCHEMA_END, start);
  if (start < 0 || end <= start) {
    throw new Error("canonical session memory schema markers are missing");
  }
  return OPENCLAW_AGENT_SCHEMA_SQL.slice(start, end).trim();
}

/** Canonical lazy schema for write-once logical-session memory subjects. */
export const AGENT_SESSION_MEMORY_SCHEMA_SQL = extractSessionMemorySchema();
