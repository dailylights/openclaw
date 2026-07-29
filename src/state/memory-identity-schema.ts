import { OPENCLAW_STATE_SCHEMA_SQL } from "./openclaw-state-schema.js";

const MEMORY_IDENTITY_SCHEMA_START = "CREATE TABLE IF NOT EXISTS memory_principals (";
const MEMORY_IDENTITY_SCHEMA_END = "CREATE TABLE IF NOT EXISTS session_state_events (";

function extractMemoryIdentitySchema(): string {
  const start = OPENCLAW_STATE_SCHEMA_SQL.indexOf(MEMORY_IDENTITY_SCHEMA_START);
  const end = OPENCLAW_STATE_SCHEMA_SQL.indexOf(MEMORY_IDENTITY_SCHEMA_END, start);
  if (start < 0 || end <= start) {
    throw new Error("canonical memory identity schema markers are missing");
  }
  return OPENCLAW_STATE_SCHEMA_SQL.slice(start, end).trim();
}

/** Canonical lazy schema for shared multiplayer-memory identity metadata. */
export const MEMORY_IDENTITY_SCHEMA_SQL = extractMemoryIdentitySchema();
