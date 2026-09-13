import { boolean, integer, jsonb, pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core';

export const policies = pgTable('policies', {
  id: uuid('id').defaultRandom().primaryKey(),
  name: text('name').notNull().unique(),
  match: jsonb('match').notNull(),
  action: text('action').notNull(),
  enabled: boolean('enabled').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export const auditLogs = pgTable('audit_logs', {
  id: uuid('id').defaultRandom().primaryKey(),
  agent: text('agent').notNull(), server: text('server').notNull(), tool: text('tool').notNull(),
  decision: text('decision').notNull(), policy: text('policy'), arguments: jsonb('arguments').notNull(),
  duration: integer('duration').notNull(), result: jsonb('result'), createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export const mcpServers = pgTable('mcp_servers', {
  id: uuid('id').defaultRandom().primaryKey(), name: text('name').notNull().unique(),
  transport: text('transport').notNull(), command: text('command'), url: text('url'), status: text('status').notNull(),
});
