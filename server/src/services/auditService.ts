import { query, memoryDb } from '../db/client.js';

export interface AuditLogRecord {
  id?: number;
  timestamp: string;
  userId: string;
  action: string;
  previousValue?: string;
  newValue?: string;
  sourceIp: string;
  result: 'SUCCESS' | 'FAILURE';
}

export async function recordAuditLog(log: Omit<AuditLogRecord, 'timestamp'>): Promise<AuditLogRecord> {
  const fullLog: AuditLogRecord = {
    ...log,
    timestamp: new Date().toISOString(),
  };

  memoryDb.auditLogs.unshift(fullLog);
  if (memoryDb.auditLogs.length > 500) memoryDb.auditLogs.pop();

  try {
    await query(
      `INSERT INTO audit_logs (timestamp, user_id, action, previous_value, new_value, source_ip, result)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        fullLog.timestamp,
        fullLog.userId,
        fullLog.action,
        fullLog.previousValue || null,
        fullLog.newValue || null,
        fullLog.sourceIp,
        fullLog.result,
      ]
    );
  } catch {
    // Memory fallback
  }

  console.log(`[Audit Service] ${fullLog.userId} -> ${fullLog.action} (${fullLog.previousValue || ''} => ${fullLog.newValue || ''})`);
  return fullLog;
}

export function getAuditLogs(): AuditLogRecord[] {
  return memoryDb.auditLogs;
}
