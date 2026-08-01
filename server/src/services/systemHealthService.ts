// Real System Health Metrics via OS Commands and Node.js APIs
import { exec } from 'child_process';
import { promisify } from 'util';
import os from 'os';

const execAsync = promisify(exec);
const isWindows = process.platform === 'win32';

export interface SystemHealthMetrics {
  hostname: string;
  platform: string;
  cpuModel: string;
  cpuCores: number;
  cpuUsagePct: number;
  totalMemoryMb: number;
  freeMemoryMb: number;
  memoryUsagePct: number;
  uptimeSeconds: number;
  nodeVersion: string;
  processMemoryMb: number;
  loadAverage?: number[];
  timestamp: string;
}

async function getCpuUsageWindows(): Promise<number> {
  try {
    const { stdout } = await execAsync('wmic cpu get LoadPercentage /Value', { timeout: 3000 });
    const match = stdout.match(/LoadPercentage=(\d+)/);
    return match ? parseInt(match[1]) : 0;
  } catch {
    return 0;
  }
}

function getCpuUsageUnix(): Promise<number> {
  return new Promise((resolve) => {
    const cpus1 = os.cpus();
    setTimeout(() => {
      const cpus2 = os.cpus();
      let totalIdle = 0, totalTick = 0;
      for (let i = 0; i < cpus1.length; i++) {
        const t1 = cpus1[i].times;
        const t2 = cpus2[i].times;
        const idle = t2.idle - t1.idle;
        const total = (t2.user - t1.user) + (t2.nice - t1.nice) + (t2.sys - t1.sys) + (t2.idle - t1.idle) + (t2.irq - t1.irq);
        totalIdle += idle;
        totalTick += total;
      }
      const usage = totalTick > 0 ? Math.round((1 - totalIdle / totalTick) * 100) : 0;
      resolve(usage);
    }, 500);
  });
}

export async function getSystemHealth(): Promise<SystemHealthMetrics> {
  const [cpuUsagePct] = await Promise.all([
    isWindows ? getCpuUsageWindows() : getCpuUsageUnix(),
  ]);

  const totalMemoryMb = Math.round(os.totalmem() / (1024 * 1024));
  const freeMemoryMb = Math.round(os.freemem() / (1024 * 1024));
  const usedMem = totalMemoryMb - freeMemoryMb;
  const memoryUsagePct = Math.round((usedMem / totalMemoryMb) * 100);
  const processMemoryMb = Math.round(process.memoryUsage().rss / (1024 * 1024));
  const cpuModel = os.cpus()[0]?.model?.trim() || 'Unknown CPU';
  const loadAvg = isWindows ? undefined : os.loadavg();

  return {
    hostname: os.hostname(),
    platform: `${process.platform} (${os.arch()})`,
    cpuModel,
    cpuCores: os.cpus().length,
    cpuUsagePct,
    totalMemoryMb,
    freeMemoryMb,
    memoryUsagePct,
    uptimeSeconds: Math.round(os.uptime()),
    nodeVersion: process.version,
    processMemoryMb,
    loadAverage: loadAvg,
    timestamp: new Date().toISOString(),
  };
}
