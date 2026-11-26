import { execFileSync } from 'node:child_process';
import type { ToolvetoConfig } from '../config.js';

export interface SandboxLifecycleResult<T> {
  seeded: boolean;
  cleanedUp: boolean;
  result: T;
}

export class DockerSandboxAdapter {
  constructor(private readonly config: ToolvetoConfig) {}

  private runShellCommand(cmd: string, timeoutMs: number): void {
    const parts = cmd.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) return;
    execFileSync(parts[0], parts.slice(1), {
      timeout: timeoutMs,
      stdio: 'pipe',
    });
  }

  public async executeWithLifecycle<T>(run: () => Promise<T>): Promise<SandboxLifecycleResult<T>> {
    const timeoutMs = this.config.sandbox?.timeoutMs ?? 30_000;
    const seedCmd = this.config.sandbox?.seed_command;
    const cleanupCmd = this.config.sandbox?.cleanup_command;
    let seeded = false;
    let cleanedUp = false;

    try {
      if (seedCmd) {
        this.runShellCommand(seedCmd, timeoutMs);
        seeded = true;
      }
      const result = await run();
      return { seeded, cleanedUp, result };
    } finally {
      if (cleanupCmd) {
        try {
          this.runShellCommand(cleanupCmd, timeoutMs);
          cleanedUp = true;
        } catch {
          // Best-effort cleanup; never mask original execution result/error
        }
      }
    }
  }
}
