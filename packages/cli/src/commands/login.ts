import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

export interface LoginOptions {
  token?: string;
  apiUrl?: string;
}

export async function loginCommand(tokenArg?: string, options: LoginOptions = {}): Promise<void> {
  const token = tokenArg || options.token || process.env.TOOLVETO_TOKEN;
  const apiUrl = options.apiUrl || process.env.TOOLVETO_API_URL || 'http://localhost:3001';

  if (!token) {
    console.error('\n❌ Error: Please provide your ToolVeto License Token.');
    console.error('Usage: toolveto login <tv_live_...>\n');
    process.exitCode = 1;
    return;
  }

  console.log('\n🔐 Validating license token with ToolVeto Cloud...');

  try {
    const res = await fetch(`${apiUrl}/api/v1/billing/license/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({})) as any;
      console.error(`\n❌ License Validation Failed: ${err.error || res.statusText}\n`);
      process.exitCode = 1;
      return;
    }

    const data = await res.json() as any;
    const configDir = path.join(os.homedir(), '.toolveto');
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }

    const configPath = path.join(configDir, 'config.json');
    fs.writeFileSync(configPath, JSON.stringify({
      token,
      tier: data.tier,
      customerId: data.customerId,
      expiresAt: data.expiresAt,
      apiUrl,
    }, null, 2));

    console.log(`\n✅ Authenticated Successfully!`);
    console.log(`   Customer:     ${data.customerId}`);
    console.log(`   Plan Tier:    ${data.tier}`);
    console.log(`   Entitlements: ${(data.entitlements || []).join(', ')}`);
    console.log(`   Config saved: ${configPath}\n`);
  } catch (err: any) {
    console.error(`\n❌ Network Error during login: ${err.message}\n`);
    process.exitCode = 1;
  }
}
