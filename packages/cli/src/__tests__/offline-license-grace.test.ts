import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import { evaluateOfflineLicenseLifecycle } from '../telemetry.js';

function mintTestEs256License(
  claims: Record<string, unknown>,
  privateKey: crypto.KeyObject
): string {
  const headerB64 = Buffer.from(
    JSON.stringify({ alg: 'ES256', typ: 'TV-ENT-LIC', kid: 'test-es256-offline' })
  ).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const sig = crypto
    .sign('sha256', Buffer.from(`${headerB64}.${payloadB64}`), {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    })
    .toString('base64url');
  return `tv_ent_${headerB64}.${payloadB64}.${sig}`;
}

describe('Offline 72-Hour Enterprise License Grace Window (Claims Register C11)', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

  const HOUR_MS = 3_600_000;
  const DAY_MS = 86_400_000;
  const baseExp = Date.UTC(2026, 10, 1, 0, 0, 0);

  const enterpriseToken = mintTestEs256License(
    {
      sub: 'cus_offline_grace_test',
      org: 'Offline Grace Verification Corp',
      tier: 'ENTERPRISE',
      environment: 'production-vpc',
      contractId: 'MSA-OFFLINE-GRACE-001',
      gracePeriodHours: 72,
      iat: baseExp - 365 * DAY_MS,
      exp: baseExp,
    },
    privateKey
  );

  it('returns VALID when >30 days remain and EXPIRING_SOON within 30 days', () => {
    const validRes = evaluateOfflineLicenseLifecycle(
      enterpriseToken,
      baseExp - 45 * DAY_MS,
      undefined,
      publicKeyPem
    );
    assert.equal(validRes.state, 'VALID');
    assert.equal(validRes.runtimeAllowed, true);
    assert.equal(validRes.attestationValid, true);

    const soonRes = evaluateOfflineLicenseLifecycle(
      enterpriseToken,
      baseExp - 10 * DAY_MS,
      undefined,
      publicKeyPem
    );
    assert.equal(soonRes.state, 'EXPIRING_SOON');
    assert.equal(soonRes.runtimeAllowed, true);
    assert.equal(soonRes.attestationValid, true);
  });

  it('keeps runtime and attestations active throughout the full 72-hour offline grace window', () => {
    const plus1h = evaluateOfflineLicenseLifecycle(
      enterpriseToken,
      baseExp + 1 * HOUR_MS,
      undefined,
      publicKeyPem
    );
    assert.equal(plus1h.state, 'GRACE_PERIOD');
    assert.equal(plus1h.runtimeAllowed, true);
    assert.equal(plus1h.attestationValid, true);
    assert.equal(plus1h.graceHoursRemaining, 71);

    const plus71h59m = evaluateOfflineLicenseLifecycle(
      enterpriseToken,
      baseExp + 72 * HOUR_MS - 60_000,
      undefined,
      publicKeyPem
    );
    assert.equal(plus71h59m.state, 'GRACE_PERIOD');
    assert.equal(plus71h59m.runtimeAllowed, true);
    assert.equal(plus71h59m.attestationValid, true);
    assert.equal(plus71h59m.graceHoursRemaining, 1);
  });

  it('transitions to EXPIRED_FAIL_OPEN with watermark strictly after 72 hours', () => {
    const afterGrace = evaluateOfflineLicenseLifecycle(
      enterpriseToken,
      baseExp + 72 * HOUR_MS + 1,
      undefined,
      publicKeyPem
    );
    assert.equal(afterGrace.state, 'EXPIRED_FAIL_OPEN');
    assert.equal(afterGrace.runtimeAllowed, true, 'Production shield must fail-open to avoid customer outage');
    assert.equal(afterGrace.attestationValid, false, 'Expired past grace must invalidate attestations');
    assert.equal(afterGrace.graceHoursRemaining, 0);
    assert.equal(afterGrace.watermark, 'UNATTESTED_LICENSE_EXPIRED');
  });

  it('honors 720-hour default grace window for airgapped-vpc licenses', () => {
    const airgappedToken = mintTestEs256License(
      {
        sub: 'cus_airgap_test',
        tier: 'ENTERPRISE',
        environment: 'airgapped-vpc',
        iat: baseExp - 365 * DAY_MS,
        exp: baseExp,
      },
      privateKey
    );

    const plus300h = evaluateOfflineLicenseLifecycle(
      airgappedToken,
      baseExp + 300 * HOUR_MS,
      undefined,
      publicKeyPem
    );
    assert.equal(plus300h.state, 'GRACE_PERIOD');
    assert.equal(plus300h.runtimeAllowed, true);
    assert.equal(plus300h.attestationValid, true);
    assert.equal(plus300h.graceHoursRemaining, 420);
  });

  it('fails closed on tampered payloads or wrong ES256 public key', () => {
    const parts = enterpriseToken.slice('tv_ent_'.length).split('.');
    const tamperedPayload = Buffer.from(
      JSON.stringify({
        sub: 'cus_offline_grace_test',
        tier: 'ENTERPRISE',
        gracePeriodHours: 99999,
        exp: baseExp + 3650 * DAY_MS,
      })
    ).toString('base64url');
    const tamperedToken = `tv_ent_${parts[0]}.${tamperedPayload}.${parts[2]}`;

    const tamperedRes = evaluateOfflineLicenseLifecycle(
      tamperedToken,
      baseExp + 1 * HOUR_MS,
      undefined,
      publicKeyPem
    );
    assert.equal(tamperedRes.state, 'UNVERIFIED_OFFLINE');
    assert.equal(tamperedRes.runtimeAllowed, false);
    assert.equal(tamperedRes.attestationValid, false);

    const wrongKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey
      .export({ type: 'spki', format: 'pem' })
      .toString();
    const wrongKeyRes = evaluateOfflineLicenseLifecycle(
      enterpriseToken,
      baseExp - DAY_MS,
      undefined,
      wrongKey
    );
    assert.equal(wrongKeyRes.state, 'UNVERIFIED_OFFLINE');
    assert.equal(wrongKeyRes.runtimeAllowed, false);
  });
});
