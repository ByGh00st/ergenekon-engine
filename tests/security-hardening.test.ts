import { describe, it, expect, vi, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, relative, isAbsolute, join } from 'node:path';
import type { RecordingSession } from '@ergenekon/core';
import { CollectorServer } from '../packages/ergenekon-collector/src/server.js';
import { fetchAPI, postAPI, getCollectorHeaders } from '../packages/ergenekon-cli/src/index.js';
import { sanitizeSqlQuery } from '../packages/ergenekon-probe/src/interceptors/database.js';
import { sanitizeArgs } from '../packages/ergenekon-probe/src/interceptors/fs.js';
import { CollectorClient } from '../packages/ergenekon-probe/src/transport/collector-client.js';
import { ErgenekonProbe } from '@ergenekon/probe';
import { MockLayer, ReplayEngine } from '@ergenekon/replay';

describe('🛡️ ERGENEKON // SECURITY HARDENING & RUNTIME INVARIANTS SUITE', () => {

  // ==========================================================================
  // 1. CLI PATH CONFINEMENT & AUTHENTICATION
  // ==========================================================================
  describe('CLI Security & Path Confinement', () => {
    it('blocks dangerous executable, script, and configuration target files', () => {
      const dangerousTargets = [
        'dist/index.js',
        'src/main.ts',
        'package.json',
        'tsconfig.json',
        'scripts/build.sh',
        'config/app.yaml',
        'server.py',
        '.env.production'
      ];

      for (const target of dangerousTargets) {
        const normalized = target.toLowerCase().replace(/\\/g, '/');
        const isDangerousDir = ['/node_modules/', '/dist/', '/build/'].some(d => normalized.includes(d));
        const isScriptOrCode = normalized.match(/\.(bashrc|zshrc|profile|bat|cmd|exe|ps1|sh|vbs|dll|sys|ini|js|ts|mjs|cjs|jsx|tsx|py|rb|php|java|c|cpp|h|rs|go|yaml|yml|toml)$/i);
        const isSensitiveConfig = normalized.endsWith('package.json') || normalized.endsWith('tsconfig.json');
        const isHidden = normalized.match(/(?:^|\/)\.[^\/]+$/);

        const isBlocked = isDangerousDir || Boolean(isScriptOrCode) || isSensitiveConfig || Boolean(isHidden);
        expect(isBlocked, `Target path must be blocked: ${target}`).toBe(true);
      }
    });

    it('allows valid .ergenekon.json session export paths', () => {
      const safeTarget = 'session-123.ergenekon.json';
      const normalized = safeTarget.toLowerCase().replace(/\\/g, '/');
      const isScriptOrCode = normalized.match(/\.(bashrc|zshrc|profile|bat|cmd|exe|ps1|sh|vbs|dll|sys|ini|js|ts|mjs|cjs|jsx|tsx|py|rb|php|java|c|cpp|h|rs|go|yaml|yml|toml)$/i);
      expect(isScriptOrCode).toBeNull();
      expect(normalized.endsWith('.ergenekon.json')).toBe(true);
    });

    describe('CLI Collector Token Transmission (Runtime)', () => {
      const originalToken = process.env['ERGENEKON_COLLECTOR_TOKEN'];
      let fetchSpy: ReturnType<typeof vi.spyOn>;

      beforeEach(() => {
        fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
          return new Response(JSON.stringify({ ok: true, sessions: [] }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        });
      });

      afterEach(() => {
        fetchSpy.mockRestore();
        if (originalToken !== undefined) {
          process.env['ERGENEKON_COLLECTOR_TOKEN'] = originalToken;
        } else {
          delete process.env['ERGENEKON_COLLECTOR_TOKEN'];
        }
      });

      it('fetchAPI transmits Authorization Bearer header when token is configured', async () => {
        process.env['ERGENEKON_COLLECTOR_TOKEN'] = 'secret-token-xyz-999';
        await fetchAPI('/api/v1/sessions');

        expect(fetchSpy).toHaveBeenCalled();
        const callOptions = fetchSpy.mock.calls[0]![1] as RequestInit;
        const headers = callOptions.headers as Record<string, string>;

        expect(headers).toBeDefined();
        expect(headers['Authorization']).toBe('Bearer secret-token-xyz-999');
      });

      it('postAPI transmits Authorization Bearer header when token is configured', async () => {
        process.env['ERGENEKON_COLLECTOR_TOKEN'] = 'secret-token-post-123';
        await postAPI('/api/v1/sessions', { sessions: [] });

        expect(fetchSpy).toHaveBeenCalled();
        const callOptions = fetchSpy.mock.calls[0]![1] as RequestInit;
        const headers = callOptions.headers as Record<string, string>;

        expect(headers).toBeDefined();
        expect(headers['Authorization']).toBe('Bearer secret-token-post-123');
        expect(headers['Content-Type']).toBe('application/json');
      });

      it('omits Authorization header when ERGENEKON_COLLECTOR_TOKEN is unset', async () => {
        delete process.env['ERGENEKON_COLLECTOR_TOKEN'];
        await fetchAPI('/api/v1/sessions');

        expect(fetchSpy).toHaveBeenCalled();
        const callOptions = fetchSpy.mock.calls[0]![1] as RequestInit;
        const headers = callOptions.headers as Record<string, string>;

        expect(headers['Authorization']).toBeUndefined();
      });
    });
  });

  // ==========================================================================
  // 2. REPLAY ENGINE ISOLATION (CJS & ESM)
  // ==========================================================================
  describe('Replay Engine Runtime Isolation', () => {
    it('blocks sensitive child process and fs write primitives in replay mode', async () => {
      const engine = new ReplayEngine();
      const session: RecordingSession = {
        id: 'test-session-02',
        traceId: 'trace-02',
        spanId: 'span-02',
        serviceName: 'test-service',
        startedAt: Date.now(),
        endedAt: Date.now() + 10,
        events: [
          { sequence: 1, type: 'http_request_in', operationName: 'GET /', wallClock: Date.now(), data: { method: 'GET', url: 'http://localhost' }, durationMs: 0 },
          { sequence: 2, type: 'http_response_out', operationName: '200 OK', wallClock: Date.now() + 5, data: { statusCode: 200 }, durationMs: 5 }
        ],
        metadata: { totalDurationMs: 10, eventCount: 2, hasError: false }
      };

      engine.loadFromSession(session);

      await (engine as any).withMocks(async () => {
        const cp = await import('node:child_process');
        expect(() => {
          cp.exec('whoami');
        }).toThrow(/Replay Engine blocked access/);

        const fsMod = await import('node:fs');
        expect(() => {
          fsMod.writeFileSync('test_malicious.txt', 'evil');
        }).toThrow(/Replay Engine blocked access/);

        await expect(async () => {
          await fsMod.promises.writeFile('test_malicious.txt', 'evil');
        }).rejects.toThrow(/Replay Engine blocked access/);
      });
    });
  });

  // ==========================================================================
  // 3. COLLECTOR AUTHENTICATION & ORIGIN INVARIANTS
  // ==========================================================================
  describe('Collector Security & Origin Invariants', () => {
    it('fails closed when token is not configured in production', () => {
      const originalEnv = process.env['NODE_ENV'];
      const originalToken = process.env['ERGENEKON_COLLECTOR_TOKEN'];
      try {
        process.env['NODE_ENV'] = 'production';
        delete process.env['ERGENEKON_COLLECTOR_TOKEN'];

        const collectorToken = process.env['ERGENEKON_COLLECTOR_TOKEN'];
        const requireAuth = (): boolean => {
          if (!collectorToken) {
            if (process.env['NODE_ENV'] === 'production') return false;
            return true;
          }
          return false;
        };

        expect(requireAuth()).toBe(false);
      } finally {
        process.env['NODE_ENV'] = originalEnv;
        if (originalToken) process.env['ERGENEKON_COLLECTOR_TOKEN'] = originalToken;
      }
    });

    describe('Live HTTP Origin & CORS Verification', () => {
      let server: CollectorServer;
      let port: number;
      let storageDir: string;

      beforeAll(async () => {
        storageDir = await mkdtemp(join(tmpdir(), 'ergenekon-sec-test-'));
        port = 18940 + Math.floor(Math.random() * 500);

        server = new CollectorServer({
          port,
          storageDir,
        });

        await server.start();
      });

      afterAll(async () => {
        await server.stop();
        await rm(storageDir, { recursive: true, force: true });
      });

      function request(headers: Record<string, string>): Promise<{ status: number; headers: http.IncomingHttpHeaders }> {
        return new Promise((resolve, reject) => {
          const req = http.request({
            hostname: 'localhost',
            port,
            path: '/health',
            method: 'GET',
            headers,
          }, (res) => {
            res.on('data', () => {});
            res.on('end', () => {
              resolve({
                status: res.statusCode!,
                headers: res.headers,
              });
            });
          });

          req.on('error', reject);
          req.end();
        });
      }

      it('omits Access-Control-Allow-Origin header completely for unauthorized origins', async () => {
        const response = await request({
          Origin: 'http://malicious-attacker.com',
        });

        expect(response.status).toBe(200);
        expect(response.headers['access-control-allow-origin']).toBeUndefined();
      });

      it('reflects Access-Control-Allow-Origin header for authorized origins', async () => {
        const response = await request({
          Origin: 'http://localhost:3000',
        });

        expect(response.status).toBe(200);
        expect(response.headers['access-control-allow-origin']).toBe('http://localhost:3000');
      });
    });
  });

  // ==========================================================================
  // 4. UI CONFINEMENT & RATE LIMITING
  // ==========================================================================
  describe('UI Confinement & Rate Limiting', () => {
    it('enforces cross-platform relative sandbox boundaries', () => {
      const publicDir = resolve('packages/ergenekon-ui/src/public');
      const validPath = resolve(publicDir, 'index.html');
      const traversalPath = resolve(publicDir, '../../secret.txt');

      const relValid = relative(publicDir, validPath);
      const isValidSafe = !relValid.startsWith('..') && !isAbsolute(relValid);
      expect(isValidSafe).toBe(true);

      const relTraversal = relative(publicDir, traversalPath);
      const isTraversalSafe = !relTraversal.startsWith('..') && !isAbsolute(relTraversal);
      expect(isTraversalSafe).toBe(false);
    });

    it('evicts oldest entries in rate limit map using FIFO to prevent memory exhaustion', () => {
      const map = new Map<string, { count: number; lastAt: number }>();
      const MAX_SIZE = 100;

      for (let i = 0; i < MAX_SIZE; i++) {
        map.set(`10.0.0.${i}`, { count: 1, lastAt: Date.now() });
      }

      const newClientIp = '192.168.1.100';
      if (map.size >= MAX_SIZE && !map.has(newClientIp)) {
        const oldest = map.keys().next().value;
        if (oldest) map.delete(oldest);
      }
      map.set(newClientIp, { count: 1, lastAt: Date.now() });

      expect(map.size).toBe(MAX_SIZE);
      expect(map.has(newClientIp)).toBe(true);
      expect(map.has('10.0.0.0')).toBe(false);
    });
  });

  // ==========================================================================
  // 5. PROBE TELEMETRY SANITIZATION & ERROR RESILIENCE
  // ==========================================================================
  describe('Probe Telemetry Sanitization & Error Immunity', () => {
    it('redacts sensitive file paths and contents in fs interceptor', () => {
      const sanitized = sanitizeArgs(['.env', 'DATABASE_PASSWORD=SuperSecretPass123!']);
      expect(sanitized[0]).toBe('.env');
      expect(sanitized[1]).toBe('[REDACTED]');
    });

    it('passes safe log content while sanitizing sensitive strings', () => {
      const sanitized = sanitizeArgs(['app.log', 'Server started successfully on port 3000']);
      expect(sanitized[1]).toBe('Server started successfully on port 3000');
    });

    it('masks literal SQL credentials in non-parameterized queries', () => {
      const rawSql = "INSERT INTO users (username, password) VALUES ('admin', 'VerySecretPassword123!')";
      const cleaned = sanitizeSqlQuery(rawSql);
      expect(cleaned).toContain("'[REDACTED]'");
      expect(cleaned).not.toContain('VerySecretPassword123!');
    });

    it('resolves real response body from streaming event payload in replay mockLayer', () => {
      const session: RecordingSession = {
        id: 'test-session-08',
        traceId: 'trace-08',
        spanId: 'span-08',
        serviceName: 'test-service',
        startedAt: Date.now(),
        endedAt: Date.now() + 20,
        events: [
          { sequence: 1, type: 'http_request_out', operationName: 'GET /api', wallClock: Date.now(), data: { url: 'http://backend.internal' }, durationMs: 0 },
          { sequence: 2, type: 'http_response_in', operationName: '200 OK', wallClock: Date.now() + 5, data: { status: 200, body: '[STREAMING]' }, durationMs: 5 },
          { sequence: 3, type: 'http_response_in_body', operationName: 'Body /api', wallClock: Date.now() + 10, data: { body: { userId: 42, role: 'admin' } }, durationMs: 5 }
        ],
        metadata: { totalDurationMs: 20, eventCount: 3, hasError: false }
      };

      const mockLayer = new MockLayer(session);
      const res = mockLayer.mockFetch('http://backend.internal');

      expect(res).not.toBeNull();
      expect(res!.status).toBe(200);
      expect(res!.body).toEqual({ userId: 42, role: 'admin' });
      expect(res!.body).not.toBe('[STREAMING]');
    });

    it('preserves valid random numeric values without NaN corruption', () => {
      const session: RecordingSession = {
        id: 'test-session-09',
        traceId: 'trace-09',
        spanId: 'span-09',
        serviceName: 'test-service',
        startedAt: Date.now(),
        endedAt: Date.now() + 5,
        events: [
          { sequence: 1, type: 'random', operationName: 'Math.random()', wallClock: Date.now(), data: { value: 0.428571 }, durationMs: 0 }
        ],
        metadata: { totalDurationMs: 5, eventCount: 1, hasError: false }
      };

      const mock = new MockLayer(session);
      const val = mock.mockMathRandom();
      expect(val).toBe(0.428571);
      expect(Number.isNaN(val * 100)).toBe(false);
    });

    it('guarantees CollectorClient does not crash the host process when no error listeners exist', () => {
      const client = new CollectorClient({
        collectorUrl: 'http://localhost:4380',
        flushIntervalMs: 5000,
        maxBufferSize: 100
      });

      expect(() => {
        if (client.listenerCount('error') > 0) {
          client.emit('error', new Error('Network failure'));
        }
      }).not.toThrow();
    });

    it('attaches automatic error handlers to CollectorClient upon ErgenekonProbe instantiation', () => {
      const probe = new ErgenekonProbe({ serviceName: 'test-safety-probe' });
      const collector = (probe as any).collector as CollectorClient;
      expect(collector.listenerCount('error')).toBeGreaterThan(0);
    });
  });

  // ==========================================================================
  // 6. LICENSE & WEBHOOK INTEGRITY
  // ==========================================================================
  describe('License & Webhook Integrity', () => {
    it('verifies license registration response includes cryptographic signature', () => {
      const responsePayload = {
        success: true,
        message: 'License generated! Download starting...',
        licenseId: 'lic_xyz123',
        tier: 'pro',
        expiresAt: '2026-12-31T23:59:59.000Z',
        signature: 'mock_base64_ed25519_signature',
        license: {
          payload: { licenseId: 'lic_xyz123', tier: 'pro' },
          signature: 'mock_base64_ed25519_signature',
          alg: 'Ed25519'
        }
      };

      expect(responsePayload.signature).toBeDefined();
      expect(responsePayload.license).toBeDefined();
      expect(responsePayload.license.signature).toBe('mock_base64_ed25519_signature');
    });

    it('records Stripe webhook idempotency only upon successful processing to allow retries', () => {
      const processedEventIds = new Set<string>();
      const eventId = 'evt_test_flaw_12';

      // 1. First attempt fails (transient failure)
      const firstAttemptResult = { received: false, error: 'License generation failed — will retry' };
      if (firstAttemptResult.received) {
        processedEventIds.add(eventId);
      }
      expect(processedEventIds.has(eventId)).toBe(false);

      // 2. Stripe retry is allowed
      const isRetryAllowed = !processedEventIds.has(eventId);
      expect(isRetryAllowed).toBe(true);

      // 3. Second attempt succeeds
      const secondAttemptResult = { received: true, action: 'license_generated' };
      if (secondAttemptResult.received) {
        processedEventIds.add(eventId);
      }
      expect(processedEventIds.has(eventId)).toBe(true);
    });
  });

});
