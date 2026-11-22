import * as net from 'node:net';

export interface FaultProxyController {
  proxyUrl: string;
  port: number;
  armNextCut: () => void;
  getStats: () => { cutsExecuted: number; headersIntercepted: number; connectionsHandled: number };
  close: () => Promise<void>;
}

/**
 * Real Post-Commit Mid-Response TCP Fault-Injection Proxy (PAT-01).
 * Interposes a raw Node TCP server in front of a Streamable HTTP MCP target.
 * When `armNextCut()` is armed, forwards the full HTTP request to the upstream
 * server, waits until the upstream begins returning `HTTP/1.1 200` headers
 * (proving the mutation already committed server-side), and immediately severs
 * the client socket (`clientSocket.destroy()`) BEFORE flushing the JSON-RPC body.
 */
export async function createMidResponseFaultProxy(targetUrl: string): Promise<FaultProxyController> {
  const parsed = new URL(targetUrl);
  const targetHost = parsed.hostname;
  const targetPort = Number(parsed.port || (parsed.protocol === 'https:' ? 443 : 80));

  let cutArmed = false;
  let cutsExecuted = 0;
  let headersIntercepted = 0;
  let connectionsHandled = 0;
  const openSockets = new Set<net.Socket>();

  const server = net.createServer((clientSocket) => {
    connectionsHandled += 1;
    openSockets.add(clientSocket);
    const shouldCutThisConnection = cutArmed;
    if (shouldCutThisConnection) {
      cutArmed = false;
    }

    const upstreamSocket = net.connect(targetPort, targetHost);
    openSockets.add(upstreamSocket);

    let responseBuffer = Buffer.alloc(0);
    let cutDone = false;

    clientSocket.on('data', (chunk) => {
      if (!upstreamSocket.destroyed) {
        upstreamSocket.write(chunk);
      }
    });

    upstreamSocket.on('data', (chunk) => {
      if (!shouldCutThisConnection) {
        if (!clientSocket.destroyed) clientSocket.write(chunk);
        return;
      }
      if (cutDone) return;

      responseBuffer = Buffer.concat([responseBuffer, chunk]);
      const headerEndIdx = responseBuffer.indexOf('\r\n\r\n');
      if (headerEndIdx !== -1) {
        headersIntercepted += 1;
        // Sever client TCP socket mid-response right after HTTP status/headers (never flushing JSON-RPC body!)
        cutDone = true;
        cutsExecuted += 1;
        clientSocket.destroy();
        upstreamSocket.destroy();
      }
    });

    const cleanup = () => {
      openSockets.delete(clientSocket);
      openSockets.delete(upstreamSocket);
      if (!clientSocket.destroyed) clientSocket.destroy();
      if (!upstreamSocket.destroyed) upstreamSocket.destroy();
    };

    clientSocket.on('error', cleanup);
    upstreamSocket.on('error', cleanup);
    clientSocket.on('close', cleanup);
    upstreamSocket.on('close', cleanup);
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  const proxyUrl = `http://127.0.0.1:${port}${parsed.pathname}${parsed.search}`;

  return {
    proxyUrl,
    port,
    armNextCut: () => {
      cutArmed = true;
    },
    getStats: () => ({
      cutsExecuted,
      headersIntercepted,
      connectionsHandled,
    }),
    close: async () => {
      for (const s of openSockets) {
        try {
          s.destroy();
        } catch {
          // Ignore already closed sockets
        }
      }
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
