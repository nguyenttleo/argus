import { buildApp } from './app.ts';
import { loadServerConfig } from './config.ts';

const config = loadServerConfig();
const app = await buildApp(config);

const shutdown = async (sig: string) => {
  console.log(`\n${sig} received - shutting down…`);
  await app.close();
  process.exit(0);
};
process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));

try {
  await app.listen({ port: config.port, host: config.host });
  console.log(`Argus API listening on http://${config.host}:${config.port}`);
  console.log(`  health:    GET http://${config.host}:${config.port}/api/health`);
  console.log(`  quarantine: ${config.quarantineEnabled ? 'enabled (encrypted, TTL sweep)' : 'hash-only retention'}`);
} catch (err) {
  console.error('Failed to start Argus API:', err);
  process.exit(1);
}
