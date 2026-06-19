import { spawn } from 'node:child_process';
import { join } from 'node:path';

const root = process.cwd();
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const webPort = process.env.PORT || process.env.WEB_PORT || '3001';
const apiPort = process.env.ARGUS_API_PORT || '8089';
const apiHost = process.env.ARGUS_API_HOST || '127.0.0.1';
const webHost = process.env.WEB_HOST || '0.0.0.0';
const children = new Set();
let shuttingDown = false;

function start(name, command, args, env) {
  const child = spawn(command, args, {
    cwd: root,
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: process.platform === 'win32' && command === npm,
  });
  children.add(child);

  const prefix = `[${name}]`;
  child.stdout.on('data', (data) => process.stdout.write(`${prefix} ${data}`));
  child.stderr.on('data', (data) => process.stderr.write(`${prefix} ${data}`));
  child.on('exit', (code, signal) => {
    children.delete(child);
    if (!shuttingDown) {
      console.error(`${prefix} exited with ${signal ?? code}`);
      shutdown(code && code > 0 ? code : 1);
    }
  });

  return child;
}

function shutdown(code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  for (const child of children) {
    if (!child.killed) child.kill('SIGTERM');
  }
  setTimeout(() => {
    for (const child of children) {
      if (!child.killed) child.kill('SIGKILL');
    }
    process.exit(code);
  }, 5000).unref();
}

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));

const argusApi = process.env.ARGUS_API || `http://${apiHost}:${apiPort}`;

start('api', 'node', [join('packages', 'server', 'src', 'main.ts')], {
  HOST: apiHost,
  PORT: apiPort,
});

start('web', npm, ['--prefix', 'web', 'run', 'start', '--', '-H', webHost, '-p', webPort], {
  ARGUS_API: argusApi,
});

console.log(`Argus public web starting on http://${webHost}:${webPort}`);
console.log(`Argus private API target is ${argusApi}`);
