import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

function runNodeGyp() {
  const env = { ...process.env };
  delete env.npm_config_node_gyp;
  return spawnSync('node-gyp rebuild --release -j max', {
    env,
    stdio: 'inherit',
    shell: true,
  });
}

function copyWindowsRuntimeDlls() {
  if (process.platform !== 'win32' || !process.env.USERPROFILE) {
    return;
  }

  const vcpkgBinDir = join(process.env.USERPROFILE, 'vcpkg', 'installed', 'x64-windows', 'bin');
  if (!existsSync(vcpkgBinDir)) {
    return;
  }

  const releaseDir = join('build', 'Release');
  mkdirSync(releaseDir, { recursive: true });

  for (const name of readdirSync(vcpkgBinDir)) {
    if (!name.endsWith('.dll')) {
      continue;
    }
    copyFileSync(join(vcpkgBinDir, name), join(releaseDir, name));
  }
}

const result = runNodeGyp();
if (result.status !== 0) {
  process.exit(result.status || 1);
}

copyWindowsRuntimeDlls();
