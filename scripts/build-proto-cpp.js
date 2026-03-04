import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const srcDir = 'protos';
const dstDir = 'native/proto';

mkdirSync(dstDir, { recursive: true });

const protoFiles = readdirSync(srcDir)
  .filter((name) => name.endsWith('.proto'))
  .map((name) => join(srcDir, name));

if (protoFiles.length === 0) {
  console.error('No .proto files found in protos/.');
  process.exit(1);
}

const vcpkgProtoc = process.env.USERPROFILE
  ? join(process.env.USERPROFILE, 'vcpkg', 'installed', 'x64-windows', 'tools', 'protobuf', 'protoc.exe')
  : '';

const protocBinary = vcpkgProtoc && existsSync(vcpkgProtoc) ? vcpkgProtoc : 'protoc';
const args = [`-I=${srcDir}`, `--cpp_out=${dstDir}`, ...protoFiles];

const result = spawnSync(protocBinary, args, { stdio: 'inherit', shell: false });
if (result.status !== 0) {
  process.exit(result.status || 1);
}