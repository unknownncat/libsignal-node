'use strict';

const { spawnSync } = require('child_process');

function runNodeGyp() {
    const env = Object.assign({}, process.env);
    delete env.npm_config_node_gyp;
    return spawnSync('node-gyp rebuild --release -j max', {
        env,
        stdio: 'inherit',
        shell: true
    });
}

const strict = process.argv.includes('--strict');
const result = runNodeGyp();
if (result.status !== 0) {
    if (strict) {
        process.exit(result.status || 1);
    }
    console.warn('native addon build skipped');
}
