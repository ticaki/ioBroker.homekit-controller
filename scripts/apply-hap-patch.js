/*
 * postinstall patcher for hap-controller.
 *
 * Why not patch-package?
 * In an ioBroker installation hap-controller is hoisted to the top-level
 * node_modules of the host (e.g. /opt/iobroker/node_modules/hap-controller),
 * while postinstall runs inside the adapter package directory. patch-package
 * only looks at ./node_modules relative to its CWD and therefore fails with
 * "package ... not present at node_modules/hap-controller" in that layout.
 *
 * This script instead resolves the real installed location via require.resolve
 * (which honours hoisting) and applies the patch idempotently. It never fails
 * the install: on an unexpected library version it logs a warning and exits 0.
 *
 * The patch itself fixes a synchronous endless loop in the encrypted frame
 * parser (_requestEncrypted): when decryption fails the `message` buffer is not
 * advanced, so the `while (message.length >= 18)` loop spins forever and blocks
 * the Node event loop (100% CPU, adapter shows up as "not running", no logs).
 * After an OOM/SIGABRT restart this produced a hanging zombie process.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const MARKER = 'avoid endless loop';

const OLD = `                        parser.execute(decryptedData);
                    }
                    catch (e) {
                        // pass
                    }`;

const NEW = `                        parser.execute(decryptedData);
                    }
                    catch (e) {
                        // Decryption failed: the encrypted stream is desynchronised (e.g. nonce/counter
                        // mismatch after an unclean disconnect or a SIGABRT that left the TCP connection
                        // half-open). \`message\` is only advanced on a *successful* decrypt above, so if we
                        // just swallow the error here this while-loop never advances and spins forever -
                        // blocking the Node event loop entirely (100% CPU, the adapter shows up as
                        // "not running", no further log output). Tear the socket down instead so the
                        // upper layers reconnect / resubscribe with fresh session keys.
                        debug(\`\${this.address}:\${this.port} Decrypting message failed, closing connection to avoid endless loop\`);
                        this.close();
                        return;
                    }`;

function resolveTarget() {
    try {
        const pkgJson = require.resolve('hap-controller/package.json');
        return path.join(path.dirname(pkgJson), 'lib', 'transport', 'ip', 'http-connection.js');
    } catch (err) {
        return null;
    }
}

function main() {
    const target = resolveTarget();
    if (!target || !fs.existsSync(target)) {
        console.warn('[apply-hap-patch] hap-controller http-connection.js not found, skipping patch');
        return;
    }

    let content = fs.readFileSync(target, 'utf8');

    if (content.includes(MARKER)) {
        console.log('[apply-hap-patch] hap-controller already patched, nothing to do');
        return;
    }

    if (!content.includes(OLD)) {
        console.warn(
            '[apply-hap-patch] expected code block not found in hap-controller ' +
                '(library version changed?) - patch NOT applied. Please re-check the fix.',
        );
        return;
    }

    content = content.replace(OLD, NEW);
    fs.writeFileSync(target, content, 'utf8');
    console.log(`[apply-hap-patch] patched ${target}`);
}

try {
    main();
} catch (err) {
    // Never break the install because of the patcher.
    console.warn(`[apply-hap-patch] failed to apply patch: ${err && err.message}`);
}
