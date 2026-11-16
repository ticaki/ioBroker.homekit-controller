/*
 * postinstall patcher for upstream dependencies (hap-controller + dnssd).
 *
 * Why not patch-package?
 * In an ioBroker installation the dependencies are hoisted to the top-level
 * node_modules of the host (e.g. /opt/iobroker/node_modules/hap-controller),
 * while postinstall runs inside the adapter package directory. patch-package
 * only looks at ./node_modules relative to its CWD and therefore fails with
 * "package ... not present at node_modules/hap-controller" in that layout.
 *
 * This script instead resolves the real installed location via require.resolve
 * (which honours hoisting) and applies each patch idempotently. It never fails
 * the install: on an unexpected library version it logs a warning and exits 0.
 *
 * Patch 1 (hap-controller): fixes a synchronous endless loop in the encrypted
 * frame parser (_requestEncrypted): when decryption fails the `message` buffer
 * is not advanced, so the `while (message.length >= 18)` loop spins forever and
 * blocks the Node event loop (100% CPU, adapter shows up as "not running", no
 * logs). After an OOM/SIGABRT restart this produced a hanging zombie process.
 *
 * Patch 2 (dnssd): fixes a synchronous endless loop in BufferWrapper.readFQDN
 * (DNS name parsing for mDNS discovery). dnssd 0.4.1 follows compression
 * pointers without any cycle/iteration guard, so a crafted or buggy mDNS packet
 * (observed in the wild as an NSEC record) whose pointer points back to itself
 * or forms a cycle makes seek() jump in circles forever - the root (0) length
 * byte is never reached, the loop spins at 100% CPU on the main thread and
 * freezes the whole adapter (shows "not running", no logs). Confirmed via a
 * live CPU profile: 82% of samples in readFQDN. We bound the loop by
 * remembering every pointer target (break on a repeat) and capping the label
 * count (RFC1035: <=127 labels per name).
 */

'use strict';

const fs = require('fs');
const path = require('path');

// Marker that identifies the *current* (reject-based) patch. Bumped from the previous
// 'avoid endless loop' so an in-place upgrade of an already-(close-only-)patched file
// is detected and re-applied instead of being skipped as "already patched".
const HAP_MARKER = 'reject so the caller fails fast';

// Pristine upstream block (swallows the error -> endless loop).
const OLD_PRISTINE = `                        parser.execute(decryptedData);
                    }
                    catch (e) {
                        // pass
                    }`;

// Previous patch (commit fce17b6): close()+return. This stopped the endless loop but
// left the request promise pending forever (it only ever settles via resolve()), so the
// caller hung until a 120s queue timeout and the adapter stayed alive=true / red in admin
// without self-healing. Detected here so we can upgrade it in place.
const OLD_CLOSE_ONLY = `                        parser.execute(decryptedData);
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

const NEW = `                        parser.execute(decryptedData);
                    }
                    catch (e) {
                        // Decryption failed: the encrypted stream is desynchronised (e.g. nonce/counter
                        // mismatch after an unclean disconnect or a SIGABRT that left the TCP connection
                        // half-open). \`message\` is only advanced on a *successful* decrypt above, so just
                        // swallowing the error makes this while-loop spin forever (100% CPU, blocked event
                        // loop). But merely closing the socket and returning is not enough either: this
                        // request Promise only ever settles via resolve() on a full response, so a bare
                        // close()+return leaves it pending forever - the caller (getCharacteristics /
                        // subscribe) hangs until a 120s queue timeout, the adapter stays alive=true and
                        // shows red in admin without ever self-healing. So: detach this parser, tear the
                        // socket down (-> 'disconnect' -> resubscribe) and reject so the caller fails fast
                        // and the reconnect / reinit path runs immediately. On the event-reader path the
                        // promise is already resolved, so reject() is a harmless no-op there.
                        debug(\`\${this.address}:\${this.port} Decrypting message failed, closing connection to avoid endless loop\`);
                        if (this.socket) {
                            this.socket.removeListener('data', bodyParser);
                        }
                        this.close();
                        return reject(e);
                    }`;

function resolveHapTarget() {
    try {
        const pkgJson = require.resolve('hap-controller/package.json');
        return path.join(path.dirname(pkgJson), 'lib', 'transport', 'ip', 'http-connection.js');
    } catch (err) {
        return null;
    }
}

function patchHapController() {
    const target = resolveHapTarget();
    if (!target || !fs.existsSync(target)) {
        console.warn('[apply-hap-patch] hap-controller http-connection.js not found, skipping patch');
        return;
    }

    let content = fs.readFileSync(target, 'utf8');

    if (content.includes(HAP_MARKER)) {
        console.log('[apply-hap-patch] hap-controller already patched (current version), nothing to do');
        return;
    }

    // Pristine library, or a file still carrying the previous close-only patch (commit
    // fce17b6) which we now upgrade in place to the reject-based version.
    let from = null;
    if (content.includes(OLD_PRISTINE)) {
        from = OLD_PRISTINE;
    } else if (content.includes(OLD_CLOSE_ONLY)) {
        from = OLD_CLOSE_ONLY;
        console.log('[apply-hap-patch] found previous close-only patch, upgrading to reject-based version');
    }

    if (!from) {
        console.warn(
            '[apply-hap-patch] expected code block not found in hap-controller ' +
                '(library version changed?) - patch NOT applied. Please re-check the fix.',
        );
        return;
    }

    content = content.replace(from, NEW);
    fs.writeFileSync(target, content, 'utf8');
    console.log(`[apply-hap-patch] patched ${target}`);
}

// ---------------------------------------------------------------------------
// Patch 2: dnssd BufferWrapper.readFQDN compression-pointer endless loop.
// ---------------------------------------------------------------------------

const DNSSD_MARKER = 'guard against compression-pointer loops';

// Pristine upstream loop (dnssd 0.4.1) - follows pointers without any guard.
const DNSSD_OLD = `      while (this.remaining() >= 0 && (len = this.readUInt8())) {
        // Handle dns compression. If the length is > 192, it means its a pointer.
        // The pointer points to a previous position in the buffer to move to and
        // read from. Pointer (a int16be) = 0xC000 + position
        if (len < 192) {
          labels.push(this.readString(len));
        } else {
          var position = (len << 8) + this.readUInt8() - 0xC000;

          // If a pointer was found, keep track of the farthest position reached
          // (the current position) before following the pointers so we can return
          // to it later after following all the compression pointers
          if (!farthest) farthest = this.position;
          this.seek(position);
        }
      }`;

const DNSSD_NEW = `      // [homekit-controller patch] guard against compression-pointer loops.
      // A crafted/buggy mDNS packet (observed as an NSEC record) can point a
      // label back to itself or form a pointer cycle. Upstream dnssd 0.4.1
      // follows pointers with no visited/iteration check, so seek() jumps in
      // circles forever, the root (0) length byte is never reached and this
      // loop spins at 100% CPU on the main thread - freezing the whole adapter.
      // We bound it: remember every pointer target (break on repeat) and cap the
      // label count (RFC1035: a name has <=127 labels).
      var _seenPtr = {};
      var _labelGuard = 0;
      while (this.remaining() >= 0 && (len = this.readUInt8())) {
        // Handle dns compression. If the length is > 192, it means its a pointer.
        // The pointer points to a previous position in the buffer to move to and
        // read from. Pointer (a int16be) = 0xC000 + position
        if (len < 192) {
          labels.push(this.readString(len));
          if (++_labelGuard > 127) break;
        } else {
          var position = (len << 8) + this.readUInt8() - 0xC000;

          // If a pointer was found, keep track of the farthest position reached
          // (the current position) before following the pointers so we can return
          // to it later after following all the compression pointers
          if (!farthest) farthest = this.position;
          // Stop if this pointer target was already followed (cycle / self-loop).
          if (_seenPtr[position]) break;
          _seenPtr[position] = true;
          this.seek(position);
        }
      }`;

function resolveDnssdTarget() {
    try {
        const pkgJson = require.resolve('dnssd/package.json');
        return path.join(path.dirname(pkgJson), 'lib', 'BufferWrapper.js');
    } catch (err) {
        return null;
    }
}

function patchDnssd() {
    const target = resolveDnssdTarget();
    if (!target || !fs.existsSync(target)) {
        console.warn('[apply-hap-patch] dnssd BufferWrapper.js not found, skipping patch');
        return;
    }

    let content = fs.readFileSync(target, 'utf8');

    if (content.includes(DNSSD_MARKER)) {
        console.log('[apply-hap-patch] dnssd already patched, nothing to do');
        return;
    }

    if (!content.includes(DNSSD_OLD)) {
        console.warn(
            '[apply-hap-patch] expected readFQDN block not found in dnssd ' +
                '(library version changed?) - patch NOT applied. Please re-check the fix.',
        );
        return;
    }

    content = content.replace(DNSSD_OLD, DNSSD_NEW);
    fs.writeFileSync(target, content, 'utf8');
    console.log(`[apply-hap-patch] patched ${target}`);
}

function main() {
    patchHapController();
    patchDnssd();
}

try {
    main();
} catch (err) {
    // Never break the install because of the patcher.
    console.warn(`[apply-hap-patch] failed to apply patch: ${err && err.message}`);
}
