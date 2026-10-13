import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { isLoopbackHttpHost, isPrivateHost } from "../src/private-host.ts";
import { allowPrivateHttpProviders, plainHttpHostAllowed } from "../src/knobs.ts";

// #2984: the predicates behind `plainHttpHostAllowed`, pinned here so a later
// edit cannot silently widen what the operator opted into. The gates that call
// them are covered in tests/agent-providers.test.ts and
// tests/external-summary-settings.test.ts.

test("#2984 loopback needs no configuration and keeps its exact spelling set", () => {
    for (const host of ["localhost", "127.0.0.1", "::1", "[::1]", " LocalHost "]) {
        assert.ok(isLoopbackHttpHost(host), host);
        assert.ok(plainHttpHostAllowed(host), `${host} allowed with the switch off`);
    }
    // Neighbours of the literal list, including the range a loopback typo lands
    // in: only the three loopback spellings pass here.
    for (const host of ["127.0.0.2", "localhost.evil", "example.com", "::2", "10.0.0.1", "100.64.0.1", ""]) {
        assert.ok(!isLoopbackHttpHost(host), host);
    }
});

test("#2984 isPrivateHost is the launcher's range set, not a superset", () => {
    for (const host of [
        "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.124.39", "169.254.1.1", "127.0.0.1", "0.0.0.0",
        "::1", "::", "fd00::12", "fe80::1", "[fd00::12]", "::ffff:10.0.0.5", "::ffff:a00:1",
        "gpu.local", "box.lan", "srv.internal",
    ]) {
        assert.ok(isPrivateHost(host), host);
    }
    // Public space stays out, and so does the CGNAT/Tailscale pool: the
    // predicate never called it private, and tests/agent-providers.test.ts
    // asserts `http://100.64.0.1:11434` is refused.
    for (const host of [
        "8.8.8.8", "172.15.255.255", "172.32.0.1", "100.64.0.1", "100.127.255.255", "169.253.0.1",
        "2001:db8::1", "2002:c0a8::1", "::ffff:8.8.8.8", "example.com", "gpu.local.evil", "",
    ]) {
        assert.ok(!isPrivateHost(host), host);
    }
});

test("#2984 the switch resolves env over file and defaults off", () => {
    const prevEnv = process.env.BILI_ALLOW_PRIVATE_HTTP_PROVIDERS;
    const prevFile = process.env.BILI_CONFIG_FILE;
    const dir = mkdtempSync(join(tmpdir(), "bili-private-host-"));
    const file = join(dir, "billion-context.json");
    try {
        delete process.env.BILI_ALLOW_PRIVATE_HTTP_PROVIDERS;
        delete process.env.BILI_CONFIG_FILE;
        assert.equal(allowPrivateHttpProviders(), false, "default off");
        assert.equal(plainHttpHostAllowed("192.168.124.39"), false, "LAN refused while off");

        process.env.BILI_ALLOW_PRIVATE_HTTP_PROVIDERS = "1";
        assert.equal(allowPrivateHttpProviders(), true);
        assert.equal(plainHttpHostAllowed("192.168.124.39"), true);
        assert.equal(plainHttpHostAllowed("::ffff:10.0.0.5"), true, "mapped IPv6 reaches the same predicate");
        assert.equal(plainHttpHostAllowed("100.64.0.1"), false, "CGNAT stays out with the switch on");
        assert.equal(plainHttpHostAllowed("8.8.8.8"), false, "public space is never reachable by this switch");

        process.env.BILI_ALLOW_PRIVATE_HTTP_PROVIDERS = "false";
        assert.equal(allowPrivateHttpProviders(), false, "only 1|true turn it on");

        writeFileSync(file, '{"network":{"allowPrivateHttpProviders":true}}', "utf8");
        delete process.env.BILI_ALLOW_PRIVATE_HTTP_PROVIDERS;
        process.env.BILI_CONFIG_FILE = file;
        assert.equal(allowPrivateHttpProviders(), true, "file layer admits it");
        process.env.BILI_ALLOW_PRIVATE_HTTP_PROVIDERS = "0";
        assert.equal(allowPrivateHttpProviders(), false, "env wins over the file");
    } finally {
        if (prevEnv === undefined) delete process.env.BILI_ALLOW_PRIVATE_HTTP_PROVIDERS;
        else process.env.BILI_ALLOW_PRIVATE_HTTP_PROVIDERS = prevEnv;
        if (prevFile === undefined) delete process.env.BILI_CONFIG_FILE;
        else process.env.BILI_CONFIG_FILE = prevFile;
        rmSync(dir, { recursive: true, force: true });
    }
});
