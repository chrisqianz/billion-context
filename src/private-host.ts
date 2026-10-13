/** Shared host classification for bili's plaintext-HTTP trust rules (#2984).
 *
 *  Four call sites ask the same question — may this upstream be dialled over
 *  plain HTTP? — and each kept its own copy of the loopback literal: the agent
 *  registry intake (`src/agent-providers.ts`), the pi plugin's pre-skip
 *  (`src/agent/pi.ts`) and the two endpoint derivations in
 *  `src/external-summary-settings.ts`. Meanwhile `src/launcher.ts` carried a
 *  second, strictly more complete private-host predicate for codex plugin
 *  mode. This module is the single home for both predicates; the policy that
 *  decides WHEN private hosts join loopback lives in `src/knobs.ts`
 *  (`plainHttpHostAllowed`).
 *
 *  Bracket note: WHATWG `URL.hostname` keeps the brackets around an IPv6
 *  literal (`new URL("http://[::1]:8000/").hostname === "[::1]"`), so both
 *  predicates accept either form and normalize first — the "[::1]" entries the
 *  four lists used to carry are live code, not dead weight.
 *
 *  Deliberately dependency-free: launcher.ts, the proxy and the bundled host
 *  plugins all import this file. */

/** Loopback hosts: plaintext HTTP with no configuration whatsoever. */
const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "::1"];

/** Lowercase + drop the IPv6 brackets `URL.hostname` hands back. */
function normalizeHost(hostname: string): string {
    const host = (hostname ?? "").trim().toLowerCase();
    return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

/** True for the loopback literal a host may always be reached over, whatever
 *  the operator configured. */
export function isLoopbackHttpHost(hostname: string): boolean {
    return LOOPBACK_HOSTS.includes(normalizeHost(hostname));
}

/** True when the host is self-hosted / on-LAN infrastructure: loopback,
 *  RFC1918, link-local, IPv6 ULA, or an mDNS/LAN name (`*.local`/`*.lan`/
 *  `*.internal`). CGNAT (100.64/10, the Tailscale pool) is NOT private here —
 *  it is a shared anycast space, not a link the operator controls.
 *
 *  Extracted verbatim from launcher.ts so the codex plugin-mode decision and
 *  the #2585 intake gates share one predicate. */
export function isPrivateHost(hostname: string): boolean {
    const host = normalizeHost(hostname);
    if (host === "localhost" || host.endsWith(".local") || host.endsWith(".lan") || host.endsWith(".internal")) return true;
    if (host.includes(":")) {
        if (host === "::1" || host === "::") return true;
        const first = host.split(":")[0] ?? "";
        if (/^f[cd]/.test(first)) return true;
        if (/^fe[89ab]/.test(first)) return true;
        const dotted = /::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(host);
        if (dotted && isPrivateIPv4(dotted[1]!)) return true;
        const hex = /::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
        if (hex) {
            const w1 = Number.parseInt(hex[1]!, 16);
            const w2 = Number.parseInt(hex[2]!, 16);
            if (isPrivateIPv4(`${w1 >> 8}.${w1 & 0xff}.${w2 >> 8}.${w2 & 0xff}`)) return true;
        }
        return false;
    }
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return isPrivateIPv4(host);
    return false;
}

/** RFC1918 + loopback + link-local IPv4 (and the 0/8 "this host" block, which
 *  nothing routes either — kept from the launcher predicate as-is). */
function isPrivateIPv4(host: string): boolean {
    const a = Number.parseInt(host.split(".")[0] ?? "", 10);
    const b = Number.parseInt(host.split(".")[1] ?? "", 10);
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    return false;
}
