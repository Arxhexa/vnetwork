import { connect } from 'cloudflare:sockets';

const DEFAULT_UUID = '';
const DEFAULT_PROXYIP = '';

export default {
    async fetch(request, env) {
        if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
            return new Response('Expected WebSocket', { status: 426 });
        }

        const userID = env.UUID || DEFAULT_UUID;
        const proxyIP = env.PROXYIP || DEFAULT_PROXYIP;
        const earlyDataHeader = request.headers.get('sec-websocket-protocol');

        const [client, server] = Object.values(new WebSocketPair());
        server.accept();

        handleSession(server, earlyDataHeader, userID, proxyIP).catch(err => {
            try { server.close(1011, err.message); } catch (_) {}
        });

        const responseHeaders = new Headers();
        if (earlyDataHeader) {
            responseHeaders.set('Sec-WebSocket-Protocol', earlyDataHeader);
        }

        return new Response(null, {
            status: 101,
            webSocket: client,
            headers: responseHeaders
        });
    }
};

async function handleSession(ws, earlyDataHeader, userID, proxyIP) {
    ws.binaryType = 'arraybuffer';
    const expectedUUID = parseUUID(userID);
    
    let earlyData = null;
    if (earlyDataHeader) {
        try { earlyData = base64ToArrayBuffer(earlyDataHeader); } catch (_) {}
    }

    const wsStream = makeWebSocketStream(ws, earlyData);
    const reader = wsStream.readable.getReader();
    let remoteSocket = null;

    // Buffer accumulator to resolve stream fragmentation
    let buffer = new Uint8Array(0);
    async function readExact(len) {
        while (buffer.byteLength < len) {
            const { value, done } = await reader.read();
            if (done) return false;
            const next = new Uint8Array(buffer.byteLength + value.byteLength);
            next.set(buffer, 0);
            next.set(value, buffer.byteLength);
            buffer = next;
        }
        return true;
    }

    try {
        // 1. Minimum VLESS header prefix: Ver (1) + UUID (16) + AddonLen (1) = 18 bytes
        if (!(await readExact(18))) throw new Error('Handshake too short');

        const clientUUID = buffer.subarray(1, 17);
        if (!timingSafeEqual(clientUUID, expectedUUID)) {
            throw new Error('Unauthorized');
        }

        const addonLen = buffer[17];
        let offset = 18 + addonLen;

        // Command (1) + Port (2) + AddressType (1) = 4 bytes
        if (!(await readExact(offset + 4))) throw new Error('Malformed header');

        const command = buffer[offset++]; // 1: TCP, 2: UDP
        const port = (buffer[offset++] << 8) | buffer[offset++];
        const addressType = buffer[offset++];

        let address = '';
        if (addressType === 1) { // IPv4
            if (!(await readExact(offset + 4))) throw new Error('Malformed IPv4');
            address = buffer.subarray(offset, offset + 4).join('.');
            offset += 4;
        } else if (addressType === 2) { // Domain
            if (!(await readExact(offset + 1))) throw new Error('Malformed domain');
            const domainLength = buffer[offset++];
            if (!(await readExact(offset + domainLength))) throw new Error('Malformed domain payload');
            address = new TextDecoder().decode(buffer.subarray(offset, offset + domainLength));
            offset += domainLength;
        } else if (addressType === 3) { // IPv6
            if (!(await readExact(offset + 16))) throw new Error('Malformed IPv6');
            const view = new DataView(buffer.buffer, buffer.byteOffset + offset, 16);
            const ipv6 = [];
            for (let i = 0; i < 8; i++) ipv6.push(view.getUint16(i * 2).toString(16));
            address = ipv6.join(':');
            offset += 16;
        } else {
            throw new Error(`Invalid address type: ${addressType}`);
        }

        const rawPayload = buffer.subarray(offset);

        if (command === 1) { // TCP
            remoteSocket = await establishTCP(address, port, proxyIP);
            ws.send(new Uint8Array([0, 0])); // VLESS response

            if (rawPayload.byteLength > 0) {
                const writer = remoteSocket.writable.getWriter();
                await writer.write(rawPayload);
                writer.releaseLock();
            }

            reader.releaseLock();

            // Symmetrical data relay with optimized low-overhead backpressure
            let packetCount = 0;

            await Promise.race([
                wsStream.readable.pipeTo(remoteSocket.writable),
                remoteSocket.readable.pipeTo(new WritableStream({
                    // Synchronous write path: Zero Promise allocations during normal streaming
                    write(chunk) {
                        if (ws.readyState !== WebSocket.OPEN) return;
                        ws.send(chunk);

                        // Sample C++ getter only every 32 chunks; pause at 16MB watermark
                        if ((++packetCount & 31) === 0 && ws.bufferedAmount > 16 * 1024 * 1024) {
                            return new Promise(resolve => {
                                const interval = setInterval(() => {
                                    if (ws.readyState !== WebSocket.OPEN || ws.bufferedAmount <= 4 * 1024 * 1024) {
                                        clearInterval(interval);
                                        resolve();
                                    }
                                }, 5);
                            });
                        }
                    }
                }))
            ]).catch(() => {});
            return;
        }

        if (command === 2 && port === 53) { // UDP DNS
            ws.send(new Uint8Array([0, 0]));
            reader.releaseLock();
            await handleUDPDNS(ws, rawPayload, wsStream.readable);
            return;
        }

        throw new Error(`Unsupported command: ${command}`);

    } finally {
        try { reader.releaseLock(); } catch (_) {}
        if (remoteSocket) {
            try { remoteSocket.close(); } catch (_) {}
        }
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
            // Drain remaining buffered data before closing to prevent truncation
            while (ws.bufferedAmount > 0) {
                if (ws.readyState !== WebSocket.OPEN) break;
                await new Promise(r => setTimeout(r, 5));
            }
            try { ws.close(); } catch (_) {}
        }
    }
}

async function establishTCP(address, port, proxyIPConfig) {
    if (!proxyIPConfig) {
        return connect({ hostname: address, port });
    }

    let directSocket = null;

    try {
        directSocket = connect({ hostname: address, port });
        await directSocket.opened;
        return directSocket;
    } catch (_) {
        if (directSocket) {
            try { directSocket.close(); } catch (_) {}
        }

        // Fast fallback to selected ProxyIP (Cloudflare-blocked destinations reject in ~0-2ms)
        const proxies = proxyIPConfig.split(',').map(s => s.trim()).filter(Boolean);
        const selected = proxies[Math.floor(Math.random() * proxies.length)];
        const { host, port: pPort } = parseHostAndPort(selected, port);

        return connect({ hostname: host, port: pPort });
    }
}

function parseHostAndPort(entry, defaultPort) {
    let host = entry;
    let port = defaultPort;

    if (entry.startsWith('[')) { // IPv6 literal: [2001:db8::1]:443
        const closeIdx = entry.indexOf(']');
        if (closeIdx !== -1) {
            host = entry.substring(1, closeIdx);
            const tail = entry.substring(closeIdx + 1);
            if (tail.startsWith(':')) port = parseInt(tail.slice(1), 10);
        }
    } else { // IPv4 or Domain: 1.1.1.1:443
        const lastColon = entry.lastIndexOf(':');
        if (lastColon !== -1) {
            host = entry.substring(0, lastColon);
            port = parseInt(entry.substring(lastColon + 1), 10);
        }
    }
    return { host, port: isNaN(port) ? defaultPort : port };
}

function makeWebSocketStream(ws, earlyData) {
    return {
        readable: new ReadableStream({
            start(controller) {
                if (earlyData) controller.enqueue(new Uint8Array(earlyData));
                ws.addEventListener('message', e => controller.enqueue(new Uint8Array(e.data)));
                ws.addEventListener('close', () => controller.close());
                ws.addEventListener('error', err => controller.error(err));
            }
        })
    };
}

async function handleUDPDNS(ws, initialPayload, readable) {
    async function resolve(query) {
        try {
            const res = await fetch('https://1.1.1.1/dns-query', {
                method: 'POST',
                headers: { 'content-type': 'application/dns-message' },
                body: query
            });
            if (!res.ok) return;
            const resp = await res.arrayBuffer();
            const out = new Uint8Array(2 + resp.byteLength);
            out[0] = (resp.byteLength >> 8) & 0xff;
            out[1] = resp.byteLength & 0xff;
            out.set(new Uint8Array(resp), 2);
            if (ws.readyState === WebSocket.OPEN) ws.send(out);
        } catch (_) {}
    }

    const processPacket = (packet) => {
        let offset = 0;
        while (offset + 2 < packet.byteLength) {
            const len = (packet[offset] << 8) | packet[offset + 1];
            offset += 2;
            if (offset + len <= packet.byteLength) {
                resolve(packet.subarray(offset, offset + len));
            }
            offset += len;
        }
    };

    if (initialPayload.byteLength > 0) processPacket(initialPayload);

    await readable.pipeTo(new WritableStream({
        write(chunk) {
            processPacket(chunk);
        }
    })).catch(() => {});
}

function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}

function parseUUID(uuid) {
    const clean = uuid.replace(/-/g, '');
    const out = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        out[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
}

function base64ToArrayBuffer(base64Url) {
    let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    if (pad) base64 += '='.repeat(4 - pad);
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}
