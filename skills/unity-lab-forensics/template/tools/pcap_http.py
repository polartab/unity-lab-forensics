#!/usr/bin/env python3
"""解析 tcpdump 抓到的 pcap（HTTP/1.x + WebSocket），输出 JSONL。

用法:
  pcap_http.py /tmp/unity-lab-example/raw/net/dg10.pcap -o /tmp/unity-lab-example/raw/logs/http.jsonl
  pcap_http.py --selftest

特性: TCP 重组（按 seq 去重/排序）、Content-Length/chunked/close 定界、
      gzip 解压、token/Cookie/Authorization 脱敏、WS 帧解析。
"""
import argparse, base64, gzip, json, struct, sys
from datetime import datetime, timezone

TOKEN_KEYS = ("token", "access_token", "sessionid", "session_id")

def redact_url(u):
    if "?" not in u:
        return u
    base, q = u.split("?", 1)
    out = []
    for kv in q.split("&"):
        k = kv.split("=", 1)[0]
        if k.lower() in TOKEN_KEYS:
            out.append(f"{k}=<redacted>")
        else:
            out.append(kv)
    return base + "?" + "&".join(out)

SENSITIVE_HDR = {"authorization", "cookie", "set-cookie", "x-token", "token", "x-auth-token"}

def redact_headers(h):
    out = {}
    for k, v in h.items():
        lk = k.lower()
        if lk in SENSITIVE_HDR:
            out[k] = "<redacted>"
        elif lk in ("referer", "origin"):
            out[k] = redact_url(v)
        else:
            out[k] = v
    return out

def redact_form(body):
    """脱敏 application/x-www-form-urlencoded body 中的 token 类字段。"""
    if not body or "=" not in body:
        return body
    out = []
    for kv in body.split("&"):
        k = kv.split("=", 1)[0]
        if k.lower() in TOKEN_KEYS:
            out.append(f"{k}=<redacted>")
        else:
            out.append(kv)
    return "&".join(out)

def header_get(h, name):
    for k, v in h.items():
        if k.lower() == name.lower():
            return v
    return ""

class Reader:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        magic = self.d[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            self.e = "<"; self.nano = False
        elif magic == b"\xa1\xb2\xc3\xd4":
            self.e = ">"; self.nano = False
        elif magic == b"\x4d\x3c\xb2\xa1":
            self.e = "<"; self.nano = True
        elif magic == b"\xa1\xb2\x3c\x4d":
            self.e = ">"; self.nano = True
        else:
            raise SystemExit("not a pcap file")
        magic, _, _, _, _, _, self.link = struct.unpack(self.e + "IHHiIII", self.d[:24])
        self.off = 24

    def packets(self):
        d, e = self.d, self.e
        while self.off + 16 <= len(d):
            ts, tus, incl, orig = struct.unpack(e + "IIII", d[self.off:self.off + 16])
            self.off += 16
            pkt = d[self.off:self.off + incl]
            self.off += incl
            t = ts + (tus / 1e9 if self.nano else tus / 1e6)
            yield t, pkt

def ipv4_tcp(pkt, link):
    if link == 1:  # Ethernet
        if len(pkt) < 14:
            return None
        et = struct.unpack(">H", pkt[12:14])[0]
        o = 14
        while et in (0x8100, 0x88A8):
            et = struct.unpack(">H", pkt[o + 2:o + 4])[0]
            o += 4
        if et != 0x0800:
            return None
    elif link == 113:  # Linux SLL
        if len(pkt) < 16 or struct.unpack(">H", pkt[14:16])[0] != 0x0800:
            return None
        o = 16
    else:
        return None
    ip = pkt[o:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0xF) * 4
    proto = ip[9]
    if proto != 6:
        return None
    src = ".".join(map(str, ip[12:16]))
    dst = ".".join(map(str, ip[16:20]))
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None
    sp, dp, seq = struct.unpack(">HHI", tcp[:8])
    doff = (tcp[12] >> 4) * 4
    flags = tcp[13]
    payload = tcp[doff:]
    return src, sp, dst, dp, seq, flags, payload

def streams(path):
    r = Reader(path)
    segs = {}
    times = {}
    for t, pkt in r.packets():
        x = ipv4_tcp(pkt, r.link)
        if not x:
            continue
        src, sp, dst, dp, seq, flags, payload = x
        k = (src, sp, dst, dp)
        segs.setdefault(k, []).append((seq, payload))
        times.setdefault(k, []).append(t)
    out = {}
    for k, items in segs.items():
        items.sort(key=lambda z: z[0])
        base = items[0][0]
        buf = bytearray()
        last_end = None
        for seq, payload in items:
            if not payload:
                continue
            off = seq - base
            if off < 0:
                continue
            if last_end is not None and off < last_end:  # 重传/重叠
                payload = payload[last_end - off:]
                off = last_end
            if off > len(buf):
                buf.extend(b"\x00" * (off - len(buf)))
            buf[off:off + len(payload)] = payload
            last_end = off + len(payload)
        out[k] = (bytes(buf), min(times[k]), max(times[k]))
    return out

def parse_headers(block):
    lines = block.split(b"\r\n")
    start = lines[0].decode("latin-1")
    hdrs = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            hdrs[k.decode("latin-1").strip()] = v.decode("latin-1").strip()
    return start, hdrs

def decode_body(body, hdrs):
    enc = (hdrs.get("Content-Encoding") or "").lower()
    if "gzip" in enc:
        try:
            body = gzip.decompress(body)
        except Exception:
            pass
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return {"base64": base64.b64encode(body).decode()}

def parse_http(buf):
    """返回 [{start, headers, body, end}]，尽力而为。"""
    msgs = []
    i = 0
    while i < len(buf):
        j = buf.find(b"\r\n\r\n", i)
        if j < 0:
            break
        head = buf[i:j]
        try:
            start, hdrs = parse_headers(head)
        except Exception:
            break
        body_start = j + 4
        te = (hdrs.get("Transfer-Encoding") or "").lower()
        cl = hdrs.get("Content-Length")
        if "chunked" in te:
            body, nxt = read_chunked(buf, body_start)
        elif cl and cl.isdigit():
            n = int(cl)
            nxt = min(body_start + n, len(buf))
            body = buf[body_start:nxt]
        else:
            if start.startswith("HTTP/"):
                code = start.split()[1] if len(start.split()) > 1 else ""
                if code.startswith("1") or code in ("204", "304"):
                    nxt = body_start
                else:
                    nxt = len(buf)
            else:
                nxt = body_start
            body = buf[body_start:nxt]
        msgs.append({"start": start, "headers": hdrs, "body": body, "end": nxt})
        if nxt <= i:
            break
        i = nxt
    return msgs

def read_chunked(buf, i):
    out = bytearray()
    while i < len(buf):
        j = buf.find(b"\r\n", i)
        if j < 0:
            break
        try:
            n = int(buf[i:j].split(b";")[0], 16)
        except ValueError:
            break
        i = j + 2
        if n == 0:
            i = buf.find(b"\r\n", i) + 2
            break
        out.extend(buf[i:i + n])
        i += n + 2
    return bytes(out), i

def ws_frames(buf, base_ts, direction, out):
    i = 0
    while i + 2 <= len(buf):
        b0, b1 = buf[i], buf[i + 1]
        op = b0 & 0x0F
        masked = b1 & 0x80
        ln = b1 & 0x7F
        i += 2
        if ln == 126:
            if i + 2 > len(buf):
                break
            ln = struct.unpack(">H", buf[i:i + 2])[0]; i += 2
        elif ln == 127:
            if i + 8 > len(buf):
                break
            ln = struct.unpack(">Q", buf[i:i + 8])[0]; i += 8
        mask = b""
        if masked:
            if i + 4 > len(buf):
                break
            mask = buf[i:i + 4]; i += 4
        if i + ln > len(buf):
            break
        payload = bytearray(buf[i:i + ln]); i += ln
        if masked:
            for k in range(len(payload)):
                payload[k] ^= mask[k % 4]
        opname = {1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}.get(op, str(op))
        try:
            txt = payload.decode("utf-8")
        except UnicodeDecodeError:
            txt = {"base64": base64.b64encode(payload).decode()}
        out.append({"type": "ws", "t": base_ts, "dir": direction, "op": opname, "payload": txt})

def analyze(path, out_path):
    st = streams(path)
    out = []
    upgrades = []          # (client_key, server_key, frames_start_c2s)
    parsed = {}
    for key, (buf, t0, t1) in st.items():
        if not buf:
            continue
        src, sp, dst, dp = key
        client, server = f"{src}:{sp}", f"{dst}:{dp}"
        msgs = parse_http(buf)
        parsed[key] = (buf, t0, msgs)
        for m in msgs:
            start, hdrs, body = m["start"], m["headers"], m["body"]
            if start.startswith(("GET ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "HEAD ", "PATCH ")):
                body_text = decode_body(body, hdrs)
                if "application/x-www-form-urlencoded" in header_get(hdrs, "content-type"):
                    body_text = redact_form(body_text)
                out.append({"type": "http", "t": t0, "client": client, "server": server,
                            "request": {"line": redact_url(start), "headers": redact_headers(hdrs),
                                        "body": body_text}})
            elif start.startswith("HTTP/"):
                out.append({"type": "http", "t": t0, "client": client, "server": server,
                            "response": {"line": start, "headers": redact_headers(hdrs),
                                         "body": decode_body(body, hdrs)}})
                if " 101 " in start:
                    upgrades.append((key, m["end"]))
    # WebSocket 双向帧
    for key, start_off in upgrades:
        src, sp, dst, dp = key
        rev = (dst, dp, src, sp)
        for k, off in ((key, start_off), (rev, None)):
            if k not in parsed:
                continue
            buf, t0, msgs = parsed[k]
            if off is None:
                off = msgs[-1]["end"] if msgs else 0
            direction = f"{k[0]}:{k[1]}->{k[2]}:{k[3]}"
            ws_frames(buf[off:], t0, direction, out)
    out.sort(key=lambda r: r["t"])
    with open(out_path, "w") as f:
        for r in out:
            r["t"] = datetime.fromtimestamp(r["t"], timezone.utc).astimezone().isoformat(timespec="milliseconds")
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"streams={len(st)} messages={len(out)} -> {out_path}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("-o", "--out", default="/tmp/unity-lab-example/raw/logs/http.jsonl")
    a = ap.parse_args()
    if not a.pcap:
        raise SystemExit("usage: pcap_http.py <pcap> -o out.jsonl")
    analyze(a.pcap, a.out)
