#!/usr/bin/env python3
# TEST FIXTURE for hack/rootd-gate.sh, run inside the test VM (often as a broker or audit uid through runuser): small
# socket clients that stand in for brokers and auditd until those areas merge. Never shipped.
#   rg.py req SOCK JSON                      one request line; prints the reply line, or "closed" if rootd hung up
#                                            (EOF or reset); 30 s of silence prints "timeout" and exits 1
#   rg.py connect IP PORT [SECS]             TCP connect; exit 0 if it connects within SECS (default 3)
#   rg.py udpdns IP                          a DNS query for example.com to IP:53; exit 0 if any reply comes back
#   rg.py flow IP PORT HOST LOG SECS         one TCP connection, an HTTP/1.1 keep-alive HEAD every 2 s for SECS; each
#                                            line in LOG is "<unix time> ok|cut <detail>"; exit 0 if never cut
#   rg.py sendfd SOCK                        sends a request with an SCM_RIGHTS fd; exit 0 if rootd closed without a reply
#                                            (not if it went silent)
#   rg.py chain SEG PREV N [close|torn|broken] appends N records in auditd's record format to SEG (O_APPEND): an open
#                                            chained to PREV (zeros if "") when SEG is empty, then intents; close adds
#                                            close{seq, last_hash}; torn first writes a partial line, "\n" and its
#                                            torn{offset, len, sha256}; broken adds a record whose prev is wrong. Prints
#                                            the hash of the last record.
import array, hashlib, json, os, socket, sys, time

TIMEOUT = object()  # rootd neither answered nor closed: not a refusal

def req(path, obj, fds=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(path)
    data = (json.dumps(obj) if isinstance(obj, dict) else obj).encode() + b"\n"
    if fds:
        s.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds).tobytes())])
    else:
        s.sendall(data)
    buf = b""
    while not buf.endswith(b"\n"):
        try:
            b = s.recv(65536)
        except ConnectionResetError:
            b = b""
        except socket.timeout:
            return TIMEOUT
        if not b:
            return None
        buf += b
    return buf.decode().strip()

def h(line):
    return hashlib.sha256(line).hexdigest()

def last_record(path):
    with open(path, "rb") as f:
        lines = [l for l in f.read().split(b"\n") if l]
    for l in reversed(lines):
        try:
            r = json.loads(l)
            return r, h(l)
        except ValueError:
            continue
    return None, None

def chain(seg, prev, n, mode):
    r, lh = last_record(seg)
    seq = (r["seq"] + 1) if r else 1
    if r:
        prev = lh
    elif not prev:
        prev = "0" * 64
    fd = os.open(seg, os.O_WRONLY | os.O_APPEND)
    def put(typ, body, link=None):
        nonlocal prev, seq
        obj = {"seq": seq, "prev": link if link is not None else prev, "type": typ, "producer": "auditd", "body": body}
        line = json.dumps(obj, separators=(",", ":")).encode()
        os.write(fd, line + b"\n")
        prev, seq = h(line), seq + 1
    for i in range(n):
        put("open" if r is None and i == 0 else "intent", {} if r is None and i == 0 else {"n": i})
    if mode == "torn":
        off = os.fstat(fd).st_size
        junk = b'{"seq":%d,"partial' % seq + b"\n"  # the crash's bytes, plus the newline auditd's restart appends
        os.write(fd, junk)
        put("torn", {"offset": off, "len": len(junk), "sha256": hashlib.sha256(junk).hexdigest()})
    if mode == "broken":
        put("intent", {"n": "x"}, link="0" * 64)  # prev is not the hash of the line before it
    if mode in ("close", "torn", "broken"):
        put("close", {"seq": seq - 1, "last_hash": prev})
    os.fsync(fd)
    os.close(fd)
    print(prev)

def flow(ip, port, host, log, secs):
    end = time.time() + secs
    out = open(log, "a", buffering=1)
    try:
        s = socket.create_connection((ip, port), timeout=5)
    except OSError as e:
        out.write("%d cut connect %s\n" % (time.time(), e))
        return 1
    s.settimeout(8)
    n = 0
    while time.time() < end:
        try:
            s.sendall(("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n" % host).encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                b = s.recv(4096)
                if not b:
                    raise OSError("server closed")
                resp += b
            n += 1
            out.write("%d ok %d %s\n" % (time.time(), n, resp.split(b"\r\n")[0].decode(errors="replace")))
        except OSError as e:
            out.write("%d cut %s\n" % (time.time(), e))
            return 1
        time.sleep(2)
    return 0

def main(a):
    if a[0] == "req":
        r = req(a[1], a[2])
        if r is TIMEOUT:
            print("timeout")
            return 1
        print(r if r is not None else "closed")
    elif a[0] == "connect":
        try:
            socket.create_connection((a[1], int(a[2])), timeout=float(a[3]) if len(a) > 3 else 3).close()
        except OSError as e:
            print(e)
            return 1
    elif a[0] == "udpdns":
        q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(q, (a[1], 53))
            s.recv(512)
        except OSError as e:
            print(e)
            return 1
    elif a[0] == "flow":
        return flow(a[1], int(a[2]), a[3], a[4], int(a[5]))
    elif a[0] == "sendfd":
        r = req(a[1], {"op": "egress.list"}, fds=[0])
        print("timeout" if r is TIMEOUT else r if r is not None else "closed")
        return 0 if r is None else 1
    elif a[0] == "chain":
        chain(a[1], a[2], int(a[3]), a[4] if len(a) > 4 else "")
    else:
        return 2
    return 0

sys.exit(main(sys.argv[1:]))
