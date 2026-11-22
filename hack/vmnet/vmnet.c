// vmnet: the test VM's network. It is QEMU's user network (libslirp, the same 10.0.2.0/24 and fec0::/64 layout), with
// one change: the guest can't reach the host's loopback. QEMU's own -netdev user can't set libslirp's
// disable_host_loopback, and restrict=on would also cut the internet that the install and the gates need.
//   vmnet SSH_PORT FWD_PORT... -- QEMU ARGS...
//     forwards 127.0.0.1:SSH_PORT to the guest's port 22, and each 10.0.2.2:FWD_PORT in the guest to 127.0.0.1:FWD_PORT
//     on the host. Every other port on 10.0.2.2 and fec0::2 is refused. It then execs QEMU, which must take the
//     network as `-netdev stream,id=ID,addr.type=fd,addr.str=3`. A child process runs the network until QEMU exits.
//   vmnet relay PORT
//     internal: libslirp runs this for each guest connection to a FWD_PORT, with the connection on stdin and stdout.
// Build: cc -O2 -Wall -o vmnet vmnet.c $(pkg-config --cflags --libs slirp) (hack/vm.sh does it).
#include <errno.h>
#include <glib.h>
#include <libslirp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static void die(const char *m) { fprintf(stderr, "vmnet: %s: %s\n", m, strerror(errno)); exit(1); }

static int port(const char *s) {
  char *e;
  long p = strtol(s, &e, 10);
  if (*s == '\0' || *e != '\0' || p < 1 || p > 65535) { fprintf(stderr, "vmnet: bad port %s\n", s); exit(2); }
  return (int)p;
}

static int write_all(int fd, const void *b, size_t n) {
  for (const char *p = b; n > 0;) {
    ssize_t w = write(fd, p, n);
    if (w < 0 && errno == EINTR) continue;
    if (w <= 0) return -1;
    p += w, n -= (size_t)w;
  }
  return 0;
}

// relay: stdin/stdout (one socket) <-> 127.0.0.1:PORT, each direction until EOF
static int relay(int p) {
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(p), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0 || connect(s, (struct sockaddr *)&a, sizeof a) < 0) return 1;
  struct pollfd f[2] = {{.fd = 0, .events = POLLIN}, {.fd = s, .events = POLLIN}};
  int to[2] = {s, 1};
  char b[65536];
  while (f[0].fd >= 0 || f[1].fd >= 0) {
    if (poll(f, 2, -1) < 0) { if (errno == EINTR) continue; return 1; }
    for (int i = 0; i < 2; i++) {
      if (f[i].fd < 0 || !f[i].revents) continue;
      ssize_t n = read(f[i].fd, b, sizeof b);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) { shutdown(to[i], SHUT_WR); f[i].fd = -1; continue; }
      if (write_all(to[i], b, (size_t)n) < 0) return 1;
    }
  }
  return 0;
}

static int qfd; // QEMU's end: frames as a 4-byte big-endian length, then the Ethernet frame

typedef struct timer { SlirpTimerCb cb; void *arg; int64_t at; struct timer *next; } timer; // at: ms, -1 = off
static timer *timers;

static int64_t now_ns(void *o) {
  (void)o;
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
static slirp_ssize_t send_packet(const void *b, size_t n, void *o) {
  (void)o;
  uint32_t h = htonl((uint32_t)n);
  struct iovec v[2] = {{&h, 4}, {(void *)b, n}};
  // writev may write part of a frame; a partial frame would desync the stream, so finish it
  ssize_t w = writev(qfd, v, 2);
  if (w < 0) w = 0;
  if ((size_t)w < 4 && write_all(qfd, (char *)&h + w, 4 - (size_t)w) < 0) exit(0);
  size_t done = (size_t)w < 4 ? 0 : (size_t)w - 4;
  if (write_all(qfd, (const char *)b + done, n - done) < 0) exit(0); // QEMU is gone
  return (slirp_ssize_t)n;
}
static void guest_error(const char *m, void *o) { (void)o; fprintf(stderr, "vmnet: guest error: %s\n", m); }
static void *timer_new(SlirpTimerCb cb, void *arg, void *o) {
  (void)o;
  timer *t = g_new0(timer, 1);
  *t = (timer){cb, arg, -1, timers};
  return timers = t;
}
static void timer_free(void *x, void *o) {
  (void)o;
  for (timer **p = &timers; *p; p = &(*p)->next)
    if (*p == x) { *p = ((timer *)x)->next; g_free(x); return; }
}
static void timer_mod(void *x, int64_t at, void *o) { (void)o; ((timer *)x)->at = at; }
static void nop_socket(slirp_os_socket s, void *o) { (void)s, (void)o; }
static void nop(void *o) { (void)o; }

static struct pollfd *pfd;
static int npfd, cap;
static int add_poll(slirp_os_socket fd, int ev, void *o) {
  (void)o;
  if (npfd == cap) pfd = g_renew(struct pollfd, pfd, cap = cap ? 2 * cap : 64);
  pfd[npfd] = (struct pollfd){.fd = fd, .events = (ev & SLIRP_POLL_IN ? POLLIN : 0) | (ev & SLIRP_POLL_OUT ? POLLOUT : 0) |
                                                  (ev & SLIRP_POLL_PRI ? POLLPRI : 0)};
  return npfd++;
}
static int get_revents(int i, void *o) {
  (void)o;
  short r = pfd[i].revents;
  return (r & POLLIN ? SLIRP_POLL_IN : 0) | (r & POLLOUT ? SLIRP_POLL_OUT : 0) | (r & POLLPRI ? SLIRP_POLL_PRI : 0) |
         (r & POLLERR ? SLIRP_POLL_ERR : 0) | (r & POLLHUP ? SLIRP_POLL_HUP : 0);
}

static void run(Slirp *s) {
  static char b[2 * 70000];
  size_t have = 0;
  for (;;) {
    npfd = 0;
    add_poll(qfd, SLIRP_POLL_IN, NULL);
    uint32_t tmo = UINT32_MAX;
    slirp_pollfds_fill_socket(s, &tmo, add_poll, NULL);
    int64_t ms = now_ns(NULL) / 1000000;
    for (timer *t = timers; t; t = t->next)
      if (t->at >= 0) tmo = t->at <= ms ? 0 : (uint32_t)MIN((int64_t)tmo, t->at - ms);
    int r = poll(pfd, (nfds_t)npfd, tmo == UINT32_MAX ? -1 : (int)MIN(tmo, 60000));
    if (r < 0 && errno != EINTR) die("poll");
    slirp_pollfds_poll(s, r < 0, get_revents, NULL);
    if (r > 0 && pfd[0].revents) {
      ssize_t n = read(qfd, b + have, sizeof b - have);
      if (n <= 0 && !(n < 0 && errno == EINTR)) exit(0); // QEMU exited
      have += n > 0 ? (size_t)n : 0;
      size_t off = 0;
      while (have - off >= 4) {
        uint32_t len;
        memcpy(&len, b + off, 4);
        len = ntohl(len);
        if (len > sizeof b - 4) { fprintf(stderr, "vmnet: frame of %u bytes\n", len); exit(1); }
        if (have - off - 4 < len) break;
        slirp_input(s, (const uint8_t *)b + off + 4, (int)len);
        off += 4 + len;
      }
      memmove(b, b + off, have - off);
      have -= off;
    }
    ms = now_ns(NULL) / 1000000;
    for (timer *t = timers; t; t = t->next)
      if (t->at >= 0 && t->at <= ms) { t->at = -1; t->cb(t->arg); }
  }
}

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "relay") == 0) return relay(port(argv[2]));
  int sep = 1;
  while (sep < argc && strcmp(argv[sep], "--") != 0) sep++;
  if (sep < 2 || sep + 1 >= argc) { fprintf(stderr, "usage: vmnet SSH_PORT FWD_PORT... -- QEMU ARGS...\n"); return 2; }

  SlirpConfig c = {.version = 6, .in_enabled = true, .in6_enabled = true, .vprefix_len = 64, .disable_host_loopback = true};
  inet_pton(AF_INET, "10.0.2.0", &c.vnetwork);
  inet_pton(AF_INET, "255.255.255.0", &c.vnetmask);
  inet_pton(AF_INET, "10.0.2.2", &c.vhost);
  inet_pton(AF_INET, "10.0.2.15", &c.vdhcp_start);
  inet_pton(AF_INET, "10.0.2.3", &c.vnameserver);
  inet_pton(AF_INET6, "fec0::", &c.vprefix_addr6);
  inet_pton(AF_INET6, "fec0::2", &c.vhost6);
  inet_pton(AF_INET6, "fec0::3", &c.vnameserver6);
  static const SlirpCb cb = {.send_packet = send_packet, .guest_error = guest_error, .clock_get_ns = now_ns,
                             .timer_new = timer_new, .timer_free = timer_free, .timer_mod = timer_mod, .notify = nop,
                             .register_poll_socket = nop_socket, .unregister_poll_socket = nop_socket};
  Slirp *s = slirp_new(&c, &cb, NULL);
  if (!s) { fprintf(stderr, "vmnet: slirp_new failed\n"); return 1; }
  struct in_addr lo = {htonl(INADDR_LOOPBACK)}, any = {0}, host = c.vhost;
  if (slirp_add_hostfwd(s, 0, lo, port(argv[1]), any, 22) < 0) die("forward 127.0.0.1:SSH_PORT (port in use?)");
  char *self = g_shell_quote(argv[0]);
  for (int i = 2; i < sep; i++) {
    char *cmd = g_strdup_printf("%s relay %d", self, port(argv[i]));
    if (slirp_add_exec(s, cmd, &host, port(argv[i])) < 0) { fprintf(stderr, "vmnet: forward %s twice\n", argv[i]); return 2; }
    g_free(cmd);
  }

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) die("socketpair");
  switch (fork()) {
  case -1: die("fork");
  case 0:
    close(sv[1]);
    qfd = sv[0];
    signal(SIGPIPE, SIG_IGN); // a closed host socket must fail the write, not kill the network
    run(s);
  }
  // QEMU gets fd 3 only: the hostfwd listener and the child's end stay out of it
  if (dup2(sv[1], 3) < 0) die("dup2");
  for (int fd = 4; fd < 1024; fd++) close(fd);
  execvp(argv[sep + 1], argv + sep + 1);
  die(argv[sep + 1]);
}
