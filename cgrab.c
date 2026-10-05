/*
 * cgrab - SCANGRAB grab client (TCP)
 *
 * Usage: ./cgrab FILE HOST PORT AUTH
 *
 * Protocol (see project description):
 *   C -> GS : INFO FILE AUTH
 *   GS -> C : INFO-RESP STATUS FILE SIZE MD5      (STATUS == OK)
 *             INFO-RESP STATUS FILE               (anything else)
 *   C -> GS : GRAB FILE AUTH
 *   GS -> C : GRAB-RESP OK FILE <raw binary bytes>
 *             GRAB-RESP STATUS <explanation>      (anything else)
 *
 * The file is saved to ./scans/FILE (created if needed, overwritten if it
 * exists). The download is verified against the size and MD5 from INFO.
 *
 * Exit status: 0 on success, 1 on any failure.
 *
 * Env var CGRAB_NEWLINE=1 appends "\n" to each command sent (off by default,
 * since the spec shows no terminator).
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <math.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define SCANS_DIR "scans"
#define RECV_TIMEOUT_SEC 30
#define CHUNK 65536
#define PROGRESS_STEP (10ULL * 1024 * 1024)

// Minimal MD5 (RFC 1321) ----------------------------------------------------------

typedef struct {
    uint32_t a, b, c, d;
    uint64_t len;
    unsigned char buf[64];
    size_t buflen;
} md5_ctx;

static const int MD5_S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
static uint32_t MD5_K[64];

static uint32_t rol32(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static void md5_init(md5_ctx *c) {
    for (int i = 0; i < 64; i++)
        MD5_K[i] = (uint32_t)(fabs(sin((double)(i + 1))) * 4294967296.0);
    c->a = 0x67452301u;
    c->b = 0xefcdab89u;
    c->c = 0x98badcfeu;
    c->d = 0x10325476u;
    c->len = 0;
    c->buflen = 0;
}

static void md5_block(md5_ctx *c, const unsigned char *p) {
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = (uint32_t)p[i * 4] | ((uint32_t)p[i * 4 + 1] << 8) |
               ((uint32_t)p[i * 4 + 2] << 16) | ((uint32_t)p[i * 4 + 3] << 24);
    uint32_t A = c->a, B = c->b, C = c->c, D = c->d;
    for (int i = 0; i < 64; i++) {
        uint32_t F;
        int g;
        if (i < 16)      { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D;          g = (3 * i + 5) % 16; }
        else             { F = C ^ (B | ~D);       g = (7 * i) % 16; }
        F = F + A + MD5_K[i] + M[g];
        A = D;
        D = C;
        C = B;
        B = B + rol32(F, MD5_S[i]);
    }
    c->a += A;
    c->b += B;
    c->c += C;
    c->d += D;
}

static void md5_update(md5_ctx *c, const unsigned char *data, size_t n) {
    c->len += n;
    while (n > 0) {
        size_t take = 64 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, data, take);
        c->buflen += take;
        data += take;
        n -= take;
        if (c->buflen == 64) {
            md5_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void md5_final_hex(md5_ctx *c, char hex[33]) {
    uint64_t bits = c->len * 8;
    unsigned char pad = 0x80, zero = 0, lb[8];
    md5_update(c, &pad, 1);
    while (c->buflen != 56) md5_update(c, &zero, 1);
    for (int i = 0; i < 8; i++) lb[i] = (unsigned char)((bits >> (8 * i)) & 0xff);
    md5_update(c, lb, 8);
    uint32_t w[4] = {c->a, c->b, c->c, c->d};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            sprintf(hex + (i * 4 + j) * 2, "%02x", (unsigned)((w[i] >> (8 * j)) & 0xff));
    hex[32] = '\0';
}


// Networking helpers ----------------------------------------------------------------------------

static int connect_to(const char *host, const char *port) {
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "ERROR: cannot resolve %s:%s (%s)\n", host, port, gai_strerror(rc));
        return -1;
    }
    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "ERROR: cannot connect to %s:%s (%s)\n", host, port, strerror(errno));
        return -1;
    }
    struct timeval tv = {RECV_TIMEOUT_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return fd;
}

static int send_all(int fd, const char *buf, size_t n) {
    while (n > 0) {
        ssize_t s = send(fd, buf, n, MSG_NOSIGNAL);
        if (s < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "ERROR: send failed: %s\n", strerror(errno));
            return -1;
        }
        buf += s;
        n -= (size_t)s;
    }
    return 0;
}

static int send_command(int fd, const char *verb, const char *file, const char *auth) {
    char cmd[2048];
    const char *term = getenv("CGRAB_NEWLINE") ? "\n" : "";
    int n = snprintf(cmd, sizeof cmd, "%s %s %s%s", verb, file, auth, term);
    if (n < 0 || (size_t)n >= sizeof cmd) {
        fprintf(stderr, "ERROR: command too long\n");
        return -1;
    }
    return send_all(fd, cmd, (size_t)n);
}

// Read one byte; returns 1 ok, 0 EOF, -1 error.
static int recv_byte(int fd, char *c) {
    for (;;) {
        ssize_t n = recv(fd, c, 1, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                fprintf(stderr, "ERROR: timed out waiting for server\n");
            else
                fprintf(stderr, "ERROR: recv failed: %s\n", strerror(errno));
            return -1;
        }
        return (int)n;
    }
}

// Read a token terminated by ' ' or '\n'. Returns the terminator, or -1.
static int read_token(int fd, char *out, size_t max) {
    size_t i = 0;
    for (;;) {
        char c;
        int r = recv_byte(fd, &c);
        if (r < 0) return -1;
        if (r == 0) {
            out[i] = '\0';
            return i > 0 ? ' ' : -1;
        }
        if (c == ' ' || c == '\n') {
            out[i] = '\0';
            return c;
        }
        if (c == '\r') continue;
        if (i + 1 >= max) {
            fprintf(stderr, "ERROR: protocol token too long\n");
            return -1;
        }
        out[i++] = c;
    }
}

// Grab whatever else is immediately available (used for error text).
static void drain_message(int fd, char *out, size_t max) {
    size_t len = 0;
    struct pollfd p = {fd, POLLIN, 0};
    out[0] = '\0';
    while (len + 1 < max && poll(&p, 1, 500) > 0) {
        ssize_t n = recv(fd, out + len, max - 1 - len, 0);
        if (n <= 0) break;
        len += (size_t)n;
    }
    out[len] = '\0';
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r')) out[--len] = '\0';
}


// INFO ---------------------------------------------------------------

static int tokenize(char *s, char *tok[], int max) {
    int n = 0;
    for (char *p = strtok(s, " \r\n"); p && n < max; p = strtok(NULL, " \r\n")) tok[n++] = p;
    return n;
}

static int do_info(const char *host, const char *port, const char *file, const char *auth,
                   unsigned long long *size, char md5[33]) {
    int fd = connect_to(host, port);
    if (fd < 0) return -1;
    printf("[INFO] requesting info for '%s' from %s:%s\n", file, host, port);
    if (send_command(fd, "INFO", file, auth) < 0) { close(fd); return -1; }

    char buf[2048];
    size_t len = 0;
    for (;;) {
        ssize_t n = recv(fd, buf + len, sizeof buf - 1 - len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "ERROR: no INFO-RESP received (%s)\n",
                    (errno == EAGAIN || errno == EWOULDBLOCK) ? "timed out" : strerror(errno));
            close(fd);
            return -1;
        }
        if (n == 0) break;
        len += (size_t)n;
        buf[len] = '\0';
        if (memchr(buf, '\n', len)) break;

        // Decide whether we already have a full response.
        char copy[2048];
        char *tok[6];
        memcpy(copy, buf, len + 1);
        int nt = tokenize(copy, tok, 6);
        if (nt >= 3 && strcmp(tok[1], "OK") != 0) break;  //error reply
        if (nt >= 5 && strlen(tok[4]) >= 32) break;       //full OK reply
        if (len >= sizeof buf - 1) break;
    }
    close(fd);
    buf[len] = '\0';
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) buf[--len] = '\0';

    if (len == 0) {
        fprintf(stderr, "ERROR: empty INFO-RESP from server\n");
        return -1;
    }
    char line[2048];
    memcpy(line, buf, len + 1);
    char *tok[6];
    int nt = tokenize(buf, tok, 6);
    if (nt < 3 || strcmp(tok[0], "INFO-RESP") != 0) {
        fprintf(stderr, "ERROR: unexpected INFO reply: %s\n", line);
        return -1;
    }
    if (strcmp(tok[1], "OK") != 0) {
        fprintf(stderr, "ERROR: server refused INFO for '%s': %s\n", file, line);
        return -1;
    }
    if (nt < 5) {
        fprintf(stderr, "ERROR: malformed INFO-RESP: %s\n", line);
        return -1;
    }
    char *end = NULL;
    errno = 0;
    *size = strtoull(tok[3], &end, 10);
    if (errno != 0 || end == tok[3] || *end != '\0') {
        fprintf(stderr, "ERROR: bad size in INFO-RESP: %s\n", tok[3]);
        return -1;
    }
    if (strlen(tok[4]) != 32) {
        fprintf(stderr, "ERROR: bad MD5 in INFO-RESP: %s\n", tok[4]);
        return -1;
    }
    for (int i = 0; i < 32; i++) {
        char ch = tok[4][i];
        md5[i] = (ch >= 'A' && ch <= 'F') ? (char)(ch - 'A' + 'a') : ch;
    }
    md5[32] = '\0';
    printf("[INFO] OK: size=%llu bytes, md5=%s\n", *size, md5);
    return 0;
}


// GRAB -------------------------------------------------------------------

static int ensure_scans_dir(void) {
    struct stat st;
    if (stat(SCANS_DIR, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        fprintf(stderr, "ERROR: '%s' exists but is not a directory\n", SCANS_DIR);
        return -1;
    }
    if (mkdir(SCANS_DIR, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "ERROR: cannot create '%s': %s\n", SCANS_DIR, strerror(errno));
        return -1;
    }
    printf("[GRAB] created directory '%s'\n", SCANS_DIR);
    return 0;
}

static int do_grab(const char *host, const char *port, const char *file, const char *auth,
                   unsigned long long size, const char *want_md5, const char *base) {
    char final_path[1024], tmp_path[1100];
    if (snprintf(final_path, sizeof final_path, "%s/%s", SCANS_DIR, base) >= (int)sizeof final_path ||
        snprintf(tmp_path, sizeof tmp_path, "%s.part", final_path) >= (int)sizeof tmp_path) {
        fprintf(stderr, "ERROR: file name too long\n");
        return -1;
    }
    if (ensure_scans_dir() < 0) return -1;

    int fd = connect_to(host, port);
    if (fd < 0) return -1;
    printf("[GRAB] requesting '%s'\n", file);
    if (send_command(fd, "GRAB", file, auth) < 0) { close(fd); return -1; }

    // Header: "GRAB-RESP STATUS FILE " then raw bytes
    char t1[64], t2[256], t3[1024];
    int d = read_token(fd, t1, sizeof t1);
    if (d < 0 || strcmp(t1, "GRAB-RESP") != 0) {
        fprintf(stderr, "ERROR: unexpected GRAB reply (got '%s')\n", t1);
        close(fd);
        return -1;
    }
    d = read_token(fd, t2, sizeof t2);
    if (d < 0) { close(fd); return -1; }
    if (strcmp(t2, "OK") != 0) {
        char rest[512] = "";
        if (d == ' ') drain_message(fd, rest, sizeof rest);
        fprintf(stderr, "ERROR: server refused GRAB: %s%s%s\n", t2, rest[0] ? " " : "", rest);
        close(fd);
        return -1;
    }
    if (d != ' ' || read_token(fd, t3, sizeof t3) != ' ') {
        fprintf(stderr, "ERROR: malformed GRAB-RESP header\n");
        close(fd);
        return -1;
    }
    if (strcmp(t3, file) != 0)
        fprintf(stderr, "WARNING: server named file '%s' (asked for '%s')\n", t3, file);

    FILE *out = fopen(tmp_path, "wb");
    if (!out) {
        fprintf(stderr, "ERROR: cannot open '%s': %s\n", tmp_path, strerror(errno));
        close(fd);
        return -1;
    }

    md5_ctx ctx;
    md5_init(&ctx);
    static unsigned char buf[CHUNK];
    unsigned long long got = 0, next_report = PROGRESS_STEP;
    int rc = 0;
    while (got < size) {
        size_t want = (size - got > CHUNK) ? CHUNK : (size_t)(size - got);
        ssize_t n = recv(fd, buf, want, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "ERROR: recv failed after %llu/%llu bytes: %s\n", got, size,
                    (errno == EAGAIN || errno == EWOULDBLOCK) ? "timed out" : strerror(errno));
            rc = -1;
            break;
        }
        if (n == 0) {
            fprintf(stderr, "ERROR: connection closed after %llu/%llu bytes\n", got, size);
            rc = -1;
            break;
        }
        if (fwrite(buf, 1, (size_t)n, out) != (size_t)n) {
            fprintf(stderr, "ERROR: write failed: %s\n", strerror(errno));
            rc = -1;
            break;
        }
        md5_update(&ctx, buf, (size_t)n);
        got += (unsigned long long)n;
        if (got >= next_report) {
            printf("[GRAB] ... %llu / %llu bytes (%d%%)\n", got, size, (int)(got * 100 / size));
            fflush(stdout);
            next_report += PROGRESS_STEP;
        }
    }
    close(fd);
    if (fclose(out) != 0 && rc == 0) {
        fprintf(stderr, "ERROR: closing '%s' failed: %s\n", tmp_path, strerror(errno));
        rc = -1;
    }
    if (rc != 0) { remove(tmp_path); return -1; }

    char got_md5[33];
    md5_final_hex(&ctx, got_md5);
    if (strcmp(got_md5, want_md5) != 0) {
        fprintf(stderr, "ERROR: MD5 mismatch for '%s' (expected %s, got %s)\n", file, want_md5, got_md5);
        remove(tmp_path);
        return -1;
    }
    if (rename(tmp_path, final_path) != 0) {
        fprintf(stderr, "ERROR: cannot move file into place: %s\n", strerror(errno));
        remove(tmp_path);
        return -1;
    }
    printf("[GRAB] OK: saved %s (%llu bytes, MD5 verified)\n", final_path, got);
    return 0;
}

// ------------------------------------------------------------------

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s FILE HOST PORT AUTH\n", argv[0]);
        return 1;
    }
    const char *file = argv[1], *host = argv[2], *port = argv[3], *auth = argv[4];

    char *end = NULL;
    long pn = strtol(port, &end, 10);
    if (*port == '\0' || *end != '\0' || pn < 1 || pn > 65535) {
        fprintf(stderr, "ERROR: invalid port '%s'\n", port);
        return 1;
    }

    // Local name: strip any directory components so we can't escape scans
    const char *base = strrchr(file, '/');
    base = base ? base + 1 : file;
    if (*base == '\0' || strcmp(base, ".") == 0 || strcmp(base, "..") == 0) {
        fprintf(stderr, "ERROR: invalid file name '%s'\n", file);
        return 1;
    }

    unsigned long long size = 0;
    char md5[33];
    if (do_info(host, port, file, auth, &size, md5) < 0) return 1;
    if (do_grab(host, port, file, auth, size, md5, base) < 0) return 1;
    return 0;
}
