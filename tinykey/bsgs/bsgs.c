// BSGS scan for EC public keys whose private scalar d satisfies |d| (mod n) <= BOUND.
// Input: lines "<label> <hex SEC1 point>" (all on one curve). Prints only "HIT <label> scalar within bound"; never the value or its size.
// Usage: bsgs <curve_sn|custom:p:a:b:gx:gy:n:h> <keys.txt> <logM> <J> <threads>
// custom: short Weierstrass, all fields hex; h is the cofactor (e.g. 1 for prime-order curves, 8 for Ed25519 in Weierstrass form).
// Limits: logM 1..31, threads 1..64. Exit status 1 on bad usage/input, 2 if any key line could not be parsed.
// Baby table: x(iG) for i=1..M. Giant step S=2M*G. For each Q test Q-jS and Q+jS, j=0..J.
// Covers d in [-(2M*J+M), 2M*J+M].
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

typedef struct { uint64_t key; uint32_t idx; } ent;
static EC_GROUP *G; static int T; static uint64_t M, J;
static ent *tab;  // sorted baby table: every index is kept, even for colliding 64-bit keys
static char **labels; static EC_POINT **Qs; static char *found; static size_t nQ;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
#define CH 2048

static void die(const char *m) { fprintf(stderr, "error: %s\n", m); exit(1); }
// low 64 bits of the affine x of a finite point
static uint64_t xkey(const EC_POINT *P, BIGNUM *x, BN_CTX *c) {
  unsigned char b[80];
  if (!EC_POINT_get_affine_coordinates(G, P, x, NULL, c) || BN_bn2binpad(x, b, 80) != 80) die("x-coordinate does not fit in 80 bytes");
  uint64_t k; memcpy(&k, b + 72, 8); return k;
}
static int entcmp(const void *a, const void *b) {
  const ent *p = a, *q = b;
  if (p->key != q->key) return p->key < q->key ? -1 : 1;
  return p->idx < q->idx ? -1 : p->idx > q->idx;
}
typedef struct { uint64_t a, b; } rng;
static void *baby(void *arg) {
  rng *r = arg; BN_CTX *c = BN_CTX_new(); BIGNUM *x = BN_new(), *s = BN_new();
  EC_POINT *P = EC_POINT_new(G); const EC_POINT *g = EC_GROUP_get0_generator(G);
  EC_POINT *buf[CH]; for (int i = 0; i < CH; i++) buf[i] = EC_POINT_new(G);
  BN_set_word(s, r->a); EC_POINT_mul(G, P, s, NULL, NULL, c);
  for (uint64_t i = r->a; i < r->b; i += CH) {
    int n = (r->b - i) < CH ? (int)(r->b - i) : CH;
    for (int k = 0; k < n; k++) { EC_POINT_copy(buf[k], P); EC_POINT_add(G, P, P, g, c); }
    EC_POINTs_make_affine(G, n, buf, c);
    for (int k = 0; k < n; k++) { tab[i + k - 1].key = xkey(buf[k], x, c); tab[i + k - 1].idx = (uint32_t)(i + k); }
  }
  return NULL;
}
static size_t next_q = 0;
// Verify candidate d = j*2M +/- i (i = 0: d = j*2M) against the full point; report only that a hit exists.
static void report(size_t qi, uint64_t j, int sign, uint32_t i, BN_CTX *c) {
  BIGNUM *d = BN_new(); EC_POINT *P = EC_POINT_new(G);
  for (int pm = -1; pm <= 1; pm += 2) {
    if (i == 0 && pm > 0) break;
    BN_set_word(d, j); BN_mul_word(d, 2 * M);
    if (pm > 0) BN_add_word(d, i); else BN_sub_word(d, i);
    if (BN_is_negative(d) || BN_is_zero(d)) continue;
    EC_POINT_mul(G, P, d, NULL, NULL, c);
    if (sign < 0) EC_POINT_invert(G, P, c);
    if (EC_POINT_cmp(G, P, Qs[qi], c) == 0) {
      pthread_mutex_lock(&mu);
      if (!found[qi]) { found[qi] = 1; printf("HIT %s scalar within bound\n", labels[qi]); fflush(stdout); }
      pthread_mutex_unlock(&mu);
    }
  }
  BN_free(d); EC_POINT_free(P);
}
static void lookup(size_t qi, uint64_t j, int sign, uint64_t key, BN_CTX *c) {
  size_t lo = 0, hi = M;
  while (lo < hi) { size_t mid = lo + (hi - lo) / 2; if (tab[mid].key < key) lo = mid + 1; else hi = mid; }
  for (; lo < M && tab[lo].key == key; lo++) report(qi, j, sign, tab[lo].idx, c);
}
static void *giant(void *arg) {
  (void)arg; BN_CTX *c = BN_CTX_new(); BIGNUM *x = BN_new(), *s = BN_new();
  EC_POINT *S = EC_POINT_new(G), *Sn = EC_POINT_new(G);
  BN_set_word(s, 2 * M); EC_POINT_mul(G, S, s, NULL, NULL, c);
  EC_POINT_copy(Sn, S); EC_POINT_invert(G, Sn, c);
  EC_POINT *R[CH]; for (int i = 0; i < CH; i++) R[i] = EC_POINT_new(G);
  size_t idx[CH];
  for (;;) {
    pthread_mutex_lock(&mu); size_t per = nQ / (T * 4); if (per < 2) per = 2; if (per > CH / 2) per = CH / 2;
    size_t a = next_q; next_q += per; pthread_mutex_unlock(&mu);
    if (a >= nQ) break;
    int n = 0; for (size_t q = a; q < a + per && q < nQ; q++) {
      idx[n] = q; EC_POINT_copy(R[n++], Qs[q]); idx[n] = q; EC_POINT_copy(R[n++], Qs[q]); }
    for (uint64_t j = 0; j <= J; j++) {
      if (j) for (int k = 0; k < n; k++) EC_POINT_add(G, R[k], R[k], (k & 1) ? S : Sn, c);
      EC_POINTs_make_affine(G, n, R, c);
      for (int k = 0; k < n; k++) {
        // even k: Q - jS -> d = j*2M +/- i ; odd k: Q + jS -> -d = j*2M +/- i
        int sign = (k & 1) ? -1 : 1;
        if (EC_POINT_is_at_infinity(G, R[k])) { report(idx[k], j, sign, 0, c); continue; }  // Q = +/- jS exactly; verified, not assumed
        lookup(idx[k], j, sign, xkey(R[k], x, c), c);
      }
    }
  }
  return NULL;
}
static uint64_t num(const char *s, const char *what, uint64_t lo, uint64_t hi) {
  char *e; errno = 0; if (*s == '-') die(what);
  unsigned long long v = strtoull(s, &e, 10);
  if (errno || *s == 0 || *e || v < lo || v > hi) { fprintf(stderr, "error: %s must be an integer in %llu..%llu\n", what, (unsigned long long)lo, (unsigned long long)hi); exit(1); }
  return v;
}
int main(int argc, char **argv) {
  if (argc != 6) { fprintf(stderr, "usage: bsgs <curve|custom:p:a:b:gx:gy:n:h> <keys.txt> <logM 1..31> <J> <threads 1..64>\n"); return 1; }
  if (!strncmp(argv[1], "custom:", 7)) {  // custom:p:a:b:gx:gy:n:h (hex), short Weierstrass
    char *f[7], *own = strdup(argv[1] + 7), *s = own; BIGNUM *v[7];
    for (int i = 0; i < 7; i++) { f[i] = strsep(&s, ":"); v[i] = NULL; if (!f[i] || !*f[i] || !BN_hex2bn(&v[i], f[i])) die("custom curve needs 7 hex fields p:a:b:gx:gy:n:h"); }
    if (s) die("custom curve has more than 7 fields");
    if (BN_is_zero(v[6])) die("cofactor must be nonzero");
    G = EC_GROUP_new_curve_GFp(v[0], v[1], v[2], NULL); if (!G) die("bad custom curve parameters");
    EC_POINT *g = EC_POINT_new(G);
    if (!EC_POINT_set_affine_coordinates(G, g, v[3], v[4], NULL) || !EC_POINT_is_on_curve(G, g, NULL) || !EC_GROUP_set_generator(G, g, v[5], v[6])) die("bad custom curve generator/order/cofactor");
    free(own);
  } else {
    int nid = OBJ_sn2nid(argv[1]); if (nid == NID_undef) nid = OBJ_txt2nid(argv[1]);
    G = nid == NID_undef ? NULL : EC_GROUP_new_by_curve_name(nid);
    if (!G) { fprintf(stderr, "error: bad curve %s\n", argv[1]); return 1; }
  }
  uint64_t lm = num(argv[3], "logM", 1, 31); M = 1ULL << lm;
  J = num(argv[4], "J", 0, ((1ULL << 62) - M) / (2 * M)); T = (int)num(argv[5], "threads", 1, 64);
  FILE *f = fopen(argv[2], "r"); if (!f) { perror(argv[2]); return 1; }
  char line[65536]; size_t cap = 1024; int bad = 0;
  labels = malloc(cap * sizeof(char *)); Qs = malloc(cap * sizeof(EC_POINT *)); if (!labels || !Qs) die("out of memory");
  BN_CTX *c = BN_CTX_new();
  while (fgets(line, sizeof line, f)) {
    line[strcspn(line, "\r\n")] = 0; if (!line[strspn(line, " \t")]) continue;
    char *sp = strrchr(line, ' ');
    EC_POINT *P = sp ? EC_POINT_hex2point(G, sp + 1, NULL, c) : NULL;
    if (!P || EC_POINT_is_at_infinity(G, P) || !EC_POINT_is_on_curve(G, P, c)) { fprintf(stderr, "bad point line: %.60s\n", line); bad = 1; continue; }
    *sp = 0;
    if (nQ == cap) { cap *= 2; labels = realloc(labels, cap * sizeof(char *)); Qs = realloc(Qs, cap * sizeof(EC_POINT *)); if (!labels || !Qs) die("out of memory"); }
    labels[nQ] = strdup(line); Qs[nQ++] = P;
  }
  fclose(f);
  found = calloc(nQ ? nQ : 1, 1); tab = malloc(M * sizeof(ent)); if (!found || !tab) die("out of memory");
  pthread_t th[64]; rng r[64];
  for (int t = 0; t < T; t++) { r[t].a = 1 + M * t / T; r[t].b = 1 + M * (t + 1) / T; if (t == T - 1) r[t].b = M + 1; pthread_create(&th[t], 0, baby, &r[t]); }
  for (int t = 0; t < T; t++) pthread_join(th[t], 0);
  qsort(tab, M, sizeof(ent), entcmp);
  fprintf(stderr, "%s: baby table %llu built; %zu keys; giant J=%llu\n", argv[1], (unsigned long long)M, nQ, (unsigned long long)J);
  for (int t = 0; t < T; t++) pthread_create(&th[t], 0, giant, 0);
  for (int t = 0; t < T; t++) pthread_join(th[t], 0);
  unsigned long long bound = 2 * M * J + M; int lb = 0; while ((1ULL << lb) < bound && lb < 63) lb++;
  printf("DONE %s keys=%zu bound |d|<=%llu (~2^%d)\n", argv[1], nQ, bound, lb);
  return bad ? 2 : 0;
}
