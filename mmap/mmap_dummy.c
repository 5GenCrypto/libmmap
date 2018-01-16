#include "mmap.h"

#include <assert.h>
#include <string.h>

typedef struct dummy_pp_t {
    mpz_t *moduli;
    size_t nslots;
    unsigned int kappa;
    int verbose;
} dummy_pp_t;

typedef struct dummy_sk_t {
    dummy_pp_t pp;
    size_t nzs;
} dummy_sk_t;

typedef struct dummy_enc_t {
    mpz_t *elems;
    unsigned int degree;
    size_t nslots;
} dummy_enc_t;

#define max(a, b) (a) > (b) ? (a) : (b)

static void
dummy_pp_free(mmap_pp pp_)
{
    dummy_pp_t *const pp = pp_;
    for (size_t i = 0; i < pp->nslots; ++i)
        mpz_clear(pp->moduli[i]);
    free(pp->moduli);
    free(pp);
}

static mmap_pp
dummy_pp_fread(FILE *fp)
{
    dummy_pp_t *pp;

    pp = calloc(1, sizeof pp[0]);
    fread(&pp->kappa, sizeof pp->kappa, 1, fp);
    fread(&pp->nslots, sizeof pp->nslots, 1, fp);
    pp->moduli = calloc(pp->nslots, sizeof(mpz_t));
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_init(pp->moduli[i]);
        mpz_inp_raw(pp->moduli[i], fp);
    }
    fread(&pp->verbose, sizeof pp->verbose, 1, fp);
    return pp;
}

static int
dummy_pp_fwrite(const mmap_pp pp_, FILE *const fp)
{
    const dummy_pp_t *const pp = pp_;
    fwrite(&pp->kappa, sizeof pp->kappa, 1, fp);
    fwrite(&pp->nslots, sizeof pp->nslots, 1, fp);
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_out_raw(fp, pp->moduli[i]);
    }
    fwrite(&pp->verbose, sizeof pp->verbose, 1, fp);
    return MMAP_OK;
}

static const mmap_pp_vtable dummy_pp_vtable = {
    .free = dummy_pp_free,
    .fread = dummy_pp_fread,
    .fwrite = dummy_pp_fwrite,
};

static mmap_sk
dummy_sk_new(const mmap_sk_params *params,
             const mmap_sk_opt_params *opts, size_t ncores,
             aes_randstate_t rng, bool verbose)
{
    dummy_sk_t *sk;
    size_t nslots;

    sk = calloc(1, sizeof sk[0]);
    if (verbose) {
        fprintf(stderr, "  λ: %lu\n", params->lambda);
        fprintf(stderr, "  κ: %lu\n", params->kappa);
        fprintf(stderr, "  γ: %lu\n", params->gamma);
        fprintf(stderr, "  ncores: %lu\n", ncores);
    }
    nslots = opts && opts->nslots ? opts->nslots : 1;
    sk->pp.moduli = calloc(nslots, sizeof sk->pp.moduli[0]);
    for (size_t i = 0; i < nslots; ++i) {
        mpz_init(sk->pp.moduli[i]);
        mpz_urandomb_aes(sk->pp.moduli[i], rng, params->lambda);
        mpz_nextprime(sk->pp.moduli[i], sk->pp.moduli[i]);
    }
    if (opts && opts->modulus)
        mpz_set(sk->pp.moduli[0], *opts->modulus);
    sk->pp.nslots = nslots;
    sk->pp.verbose = verbose;
    sk->nzs = params->gamma;
    sk->pp.kappa = params->kappa;
    return sk;
}

static mmap_pp
dummy_sk_pp(mmap_sk sk_)
{
    dummy_sk_t *sk = sk_;
    dummy_pp_t *pp;

    pp = calloc(1, sizeof pp[0]);
    pp->nslots = sk->pp.nslots;
    pp->kappa = sk->pp.kappa;
    pp->verbose = sk->pp.verbose;
    pp->moduli = calloc(pp->nslots, sizeof pp->moduli[0]);
    for (size_t i = 0; i < pp->nslots; ++i)
        mpz_init_set(pp->moduli[i], sk->pp.moduli[i]);
    return pp;
}

static void
dummy_sk_free(mmap_sk sk_)
{
    dummy_sk_t *sk = sk_;
    for (size_t i = 0; i < sk->pp.nslots; ++i) {
        mpz_clear(sk->pp.moduli[i]);
    }
    free(sk->pp.moduli);
    free(sk);
}

static mmap_sk
dummy_sk_fread(FILE *const fp)
{
    return dummy_pp_fread(fp);
}

static int
dummy_sk_fwrite(const mmap_sk sk_, FILE *const fp)
{
    const dummy_sk_t *const sk = sk_;
    return dummy_pp_fwrite((mmap_pp) &sk->pp, fp);
}

static mpz_t *
dummy_sk_get_moduli(const mmap_sk sk_)
{
    const dummy_sk_t *const sk = sk_;
    return sk->pp.moduli;
}

static size_t
dummy_sk_nslots(const mmap_sk sk_)
{
    const dummy_sk_t *sk = sk_;
    return sk->pp.nslots;
}

static size_t
dummy_sk_nzs(const mmap_sk sk_)
{
    const dummy_sk_t *sk = sk_;
    return sk->nzs;
}

static const mmap_sk_vtable dummy_sk_vtable =
{ .new = dummy_sk_new,
  .free = dummy_sk_free,
  .fread = dummy_sk_fread,
  .fwrite = dummy_sk_fwrite,
  .pp = dummy_sk_pp,
  .plaintext_fields = dummy_sk_get_moduli,
  .nslots = dummy_sk_nslots,
  .nzs = dummy_sk_nzs,
};

static mmap_enc
dummy_enc_new(const mmap_pp pp_)
{
    const dummy_pp_t *const pp = pp_;
    dummy_enc_t *enc;

    enc = calloc(1, sizeof enc[0]);
    enc->elems = calloc(pp->nslots, sizeof(mpz_t));
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_init(enc->elems[i]);
    }
    enc->nslots = pp->nslots;
    enc->degree = 0;        /* Set when encoding */
    return enc;
}

static void
dummy_enc_free(const mmap_enc enc_)
{
    dummy_enc_t *const enc = enc_;
    for (size_t i = 0; i < enc->nslots; ++i) {
        mpz_clear(enc->elems[i]);
    }
    free(enc->elems);
    free(enc);
}

static mmap_enc
dummy_enc_fread(FILE *const fp)
{
    dummy_enc_t *enc;

    enc = calloc(1, sizeof enc[0]);
    (void) fread(&enc->degree, sizeof enc->degree, 1, fp);
    (void) fread(&enc->nslots, sizeof enc->nslots, 1, fp);
    enc->elems = calloc(enc->nslots, sizeof enc->elems[0]);
    for (size_t i = 0; i < enc->nslots; ++i) {
        mpz_init(enc->elems[i]);
        mpz_inp_raw(enc->elems[i], fp);
    }
    return enc;
}

static int
dummy_enc_fwrite(const mmap_enc enc_, FILE *const fp)
{
    const dummy_enc_t *const enc = enc_;
    (void) fwrite(&enc->degree, sizeof enc->degree, 1, fp);
    (void) fwrite(&enc->nslots, sizeof enc->nslots, 1, fp);
    for (size_t i = 0; i < enc->nslots; ++i)
        mpz_out_raw(fp, enc->elems[i]);
    return MMAP_OK;
}

static void
dummy_enc_set(const mmap_enc dest_, const mmap_enc src_)
{
    dummy_enc_t *const dest = dest_;
    const dummy_enc_t *const src = src_;
    assert(dest->nslots == src->nslots);
    dest->degree = src->degree;
    for (size_t i = 0; i < dest->nslots; ++i) {
        mpz_set(dest->elems[i], src->elems[i]);
    }
}

static int
dummy_enc_add(const mmap_enc dest_, const mmap_pp pp_,
              const mmap_enc a_, const mmap_enc b_)
{
    dummy_enc_t *const dest = dest_;
    const dummy_pp_t *const pp = pp_;
    const dummy_enc_t *const a = a_;
    const dummy_enc_t *const b = b_;

    assert(dest->nslots == a->nslots);
    assert(dest->nslots == b->nslots);

    dest->degree = max(a->degree, b->degree);
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_add(dest->elems[i], a->elems[i], b->elems[i]);
        mpz_mod(dest->elems[i], dest->elems[i], pp->moduli[i]);
    }
    return MMAP_OK;
}

static int
dummy_enc_sub(const mmap_enc dest_, const mmap_pp pp_,
              const mmap_enc a_, const mmap_enc b_)
{
    dummy_enc_t *const dest = dest_;
    const dummy_pp_t *const pp = pp_;
    const dummy_enc_t *const a = a_;
    const dummy_enc_t *const b = b_;

    assert(dest->nslots == a->nslots);
    assert(dest->nslots == b->nslots);

    dest->degree = max(a->degree, b->degree);
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_sub(dest->elems[i], a->elems[i], b->elems[i]);
        mpz_mod(dest->elems[i], dest->elems[i], pp->moduli[i]);
    }
    return MMAP_OK;
}

static int
dummy_enc_mul(const mmap_enc dest_, const mmap_pp pp_,
              const mmap_enc a_, const mmap_enc b_, size_t idx)
{
    (void) idx;
    dummy_enc_t *const dest = dest_;
    const dummy_pp_t *const pp = pp_;
    const dummy_enc_t *const a = a_;
    const dummy_enc_t *const b = b_;

    assert(dest->nslots == a->nslots);
    assert(dest->nslots == b->nslots);

    dest->degree = a->degree + b->degree;
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_mul(dest->elems[i], a->elems[i], b->elems[i]);
        mpz_mod(dest->elems[i], dest->elems[i], pp->moduli[i]);
    }
    return MMAP_OK;
}

static bool
dummy_enc_is_zero(const mmap_enc enc_, const mmap_pp pp_)
{
    const dummy_enc_t *const enc = enc_;
    const dummy_pp_t *const pp = pp_;
    bool ret = true;
    if (enc->degree != pp->kappa) {
        if (pp->verbose)
            fprintf(stderr, "warning: degrees not equal (%u != %u)\n", enc->degree, pp->kappa);
    }
    for (size_t i = 0; i < pp->nslots; ++i) {
        ret &= (mpz_cmp_ui(enc->elems[i], 0) == 0);
    }
    return ret;
}

static int
dummy_encode(const mmap_enc enc_, const mmap_sk sk_, size_t n, mpz_t *plaintext, void *extra)
{
    (void) sk_; (void) extra;
    dummy_enc_t *const enc = enc_;
    enc->degree = 1;
    for (size_t i = 0; i < n; ++i) {
        mpz_set(enc->elems[i], plaintext[i]);
    }
    return MMAP_OK;
}

static void
dummy_print(const mmap_enc enc_)
{
    const dummy_enc_t *const enc = enc_;
    for (size_t i = 0; i < enc->nslots; ++i) {
        gmp_printf("%Zd ", enc->elems[i]);
    }
    printf("\n");
}

static unsigned int
dummy_degree(const mmap_enc enc_)
{
    const dummy_enc_t *const enc = enc_;
    return enc->degree;
}

static const mmap_enc_vtable dummy_enc_vtable =
{ .new = dummy_enc_new,
  .free = dummy_enc_free,
  .fread = dummy_enc_fread,
  .fwrite = dummy_enc_fwrite,
  .set = dummy_enc_set,
  .add = dummy_enc_add,
  .sub = dummy_enc_sub,
  .mul = dummy_enc_mul,
  .is_zero = dummy_enc_is_zero,
  .encode = dummy_encode,
  .degree = dummy_degree,
  .print = dummy_print,
};

const mmap_vtable dummy_vtable =
{ .pp  = &dummy_pp_vtable,
  .sk  = &dummy_sk_vtable,
  .enc = &dummy_enc_vtable,
};
