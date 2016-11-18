#include "mmap.h"
#include <aesrand/aesrand_gmp.h>
#include <assert.h>

typedef struct dummy_pp_t {
    mpz_t *moduli;
    size_t nslots;
    size_t kappa;
} dummy_pp_t;
typedef struct dummy_sk_t {
    dummy_pp_t pp;
    size_t nzs;
} dummy_sk_t;
typedef struct dummy_enc_t {
    mpz_t *elems;
    size_t degree;
    size_t nslots;
} dummy_enc_t;

#define max(a, b) (a) > (b) ? (a) : (b)

static mmap_ro_pp
dummy_pp_init(const mmap_ro_sk sk_)
{
    const dummy_sk_t *const sk = sk_;
    return &sk->pp;
}

static void
dummy_pp_clear(mmap_pp pp_)
{
    dummy_pp_t *pp = pp_;
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_clear(pp->moduli[i]);
    }
    free(pp->moduli);
}

static void
dummy_pp_read(const mmap_pp pp_, FILE *const fp)
{
    dummy_pp_t *const pp = pp_;
    fscanf(fp, "%lu\n", &pp->kappa);
    fscanf(fp, "%lu\n", &pp->nslots);
    pp->moduli = calloc(pp->nslots, sizeof(mpz_t));
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_init(pp->moduli[i]);
        mpz_inp_raw(pp->moduli[i], fp);
        (void) fscanf(fp, "\n");
    }
}

static void
dummy_pp_write(const mmap_ro_pp pp_, FILE *const fp)
{
    const dummy_pp_t *const pp = pp_;
    fprintf(fp, "%lu\n", pp->kappa);
    fprintf(fp, "%lu\n", pp->nslots);
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_out_raw(fp, pp->moduli[i]);
        (void) fprintf(fp, "\n");
    }
}

static const mmap_pp_vtable dummy_pp_vtable =
{ .clear = dummy_pp_clear,
  .fread = dummy_pp_read,
  .fwrite = dummy_pp_write,
  .size = sizeof(dummy_pp_t)
};

static int
dummy_state_init(const mmap_sk sk_, size_t lambda, size_t kappa, 
                 size_t gamma, int *pows, size_t nslots, size_t ncores,
                 aes_randstate_t rng, bool verbose)
{
    dummy_sk_t *const sk = sk_;
    (void) pows, (void) ncores, (void) verbose;
    if (nslots == 0)
        nslots = 1;
    sk->pp.moduli = calloc(nslots, sizeof(mpz_t));
    for (size_t i = 0; i < nslots; ++i) {
        mpz_init(sk->pp.moduli[i]);
        mpz_urandomb_aes(sk->pp.moduli[i], rng, lambda);
        mpz_nextprime(sk->pp.moduli[i], sk->pp.moduli[i]);
    }
    sk->pp.nslots = nslots;
    sk->nzs = gamma;
    sk->pp.kappa = kappa;
    return MMAP_OK;
}

static void
dummy_state_clear(const mmap_sk sk_)
{
    dummy_sk_t *const sk = sk_;
    for (size_t i = 0; i < sk->pp.nslots; ++i) {
        mpz_clear(sk->pp.moduli[i]);
    }
    free(sk->pp.moduli);
}

static void
dummy_state_read(const mmap_sk sk_, FILE *const fp)
{
    dummy_sk_t *const sk = sk_;
    (void) fscanf(fp, "%lu\n", &sk->pp.kappa);
    (void) fscanf(fp, "%lu\n", &sk->pp.nslots);
    sk->pp.moduli = calloc(sk->pp.nslots, sizeof(mpz_t));
    for (size_t i = 0; i < sk->pp.nslots; ++i) {
        mpz_init(sk->pp.moduli[i]);
        mpz_inp_raw(sk->pp.moduli[i], fp);
        (void) fscanf(fp, "\n");
    }
}

static void
dummy_state_write(const mmap_ro_sk sk_, FILE *const fp)
{
    const dummy_sk_t *const sk = sk_;
    (void) fprintf(fp, "%lu\n", sk->pp.kappa);
    (void) fprintf(fp, "%lu\n", sk->pp.nslots);
    for (size_t i = 0; i < sk->pp.nslots; ++i) {
        mpz_out_raw(fp, sk->pp.moduli[i]);
        (void) fprintf(fp, "\n");
    }
}

static fmpz_t *
dummy_state_get_moduli(const mmap_ro_sk sk_)
{
    const dummy_sk_t *const sk = sk_;
    fmpz_t *moduli;

    moduli = calloc(sk->pp.nslots, sizeof(fmpz_t));
    for (size_t i = 0; i < sk->pp.nslots; ++i) {
        fmpz_init(moduli[i]);
        fmpz_set_mpz(moduli[i], sk->pp.moduli[i]);
    }
    return moduli;
}

static size_t
dummy_state_nslots(const mmap_ro_sk sk_)
{
    const dummy_sk_t *const sk = sk_;
    return sk->pp.nslots;
}

static size_t
dummy_state_nzs(const mmap_ro_sk sk_)
{
    const dummy_sk_t *const sk = sk_;
    return sk->nzs;
}

static const mmap_sk_vtable dummy_sk_vtable =
{ .init = dummy_state_init,
  .clear = dummy_state_clear,
  .fread = dummy_state_read,
  .fwrite = dummy_state_write,
  .pp = dummy_pp_init,
  .plaintext_fields = dummy_state_get_moduli,
  .nslots = dummy_state_nslots,
  .nzs = dummy_state_nzs,
  .size = sizeof(dummy_sk_t),
};

static void
dummy_enc_init(const mmap_enc enc_, const mmap_ro_pp pp_)
{
    const dummy_pp_t *const pp = pp_;
    dummy_enc_t *const enc = enc_;
    enc->elems = calloc(pp->nslots, sizeof(mpz_t));
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_init(enc->elems[i]);
    }
    enc->nslots = pp->nslots;
    enc->degree = 0;        /* Set when encoding */
}

static void
dummy_enc_clear(const mmap_enc enc_)
{
    dummy_enc_t *const enc = enc_;
    for (size_t i = 0; i < enc->nslots; ++i) {
        mpz_clear(enc->elems[i]);
    }
    free(enc->elems);
}

static void
dummy_enc_fread(const mmap_enc enc_, FILE *const fp)
{
    dummy_enc_t *const enc = enc_;
    (void) fscanf(fp, "%lu\n", &enc->degree);
    (void) fscanf(fp, "%lu\n", &enc->nslots);
    enc->elems = calloc(enc->nslots, sizeof(mpz_t));
    for (size_t i = 0; i < enc->nslots; ++i) {
        mpz_init(enc->elems[i]);
        mpz_inp_raw(enc->elems[i], fp);
        (void) fscanf(fp, "\n");
    }
}

static void
dummy_enc_fwrite(const mmap_ro_enc enc_, FILE *const fp)
{
    const dummy_enc_t *const enc = enc_;
    (void) fprintf(fp, "%lu\n", enc->degree);
    (void) fprintf(fp, "%lu\n", enc->nslots);
    for (size_t i = 0; i < enc->nslots; ++i) {
        mpz_out_raw(fp, enc->elems[i]);
        (void) fprintf(fp, "\n");
    }
}

static void
dummy_enc_set(const mmap_enc dest_, const mmap_ro_enc src_)
{
    dummy_enc_t *const dest = dest_;
    const dummy_enc_t *const src = src_;
    assert(dest->nslots == src->nslots);
    dest->degree = src->degree;
    for (size_t i = 0; i < dest->nslots; ++i) {
        mpz_set(dest->elems[i], src->elems[i]);
    }
}

static void
dummy_enc_add(const mmap_enc dest_, const mmap_ro_pp pp_,
              const mmap_ro_enc a_, const mmap_ro_enc b_)
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
}

static void
dummy_enc_sub(const mmap_enc dest_, const mmap_ro_pp pp_,
              const mmap_ro_enc a_, const mmap_ro_enc b_)
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
}

static void
dummy_enc_mul(const mmap_enc dest_, const mmap_ro_pp pp_,
              const mmap_ro_enc a_, const mmap_ro_enc b_)
{
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
}

static bool
dummy_enc_is_zero(const mmap_ro_enc enc_, const mmap_ro_pp pp_)
{
    const dummy_enc_t *const enc = enc_;
    const dummy_pp_t *const pp = pp_;
    bool ret = true;
    assert(enc->degree == pp->kappa);
    for (size_t i = 0; i < pp->nslots; ++i) {
        ret &= (mpz_cmp_ui(enc->elems[i], 0) == 0);
    }
    return ret;
}

static void
dummy_encode(const mmap_enc enc_, const mmap_ro_sk sk_,
             size_t n, const fmpz_t *plaintext, int *group)
{
    dummy_enc_t *const enc = enc_;
    const dummy_sk_t *const sk = sk_;
    (void) sk, (void) group;
    assert(n <= sk->pp.nslots);
    enc->degree = 1;
    for (size_t i = 0; i < n; ++i) {
        fmpz_get_mpz(enc->elems[i], plaintext[i]);
    }
}

static void
dummy_print(const mmap_ro_enc enc_)
{
    const dummy_enc_t *const enc = enc_;
    for (size_t i = 0; i < enc->nslots; ++i) {
        gmp_printf("%Zd ", enc->elems[i]);
    }
    printf("\n");
}

static const mmap_enc_vtable dummy_enc_vtable =
{ .init = dummy_enc_init,
  .clear = dummy_enc_clear,
  .fread = dummy_enc_fread,
  .fwrite = dummy_enc_fwrite,
  .set = dummy_enc_set,
  .add = dummy_enc_add,
  .sub = dummy_enc_sub,
  .mul = dummy_enc_mul,
  .is_zero = dummy_enc_is_zero,
  .encode = dummy_encode,
  /* .print = dummy_print, */
  .size = sizeof(dummy_enc_t),
};

const mmap_vtable dummy_vtable =
{ .pp  = &dummy_pp_vtable,
  .sk  = &dummy_sk_vtable,
  .enc = &dummy_enc_vtable,
};
