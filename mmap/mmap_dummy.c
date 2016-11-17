#include "mmap.h"

typedef struct dummy_pp_t {
    mpz_t *moduli;
    size_t nslots;
    size_t kappa;
} dummy_pp_t;
typedef struct dummy_sk_t {
    mpz_t *moduli;
    size_t nslots;
    size_t nzs;
    size_t kappa;
} dummy_sk_t;
struct dummy_enc_t {
    mpz_t *elems;
    size_t degree;
    size_t nslots;
};

#define my(sk) (sk)->dummy_self
#define max(a, b) (a) > (b) ? (a) : (b)

static mmap_ro_pp
dummy_pp_init(const mmap_ro_sk sk_)
{
    const dummy_sk_t *const sk = sk_;
    /* TODO: this is a leak: applications are not supposed to call clear/free
     * on pp's they get from this function; it is sk->clear()'s job to do so,
     * and it can't, because the sk isn't keeping a reference to the pp created
     * here */
    dummy_pp_t *pp = calloc(1, sizeof(dummy_pp_t));
    pp->moduli = calloc(sk->nslots, sizeof(mpz_t));
    for (size_t i = 0; i < sk->nslots; ++i) {
        mpz_init(pp->moduli[i]);
        mpz_set(pp->moduli[i], sk->moduli[i]);
    }
    pp->nslots = sk->nslots;
    pp->kappa = sk->kappa;
    return pp;
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
    sk->moduli = calloc(nslots, sizeof(mpz_t));
    for (size_t i = 0; i < nslots; ++i) {
        mpz_init(sk->moduli[i]);
        mpz_urandomb_aes(sk->moduli[i], rng, lambda);
        mpz_nextprime(sk->moduli[i], sk->moduli[i]);
    }
    sk->nslots = nslots;
    sk->nzs = gamma;
    sk->kappa = kappa;
    return MMAP_OK;
}

static void
dummy_state_clear(const mmap_sk sk_)
{
    dummy_sk_t *const sk = sk_;
    for (size_t i = 0; i < sk->nslots; ++i) {
        mpz_clear(sk->moduli[i]);
    }
    free(sk->moduli);
}

static void
dummy_state_read(const mmap_sk sk_, FILE *const fp)
{
    dummy_sk_t *const sk = sk_;
    (void) fscanf(fp, "%lu\n", &sk->kappa);
    (void) fscanf(fp, "%lu\n", &sk->nslots);
    sk->moduli = calloc(sk->nslots, sizeof(mpz_t));
    for (size_t i = 0; i < sk->nslots; ++i) {
        mpz_init(sk->moduli[i]);
        mpz_inp_raw(sk->moduli[i], fp);
        (void) fscanf(fp, "\n");
    }
}

static void
dummy_state_write(const mmap_ro_sk sk_, FILE *const fp)
{
    const dummy_sk_t *const sk = sk_;
    (void) fprintf(fp, "%lu\n", sk->kappa);
    (void) fprintf(fp, "%lu\n", sk->nslots);
    for (size_t i = 0; i < sk->nslots; ++i) {
        mpz_out_raw(fp, sk->moduli[i]);
        (void) fprintf(fp, "\n");
    }
}

static fmpz_t *
dummy_state_get_moduli(const mmap_ro_sk sk_)
{
    const dummy_sk_t *const sk = sk_;
    fmpz_t *moduli;

    moduli = calloc(sk->nslots, sizeof(fmpz_t));
    for (size_t i = 0; i < sk->nslots; ++i) {
        fmpz_init(moduli[i]);
        fmpz_set_mpz(moduli[i], sk->moduli[i]);
    }
    return moduli;
}

static size_t
dummy_state_nslots(const mmap_ro_sk sk_)
{
    const dummy_sk_t *const sk = sk_;
    return sk->nslots;
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
dummy_enc_init(mmap_enc *const enc, const mmap_ro_pp pp_)
{
    const dummy_pp_t *const pp = pp_;
    my(enc) = calloc(1, sizeof(dummy_enc_t));
    my(enc)->elems = calloc(pp->nslots, sizeof(mpz_t));
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_init(my(enc)->elems[i]);
    }
    my(enc)->nslots = pp->nslots;
    my(enc)->degree = 0;        /* Set when encoding */
}

static void
dummy_enc_clear(mmap_enc *const enc)
{
    for (size_t i = 0; i < my(enc)->nslots; ++i) {
        mpz_clear(my(enc)->elems[i]);
    }
    free(my(enc)->elems);
    free(my(enc));
}

static void
dummy_enc_fread(mmap_enc *enc, FILE *const fp)
{
    my(enc) = calloc(1, sizeof(dummy_enc_t));
    (void) fscanf(fp, "%lu\n", &my(enc)->degree);
    (void) fscanf(fp, "%lu\n", &my(enc)->nslots);
    my(enc)->elems = calloc(my(enc)->nslots, sizeof(mpz_t));
    for (size_t i = 0; i < my(enc)->nslots; ++i) {
        mpz_init(my(enc)->elems[i]);
        mpz_inp_raw(my(enc)->elems[i], fp);
        (void) fscanf(fp, "\n");
    }
}

static void
dummy_enc_fwrite(const mmap_enc *const enc, FILE *const fp)
{
    (void) fprintf(fp, "%lu\n", my(enc)->degree);
    (void) fprintf(fp, "%lu\n", my(enc)->nslots);
    for (size_t i = 0; i < my(enc)->nslots; ++i) {
        mpz_out_raw(fp, my(enc)->elems[i]);
        (void) fprintf(fp, "\n");
    }
}

static void
dummy_enc_set(mmap_enc *const dest, const mmap_enc *const src)
{
    assert(my(dest)->nslots == my(src)->nslots);
    my(dest)->degree = my(src)->degree;
    for (size_t i = 0; i < my(dest)->nslots; ++i) {
        mpz_set(my(dest)->elems[i], my(src)->elems[i]);
    }
}

static void
dummy_enc_add(mmap_enc *const dest, const mmap_ro_pp pp_,
              const mmap_enc *const a, const mmap_enc *const b)
{
    assert(my(dest)->nslots == my(a)->nslots);
    assert(my(dest)->nslots == my(b)->nslots);

    const dummy_pp_t *const pp = pp_;
    my(dest)->degree = max(my(a)->degree, my(b)->degree);
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_add(my(dest)->elems[i], my(a)->elems[i], my(b)->elems[i]);
        mpz_mod(my(dest)->elems[i], my(dest)->elems[i], pp->moduli[i]);
    }
}

static void
dummy_enc_sub(mmap_enc *const dest, const mmap_ro_pp pp_,
              const mmap_enc *const a, const mmap_enc *const b)
{
    assert(my(dest)->nslots == my(a)->nslots);
    assert(my(dest)->nslots == my(b)->nslots);

    const dummy_pp_t *const pp = pp_;
    my(dest)->degree = max(my(a)->degree, my(b)->degree);
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_sub(my(dest)->elems[i], my(a)->elems[i], my(b)->elems[i]);
        mpz_mod(my(dest)->elems[i], my(dest)->elems[i], pp->moduli[i]);
    }
}

static void
dummy_enc_mul(mmap_enc *const dest, const mmap_ro_pp pp_,
              const mmap_enc *const a, const mmap_enc *const b)
{
    assert(my(dest)->nslots == my(a)->nslots);
    assert(my(dest)->nslots == my(b)->nslots);

    const dummy_pp_t *const pp = pp_;
    my(dest)->degree = my(a)->degree + my(b)->degree;
    for (size_t i = 0; i < pp->nslots; ++i) {
        mpz_mul(my(dest)->elems[i], my(a)->elems[i], my(b)->elems[i]);
        mpz_mod(my(dest)->elems[i], my(dest)->elems[i], pp->moduli[i]);
    }
}

static bool
dummy_enc_is_zero(const mmap_enc *const enc, const mmap_ro_pp pp_)
{
    const dummy_pp_t *const pp = pp_;
    bool ret = true;
    assert(my(enc)->degree == pp->kappa);
    for (size_t i = 0; i < pp->nslots; ++i) {
        ret &= (mpz_cmp_ui(my(enc)->elems[i], 0) == 0);
    }
    return ret;
}

static void
dummy_encode(mmap_enc *const enc, const mmap_ro_sk sk_,
             size_t n, const fmpz_t *plaintext, int *group)
{
    const dummy_sk_t *const sk = sk_;
    (void) sk, (void) group;
    assert(n <= sk->nslots);
    my(enc)->degree = 1;
    for (size_t i = 0; i < n; ++i) {
        fmpz_get_mpz(my(enc)->elems[i], plaintext[i]);
    }
}

static void
dummy_print(mmap_enc *const enc)
{
    for (size_t i = 0; i < my(enc)->nslots; ++i) {
        gmp_printf("%Zd ", my(enc)->elems[i]);
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
