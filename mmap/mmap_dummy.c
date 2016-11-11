#include "mmap.h"

struct dummy_pp_t {
    mpz_t *moduli;
    size_t nslots;
};
struct dummy_sk_t {
    mpz_t *moduli;
    size_t nslots;
    size_t nzs;
};
struct dummy_enc_t {
    mpz_t *elems;
    size_t nslots;
};

#define my(sk) (sk)->dummy_self

static const mmap_pp *
dummy_pp_init(const mmap_sk *const sk)
{
    mmap_pp *pp = calloc(1, sizeof(mmap_pp));
    my(pp) = calloc(1, sizeof(dummy_pp_t));
    my(pp)->moduli = calloc(my(sk)->nslots, sizeof(mpz_t));
    for (size_t i = 0; i < my(sk)->nslots; ++i) {
        mpz_init(my(pp)->moduli[i]);
        mpz_set(my(pp)->moduli[i], my(sk)->moduli[i]);
    }
    my(pp)->nslots = my(sk)->nslots;
    return pp;
}

static void
dummy_pp_clear(mmap_pp *pp)
{
    for (size_t i = 0; i < my(pp)->nslots; ++i) {
        mpz_clear(my(pp)->moduli[i]);
    }
    free(my(pp)->moduli);
    free(my(pp));
    free(pp);
}

static void
dummy_pp_read(mmap_pp *const pp, FILE *const fp)
{
    my(pp) = calloc(1, sizeof(dummy_pp_t));
    fscanf(fp, "%lu\n", &my(pp)->nslots);
    my(pp)->moduli = calloc(my(pp)->nslots, sizeof(mpz_t));
    for (size_t i = 0; i < my(pp)->nslots; ++i) {
        mpz_init(my(pp)->moduli[i]);
        mpz_inp_raw(my(pp)->moduli[i], fp);
        (void) fscanf(fp, "\n");
    }
}

static void
dummy_pp_write(const mmap_pp *const pp, FILE *const fp)
{
    fprintf(fp, "%lu\n", my(pp)->nslots);
    for (size_t i = 0; i < my(pp)->nslots; ++i) {
        mpz_out_raw(fp, my(pp)->moduli[i]);
        (void) fprintf(fp, "\n");
    }
}

static const mmap_pp_vtable dummy_pp_vtable =
{ .clear = dummy_pp_clear,
  .fread = dummy_pp_read,
  .fwrite = dummy_pp_write,
  .size = sizeof(mmap_pp)
};

static int
dummy_state_init(mmap_sk *const sk, size_t lambda, size_t kappa, 
                 size_t gamma, int *pows, size_t nslots, size_t ncores,
                 aes_randstate_t rng, bool verbose)
{
    (void) kappa, (void) pows, (void) ncores, (void) verbose;
    if (nslots == 0)
        nslots = 1;
    my(sk) = malloc(sizeof(dummy_sk_t));
    my(sk)->moduli = calloc(nslots, sizeof(mpz_t));
    for (size_t i = 0; i < nslots; ++i) {
        mpz_init(my(sk)->moduli[i]);
        mpz_urandomb_aes(my(sk)->moduli[i], rng, lambda);
        mpz_nextprime(my(sk)->moduli[i], my(sk)->moduli[i]);
    }
    my(sk)->nslots = nslots;
    my(sk)->nzs = gamma;
    return MMAP_OK;
}

static void
dummy_state_clear(mmap_sk *const sk)
{
    for (size_t i = 0; i < my(sk)->nslots; ++i) {
        mpz_clear(my(sk)->moduli[i]);
    }
    free(my(sk)->moduli);
    free(my(sk));
}

static void
dummy_state_read(mmap_sk *const sk, FILE *const fp)
{
    my(sk) = calloc(1, sizeof(dummy_sk_t));
    (void) fscanf(fp, "%lu\n", &my(sk)->nslots);
    my(sk)->moduli = calloc(my(sk)->nslots, sizeof(mpz_t));
    for (size_t i = 0; i < my(sk)->nslots; ++i) {
        mpz_init(my(sk)->moduli[i]);
        mpz_inp_raw(my(sk)->moduli[i], fp);
        (void) fscanf(fp, "\n");
    }
}

static void
dummy_state_write(const mmap_sk *const sk, FILE *const fp)
{
    (void) fprintf(fp, "%lu\n", my(sk)->nslots);
    for (size_t i = 0; i < my(sk)->nslots; ++i) {
        mpz_out_raw(fp, my(sk)->moduli[i]);
        (void) fprintf(fp, "\n");
    }
}

static fmpz_t *
dummy_state_get_moduli(const mmap_sk *const sk)
{
    fmpz_t *moduli;

    moduli = calloc(my(sk)->nslots, sizeof(fmpz_t));
    for (size_t i = 0; i < my(sk)->nslots; ++i) {
        fmpz_init(moduli[i]);
        fmpz_set_mpz(moduli[i], my(sk)->moduli[i]);
    }
    return moduli;
}

static size_t
dummy_state_nslots(const mmap_sk *const sk)
{
    return my(sk)->nslots;
}

static size_t
dummy_state_nzs(const mmap_sk *const sk)
{
    return my(sk)->nzs;
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
dummy_enc_init(mmap_enc *const enc, const mmap_pp *const pp)
{
    my(enc) = calloc(1, sizeof(dummy_enc_t));
    my(enc)->elems = calloc(my(pp)->nslots, sizeof(mpz_t));
    for (size_t i = 0; i < my(pp)->nslots; ++i) {
        mpz_init(my(enc)->elems[i]);
    }
    my(enc)->nslots = my(pp)->nslots;
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
    (void) fprintf(fp, "%lu\n", my(enc)->nslots);
    for (size_t i = 0; i < my(enc)->nslots; ++i) {
        mpz_out_raw(fp, my(enc)->elems[i]);
        (void) fprintf(fp, "\n");
    }
}

static void
dummy_enc_set(mmap_enc *const dest, const mmap_enc *const src)
{
    assert(src->dummy_self->nslots == my(dest)->nslots);
    for (size_t i = 0; i < my(dest)->nslots; ++i) {
        mpz_set(my(dest)->elems[i], my(src)->elems[i]);
    }
}

static void
dummy_enc_add(mmap_enc *const dest, const mmap_pp *const pp,
              const mmap_enc *const a, const mmap_enc *const b)
{
    for (size_t i = 0; i < my(pp)->nslots; ++i) {
        mpz_add(my(dest)->elems[i], my(a)->elems[i], my(b)->elems[i]);
        mpz_mod(my(dest)->elems[i], my(dest)->elems[i], my(pp)->moduli[i]);
    }
}

static void
dummy_enc_sub(mmap_enc *const dest, const mmap_pp *const pp,
              const mmap_enc *const a, const mmap_enc *const b)
{
    for (size_t i = 0; i < my(pp)->nslots; ++i) {
        mpz_sub(my(dest)->elems[i], my(a)->elems[i], my(b)->elems[i]);
        mpz_mod(my(dest)->elems[i], my(dest)->elems[i], my(pp)->moduli[i]);
    }
}

static void
dummy_enc_mul(mmap_enc *const dest, const mmap_pp *const pp,
              const mmap_enc *const a, const mmap_enc *const b)
{
    for (size_t i = 0; i < my(pp)->nslots; ++i) {
        mpz_mul(my(dest)->elems[i], my(a)->elems[i], my(b)->elems[i]);
        mpz_mod(my(dest)->elems[i], my(dest)->elems[i], my(pp)->moduli[i]);
    }
}

static bool
dummy_enc_is_zero(const mmap_enc *const enc, const mmap_pp *const pp)
{
    bool ret = true;
    for (size_t i = 0; i < my(pp)->nslots; ++i) {
        ret &= mpz_cmp_ui(my(enc)->elems[i], 0) == 0;
    }
    return ret;
}

static void
dummy_encode(mmap_enc *const enc, const mmap_sk *const sk,
             size_t n, const fmpz_t *plaintext, int *group)
{
    (void) sk, (void) group;
    assert(n <= my(sk)->nslots);
    for (size_t i = 0; i < n; ++i) {
        fmpz_get_mpz(my(enc)->elems[i], plaintext[i]);
    }
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
  .size = sizeof(dummy_enc_t),
};

const mmap_vtable dummy_vtable =
{ .pp  = &dummy_pp_vtable,
  .sk  = &dummy_sk_vtable,
  .enc = &dummy_enc_vtable,
};
