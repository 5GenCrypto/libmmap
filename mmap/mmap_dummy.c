#include "mmap.h"

#ifdef __GNUC__
#define __UNUSED__ __attribute__ ((unused))
#else
#define __UNUSED__
#endif

static const mmap_pp *
dummy_pp_init(const mmap_sk *const sk)
{
    mmap_pp *pp = calloc(1, sizeof(mmap_pp));
    pp->dummy_self.moduli = calloc(2, sizeof(mpz_t));
    for (int i = 0; i < 2; ++i) {
        mpz_init(pp->dummy_self.moduli[i]);
        mpz_set(pp->dummy_self.moduli[i], sk->dummy_self.moduli[i]);
    }
    return pp;
}

static void
dummy_pp_clear(mmap_pp *pp)
{
    for (int i = 0; i < 2; ++i) {
        mpz_clear(pp->dummy_self.moduli[i]);
    }
    free(pp->dummy_self.moduli);
    free(pp);
}

static void
dummy_pp_read(mmap_pp *const pp, FILE *const fp)
{
    pp->dummy_self.moduli = calloc(2, sizeof(mpz_t));
    for (int i = 0; i < 2; ++i) {
        mpz_init(pp->dummy_self.moduli[i]);
        mpz_inp_raw(pp->dummy_self.moduli[i], fp);
    }
}

static void
dummy_pp_write(const mmap_pp *const pp, FILE *const fp)
{
    for (int i = 0; i < 2; ++i) {
        mpz_out_raw(fp, pp->dummy_self.moduli[i]);
    }
}

static const mmap_pp_vtable dummy_pp_vtable =
{ .clear = dummy_pp_clear,
  .fread = dummy_pp_read,
  .fwrite = dummy_pp_write,
  .size = sizeof(mmap_pp)
};

static void
dummy_state_init(mmap_sk *const sk, size_t lambda,
                 size_t kappa, size_t gamma, int *pows,
                 unsigned long ncores, aes_randstate_t rng,
                 bool verbose)
{
    sk->dummy_self.moduli = calloc(2, sizeof(mpz_t));
    for (int i = 0; i < 2; ++i) {
        mpz_init(sk->dummy_self.moduli[i]);
        mpz_urandomb_aes(sk->dummy_self.moduli[i], rng, lambda);
    }
}

static void
dummy_state_clear(mmap_sk *const sk)
{
    for (int i = 0; i < 2; ++i) {
        mpz_clear(sk->dummy_self.moduli[i]);
    }
    free(sk->dummy_self.moduli);
}

static void
dummy_state_read(mmap_sk *const sk, FILE *const fp)
{
    sk->dummy_self.moduli = calloc(2, sizeof(mpz_t));
    for (int i = 0; i < 2; ++i) {
        mpz_init(sk->dummy_self.moduli[i]);
        mpz_inp_raw(sk->dummy_self.moduli[i], fp);
        (void) fscanf(fp, "\n");
    }
}

static void
dummy_state_write(const mmap_sk *const sk, FILE *const fp)
{
    for (int i = 0; i < 2; ++i) {
        mpz_out_raw(fp, sk->dummy_self.moduli[i]);
        (void) fprintf(fp, "\n");
    }
}

static fmpz_t *
dummy_state_get_moduli(const mmap_sk *const sk)
{
    fmpz_t *moduli;

    moduli = calloc(2, sizeof(fmpz_t));
    for (int i = 0; i < 2; ++i) {
        fmpz_init(moduli[i]);
        fmpz_set_mpz(moduli[i], sk->dummy_self.moduli[i]);
    }
    return moduli;
}

static size_t
dummy_state_nslots(const mmap_sk *const sk __attribute__ ((unused)))
{
    return 2;
}

static const mmap_sk_vtable dummy_sk_vtable =
{ .init = dummy_state_init,
  .clear = dummy_state_clear,
  .fread = dummy_state_read,
  .fwrite = dummy_state_write,
  .pp = dummy_pp_init,
  .size = 0,
  .plaintext_fields = dummy_state_get_moduli,
  .nslots = dummy_state_nslots,
};

static void
dummy_enc_init(mmap_enc *const enc, const mmap_pp *const pp)
{
    (void) pp;
    enc->dummy_self.elems = calloc(2, sizeof(mpz_t));
    for (int i = 0; i < 2; ++i) {
        mpz_init(enc->dummy_self.elems[i]);
    }
}

static void
dummy_enc_clear(mmap_enc *const enc)
{
    for (int i = 0; i < 2; ++i) {
        mpz_clear(enc->dummy_self.elems[i]);
    }
}

static void
dummy_enc_fread(mmap_enc *enc, FILE *const fp)
{
    for (int i = 0; i < 2; ++i) {
        mpz_init(enc->dummy_self.elems[i]);
        mpz_inp_raw(enc->dummy_self.elems[i], fp);
    }
}

static void
dummy_enc_fwrite(const mmap_enc *const enc, FILE *const fp)
{
    for (int i = 0; i < 2; ++i) {
        mpz_out_raw(fp, enc->dummy_self.elems[i]);
    }
}

static void
dummy_enc_set(mmap_enc *const dest, const mmap_enc *const src)
{
    for (int i = 0; i < 2; ++i) {
        mpz_set(dest->dummy_self.elems[i], src->dummy_self.elems[i]);
    }
}

static void
dummy_enc_add(mmap_enc *const dest, const mmap_pp *const pp,
              const mmap_enc *const a, const mmap_enc *const b)
{
    for (int i = 0; i < 2; ++i) {
        mpz_add(dest->dummy_self.elems[i], a->dummy_self.elems[i], b->dummy_self.elems[i]);
        mpz_mod(dest->dummy_self.elems[i], dest->dummy_self.elems[i], pp->dummy_self.moduli[i]);
    }
}

static void
dummy_enc_sub(mmap_enc *const dest, const mmap_pp *const pp,
              const mmap_enc *const a, const mmap_enc *const b)
{
    for (int i = 0; i < 2; ++i) {
        mpz_sub(dest->dummy_self.elems[i], a->dummy_self.elems[i], b->dummy_self.elems[i]);
        mpz_mod(dest->dummy_self.elems[i], dest->dummy_self.elems[i], pp->dummy_self.moduli[i]);
    }
}

static void
dummy_enc_mul(mmap_enc *const dest, const mmap_pp *const pp,
              const mmap_enc *const a, const mmap_enc *const b)
{
    for (int i = 0; i < 2; ++i) {
        mpz_mul(dest->dummy_self.elems[i], a->dummy_self.elems[i], b->dummy_self.elems[i]);
        mpz_mod(dest->dummy_self.elems[i], dest->dummy_self.elems[i], pp->dummy_self.moduli[i]);
    }
}

static bool
dummy_enc_is_zero(const mmap_enc *const enc, const mmap_pp *const pp __UNUSED__)
{
    bool ret = true;
    for (int i = 0; i < 2; ++i) {
        ret &= mpz_cmp_ui(enc->dummy_self.elems[i], 0) == 0;
    }
    return ret;
}

static void
dummy_encode(mmap_enc *const enc, const mmap_sk *const sk,
             int n, const fmpz_t *plaintext, int *group)
{
    assert(n <= 2);
    for (int i = 0; i < n; ++i) {
        fmpz_get_mpz(enc->dummy_self.elems[i], plaintext[i]);        
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
  .size = sizeof(mmap_enc),
};

const mmap_vtable dummy_vtable =
{ .pp  = &dummy_pp_vtable,
  .sk  = &dummy_sk_vtable,
  .enc = &dummy_enc_vtable,
};
