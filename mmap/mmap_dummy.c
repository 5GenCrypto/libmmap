#include "mmap.h"

static const mmap_pp *
dummy_pp_init(const mmap_sk *const sk)
{
    mmap_pp *pp = calloc(1, sizeof(mmap_pp));
    pp->dummy_self.moduli = calloc(sk->dummy_self.nslots, sizeof(mpz_t));
    for (size_t i = 0; i < sk->dummy_self.nslots; ++i) {
        mpz_init(pp->dummy_self.moduli[i]);
        mpz_set(pp->dummy_self.moduli[i], sk->dummy_self.moduli[i]);
    }
    pp->dummy_self.nslots = sk->dummy_self.nslots;
    return pp;
}

static void
dummy_pp_clear(mmap_pp *pp)
{
    for (size_t i = 0; i < pp->dummy_self.nslots; ++i) {
        mpz_clear(pp->dummy_self.moduli[i]);
    }
    free(pp->dummy_self.moduli);
    free(pp);
}

static void
dummy_pp_read(mmap_pp *const pp, FILE *const fp)
{
    fscanf(fp, "%lu\n", &pp->dummy_self.nslots);
    pp->dummy_self.moduli = calloc(pp->dummy_self.nslots, sizeof(mpz_t));
    for (size_t i = 0; i < pp->dummy_self.nslots; ++i) {
        mpz_init(pp->dummy_self.moduli[i]);
        mpz_inp_raw(pp->dummy_self.moduli[i], fp);
        (void) fscanf(fp, "\n");
    }
}

static void
dummy_pp_write(const mmap_pp *const pp, FILE *const fp)
{
    fprintf(fp, "%lu\n", pp->dummy_self.nslots);
    for (size_t i = 0; i < pp->dummy_self.nslots; ++i) {
        mpz_out_raw(fp, pp->dummy_self.moduli[i]);
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
dummy_state_init(mmap_sk *const sk, size_t lambda, size_t kappa, size_t nslots,
                 size_t gamma, int *pows, unsigned long ncores,
                 aes_randstate_t rng, bool verbose)
{
    (void) kappa, (void) gamma, (void) pows, (void) ncores, (void) verbose;
    if (nslots == 0)
        nslots = 1;
    sk->dummy_self.moduli = calloc(nslots, sizeof(mpz_t));
    for (size_t i = 0; i < nslots; ++i) {
        mpz_init(sk->dummy_self.moduli[i]);
        mpz_urandomb_aes(sk->dummy_self.moduli[i], rng, lambda);
    }
    sk->dummy_self.nslots = nslots;
    return MMAP_OK;
}

static void
dummy_state_clear(mmap_sk *const sk)
{
    for (size_t i = 0; i < sk->dummy_self.nslots; ++i) {
        mpz_clear(sk->dummy_self.moduli[i]);
    }
    free(sk->dummy_self.moduli);
}

static void
dummy_state_read(mmap_sk *const sk, FILE *const fp)
{
    (void) fscanf(fp, "%lu\n", &sk->dummy_self.nslots);
    sk->dummy_self.moduli = calloc(sk->dummy_self.nslots, sizeof(mpz_t));
    for (size_t i = 0; i < sk->dummy_self.nslots; ++i) {
        mpz_init(sk->dummy_self.moduli[i]);
        mpz_inp_raw(sk->dummy_self.moduli[i], fp);
        (void) fscanf(fp, "\n");
    }
}

static void
dummy_state_write(const mmap_sk *const sk, FILE *const fp)
{
    (void) fprintf(fp, "%lu\n", sk->dummy_self.nslots);
    for (size_t i = 0; i < sk->dummy_self.nslots; ++i) {
        mpz_out_raw(fp, sk->dummy_self.moduli[i]);
        (void) fprintf(fp, "\n");
    }
}

static fmpz_t *
dummy_state_get_moduli(const mmap_sk *const sk)
{
    fmpz_t *moduli;

    moduli = calloc(sk->dummy_self.nslots, sizeof(fmpz_t));
    for (size_t i = 0; i < sk->dummy_self.nslots; ++i) {
        fmpz_init(moduli[i]);
        fmpz_set_mpz(moduli[i], sk->dummy_self.moduli[i]);
    }
    return moduli;
}

static size_t
dummy_state_nslots(const mmap_sk *const sk)
{
    return sk->dummy_self.nslots;
}

static size_t
dummy_state_nzs(const mmap_sk *const sk)
{
    (void) sk;
    return 50;                  /* TODO: fixme */
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
    enc->dummy_self.elems = calloc(pp->dummy_self.nslots, sizeof(mpz_t));
    for (size_t i = 0; i < pp->dummy_self.nslots; ++i) {
        mpz_init(enc->dummy_self.elems[i]);
    }
    enc->dummy_self.nslots = pp->dummy_self.nslots;
}

static void
dummy_enc_clear(mmap_enc *const enc)
{
    for (size_t i = 0; i < enc->dummy_self.nslots; ++i) {
        mpz_clear(enc->dummy_self.elems[i]);
    }
}

static void
dummy_enc_fread(mmap_enc *enc, FILE *const fp)
{
    for (size_t i = 0; i < enc->dummy_self.nslots; ++i) {
        mpz_inp_raw(enc->dummy_self.elems[i], fp);
        (void) fscanf(fp, "\n");
    }
    (void) fscanf(fp, "%lu\n", &enc->dummy_self.nslots);
}

static void
dummy_enc_fwrite(const mmap_enc *const enc, FILE *const fp)
{
    for (size_t i = 0; i < enc->dummy_self.nslots; ++i) {
        mpz_out_raw(fp, enc->dummy_self.elems[i]);
        (void) fprintf(fp, "\n");
    }
    (void) fprintf(fp, "%lu\n", enc->dummy_self.nslots);
}

static void
dummy_enc_set(mmap_enc *const dest, const mmap_enc *const src)
{
    assert(src->dummy_self.nslots == dest->dummy_self.nslots);
    for (size_t i = 0; i < dest->dummy_self.nslots; ++i) {
        mpz_set(dest->dummy_self.elems[i], src->dummy_self.elems[i]);
    }
}

static void
dummy_enc_add(mmap_enc *const dest, const mmap_pp *const pp,
              const mmap_enc *const a, const mmap_enc *const b)
{
    for (size_t i = 0; i < pp->dummy_self.nslots; ++i) {
        mpz_add(dest->dummy_self.elems[i], a->dummy_self.elems[i], b->dummy_self.elems[i]);
        mpz_mod(dest->dummy_self.elems[i], dest->dummy_self.elems[i], pp->dummy_self.moduli[i]);
    }
}

static void
dummy_enc_sub(mmap_enc *const dest, const mmap_pp *const pp,
              const mmap_enc *const a, const mmap_enc *const b)
{
    for (size_t i = 0; i < pp->dummy_self.nslots; ++i) {
        mpz_sub(dest->dummy_self.elems[i], a->dummy_self.elems[i], b->dummy_self.elems[i]);
        mpz_mod(dest->dummy_self.elems[i], dest->dummy_self.elems[i], pp->dummy_self.moduli[i]);
    }
}

static void
dummy_enc_mul(mmap_enc *const dest, const mmap_pp *const pp,
              const mmap_enc *const a, const mmap_enc *const b)
{
    for (size_t i = 0; i < pp->dummy_self.nslots; ++i) {
        mpz_mul(dest->dummy_self.elems[i], a->dummy_self.elems[i], b->dummy_self.elems[i]);
        mpz_mod(dest->dummy_self.elems[i], dest->dummy_self.elems[i], pp->dummy_self.moduli[i]);
    }
}

static bool
dummy_enc_is_zero(const mmap_enc *const enc, const mmap_pp *const pp)
{
    bool ret = true;
    for (size_t i = 0; i < pp->dummy_self.nslots; ++i) {
        ret &= mpz_cmp_ui(enc->dummy_self.elems[i], 0) == 0;
    }
    return ret;
}

static void
dummy_encode(mmap_enc *const enc, const mmap_sk *const sk,
             size_t n, const fmpz_t *plaintext, int *group)
{
    (void) sk, (void) group;
    assert(n <= sk->dummy_self.nslots);
    for (size_t i = 0; i < n; ++i) {
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
  .size = sizeof(dummy_enc_t),
};

const mmap_vtable dummy_vtable =
{ .pp  = &dummy_pp_vtable,
  .sk  = &dummy_sk_vtable,
  .enc = &dummy_enc_vtable,
};
