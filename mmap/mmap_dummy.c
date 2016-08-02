#include "mmap.h"
#include "mmap_dummy.h"

#ifdef __GNUC__
#define __UNUSED__ __attribute__ ((unused))
#else
#define __UNUSED__
#endif

static const mmap_pp *const
dummy_pp_init(const mmap_sk *const sk)
{
    mmap_pp *pp = calloc(1, sizeof(mmap_pp));
    mpz_init_set_ui(pp->dummy_self, 71);
    return pp;
}

static void
dummy_pp_clear(mmap_pp *pp)
{
    mpz_clear(pp->dummy_self);
}

static void
dummy_pp_read(mmap_pp *const pp, FILE *const fp)
{
    mpz_init(pp->dummy_self);
    mpz_inp_raw(pp->dummy_self, fp);
}

static void
dummy_pp_write(const mmap_pp *const pp, FILE *const fp)
{
    mpz_out_raw(fp, pp->dummy_self);
}

static const mmap_pp_vtable dummy_pp_vtable =
{ .clear = dummy_pp_clear,
  .fread = dummy_pp_read,
  .fwrite = dummy_pp_write,
  .size = sizeof(mmap_pp)
};

static void
dummy_state_init(mmap_sk *const sk, size_t lambda, size_t kappa, size_t gamma,
                 aes_randstate_t rng, bool verbose)
{}

static void
dummy_state_clear(mmap_sk *const sk)
{}

static void
dummy_state_read(mmap_sk *const sk __UNUSED__, FILE *const fp __UNUSED__)
{}

static void
dummy_state_write(const mmap_sk *const sk __UNUSED__, FILE *const fp __UNUSED__)
{}

static void
dummy_state_get_modulus(const mmap_sk *const sk __UNUSED__, fmpz_t out)
{
    fmpz_set_ui(out, 71);
}

static const mmap_sk_vtable dummy_sk_vtable =
{ .init = dummy_state_init,
  .clear = dummy_state_clear,
  .fread = dummy_state_read,
  .fwrite = dummy_state_write,
  .pp = dummy_pp_init,
  .size = 0,
  .plaintext_field = dummy_state_get_modulus,
};

static void
dummy_enc_init(mmap_enc *const enc, const mmap_pp *const pp __UNUSED__)
{
    mpz_init(enc->dummy_self);
}

static void
dummy_enc_clear(mmap_enc *const enc)
{
    mpz_clear(enc->dummy_self);
}

static void
dummy_enc_fread(mmap_enc *enc, FILE *const fp)
{
    mpz_init(enc->dummy_self);
    mpz_inp_raw(enc->dummy_self, fp);
}

static void
dummy_enc_fwrite(const mmap_enc *const enc, FILE *const fp)
{
    mpz_out_raw(fp, enc->dummy_self);
}

static void
dummy_enc_set(mmap_enc *const dest, const mmap_enc *const src)
{
    mpz_set(dest->dummy_self, src->dummy_self);
}

static void
dummy_enc_add(mmap_enc *const dest, const mmap_pp *const pp,
              const mmap_enc *const a, const mmap_enc *const b)
{
    mpz_add(dest->dummy_self, a->dummy_self, b->dummy_self);
    mpz_mod(dest->dummy_self, dest->dummy_self, pp->dummy_self);
}

static void
dummy_enc_mul(mmap_enc *const dest, const mmap_pp *const pp,
              const mmap_enc *const a, const mmap_enc *const b)
{
    mpz_mul(dest->dummy_self, a->dummy_self, b->dummy_self);
    mpz_mod(dest->dummy_self, dest->dummy_self, pp->dummy_self);
}

static bool
dummy_enc_is_zero(const mmap_enc *const enc, const mmap_pp *const pp __UNUSED__)
{
    return mpz_cmp_ui(enc->dummy_self, 0) == 0;
}

static void
dummy_encode(mmap_enc *const enc, const mmap_sk *const sk, int n,
             const fmpz_t *plaintext, int *group, aes_randstate_t rng)
{
    fmpz_get_mpz(enc->dummy_self, plaintext[0]);
}

static const mmap_enc_vtable dummy_enc_vtable =
{ .init = dummy_enc_init,
  .clear = dummy_enc_clear,
  .fread = dummy_enc_fread,
  .fwrite = dummy_enc_fwrite,
  .set = dummy_enc_set,
  .add = dummy_enc_add,
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
