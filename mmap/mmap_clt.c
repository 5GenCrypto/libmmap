#include "mmap.h"
#include "mmap_clt.h"

#include <clt13.h>
#include <gmp.h>

static void
clt_pp_free_wrapper(mmap_pp pp)
{
    clt_pp_free(pp);
}

static mmap_pp
clt_pp_fread_wrapper(FILE *fp)
{
    return clt_pp_fread(fp);
}

static int
clt_pp_fwrite_wrapper(const mmap_pp pp, FILE *fp)
{
    return clt_pp_fwrite(pp, fp);
}

static const mmap_pp_vtable clt_pp_vtable =
  { .free  = clt_pp_free_wrapper
  , .fread  = clt_pp_fread_wrapper
  , .fwrite = clt_pp_fwrite_wrapper
  };

static mmap_sk
clt_state_new_wrapper(const mmap_sk_params *params_,
                      const mmap_sk_opt_params *opts_, size_t ncores,
                      aes_randstate_t rng, bool verbose)
{
    clt_state_t *sk;
    bool new_pows = false;
    int *pows;
    int flags = CLT_FLAG_OPT_CRT_TREE | CLT_FLAG_OPT_PARALLEL_ENCODE;
    if (verbose)
        flags |= CLT_FLAG_VERBOSE;

    if (params_ == NULL)
        return NULL;

    pows = params_->pows;
    if (pows == NULL) {
        new_pows = true;
        pows = calloc(params_->gamma, sizeof pows[0]);
        for (size_t i = 0; i < params_->gamma; i++) {
            pows[i] = 1;
        }
    }
    clt_params_t params = {
        .lambda = params_->lambda,
        .kappa = params_->kappa,
        .nzs = params_->gamma,
        .pows = pows,
    };
    clt_opt_params_t opts = {
        .slots = opts_ ? opts_->nslots : 0,
        .moduli = (opts_ && opts_->modulus) ? opts_->modulus : NULL,
        .nmoduli = opts_ && opts_->modulus ? 1 : 0,
    };
    sk = clt_state_new(&params, &opts, ncores, flags, rng);
    if (new_pows)
        free(pows);
    return sk;
}

static void
clt_state_free_wrapper(mmap_sk sk)
{
    clt_state_free(sk);
}

static mmap_sk
clt_state_fread_wrapper(FILE *fp)
{
    return clt_state_fread(fp);
}

static int
clt_state_fwrite_wrapper(const mmap_sk sk, FILE *fp)
{
    return clt_state_fwrite(sk, fp);
}

static mpz_t *
clt_state_get_moduli(const mmap_sk sk)
{
    return clt_state_moduli(sk);
}

static mmap_pp
clt_pp_init_wrapper(const mmap_sk sk)
{
    return clt_pp_new(sk);
}

static size_t
clt_state_nslots_wrapper(const mmap_sk sk)
{
    return clt_state_nslots(sk);
}

static size_t
clt_state_nzs_wrapper(const mmap_sk sk)
{
    return clt_state_nzs(sk);
}

static const
mmap_sk_vtable clt_sk_vtable =
  { .new    = clt_state_new_wrapper
  , .free   = clt_state_free_wrapper
  , .fread  = clt_state_fread_wrapper
  , .fwrite = clt_state_fwrite_wrapper
  , .pp     = clt_pp_init_wrapper
  , .plaintext_fields = clt_state_get_moduli
  , .nslots = clt_state_nslots_wrapper
  , .nzs = clt_state_nzs_wrapper
  };

static mmap_enc
clt_enc_new_wrapper(const mmap_pp pp)
{
    (void) pp;
    return clt_elem_new();
}

static void
clt_enc_free_wrapper(mmap_enc enc)
{
    clt_elem_free(enc);
}

static mmap_enc
clt_enc_fread_wrapper(FILE *fp)
{
    clt_elem_t *enc;
    enc = clt_elem_new();
    clt_elem_fread(enc, fp);
    return enc;
}

static int
clt_enc_fwrite_wrapper(const mmap_enc enc, FILE *fp)
{
    return clt_elem_fwrite(enc, fp);
}

static void
clt_enc_set_wrapper(mmap_enc dest, const mmap_enc src)
{
    clt_elem_set(dest, src);
}

static int
clt_enc_add_wrapper(mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b)
{
    return clt_elem_add(dest, pp, a, b);
}

static int
clt_enc_sub_wrapper(const mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b)
{
    return clt_elem_sub(dest, pp, a, b);
}

static int
clt_enc_mul_wrapper(const mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b)
{
    return clt_elem_mul(dest, pp, a, b);
}

static bool
clt_enc_is_zero_wrapper(const mmap_enc enc, const mmap_pp pp)
{
    return clt_is_zero(enc, pp);
}

static int
clt_encode_wrapper(mmap_enc enc, const mmap_sk sk, size_t n, mpz_t *plaintext, int *pows, size_t level)
{
    (void) level;
    return clt_encode(enc, sk, n, plaintext, pows);
}

static void
clt_print_wrapper(const mmap_enc enc)
{
    clt_elem_print(enc);
}

static const mmap_enc_vtable clt_enc_vtable =
  { .new     = clt_enc_new_wrapper
  , .free    = clt_enc_free_wrapper
  , .fread   = clt_enc_fread_wrapper
  , .fwrite  = clt_enc_fwrite_wrapper
  , .set     = clt_enc_set_wrapper
  , .add     = clt_enc_add_wrapper
  , .sub     = clt_enc_sub_wrapper
  , .mul     = clt_enc_mul_wrapper
  , .is_zero = clt_enc_is_zero_wrapper
  , .encode  = clt_encode_wrapper
  , .degree  = NULL
  , .print   = clt_print_wrapper
  };

const mmap_vtable clt_vtable =
  { .pp  = &clt_pp_vtable
  , .sk  = &clt_sk_vtable
  , .enc = &clt_enc_vtable
  };
