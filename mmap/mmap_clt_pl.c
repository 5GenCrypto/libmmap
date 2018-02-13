#include "mmap.h"
#include "mmap_clt_pl.h"

#include <clt_pl.h>
#include <gmp.h>

static void
pp_free(mmap_pp pp)
{
    clt_pl_pp_free(pp);
}

static mmap_pp
pp_fread(FILE *fp)
{
    return clt_pl_pp_fread(fp);
}

static int
pp_fwrite(const mmap_pp pp, FILE *fp)
{
    return clt_pl_pp_fwrite(pp, fp);
}

static const mmap_pp_vtable clt_pl_pp_vtable =
  { .free   = pp_free
  , .fread  = pp_fread
  , .fwrite = pp_fwrite
  };

static mmap_sk
state_new(const mmap_sk_params *params_,
          const mmap_sk_opt_params *opts_, size_t ncores,
          aes_randstate_t rng, bool verbose)
{
    clt_pl_state_t *sk;
    bool new_pows = false;
    int *pows;
    int flags = CLT_PL_FLAG_NONE;
    if (verbose)
        flags |= CLT_PL_FLAG_VERBOSE;

    if (params_ == NULL)
        return NULL;
    if (opts_ == NULL || opts_->is_polylog == false) {
        fprintf(stderr, "error: must specify polylog optional parameters\n");
        return NULL;
    }

    pows = params_->pows;
    if (pows == NULL) {
        new_pows = true;
        pows = calloc(params_->gamma, sizeof pows[0]);
        for (size_t i = 0; i < params_->gamma; i++) {
            pows[i] = 1;
        }
    }
    clt_pl_params_t params = {
        .lambda = params_->lambda,
        .nlevels = opts_->polylog.nlevels,
        .nswitches = opts_->polylog.nswitches,
        .sparams = (switch_params_t **) opts_->polylog.sparams,
        .nzs = params_->gamma,
        .pows = pows,
    };
    clt_pl_opt_params_t opts = {
        .slots = opts_ ? opts_->nslots : 0,
        .moduli = (opts_ && opts_->modulus) ? opts_->modulus : NULL,
        .nmoduli = opts_ && opts_->modulus ? 1 : 0,
        .wordsize = opts_->polylog.wordsize,
    };
    sk = clt_pl_state_new(&params, &opts, ncores, flags, rng);
    if (new_pows)
        free(pows);
    return sk;
}

static void
state_free(mmap_sk sk)
{
    clt_pl_state_free(sk);
}

static mmap_sk
state_fread(FILE *fp)
{
    return clt_pl_state_fread(fp);
}

static int
state_fwrite(const mmap_sk sk, FILE *fp)
{
    return clt_pl_state_fwrite(sk, fp);
}

static mpz_t *
state_get_moduli(const mmap_sk sk)
{
    return clt_pl_state_moduli(sk);
}

static mmap_pp
pp_new(const mmap_sk sk)
{
    return clt_pl_pp_new(sk);
}

static size_t
state_nslots(const mmap_sk sk)
{
    return clt_pl_state_nslots(sk);
}

static size_t
state_nzs(const mmap_sk sk)
{
    return clt_pl_state_nzs(sk);
}

static const
mmap_sk_vtable clt_pl_sk_vtable =
  { .new    = state_new
  , .free   = state_free
  , .fread  = state_fread
  , .fwrite = state_fwrite
  , .pp     = pp_new
  , .plaintext_fields = state_get_moduli
  , .nslots = state_nslots
  , .nzs    = state_nzs
  };

static mmap_enc
enc_new(const mmap_pp pp)
{
    (void) pp;
    return clt_elem_new();
}

static void
enc_free(mmap_enc enc)
{
    clt_elem_free(enc);
}

static mmap_enc
enc_fread(FILE *fp)
{
    clt_elem_t *enc;

    enc = clt_elem_new();
    clt_elem_fread(enc, fp);
    return enc;
}

static int
enc_fwrite(const mmap_enc enc, FILE *fp)
{
    return clt_elem_fwrite(enc, fp);
}

static void
enc_set(mmap_enc dest, const mmap_enc src)
{
    clt_elem_set(dest, src);
}

static int
enc_add(mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b)
{
    return clt_pl_elem_add(dest, pp, a, b);
}

static int
enc_sub(const mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b)
{
    return clt_pl_elem_sub(dest, pp, a, b);
}

static int
enc_mul(const mmap_enc dest, const mmap_pp pp, const mmap_enc a, const mmap_enc b)
{
    return clt_pl_elem_mul(dest, pp, a, b);
}

static bool
enc_is_zero(const mmap_enc enc, const mmap_pp pp)
{
    return clt_pl_is_zero(enc, pp);
}

static int
encode(mmap_enc enc, const mmap_sk sk, size_t n, const mpz_t *plaintext, const int *pows, size_t level)
{
    clt_pl_encode_params_t args = { .ix = pows, .level = level };
    return clt_pl_encode(enc, sk, n, (mpz_t *) plaintext, &args); /* XXX */
}

static void
enc_print(const mmap_enc enc)
{
    clt_elem_print(enc);
}

static const mmap_enc_vtable clt_pl_enc_vtable =
  { .new     = enc_new
  , .free    = enc_free
  , .fread   = enc_fread
  , .fwrite  = enc_fwrite
  , .set     = enc_set
  , .add     = enc_add
  , .sub     = enc_sub
  , .mul     = enc_mul
  , .is_zero = enc_is_zero
  , .encode  = encode
  , .degree  = NULL
  , .print   = enc_print
  };

const mmap_vtable clt_pl_vtable =
  { .pp  = &clt_pl_pp_vtable
  , .sk  = &clt_pl_sk_vtable
  , .enc = &clt_pl_enc_vtable
  };
