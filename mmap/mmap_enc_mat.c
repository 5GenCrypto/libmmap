#include "mmap.h"
#include <assert.h>

void
mmap_enc_mat_init(const_mmap_vtable mmap, const mmap_pp params,
                  mmap_enc_mat_t m, int nrows, int ncols)
{
    m->nrows = nrows;
    m->ncols = ncols;
    m->m = malloc(nrows * sizeof(mmap_enc *));
    assert(m->m);
    for(int i = 0; i < m->nrows; i++) {
        m->m[i] = malloc(m->ncols * sizeof(mmap_enc));
        assert(m->m[i]);
        for(int j = 0; j < m->ncols; j++) {
            m->m[i][j] = mmap->enc->new(params);
        }
    }
}

void
mmap_enc_mat_clear(const_mmap_vtable mmap, mmap_enc_mat_t m)
{
    for(int i = 0; i < m->nrows; i++) {
        for(int j = 0; j < m->ncols; j++) {
            mmap->enc->free(m->m[i][j]);
        }
        free(m->m[i]);
    }
    free(m->m);
}


void
mmap_enc_mat_mul(const_mmap_vtable mmap, const mmap_pp params,
                 mmap_enc_mat_t r, mmap_enc_mat_t m1, mmap_enc_mat_t m2)
{
    mmap_enc tmp;
    mmap_enc_mat_t tmp_mat;

    tmp = mmap->enc->new(params);

    mmap_enc_mat_init(mmap, params, tmp_mat, m1->nrows, m2->ncols);

    assert(m1->ncols == m2->nrows);

    for(int i = 0; i < m1->nrows; i++) {
        for(int j = 0; j < m2->ncols; j++) {
            for(int k = 0; k < m1->ncols; k++) {
                mmap->enc->mul(tmp, params, m1->m[i][k], m2->m[k][j]);
                mmap->enc->add(tmp_mat->m[i][j], params, tmp_mat->m[i][j], tmp);
            }
        }
    }

    mmap_enc_mat_clear(mmap, r);
    mmap_enc_mat_init(mmap, params, r, m1->nrows, m2->ncols);

    for(int i = 0; i < r->nrows; i++) {
        for(int j = 0; j < r->ncols; j++) {
            mmap->enc->set(r->m[i][j], tmp_mat->m[i][j]);
        }
    }

    mmap_enc_mat_clear(mmap, tmp_mat);
    mmap->enc->free(tmp);
}

void
mmap_enc_mat_mul_par(const_mmap_vtable mmap, const mmap_pp params,
                     mmap_enc_mat_t r, mmap_enc_mat_t m1, mmap_enc_mat_t m2)
{
    mmap_enc_mat_t tmp_mat;

    mmap_enc_mat_init(mmap, params, tmp_mat, m1->nrows, m2->ncols);

    assert(m1->ncols == m2->nrows);

#pragma omp parallel for schedule(dynamic,1) collapse(2)
    for(int i = 0; i < m1->nrows; i++) {
        for(int j = 0; j < m2->ncols; j++) {
            for(int k = 0; k < m1->ncols; k++) {
                mmap_enc *tmp;
                tmp = mmap->enc->new(params);
                mmap->enc->mul(tmp, params, m1->m[i][k], m2->m[k][j]);
                mmap->enc->add(tmp_mat->m[i][j], params, tmp_mat->m[i][j], tmp);
                mmap->enc->free(tmp);
            }
        }
    }

    mmap_enc_mat_clear(mmap, r);
    mmap_enc_mat_init(mmap, params, r, m1->nrows, m2->ncols);

    for(int i = 0; i < r->nrows; i++) {
        for(int j = 0; j < r->ncols; j++) {
            mmap->enc->set(r->m[i][j], tmp_mat->m[i][j]);
        }
    }

    mmap_enc_mat_clear(mmap, tmp_mat);
}
