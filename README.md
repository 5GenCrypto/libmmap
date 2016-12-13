# libmmap - Multilinear map library

`libmmap` provides a unified API for multilinear map operations and three implementations of the API. The API is organized in an object-oriented style. There are three objects of interest:

* Secret keys
* Public parameters/keys
* Encodings

The general flow for using these operations is to do a key generation operation, which produces both a secret key and a public key; use the secret key to produce some encodings; then use the public key to do arithmetic and zero-testing on the encodings. Our library also provides some facilities for disk serialization and deserialization.

There are three extant implementations of the API, backed by the gghlite library, the libclt library, and an insecure dummy implementation which stores and operates on plaintexts intended for debugging use only.

Encodings are implicitly associated with a bag of tags, and there is a fixed bag at which zero-tests can be performed. We represent a bag as an `int *`: the tags in the bags are indices in this array, and the values at those indices are the multiplicities. Thus, for example, the array `(int[]) { 3, 0, 1 }` represents a bag over a three-tag universe, with tag 0 having multiplicity 3, tag 1 having multiplicity 0, and tag 2 having multiplicity 1.

## Object system

We use a simplified object-oriented-like system. Each object consists of a C struct (which should be viewed as opaque to consumers of the API) together with a vtable containing function pointers (which are permitted to poke at the internals of the struct). For example, the public key object is modeled by this snippet from [`mmap.h`](mmap/mmap.h):

    typedef void *mmap_pp;
    typedef const void *mmap_ro_pp;

    typedef struct {
      void (*const clear)(mmap_pp);
      void (*const fread)(mmap_pp, FILE *);
      void (*const fwrite)(mmap_ro_pp, FILE *);
      const size_t size;
    } mmap_pp_vtable;

Thus public keys support writing to disk (via `fwrite`), reading from disk (via `fread`), and destruction (via `clear`). By convention, the first argument to each method is the instance to invoke that method on.

Some methods are common to several different objects:

* `size` (not actually a method, but a field common to all objects) tells how many bytes the associated struct takes. Implementors of a vtable should set this with an appropriate `sizeof` expression.
* `init` initializes an instance from the remaining arguments.
* `clear` destroys an instance, deallocating any memory reserved during `init` or other operations.
* `fread` initializes an instance from disk. For simplicity, it exits the program if parsing fails.
* `fwrite` serializes an instance to disk.

Users of an object follow this protocol:

1. Use `malloc` or similar to reserve a chunk of at least `size` bytes.
2. Use `init` or `fread` to initialize the structure contents sensibly.
3. Use other operations provided by the vtable.
4. Use `clear` to dispose of the structure contents.
5. Use `free` to release the chunk of bytes from step 1.

Implementors of a vtable may therefore assume that object instances passed to them are pointers to an appropriately sized chunk of bytes, and that the object instances are sensibly initialized unless we are currently calling `init` or `fread`.

## Public keys

Public keys have no object-specific methods; they exist primarily to be parameters to other objects' methods.

Additionally, they have no `init` method, and so some public keys should not be `clear`ed! In particular, public keys read from disk with `fread` should be, but public keys retrieved from a private key via the private key's `pp` method should not be `clear`ed and should not be used after their associated secret key is `clear`ed.

The full interface is given in `mmap/mmap.h` by `mmap_pp_vtable`:

    typedef struct {
      void (*const clear)(mmap_pp);
      void (*const fread)(mmap_pp, FILE *);
      void (*const fwrite)(mmap_ro_pp, FILE *);
      const size_t size;
    } mmap_pp_vtable;

## Private keys

Private keys offer key generation via their `init` operation, which has this type:

    int (*const init)(mmap_sk, size_t, size_t, size_t, int *, size_t, size_t, aes_randstate_t, bool);

The arguments to this method are:
* the security parameter (lambda),
* how many multiplications need to be supported (kappa),
* the number of tags in the universe that the zero-test operates at (gamma),
* the universe that the zero-test operates at, or pass `NULL` for the bag that contains each tag once,
* how many plaintexts each encoding must be able to store,
* how much parallelism to use,
* a random seed (which will be modified in-place during the method call), and
* a verbosity level.

The return value is one of `MMAP_OK` or `MMAP_ERR` indicating whether the requested parameters were supported by the multilinear map implementation.

The `pp` method returns the associated public key. As noted in the section on public keys, the public keys acquired from this method (rather than via the public key's `fread` method) should not be `clear`ed (and implementors of a secret key object's `clear` method are responsible for making sure any data in the `pp` returned from this method is also `clear`ed).

Although you ask for encodings to be able to store a certain number of plaintexts during initialization, the actual encoding may be able to store more plaintexts than requested. You can ask how many plaintexts you can store with the `nslots` query.

By assumption, a single collection of plaintexts to be encoded with this key are drawn from Z/p1 x ... x Z/pk for some primes p1, ..., pk, where k is the number returned by `nslots`. You can ask what the values of the primes p1, ..., pk are via the `plaintext_fields` method. The caller is responsible for `free`ing the array of numbers returned from this method.

You can ask about the `gamma` parameter sent to the `init` method with the `nzs` method.

The full interface is given by `mmap_sk_vtable`:

    typedef struct {
      int (*const init)(mmap_sk, size_t, size_t, size_t, int *, size_t, size_t, aes_randstate_t, bool);
      void (*const clear)(mmap_sk);
      void (*const fread)(mmap_sk, FILE *);
      void (*const fwrite)(mmap_ro_sk, FILE *);
      const size_t size;

      mmap_ro_pp (*const pp)(mmap_ro_sk);
      fmpz_t * (*const plaintext_fields)(mmap_ro_sk);
      size_t (*const nslots)(mmap_ro_sk);
      size_t (*const nzs)(mmap_ro_sk);
    } mmap_sk_vtable;

## Encodings

Encodings can be added (with `add`), multiplied (with `mul`), and copied (with `set`). In all cases, the instance supplied as the first parameter is overwritten with the result of the operation. Zero-testing can be performed with the `is_zero` method.

It is assumed that the encodings passed to `add` have the same set of tags (in which case the result will also have this set of tags), and that the encodings passed to `mul` have disjoint sets of tags (in which case the result will be tagged with the union of these two sets). This property is not checked.

If you have access to the secret key, you can also produce fresh encodings of plaintexts with the `encode` method, which has this type:

    void (*const encode)(mmap_enc, mmap_ro_sk, size_t, const fmpz_t *, int *);

The arguments to this method are:

* the secret key,
* the number of plaintext slots to encode (assuming the backend supports multiple-slot plaintexts), which must not exceed the number of slots available in this key (see `nslots` above),
* the plaintext slots themselves in an array whose length is given by the previous argument, and
* an array of `0`s and `1`s as long as the universe specified during key generation, telling which tags in the universe should be applied to the encoding.

The full interface is given by `mmap_enc_vtable`:

    typedef struct {
      void (*const init)(mmap_enc, mmap_ro_pp);
      void (*const clear)(mmap_enc);
      void (*const fread)(mmap_enc, FILE *);
      void (*const fwrite)(mmap_ro_enc, FILE *);
      const size_t size;

      void (*const set)(mmap_enc, mmap_ro_enc);
      void (*const add)(mmap_enc, mmap_ro_pp, mmap_ro_enc, mmap_ro_enc);
      void (*const sub)(mmap_enc, mmap_ro_pp, mmap_ro_enc, mmap_ro_enc);
      void (*const mul)(mmap_enc, mmap_ro_pp, mmap_ro_enc, mmap_ro_enc);
      bool (*const is_zero)(mmap_ro_enc, mmap_ro_pp);
      void (*const encode)(mmap_enc, mmap_ro_sk, size_t, const fmpz_t *, int *);
    } mmap_enc_vtable;

## Miscellaneous

For convenience, we provide a top-level `mmap_vtable` type which contains a vtable for each kind of object. The three extant implementations each provide a value of this type: [`mmap_clt.h`](mmap/mmap_clt.h) provides `clt_vtable`, [`mmap_gghlite.h`](mmap/mmap_gghlite.h) provides `gghlite_vtable`, and [`mmap_dummy.h`](mmap/mmap_dummy.h) provides `dummy_vtable`.

We also implement a few matrix-like operations on encodings. The implementation uses the naive O(m\*n\*p) algorithm for multiplication, calling the encoding object's `mul` and `add` methods as appropriate. For historical reasons, the interface to these operations does not use the object-oriented style described above. The `mmap.h` header has the complete interface, which includes little more than the `init`, `clear`, and `mul` methods one might expect:

    struct _mmap_enc_mat_struct {
      int nrows; // number of rows in the matrix
      int ncols; // number of columns in the matrix
      mmap_enc **m;
    };
    typedef struct _mmap_enc_mat_struct mmap_enc_mat_t[1];

    void
    mmap_enc_mat_init(const_mmap_vtable mmap, const mmap_ro_pp params,
                      mmap_enc_mat_t m, int nrows, int ncols);
    void
    mmap_enc_mat_clear(const_mmap_vtable mmap, mmap_enc_mat_t m);
    void
    mmap_enc_mat_mul(const_mmap_vtable mmap, const mmap_ro_pp params,
                     mmap_enc_mat_t r, mmap_enc_mat_t m1, mmap_enc_mat_t m2);
    void
    mmap_enc_mat_mul_par(const_mmap_vtable mmap, const mmap_ro_pp params,
                         mmap_enc_mat_t r, mmap_enc_mat_t m1, mmap_enc_mat_t m2);
