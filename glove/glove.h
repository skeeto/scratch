// This is free and unencumbered software released into the public domain.
#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t  db_size;
    int32_t num_words;
    int32_t num_dims;
    int32_t _reserved1[1];
} glove_specs;

typedef struct {
    int32_t  num_words;
    int32_t  num_dims;
    int32_t  _reserved1[1];
    void    *_reserved2[4];
} glove;

// Compute parameters for the dataset, including the database size for
// the caller to allocate. The size is zero if the input is too large
// for a database.
void glove_examine(glove_specs *, const void *txt, size_t len);

// Populate the database from the dataset. The database is position
// independent, designed to be dumped to a file and memory-mapped for
// lookups.
void glove_make_db(void *db, glove_specs *, const void *txt, size_t len);

// Prepare a database for lookups by retrieving its parameters.
void glove_load_db(glove *, const void *db);

// Lookup a word in the database, returning its embedding, or null if
// not found. The returned object is within the database buffer and so
// shares its lifetime.
float *glove_get_embedding(const glove *, const char *word);
