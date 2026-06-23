/*
 * plat_store.h - a tiny key->value store over the board's `storage` flash
 * partition (NVS), with a SINGLE shared mount.
 *
 * Both the anti-rollback counters (plat_counter.c) and the enrolled device
 * identity (provision/identity.c) persist small records here. They MUST go
 * through one NVS instance: two nvs_fs handles over the same flash region would
 * manage its sectors independently and corrupt each other. This module is that
 * single owner; callers address records by a small integer id.
 */
#ifndef MESHANICS_PLAT_STORE_H
#define MESHANICS_PLAT_STORE_H

#include <stddef.h>
#include <stdint.h>

/* plat_store_read copies up to len bytes of record `id` into buf and returns the
 * number of bytes the record holds (which may exceed len if buf was too small -
 * treat that as an error), or <0 if the record is absent or NVS is unavailable. */
int plat_store_read(uint16_t id, void *buf, size_t len);

/* plat_store_write persists `len` bytes as record `id`. Returns 0 on success
 * (including when the value is unchanged), <0 on error. */
int plat_store_write(uint16_t id, const void *buf, size_t len);

/* plat_store_delete removes record `id`. Returns 0 on success. */
int plat_store_delete(uint16_t id);

/* plat_store_exists returns 1 if record `id` is present, 0 otherwise. */
int plat_store_exists(uint16_t id);

#endif /* MESHANICS_PLAT_STORE_H */
