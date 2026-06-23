/*
 * plat_net.h - internal seam between the networking implementation (plat_net.c)
 * and the firmware-staging implementation (plat_mcuboot.c). Not part of the
 * public plat.h surface; it only exposes the byte-range firmware fetch the
 * installer drives.
 */
#ifndef MESHANICS_PLAT_NET_H
#define MESHANICS_PLAT_NET_H

#include <stddef.h>
#include <stdint.h>

/* plat_fw_sink receives successive firmware body chunks as they stream in; last
 * is non-zero on the final chunk. Return 0 to continue, non-zero to abort. */
typedef int (*plat_fw_sink)(const uint8_t *data, size_t len, int last, void *ctx);

/* plat_net_firmware_download streams the whole firmware image over a SINGLE mTLS
 * connection (GET /device/firmware), feeding the body to sink chunk by chunk.
 * One connection - not one TLS handshake per block - so it is fast and does not
 * thrash a memory-tight device. Returns 0 once exactly expect_size body bytes
 * have been delivered, <0 on a transport/HTTP error or a short stream. */
int plat_net_firmware_download(uint64_t expect_size, plat_fw_sink sink, void *ctx);

#endif /* MESHANICS_PLAT_NET_H */
