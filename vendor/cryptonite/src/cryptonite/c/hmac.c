/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <string.h>

#include "hmac.h"
#include "dstu7564.h"
#include "gost34_311.h"
#include "sha1.h"
#include "md5.h"
#include "byte_array_internal.h"
#include "macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/hmac.c"

#define HMAC_MAX_BLOCK_SIZE   128

typedef enum {
    HMAC_MODE_GOST34_311 = 0,
    HMAC_MODE_SHA1,
    HMAC_MODE_SHA2,
    HMAC_MODE_MD5,
    HMAC_MODE_DSTU7564,
} HmacModeId;

/** Контекст выработки хэш-вектора. */

struct HmacCtx_st {
    ByteArray *k_ipad;
    ByteArray *k_opad;
    size_t block_len;
    HmacModeId mode_id;
    ByteArray *kmac_key;
    union {
        Gost34311Ctx *gost34311;
        Sha1Ctx *sha1;
        Sha2Ctx *sha2;
        Md5Ctx *md5;
        Dstu7564Ctx *dstu7564;
    } mode;
};

static int hmac_dstu7564_reset(HmacCtx *ctx, const ByteArray *key)
{
    int ret = RET_OK;
    Dstu7564Ctx *fresh_ctx = NULL;
    ByteArray *fresh_key = NULL;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(ba_get_len(key) == ctx->block_len);

    CHECK_NOT_NULL(fresh_key = ba_copy_with_alloc(key, 0, 0));
    CHECK_NOT_NULL(fresh_ctx = dstu7564_alloc(DSTU7564_SBOX_1));
    DO(dstu7564_init_kmac(fresh_ctx, fresh_key, ctx->block_len));

    dstu7564_free(ctx->mode.dstu7564);
    ba_free_private(ctx->kmac_key);
    ctx->mode.dstu7564 = fresh_ctx;
    ctx->kmac_key = fresh_key;
    fresh_ctx = NULL;
    fresh_key = NULL;

cleanup:

    dstu7564_free(fresh_ctx);
    ba_free_private(fresh_key);
    return ret;
}

HmacCtx *hmac_alloc_dstu7564(Dstu7564Variant variant)
{
    int ret = RET_OK;
    HmacCtx *ctx = NULL;

    CHECK_PARAM(variant == DSTU7564_VARIANT_256 ||
            variant == DSTU7564_VARIANT_384 || variant == DSTU7564_VARIANT_512);
    CALLOC_CHECKED(ctx, sizeof(HmacCtx))
    ctx->mode_id = HMAC_MODE_DSTU7564;
    ctx->block_len = (size_t)variant;
    CHECK_NOT_NULL(ctx->mode.dstu7564 = dstu7564_alloc(DSTU7564_SBOX_1));

cleanup:

    if (ret != RET_OK) {
        hmac_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

HmacCtx *hmac_alloc_gost34_311(Gost28147SboxId sbox_id, const ByteArray *sync)
{
    int ret = RET_OK;
    HmacCtx *ctx = NULL;

    CALLOC_CHECKED(ctx, sizeof(HmacCtx))
    ctx->mode_id = HMAC_MODE_GOST34_311;
    CHECK_NOT_NULL(ctx->mode.gost34311 = gost34_311_alloc(sbox_id, sync));
    ctx->block_len = 32;

cleanup:

    if (ret != RET_OK) {
        hmac_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

static int hmac_hash_update(HmacCtx *ctx, const ByteArray *data)
{
    int ret = RET_OK;

    switch (ctx->mode_id) {
    case HMAC_MODE_GOST34_311:
        DO(gost34_311_update(ctx->mode.gost34311, data));
        break;
    case HMAC_MODE_SHA1:
        DO(sha1_update(ctx->mode.sha1, data));
        break;
    case HMAC_MODE_SHA2:
        DO(sha2_update(ctx->mode.sha2, data));
        break;
    case HMAC_MODE_MD5:
        DO(md5_update(ctx->mode.md5, data));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

static int hmac_hash_final(HmacCtx *ctx, ByteArray **hash)
{
    int ret = RET_OK;

    switch (ctx->mode_id) {
    case HMAC_MODE_GOST34_311:
        DO(gost34_311_final(ctx->mode.gost34311, hash));
        break;
    case HMAC_MODE_SHA1:
        DO(sha1_final(ctx->mode.sha1, hash));
        break;
    case HMAC_MODE_SHA2:
        DO(sha2_final(ctx->mode.sha2, hash));
        break;
    case HMAC_MODE_MD5:
        DO(md5_final(ctx->mode.md5, hash));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

HmacCtx *hmac_alloc_gost34_311_user_sbox(const ByteArray *sbox, const ByteArray *sync)
{
    int ret = RET_OK;
    HmacCtx *ctx =  NULL;

    CALLOC_CHECKED(ctx, sizeof(HmacCtx))
    ctx->mode_id = HMAC_MODE_GOST34_311;
    CHECK_NOT_NULL(ctx->mode.gost34311 = gost34_311_alloc_user_sbox(sbox, sync));
    ctx->block_len = 32;

cleanup:

    if (ret != RET_OK) {
        hmac_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

HmacCtx *hmac_alloc_sha1(void)
{
    int ret = RET_OK;
    HmacCtx *ctx =  NULL;

    CALLOC_CHECKED(ctx, sizeof(HmacCtx))
    ctx->mode_id = HMAC_MODE_SHA1;
    CHECK_NOT_NULL(ctx->mode.sha1 = sha1_alloc());
    ctx->block_len = 64;

cleanup:

    if (ret != RET_OK) {
        hmac_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

HmacCtx *hmac_alloc_sha2(Sha2Variant variant)
{
    int ret = RET_OK;
    HmacCtx *ctx =  NULL;

    CALLOC_CHECKED(ctx, sizeof(HmacCtx))
    ctx->mode_id = HMAC_MODE_SHA2;
    CHECK_NOT_NULL(ctx->mode.sha2 = sha2_alloc(variant));

    switch (variant) {
    case SHA2_VARIANT_224:
    case SHA2_VARIANT_256:
        ctx->block_len = 64;
        break;
    case SHA2_VARIANT_384:
    case SHA2_VARIANT_512:
        ctx->block_len = 128;
        break;
    default:
        SET_ERROR(RET_INVALID_PARAM);
    }

cleanup:

    if (ret != RET_OK) {
        hmac_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

HmacCtx *hmac_alloc_md5(void)
{
    int ret = RET_OK;
    HmacCtx *ctx =  NULL;

    CALLOC_CHECKED(ctx, sizeof(HmacCtx))
    ctx->mode_id = HMAC_MODE_MD5;
    CHECK_NOT_NULL(ctx->mode.md5 = md5_alloc());
    ctx->block_len = 64;

cleanup:

    if (ret != RET_OK) {
        hmac_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

int hmac_init(HmacCtx *ctx, const ByteArray *key)
{
    ByteArray *ba_tmp = NULL;
    ByteArray *key_tmp = NULL;
    uint8_t k_ipad[HMAC_MAX_BLOCK_SIZE];
    uint8_t k_opad[HMAC_MAX_BLOCK_SIZE];
    size_t i;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);

    if (ctx->mode_id == HMAC_MODE_DSTU7564) {
        DO(hmac_dstu7564_reset(ctx, key));
        goto cleanup;
    }

    if (key->len > 64) {
        DO(hmac_hash_update(ctx, key));
        DO(hmac_hash_final(ctx, &key_tmp));
    } else {
        CHECK_NOT_NULL(key_tmp = ba_copy_with_alloc(key, 0, 0));
    }

    memset(k_ipad, 0, ctx->block_len);
    memset(k_opad, 0, ctx->block_len);

    DO(ba_to_uint8(key_tmp, k_ipad, key_tmp->len));
    DO(ba_to_uint8(key_tmp, k_opad, key_tmp->len));

    /*RFC const*/
    for (i = 0; i < ctx->block_len; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    CHECK_NOT_NULL(ctx->k_ipad = ba_alloc_from_uint8(k_ipad, ctx->block_len));
    DO(hmac_hash_update(ctx, ctx->k_ipad));
    CHECK_NOT_NULL(ctx->k_opad = ba_alloc_from_uint8(k_opad, ctx->block_len));
cleanup:

    ba_free_private(key_tmp);
    ba_free(ba_tmp);

    return ret;
}

int hmac_update(HmacCtx *ctx, const ByteArray *data)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);

    if (ctx->mode_id == HMAC_MODE_DSTU7564) {
        DO(dstu7564_update_kmac(ctx->mode.dstu7564, data));
    } else {
        DO(hmac_hash_update(ctx, data));
    }

cleanup:

    return ret;
}

int hmac_final(HmacCtx *ctx, ByteArray **hmac)
{
    ByteArray *upd_hmac = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hmac != NULL);

    if (ctx->mode_id == HMAC_MODE_DSTU7564) {
        CHECK_PARAM(ctx->kmac_key != NULL);
        DO(dstu7564_final_kmac(ctx->mode.dstu7564, hmac));
        /* Reset транзакційний: старі секретні буфери знищуються лише після
         * успішної ініціалізації нового контексту та копії ключа. */
        DO(hmac_dstu7564_reset(ctx, ctx->kmac_key));
        goto cleanup;
    }

    DO(hmac_hash_final(ctx, &upd_hmac));
    DO(hmac_hash_update(ctx, ctx->k_opad));
    DO(hmac_hash_update(ctx, upd_hmac));
    DO(hmac_hash_final(ctx, hmac));

    DO(hmac_hash_update(ctx, ctx->k_ipad));
cleanup:

    ba_free(upd_hmac);

    return ret;
}

/**
 * Очищает контекст ГОСТ 34.311.
 *
 * @param ctx контекст ГОСТ 34.311
 */
void hmac_free(HmacCtx *ctx)
{
    if (ctx) {
        switch (ctx->mode_id) {
        case HMAC_MODE_GOST34_311:
            gost34_311_free(ctx->mode.gost34311);
            break;
        case HMAC_MODE_SHA1:
            sha1_free(ctx->mode.sha1);
            break;
        case HMAC_MODE_SHA2:
            sha2_free(ctx->mode.sha2);
            break;
        case HMAC_MODE_MD5:
            md5_free(ctx->mode.md5);
            break;
        case HMAC_MODE_DSTU7564:
            dstu7564_free(ctx->mode.dstu7564);
            break;
        }
        ba_free_private(ctx->kmac_key);
        ba_free(ctx->k_opad);
        ba_free(ctx->k_ipad);
        free(ctx);
    }
}
