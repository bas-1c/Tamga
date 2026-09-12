/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_HMAC_H
#define CRYPTONITE_HMAC_H

#include "byte_array.h"
#include "dstu7564.h"
#include "gost28147.h"
#include "sha2.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст ГОСТ 34.311
 */
typedef struct HmacCtx_st HmacCtx;

typedef enum {
    DSTU7564_VARIANT_256 = 32,
    DSTU7564_VARIANT_384 = 48,
    DSTU7564_VARIANT_512 = 64
} Dstu7564Variant;

/**
 * Створює контекст HMAC на базі ГОСТ 34.311 зі стандартним sbox.
 *
 * @param sbox_id ідентифікатор стандартної таблиці замін
 * @param sync синхропосилка
 * @return контекст HMAC
 */
CRYPTONITE_EXPORT HmacCtx *hmac_alloc_gost34_311(Gost28147SboxId sbox_id, const ByteArray *sync);

/**
 * Створює контекст HMAC на базі ГОСТ 34.311 зі стандартним sbox.
 *
 * @param sbox користувацький sbox
 * @param sync синхропосилка
 * @return контекст HMAC
 */
CRYPTONITE_EXPORT HmacCtx *hmac_alloc_gost34_311_user_sbox(const ByteArray *sbox, const ByteArray *sync);

/**
 * Створює контекст HMAC на базі SHA1.
 *
 * @return контекст HMAC
 */
CRYPTONITE_EXPORT HmacCtx *hmac_alloc_sha1(void);

/**
 * Створює контекст HMAC на базі SHA2.
 *
 * @param variant тип геша
 * @return контекст HMAC
 */
CRYPTONITE_EXPORT HmacCtx *hmac_alloc_sha2(Sha2Variant variant);

/**
 * Створює контекст KMAC на базі ДСТУ 7564 (Купина).
 *
 * @param variant розмір імітовставки
 * @return контекст HMAC/KMAC
 */
CRYPTONITE_EXPORT HmacCtx *hmac_alloc_dstu7564(Dstu7564Variant variant);

/**
 * Створює контекст HMAC на базі MD5.
 *
 * @return контекст HMAC
 */
CRYPTONITE_EXPORT HmacCtx *hmac_alloc_md5(void);

/**
 * Ініціалізує контекст для виробки HMAC.
 *
 * @param ctx контекст
 * @param key секретний ключ
 * @return код помилки
 */
CRYPTONITE_EXPORT int hmac_init(HmacCtx *ctx, const ByteArray *key);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст ГОСТ 34.311
 * @param data дані для шифрування
 * @return код помилки
 */
CRYPTONITE_EXPORT int hmac_update(HmacCtx *ctx, const ByteArray *data);

/**
 * Завершує вироботку геша і повертає його значення.
 *
 * @param ctx контекст ГОСТ 34.311
 * @param hash геш вектор
 * @return код помилки
 */
CRYPTONITE_EXPORT int hmac_final(HmacCtx *ctx, ByteArray **hash);

/**
 * Звільняє контекст ГОСТ 34.311.
 *
 * @param ctx контекст ГОСТ 34.311
 */
CRYPTONITE_EXPORT void hmac_free(HmacCtx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
