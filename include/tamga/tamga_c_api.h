#ifndef TAMGA_C_API_H
#define TAMGA_C_API_H

/**
 * @file tamga_c_api.h
 * @brief Стабільний публічний C ABI для взаємодії з бібліотекою Tamga (КЕП / ДСТУ 4145-2002).
 */

#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(TAMGA_LIB_EXPORTS) || defined(tamga_lib_EXPORTS)
        #define TAMGA_C_API __declspec(dllexport)
    #elif defined(TAMGA_STATIC_DEFINE)
        #define TAMGA_C_API
    #else
        #define TAMGA_C_API __declspec(dllimport)
    #endif
#elif defined(__GNUC__) && __GNUC__ >= 4
    #define TAMGA_C_API __attribute__((visibility("default")))
#else
    #define TAMGA_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Непрозорий дескриптор сесії Tamga.
 */
typedef struct tamga_session_opaque* tamga_session_t;

/**
 * @brief Коди результатів виконання функцій C API.
 */
typedef enum {
    TAMGA_C_OK = 0,                     /**< Успішне виконання */
    TAMGA_C_ERR_INVALID_ARGUMENT = 1,   /**< Некоректні аргументи */
    TAMGA_C_ERR_KEY_NOT_LOADED = 2,     /**< Ключ не завантажено або помилка контейнера */
    TAMGA_C_ERR_ONLINE_UNAVAILABLE = 3, /**< Онлайн-сервіс (OCSP/TSP/ЦЗО) недоступний */
    TAMGA_C_ERR_SIGNATURE_INVALID = 4,  /**< Криптографічний підпис недійсний */
    TAMGA_C_ERR_CERT_EXPIRED = 5,       /**< Термін дії сертифіката вичерпано */
    TAMGA_C_ERR_CERT_REVOKED = 6,       /**< Зарезервовано для точного verdict відкликання */
    TAMGA_C_ERR_POLICY_INVALID = 7,     /**< Помилка перевірки політики довіри */
    TAMGA_C_ERR_NOT_INITIALIZED = 8,    /**< Сесію не ініціалізовано */
    TAMGA_C_ERR_INTERNAL = 9,           /**< Внутрішня або системна помилка */
    TAMGA_C_ERR_NOT_SUPPORTED = 10,     /**< Функція або формат не підтримується */
    TAMGA_C_ERR_SETTINGS_REQUIRED = 11, /**< Потрібно налаштувати сесію */
    TAMGA_C_ERR_GUI_NOT_AVAILABLE = 12, /**< GUI недоступний у поточному середовищі */
    TAMGA_C_ERR_REVOCATION_FAILED = 13, /**< Перевірка відкликання не завершилась успішно */
    /* Н-10: раніше TrustValidationFailed, PolicyValidationFailed і
     * TimestampValidationFailed зводилися в один TAMGA_C_ERR_POLICY_INVALID,
     * тож FFI-споживач не міг відрізнити проблему довіри від проблеми мітки
     * часу. Розширення append-only: наявні значення не змінюються, старий код
     * продовжує працювати, але тепер бачить точнішу причину. */
    TAMGA_C_ERR_TRUST_FAILED = 14,      /**< Ланцюг довіри не підтверджено */
    TAMGA_C_ERR_TIMESTAMP_FAILED = 15   /**< Перевірка мітки часу не пройдена */
} tamga_c_error_code_t;

/**
 * @brief Отримати версію бібліотеки Tamga.
 * @return Рядок версії у форматі "MAJOR.MINOR.PATCH" (статичний буфер, не звільняти).
 */
TAMGA_C_API const char* tamga_version(void);

/**
 * @brief Створити нову сесію Tamga.
 * @return Дескриптор сесії або NULL у разі нестачі пам'яті.
 * @note Один дескриптор сесії не можна використовувати одночасно з кількох
 * потоків. Для паралельної роботи створюйте окрему сесію на кожен потік.
 */
TAMGA_C_API tamga_session_t tamga_session_create(void);

/**
 * @brief Знищити сесію Tamga та звільнити всі пов'язані ресурси.
 * @param session Дескриптор сесії.
 */
TAMGA_C_API void tamga_session_destroy(tamga_session_t session);

/**
 * @brief Налаштувати та ініціалізувати сесію.
 * @param session Дескриптор сесії.
 * @param work_dir Шлях до робочого каталогу кешу (або NULL/порожній для дефолтного).
 * @param offline_mode 1 для роботи без мережі, 0 для дозволу онлайн-запитів.
 * @param trust_mode Режим довіри ("strict" або "compatibility", NULL для "strict").
 * @return TAMGA_C_OK або код помилки.
 */
TAMGA_C_API int tamga_session_configure(
    tamga_session_t session,
    const char* work_dir,
    int offline_mode,
    const char* trust_mode
);

/**
 * @brief Завантажити закритий ключ із файлу контейнера.
 * @param session Дескриптор сесії.
 * @param path Шлях до файлу ключа (.jks, .p12, .dat, .pem, .der).
 * @param password Пароль контейнера/сховища.
 * @param key_password Пароль окремого ключа (або NULL).
 * @param alias Аліас ключа (для JKS/PKCS#12 або NULL).
 * @return TAMGA_C_OK або код помилки.
 */
TAMGA_C_API int tamga_session_read_key_file(
    tamga_session_t session,
    const char* path,
    const char* password,
    const char* key_password,
    const char* alias
);

/**
 * @brief Завантажити закритий ключ через JSON-дескриптор носія.
 * @param session Дескриптор сесії.
 * @param descriptor_json JSON-рядок із параметрами ключа (path, certPath, ca, subject тощо).
 * @param password Пароль ключа/контейнера.
 * @return TAMGA_C_OK або код помилки.
 */
TAMGA_C_API int tamga_session_read_key_descriptor(
    tamga_session_t session,
    const char* descriptor_json,
    const char* password
);

/**
 * @brief Перевірити, чи завантажено закритий ключ у сесії.
 * @param session Дескриптор сесії.
 * @return 1 якщо завантажено, 0 якщо ні.
 */
TAMGA_C_API int tamga_session_is_key_loaded(tamga_session_t session);

/*
 * Мітка часу RFC 3161: відповідність «формат -> режим» (С-04).
 *
 * Одна таблиця для tamga_session_sign_file і tamga_session_sign_data. До
 * 2026-08-26 вони розходилися: для "cms"/"cms-detached" файловий шлях робив
 * мережевий TSP-запит, а буферний не додавав мітки ніколи — за ідентичних
 * аргументів і без жодної згадки тут.
 *
 *   "cades-bes"                -> мітка не додається (профіль її не має);
 *   "cades-t"                  -> мітка ОБОВ'ЯЗКОВА; без неї підписання
 *                                 завершується помилкою;
 *   решта ("cms", "cms-detached", "cms-attached", "xades*", "pades", "asic-*")
 *                              -> best-effort: мітка додається, якщо TSA
 *                                 налаштована й доступна, інакше підпис
 *                                 створюється без неї.
 *
 * Best-effort означає мережевий запит при offline=false. Якщо мережа
 * небажана — вимикайте її через налаштування сесії, а не через вибір формату.
 */

/**
 * @brief Підписати файл.
 * @param session Дескриптор сесії із завантаженим ключем.
 * @param input_path Шлях до вхідного файлу.
 * @param output_path Шлях до вихідного файлу (підпису або підписаного документа).
 * @param format Формат підпису ("cms"/"cms-detached", "cms-attached", "cades-bes", "cades-t", "xades"/"xades-bes", "xades-t", "pades", "asic-s", "asic-e"). Порожній формат означає CMS detached.
 * @return TAMGA_C_OK або код помилки.
 */
TAMGA_C_API int tamga_session_sign_file(
    tamga_session_t session,
    const char* input_path,
    const char* output_path,
    const char* format
);

/**
 * @brief Підписати блок даних у пам'яті.
 * @param session Дескриптор сесії із завантаженим ключем.
 * @param data Вказівник на вхідні дані.
 * @param data_len Розмір вхідних даних у байтах.
 * @param format Формат підпису ("cms"/"cms-detached", "cms-attached", "cades-bes", "cades-t", "xades"/"xades-bes", "xades-t", "pades"). Порожній формат означає CMS detached.
 * @param out_data Вихідний вказівник на виділений буфер з підписом (звільняти через tamga_free_bytes).
 * @param out_len Вихідний розмір підпису в байтах.
 * @return TAMGA_C_OK або код помилки.
 */
TAMGA_C_API int tamga_session_sign_data(
    tamga_session_t session,
    const uint8_t* data,
    size_t data_len,
    const char* format,
    uint8_t** out_data,
    size_t* out_len
);

/**
 * @brief Перевірити підпис файлу.
 * @param session Дескриптор сесії.
 * @param input_path Шлях до вхідного файлу (або підписаного документа для pades/xades/asic/attached).
 * @param signature_path Шлях до файлу detached-підпису (може бути NULL для pades/xades/asic/attached).
 * @param format Формат підпису ("cms"/"cms-detached", "cms-attached", "cades-bes", "cades-t", "xades"/"xmldsig", "pades", "asic-s", "asic-e", "asic-e-xades"). Порожній формат означає CMS detached.
 * @param out_valid Вказівник на int, куди буде записано 1 (валідний) або 0 (невалідний).
 * @return TAMGA_C_OK або код помилки.
 */
TAMGA_C_API int tamga_session_verify_file(
    tamga_session_t session,
    const char* input_path,
    const char* signature_path,
    const char* format,
    int* out_valid
);

/**
 * @brief Перевірити підпис блоку даних у пам'яті.
 * @param session Дескриптор сесії.
 * @param data Вказівник на оригінальні дані.
 * @param data_len Розмір оригінальних даних.
 * @param signature Вказівник на підпис (може бути NULL, якщо data містить attached CMS або XAdES XML).
 * @param signature_len Розмір підпису.
 * @param format Формат підпису ("cms"/"cms-detached", "cms-attached", "cades-bes", "cades-t", "xades"/"xmldsig", "pades"). Порожній формат означає CMS detached.
 * @param out_valid Вказівник на int: 1 (валідний), 0 (невалідний).
 * @return TAMGA_C_OK або код помилки.
 */
TAMGA_C_API int tamga_session_verify_data(
    tamga_session_t session,
    const uint8_t* data,
    size_t data_len,
    const uint8_t* signature,
    size_t signature_len,
    const char* format,
    int* out_valid
);

/**
 * @brief Синхронізувати кеш довірчого списку ЦЗО.
 * @param session Дескриптор сесії (повинен бути в online-режимі).
 * @return TAMGA_C_OK або код помилки.
 */
TAMGA_C_API int tamga_session_sync_trust_list(tamga_session_t session);

/**
 * @brief Отримати повідомлення про останню помилку в сесії.
 * @param session Дескриптор сесії.
 * @return Рядок повідомлення (дійсний до наступного виклику сесії).
 */
TAMGA_C_API const char* tamga_session_get_last_error(tamga_session_t session);

/**
 * @brief Отримати числовий код останньої помилки в сесії.
 * @param session Дескриптор сесії.
 * @return Числовий код tamga_c_error_code_t.
 */
TAMGA_C_API int tamga_session_get_last_error_code(tamga_session_t session);

/**
 * @brief Отримати технічний JSON-звіт останньої перевірки (GetReport).
 * @param session Дескриптор сесії.
 * @return JSON-рядок (дійсний до наступного виклику сесії) або NULL.
 */
TAMGA_C_API const char* tamga_session_get_last_report(tamga_session_t session);

/**
 * @brief Отримати користувацький JSON-звіт останньої перевірки (GetUserReport).
 * @param session Дескриптор сесії.
 * @return JSON-рядок (дійсний до наступного виклику сесії) або NULL.
 */
TAMGA_C_API const char* tamga_session_get_user_report(tamga_session_t session);

/**
 * @brief Звільнити пам'ять виділеного масиву байтів.
 * @param ptr Вказівник, отриманий з функцій Tamga C API.
 */
TAMGA_C_API void tamga_free_bytes(uint8_t* ptr);

/**
 * @brief Звільнити пам'ять динамічно виділеного рядка.
 * @param str Рядок, отриманий з функцій Tamga C API.
 */
TAMGA_C_API void tamga_free_string(char* str);

#ifdef __cplusplus
}
#endif

#endif /* TAMGA_C_API_H */
