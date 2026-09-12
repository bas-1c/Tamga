# Vendor-залежності

## Склад

- `cryptonite/` — upstream-копія `privat-it/cryptonite` на коміті `3618d340d22e27a6becf97d89c453f8e64068a39`.
- `1c-nativeapi-sdk/include/` — заголовки SDK NativeAPI 1С, потрібні для збірки C++-компоненти.

## Правила

- `vendor/cryptonite` слід вважати зовнішнім кодом. Для наших відхилень потрібно вести окрему patch queue в `patches/cryptonite/`.
- `vendor/1c-nativeapi-sdk/include` є build-time залежністю. Це не місце для власної логіки проєкту.
- Зведений перелік сторонніх notices і ризиків публікації див. у кореневих файлах `NOTICE` та `THIRD_PARTY_NOTICES.md`.
