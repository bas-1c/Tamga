# Перевірки

`tests/tamga_tests.cpp` реєструє сюїти з `tests/suites/`; спільні засоби містяться в `tests/support/`. Окремі executable targets перевіряють форматні парсери, безпеку, експорти, встановлення пакета та контракти.

Після збірки:

```powershell
ctest --test-dir build-x64-shipping --show-only=json-v1
ctest --test-dir build-x64-shipping --output-on-failure
```

Кількість CTest entries перевіряється під час configure у `tests/CMakeLists.txt`. Це не кількість внутрішніх test cases. Додаткові інтеграційні сценарії підключаються через `TAMGA_PRIVATE_TEST_DIR`, а корпус — через `TAMGA_TEST_DATA_ROOT`. Звичайний checkout їх не потребує. Відсутність зовнішньої timestamp-фікстури явно позначається як пропущений сценарій всередині основної сюїти.

`tamga-installed-package-consumer` збирає окремий C/C++ consumer встановленого пакета. Export gates звіряють NativeAPI та C ABI. Fuzz corpus replay є детермінованим повтором підготовлених входів; це не нова fuzz-кампанія.

Живі мережеві сценарії вимкнено за замовчуванням. `TAMGA_ENABLE_LIVE_POLICY_TESTS=ON` реєструє їх окремо; код 77 означає Skip через недоступність зовнішньої служби. Успіх offline-тестів не доводить доступність OCSP/TSP.

ASan не замінює UBSan; MSVC не підтримує UBSan. Windows і Linux, x86 і x64 перевіряються окремо. Результат стосується конкретного commit/дерева, компілятора, архітектури та flags.
