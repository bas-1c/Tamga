# Fuzz-цілі та повтор корпусу

Уся вхідна поверхня Tamga — **чужі байти**: контейнер від Вчасно, PDF від Дії,
DER від КНЕДП. Решта тестів доводить, що *відомі добрі* входи працюють; ці цілі
відповідають на інше питання — що станеться на пошкодженому вході.

## Чотири поверхні

| Ціль | Що розбирає | Чим цікава |
| --- | --- | --- |
| `fuzz_asic.cpp` | ZIP (miniz) + `ASiCManifest` | zip-bomb, path traversal, дублікати entry-імен |
| `fuzz_xml.cpp` | libxml2 + власний XMLDSIG-рушій, довірчий список | XXE, entity-expansion, signature wrapping |
| `fuzz_pdf.cpp` | qpdf + розбір `/ByteRange`, `/Contents`, `/DSS` | що саме покрито підписом; джерело сертифікатів TSA |
| `fuzz_asn1.cpp` | vendored cryptonite | C із ручними `malloc`/`free` — тут уже знаходили витоки |

`fuzz_asn1` найцінніша: усі виявлені досі дефекти пам'яті в проєкті —
з cryptonite або з коду, що ним керує. Знахідки звідти оформлюються записом у
черзі `patches/cryptonite/`, а не правкою дерева `vendor/` напряму.

## Два режими з одного файла

Кожна ціль має канонічну сигнатуру libFuzzer (`LLVMFuzzerTestOneInput`), але
libFuzzer доступний лише в Clang. Основний шлях проєкту — MSVC, який дає ASan
без libFuzzer. Тому:

**Повтор корпусу** (типово). До цілі долінковується `fuzz_replay_main.cpp`, і
вона стає звичайним CTest-тестом, який проганяє наявні файли. Нових дефектів не
шукає — її робота в тому, щоб уже знайдене не повернулося. Реальну користь дає
разом із санітайзерами:

```bash
cmake -S . -B build-asan -G Ninja -DTAMGA_ENABLE_SANITIZERS=ON -DTAMGA_BUILD_TESTS=ON
cmake --build build-asan
ctest --test-dir build-asan -R fuzz --output-on-failure
```

**libFuzzer** (потрібен Clang або clang-cl) — ціль ГЕНЕРУЄ входи:

```bash
cmake -S . -B build-fuzz -G Ninja \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DTAMGA_ENABLE_SANITIZERS=ON -DTAMGA_ENABLE_LIBFUZZER=ON -DTAMGA_BUILD_TESTS=ON
cmake --build build-fuzz
./build-fuzz/tests/fuzz/tamga-fuzz-asn1 tests/fuzz/corpus/asn1 tests/fixtures -max_total_time=600
```

## Корпус

`corpus/<ціль>/` містить лише **синтетичні** насіннєві файли: обрізаний ZIP,
`billion laughs`, PDF із неможливим `/ByteRange`, DER із довжиною біля
`SIZE_MAX` тощо. Усе разом — близько 24 КБ.

Кожна ціль також читає перевірені public fixtures із 	ests/fixtures/: синтетичні контейнери та публічні сертифікати. Файли .b64 драйвер декодує сам. Усі файли подаються незалежно від розширення, щоб перевірити відхилення некоректних форматів.

Особисті документи й робочі ключі до public-корпусу не входять. Походження — у [fixtures/README.md](../fixtures/README.md).

## Сторож проти порожнього прогону

Драйвер повертає ненульовий код, якщо не знайшов ЖОДНОГО файла. Це не
перестраховка: у цьому проєкті вже кілька разів «зелені тести» насправді
означали, що шлях виконання не запускався взагалі. Тест, який мовчки не читає
корпус, був би рівно тією ж пасткою.

## Обмеження

- **UBSan під MSVC недоступний.** Ловляться помилки пам'яті, але не переповнення
  знакових типів і не хибні зсуви — а це типові дефекти парсерів. Повний набір
  доступний лише у Clang-збірці.
- **Анотації STL-контейнерів вимкнено** в ASan-збірці MSVC (несумісність із
  прибудованими залежностями vcpkg) — зникає детекція container-overflow.
  Деталі й спосіб увімкнути назад — у `cmake/Sanitizers.cmake`.
- **Повтор корпусу не є фаззингом.** Він не генерує входів. Наявність цих
  тестів у CI не означає, що поверхні пропрацьовані фаззером.

Запуск усієї матриці — у [testing-strategy.md](../../docs/testing-strategy.md).
