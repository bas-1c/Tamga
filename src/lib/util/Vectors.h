#pragma once

// Дрібні операції над `std::vector` — одні на весь проєкт (ADR-027).
//
// `AppendAll` існував у ТРЬОХ визначеннях: `net/CertificateFetcher.cpp`
// (над `std::uint8_t`), `validation/SigningTimeResolver.cpp` і
// `validation/ValidationEngine.cpp` (обидва над `std::string`). Тіла тотожні —
// просто жодне не було доступне ззовні свого файлу.
//
// Чесно про вагу цієї конкретної консолідації: розійтися тут не було чому —
// у `insert(end, begin, end)` немає інваріанта, який можна помилково змінити.
// Це прибирання шуму, а не виправлення дефекту, і храповик не має вдавати
// інше. Але 27 місць виклику виправдовують ім'я: `AppendAll(a, b)` читається
// краще за `a.insert(a.end(), b.begin(), b.end())`, повторене 27 разів.
//
// Шаблон замість трьох перевантажень — бо копії відрізнялися лише типом
// елемента, і будь-яка наступна копія відрізнялася б так само.

#include <vector>

namespace tamga::util {

template <typename T>
void AppendAll(std::vector<T>& target, const std::vector<T>& source) {
    target.insert(target.end(), source.begin(), source.end());
}

} // namespace tamga::util
