# Tamga

Бібліотека C++17 для українського КЕП, компонента NativeAPI для 1С/BAS та CLI. Версія визначена в `CMakeLists.txt` і `vcpkg.json`.

Підтримуються контейнери CMS/CAdES, ASiC, XMLDSIG/XAdES і PAdES у межах обраних [параметрів збірки](docs/building.md). Криптографічна цілісність підпису, довіра до сертифіката, відкликання та час мають окремі результати у звіті.

- [Збірка й тести](docs/building.md)
- [Посібник користувача](docs/user-guide.md)
- [NativeAPI: повний контракт EN/RU](docs/component-methods.md)
- [C/C++ API](docs/library-api.md), [CLI](docs/cli.md), [коди помилок](docs/error-codes.md)
- [Формати підписів](docs/signature-formats-and-containers.md), [контейнери ключів](docs/key-containers.md)
- [Безпека та обмеження](docs/security.md), [пінінг довірчого списку](docs/trust-list-pinning-howto.md)
- [Приклади 1С/BAS](example_1c/README.md)

Власний код — [BSD-3-Clause](LICENSE). Сторонні компоненти зберігають власні умови: [NOTICE](NOTICE), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
