#pragma once

// Єдиний розбір DER TLV для всього проєкту (Хвиля 8, п.2).
//
// До консолідації в дереві існували ЧОТИРИ незалежні декодери довжини DER:
// `core/KeyParsers.cpp`, `core/session/SessionHelpers.ipp`,
// `core/cryptonite/Names.cpp` і `core/policy/CertificateChainValidator.cpp`.
// С-06 виправив переповнення `offset + length <= limit` лише в першому з них,
// і саме це зафіксовано в аудиті як клас помилки, а не як окремий дефект:
// одну копію полагодили, три лишилися. Дві з них (`Names.cpp`,
// `CertificateChainValidator.cpp`) дослівно містили ту саму вразливу форму
// `offset + value_len > total_size`.
//
// Тому реалізація тут одна, і вона свідомо НЕ покладається на інваріанти
// викликача: усі перевірки меж робляться всередині, у формі, стійкій до
// переповнення. Ризик вищий у 32-бітній збірці (x86-компонента для тонкого
// клієнта 1С), де переповнення досягається меншими значеннями.

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tamga::util {

struct TlvView {
    std::uint8_t tag{0};
    std::size_t value_offset{0};
    std::size_t value_length{0};
    std::size_t next_offset{0};
};

// Розбирає довжину DER, починаючи з `offset`, і зсуває `offset` на початок
// значення. Повертає `false`, якщо кодування некоректне АБО значення не
// вміщується в `limit`. Перевірка вміщення входить у контракт саме тому, що
// винесення її на бік викликача й породило С-06.
//
// Вказівникова форма обслуговує і `std::vector`, і сирі буфери, які віддає
// ASN.1-декодер cryptonite (`ANY_t::buf`).
bool ParseDerLength(const std::uint8_t* data,
                    std::size_t limit,
                    std::size_t& offset,
                    std::size_t& length);

// Розбирає один TLV за зсувом `offset` у межах `limit`.
bool ParseTlvAt(const std::uint8_t* data,
                std::size_t offset,
                std::size_t limit,
                TlvView& out);

bool ParseDerLength(const std::vector<std::uint8_t>& data,
                    std::size_t limit,
                    std::size_t& offset,
                    std::size_t& length);

bool ParseTlvAt(const std::vector<std::uint8_t>& data,
                std::size_t offset,
                std::size_t limit,
                TlvView& out);

// Межа за замовчуванням — увесь буфер.
bool ParseTlvAt(const std::vector<std::uint8_t>& data, std::size_t offset, TlvView& out);

}  // namespace tamga::util
