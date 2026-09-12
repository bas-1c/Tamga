#include "util/Utf.h"

#include <cstdint>

namespace tamga::util {

namespace {

constexpr std::size_t kMaxImplicitShortWcharLength = 1U << 20U;

std::size_t MeasureShortWchar(const char16_t* src) {
    std::size_t len = 0;
    while (len < kMaxImplicitShortWcharLength && src[len] != 0) {
        ++len;
    }
    return len;
}

std::wstring Utf16ToWide(std::u16string_view src) {
    std::wstring out;
    out.reserve(src.size());

    if constexpr (sizeof(wchar_t) == sizeof(char16_t)) {
        for (const char16_t ch : src) {
            out.push_back(static_cast<wchar_t>(ch));
        }
        return out;
    }

    for (std::size_t i = 0; i < src.size(); ++i) {
        const char16_t lead = src[i];
        if (lead >= 0xD800 && lead <= 0xDBFF && i + 1 < src.size()) {
            const char16_t trail = src[i + 1];
            if (trail >= 0xDC00 && trail <= 0xDFFF) {
                const std::uint32_t code_point =
                    0x10000U + ((static_cast<std::uint32_t>(lead) - 0xD800U) << 10U) +
                    (static_cast<std::uint32_t>(trail) - 0xDC00U);
                out.push_back(static_cast<wchar_t>(code_point));
                ++i;
                continue;
            }
        }

        out.push_back(static_cast<wchar_t>(lead));
    }

    return out;
}

std::u16string WideToUtf16(std::wstring_view src) {
    std::u16string out;
    out.reserve(src.size());

    if constexpr (sizeof(wchar_t) == sizeof(char16_t)) {
        for (const wchar_t ch : src) {
            out.push_back(static_cast<char16_t>(ch));
        }
        return out;
    }

    for (const wchar_t ch : src) {
        const auto code_point = static_cast<std::uint32_t>(ch);
        if (code_point <= 0xFFFFU) {
            out.push_back(static_cast<char16_t>(code_point));
            continue;
        }

        const std::uint32_t adjusted = code_point - 0x10000U;
        out.push_back(static_cast<char16_t>(0xD800U + ((adjusted >> 10U) & 0x3FFU)));
        out.push_back(static_cast<char16_t>(0xDC00U + (adjusted & 0x3FFU)));
    }

    return out;
}


bool DecodeUtf8ToUtf16(std::string_view src, std::u16string& out) {
    out.clear();
    out.reserve(src.size());

    std::size_t i = 0;
    while (i < src.size()) {
        const auto lead = static_cast<unsigned char>(src[i++]);
        std::uint32_t code_point = 0;
        std::size_t continuation_count = 0;

        if (lead <= 0x7FU) {
            code_point = lead;
        } else if ((lead & 0xE0U) == 0xC0U) {
            code_point = lead & 0x1FU;
            continuation_count = 1;
            if (code_point == 0) {
                return false;
            }
        } else if ((lead & 0xF0U) == 0xE0U) {
            code_point = lead & 0x0FU;
            continuation_count = 2;
        } else if ((lead & 0xF8U) == 0xF0U) {
            code_point = lead & 0x07U;
            continuation_count = 3;
        } else {
            return false;
        }

        if (i + continuation_count > src.size()) {
            return false;
        }

        for (std::size_t j = 0; j < continuation_count; ++j) {
            const auto continuation = static_cast<unsigned char>(src[i++]);
            if ((continuation & 0xC0U) != 0x80U) {
                return false;
            }
            code_point = (code_point << 6U) | (continuation & 0x3FU);
        }

        if ((continuation_count == 1 && code_point < 0x80U) ||
            (continuation_count == 2 && code_point < 0x800U) ||
            (continuation_count == 3 && code_point < 0x10000U) ||
            code_point > 0x10FFFFU ||
            (code_point >= 0xD800U && code_point <= 0xDFFFU)) {
            return false;
        }

        if (code_point <= 0xFFFFU) {
            out.push_back(static_cast<char16_t>(code_point));
        } else {
            const std::uint32_t adjusted = code_point - 0x10000U;
            out.push_back(static_cast<char16_t>(0xD800U + ((adjusted >> 10U) & 0x3FFU)));
            out.push_back(static_cast<char16_t>(0xDC00U + (adjusted & 0x3FFU)));
        }
    }

    return true;
}

bool EncodeUtf16ToUtf8(std::u16string_view src, std::string& out) {
    out.clear();
    out.reserve(src.size());

    for (std::size_t i = 0; i < src.size(); ++i) {
        std::uint32_t code_point = src[i];
        if (code_point >= 0xD800U && code_point <= 0xDBFFU) {
            if (i + 1 >= src.size()) {
                return false;
            }
            const auto trail = static_cast<std::uint32_t>(src[i + 1]);
            if (trail < 0xDC00U || trail > 0xDFFFU) {
                return false;
            }
            code_point = 0x10000U + ((code_point - 0xD800U) << 10U) + (trail - 0xDC00U);
            ++i;
        } else if (code_point >= 0xDC00U && code_point <= 0xDFFFU) {
            return false;
        }

        if (!AppendUtf8CodePoint(code_point, out)) {
            return false;
        }
    }

    return true;
}

} // namespace

bool AppendUtf8CodePoint(const std::uint32_t code_point, std::string& out) {
    if (code_point > 0x10FFFFU || (code_point >= 0xD800U && code_point <= 0xDFFFU)) {
        return false;
    }
    if (code_point <= 0x7FU) {
        out.push_back(static_cast<char>(code_point));
        return true;
    }
    if (code_point <= 0x7FFU) {
        out.push_back(static_cast<char>(0xC0U | ((code_point >> 6U) & 0x1FU)));
        out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
        return true;
    }
    if (code_point <= 0xFFFFU) {
        out.push_back(static_cast<char>(0xE0U | ((code_point >> 12U) & 0x0FU)));
        out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
        return true;
    }

    out.push_back(static_cast<char>(0xF0U | ((code_point >> 18U) & 0x07U)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    return true;
}

std::wstring FromShortWchar(const char16_t* src, std::size_t len) {
    if (src == nullptr) return {};
    if (len == 0) {
        len = MeasureShortWchar(src);
    }

    const std::u16string input(src, src + len);
    return Utf16ToWide(input);
}

std::u16string ToShortWchar(std::wstring_view src) {
    return WideToUtf16(src);
}

std::wstring FromUtf8(std::string_view src) {
    std::u16string utf16;
    if (!DecodeUtf8ToUtf16(src, utf16)) {
        return {};
    }
    return Utf16ToWide(utf16);
}

std::string ToUtf8(std::wstring_view src) {
    std::string out;
    if (!EncodeUtf16ToUtf8(WideToUtf16(src), out)) {
        return {};
    }
    return out;
}

bool TryDecodeUtf8ToUtf16(std::string_view src, std::u16string& out) {
    return DecodeUtf8ToUtf16(src, out);
}

bool TryEncodeUtf16ToUtf8(std::u16string_view src, std::string& out) {
    return EncodeUtf16ToUtf8(src, out);
}

} // namespace tamga::util
