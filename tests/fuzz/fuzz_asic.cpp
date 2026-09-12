// Fuzz-ціль: ASiC-контейнер (ZIP + маніфест).
//
// Поверхня: чужий `.asice`/`.asics` від Вчасно, M.E.Doc, Дії. Історично саме
// тут живуть zip-bomb, path traversal і дублікати entry-імен — усі три вже
// представлені у tests/fixtures/security/asic.

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "asic/AsicContainers.h"
#include "asic/AsicReader.h"

namespace {

// Верхня межа входу. Не «оптимізація»: без неї фаззер витрачає час на
// нецікаві гігабайтні входи, а ASan-прогін у CI впирається в пам'ять.
constexpr std::size_t kMaxInput = 8u * 1024u * 1024u;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > kMaxInput) {
        return 0;
    }
    const std::vector<std::uint8_t> input(data, data + size);

    {
        tamga::asic::AsicReader reader;
        std::string error;
        if (reader.LoadFromBuffer(input, error)) {
            std::string mimetype;
            (void)reader.GetMimetype(mimetype);

            std::vector<tamga::asic::AsicFileEntry> files;
            std::string files_error;
            if (reader.GetFiles(files, files_error)) {
                for (const auto& entry : files) {
                    std::vector<std::uint8_t> extracted;
                    std::string extract_error;
                    (void)reader.ExtractFile(entry.name, extracted, extract_error);
                }
            }
        }
    }

    {
        tamga::asic::AsicSContent content;
        std::string error;
        (void)tamga::asic::AsicSContainer::Unpack(input, content, error);
    }

    {
        tamga::asic::AsicEContent content;
        std::string error;
        (void)tamga::asic::AsicEContainer::Unpack(input, content, error);
    }

    // Маніфест розбирається з тексту, тож ті самі байти йдуть і сюди: розбір
    // ASiCManifest — окремий шлях, який не залежить від валідності ZIP.
    {
        const std::string as_text(reinterpret_cast<const char*>(data), size);
        std::string signature_uri;
        std::vector<tamga::asic::AsicDataObjectRef> data_refs;
        (void)tamga::asic::ParseAsicManifestXml(as_text, signature_uri, data_refs);
        (void)tamga::asic::GetMimeTypeFromFilename(as_text);
    }

    return 0;
}
