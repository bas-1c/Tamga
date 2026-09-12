# П-16: попередження компілятора є помилками, і збірка захищена Control Flow
# Guard.
#
# Доти обидві половини були заявлені, але не діяли. `/W4` (чи `-Wall -Wextra
# -Wpedantic`) вмикався, але попередження НІДЕ не були помилками і жоден крок CI
# їх не перевіряв — тобто рівень діагностики був підвищений, а наслідків у
# нього не було. Борг при цьому виявився нульовим: три чисті збірки з уже
# ввімкненим `/WX` (базова 499 кроків, постачання 543, vendor-off 130) дали
# 0 рядків із `warning`. Саме тому вмикати його можна зараз, не тягнучи за
# собою хвіст виправлень; за рік боргу вже не було б куди подітися.

function(tamga_enable_project_warnings target)
    if(NOT TARGET ${target})
        message(FATAL_ERROR "Tamga warning policy requested for unknown target: ${target}")
    endif()

    # `/WX` і `-Werror` навмисно роздаються ЧЕРЕЗ target_compile_options, а не
    # глобальним add_compile_options: глобальний прапорець зачепив би
    # vendor/cryptonite, який репозиторій тримає максимально близьким до
    # upstream (AGENTS.md, «Політика щодо vendor»). Чужий код не зобов'язаний
    # бути чистим під нашим рівнем діагностики, і зробити його таким можна було
    # б лише правками у vendor — тобто ціною, заради якої політика й існує.
    # Тому вимога діє рівно на first-party цілях, які проходять через цю
    # функцію: tamga-core-objects, tamga-c-api-objects, tamga-nativeapi-objects,
    # tamga-cli, діагностичні tools і всі тестові та fuzz-цілі.
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()

function(tamga_enable_project_compile_policy target)
    tamga_enable_project_warnings(${target})

    if(MSVC)
        target_compile_options(${target} PRIVATE /utf-8 /EHsc /permissive-)
        target_compile_definitions(${target} PRIVATE UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    endif()
endfunction()

if(MSVC)
    # `/guard:cf` — Control Flow Guard. На відміну від `/WX`, це не діагностика,
    # а кодогенерація: компілятор додає перевірку цілі перед кожним непрямим
    # викликом, а лінкер записує в образ таблицю дозволених цілей. Без
    # ЛІНКЕРНОГО прапорця таблиці немає, і перевірки в коді лишаються без
    # ефекту — тому він тут двічі, і це не дублювання.
    #
    # Чому саме тут доречно глобально, на відміну від `/WX`: CFG має сенс лише
    # тоді, коли ним покритий увесь модуль. Непокритий об'єктний файл лишає в
    # образі непрозорі непрямі виклики — а найцінніша для покриття ділянка тут
    # якраз vendor/cryptonite: це C-код, який розбирає ASN.1 із недовіреного
    # входу (docs/security.md). Прапорець не змінює вихідних текстів і не
    # породжує попереджень, тож політику «vendor близький до upstream» він не
    # порушує — вона про зміни в коді, а не про режим збірки. Той самий підхід
    # уже застосовано поруч до `/sdl`.
    add_compile_options(/sdl /guard:cf)

    # `/CETCOMPAT` (апаратний shadow stack, Intel CET) свідомо НЕ додано.
    # Причини, у порядку ваги:
    #   1. Це не захист, а ЗАЯВА про сумісність усього коду в образі. У
    #      `Tamga.dll` статично лінкуються cryptonite і — у конфігурації
    #      постачання — libxml2, qpdf, zlib із vcpkg. Ручного розкручування
    #      стека (`setjmp`/`longjmp`, фібри) у `src/` і `vendor/cryptonite` не
    #      знайдено, але порти vcpkg під цим кутом не переглядалися.
    #   2. Прапорець лише x64, а `windows-msvc.yml` збирає ще й x86 — знадобився
    #      би окремий guard за розрядністю.
    #   3. Перевірити заяву нічим: машини з увімкненим CET у цьому середовищі
    #      немає, тож прапорець пішов би в реліз неперевіреним.
    # Якщо його додавати, то окремою зміною разом зі стендом, на якому видно,
    # що процес-хазяїн (1С) із увімкненим shadow stack справді завантажує
    # бібліотеку й підписує.

    # С-09: раніше тут стояло БЕЗУМОВНЕ присвоєння
    # `set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded...")`, яке перезаписувало
    # коректний guard із кореневого CMakeLists.txt:22. Через це опція
    # TAMGA_MSVC_STATIC_RUNTIME=OFF не діяла зовсім: збірка все одно виходила
    # з /MT, а заявлена конфігурація /MD була недосяжною. Присвоєння має бути
    # рівно одне й лише за опцією — те, що в корені; тут його немає.
    add_link_options(
        /guard:cf
        $<$<CONFIG:Release>:/OPT:REF>
        $<$<CONFIG:Release>:/OPT:ICF>
    )
else()
    add_compile_options(
        -fvisibility=hidden
        $<$<CONFIG:Release>:-fstack-protector-strong>
    )
    add_compile_definitions($<$<CONFIG:Release>:_FORTIFY_SOURCE=2>)
endif()
