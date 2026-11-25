// =============================================================================
//  10_filecheck_clipboard.inc
//
//  Новая вкладка раздела Check: "file check".
//  - Задача 1: сканирование ПК на файлы, у которых фактический тип (по
//    сигнатуре/magic bytes) не совпадает с расширением (напр. w.png = EXE).
//  - Задача 2 (безопасная часть): показать текущий текст буфера обмена,
//    перечислить процессы, связанные с cbdhsvc / Clipboard User Service,
//    и прочитать ОФИЦИАЛЬНУЮ историю буфера Windows (Win+V), если она включена.
//
//  Стиль и архитектура повторяют существующие вкладки (AUTOMATION_OUTPUT_*,
//  StartAutomationScan, SetAutomationLines, pipe-разделённые колонки).
//
//  БЕЗОПАСНОСТЬ:
//   * файлы НИКОГДА не запускаются — только открываются на чтение;
//   * читаются лишь метаданные и первые байты (заголовок);
//   * все ошибки доступа проглатываются, обход не падает и не виснет;
//   * НЕ реализовано "восстановление стёртого буфера" из памяти cbdhsvc —
//     это техника инфостилеров; используется только официальный API истории.
// =============================================================================

#include <vector>
#include <string>
#include <algorithm>
#include <cwctype>
#include <cstdint>
#include <chrono>
#include <thread>
#include <atomic>

// -----------------------------------------------------------------------------
//  Зависимости от 01/02:
//    * enum AUTOMATION_OUTPUT_FILECHECK / AUTOMATION_OUTPUT_CLIPBOARD — в 01;
//    * std::atomic_bool g_automationFileCheckWorking — в 01;
//    * g_fileCheckLines / g_clipboardLines и их scroll offsets — в 01;
//    * SetAutomationLines / SetAutomationStatusLine / InvalidateAutomationPanel /
//      AutomationWorkingRef / AutomationLinesRef — в 02.
//  Поэтому этот файл должен подключаться СРАЗУ ПОСЛЕ 02_state_paths_urls.inc.
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//  1. РАСШИРЯЕМАЯ ТАБЛИЦА СИГНАТУР
//
//  Чтобы добавить новый тип файла — просто допишите строку в g_fileSignatures.
//  offset  — смещение, с которого сравниваются байты;
//  bytes   — эталонные байты сигнатуры;
//  mask    — необязательная маска (0xFF = значим, 0x00 = игнор), пустая = точное
//            сравнение;
//  type    — короткое имя типа ("PNG", "EXE/DLL(PE)", ...);
//  exts    — расширения, которые СЧИТАЮТСЯ нормальными для этого типа.
// -----------------------------------------------------------------------------
struct FileTypeSignature
{
    size_t                     offset;
    std::vector<uint8_t>       bytes;
    std::vector<uint8_t>       mask;   // может быть пустой
    std::wstring               type;
    std::vector<std::wstring>  exts;   // ожидаемые расширения (нижний регистр, без точки)
};

// Базовый набор распространённых форматов. Легко расширяется.
static const std::vector<FileTypeSignature>& GetFileSignatures()
{
    static const std::vector<FileTypeSignature> sigs = {
        // Изображения
        { 0, { 0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A }, {}, L"PNG",  { L"png" } },
        { 0, { 0xFF,0xD8,0xFF },                          {}, L"JPEG", { L"jpg", L"jpeg" } },
        { 0, { 0x47,0x49,0x46,0x38 },                     {}, L"GIF",  { L"gif" } },
        { 0, { 0x42,0x4D },                               {}, L"BMP",  { L"bmp" } },
        // Документы
        { 0, { 0x25,0x50,0x44,0x46,0x2D },                {}, L"PDF",  { L"pdf" } },
        // ZIP-контейнер (jar/docx/apk/...). Нужен, чтобы ловить JAR-читы,
        // переименованные в .png/.txt и т.п. Шум от обычных архивов режется
        // умным анализом в EvaluateFile (показываются только jar-like/cheat).
        { 0, { 0x50,0x4B,0x03,0x04 },                     {}, L"ZIP/JAR", { L"zip", L"jar", L"docx", L"xlsx", L"pptx", L"apk", L"war", L"epub", L"odt", L"ods", L"odp", L"cbz", L"kmz", L"ipa" } },
        { 0, { 0x50,0x4B,0x05,0x06 },                     {}, L"ZIP/JAR", { L"zip", L"jar", L"docx", L"xlsx", L"pptx", L"apk", L"war", L"epub", L"odt", L"ods", L"odp", L"cbz", L"kmz", L"ipa" } },
        // Класс-файл Java
        { 0, { 0xCA,0xFE,0xBA,0xBE },                     {}, L"JavaClass", { L"class" } },
        // ELF (не-Windows исполняемый — на Windows это подозрительно)
        { 0, { 0x7F,0x45,0x4C,0x46 },                     {}, L"ELF", { } },
        // Windows PE (MZ) — тип уточняется анализом PE-заголовка (EXE vs DLL)
        // Некоторые программы намеренно используют PE/DLL под собственными
        // расширениями: аудиофильтры Miles (.asi/.flt), resource DLL (.rll),
        // библиотеки типов (.tlb/.olb) и языковые модули Radmin (.lng_rad).
        // Для них сигнатура MZ/PE соответствует формату, а не маскировке.
        { 0, { 0x4D,0x5A },                               {}, L"PE(MZ)",
          { L"exe", L"dll", L"sys", L"scr", L"cpl", L"ocx", L"drv",
            L"pyd", L"mui", L"efi", L"ax", L"asi", L"flt", L"rll",
            L"tlb", L"olb", L"lng_rad", L"sfx" } },
    };
    return sigs;
}

// -----------------------------------------------------------------------------
//  2. АНАЛИЗ PE-ЗАГОЛОВКА (EXE / DLL)
//
//  Для файла, начинающегося с 'MZ', читаем e_lfanew, проверяем 'PE\0\0',
//  затем по Characteristics в IMAGE_FILE_HEADER отличаем DLL от EXE.
//  Работаем строго с буфером первых байт — файл не мапится и не исполняется.
// -----------------------------------------------------------------------------
static std::wstring ClassifyPE(const std::vector<uint8_t>& buf)
{
    // e_lfanew находится по смещению 0x3C (4 байта, little-endian)
    if (buf.size() < 0x40) return L"PE(MZ)";
    uint32_t peOff = static_cast<uint32_t>(buf[0x3C]) |
                     (static_cast<uint32_t>(buf[0x3D]) << 8) |
                     (static_cast<uint32_t>(buf[0x3E]) << 16) |
                     (static_cast<uint32_t>(buf[0x3F]) << 24);

    // Нужны сигнатура 'PE\0\0' (4) + IMAGE_FILE_HEADER (20). Characteristics в
    // конце file header: peOff + 4 + 18.
    if (peOff == 0 || static_cast<size_t>(peOff) + 24 > buf.size())
        return L"PE(MZ)";
    if (!(buf[peOff] == 'P' && buf[peOff + 1] == 'E' &&
          buf[peOff + 2] == 0 && buf[peOff + 3] == 0))
        return L"DOS/MZ"; // MZ есть, но не PE — старый DOS-стаб и т.п.

    uint16_t characteristics = static_cast<uint16_t>(buf[peOff + 22]) |
                               (static_cast<uint16_t>(buf[peOff + 23]) << 8);
    const uint16_t IMAGE_FILE_DLL_FLAG = 0x2000;
    if (characteristics & IMAGE_FILE_DLL_FLAG)
        return L"DLL(PE)";
    return L"EXE(PE)";
}

// Уточнение ZIP-контейнера: JAR обычно содержит META-INF/ или .class.
// Здесь мы работаем только по первым байтам, поэтому ограничиваемся общим
// типом "ZIP/JAR" — расширения jar/zip/docx и т.п. считаются валидными.

// -----------------------------------------------------------------------------
//  3. ОПРЕДЕЛЕНИЕ РЕАЛЬНОГО ТИПА ФАЙЛА
//
//  Открывает файл ТОЛЬКО на чтение (FILE_SHARE_READ, OPEN_EXISTING) и читает
//  первые заголовочные байты. Ничего не исполняет. Возвращает "" если тип не
//  распознан (нет сигнатуры).
// -----------------------------------------------------------------------------
static bool MatchSignature(const std::vector<uint8_t>& buf, const FileTypeSignature& s)
{
    if (buf.size() < s.offset + s.bytes.size()) return false;
    for (size_t i = 0; i < s.bytes.size(); ++i)
    {
        uint8_t b = buf[s.offset + i];
        uint8_t m = (i < s.mask.size()) ? s.mask[i] : 0xFF;
        if ((b & m) != (s.bytes[i] & m)) return false;
    }
    return true;
}

static std::wstring FileCheckIoPath(const std::wstring& path)
{
    if (path.rfind(L"\\\\?\\", 0) == 0) return path;
    // Directory scans already produce absolute paths. Avoid GetFullPathNameW
    // and a temporary buffer for every file in the tree.
    if (path.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + path.substr(2);
    if (path.size() >= 3 && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/'))
        return L"\\\\?\\" + path;
    DWORD length = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (!length) return path;
    std::vector<wchar_t> buffer(length);
    DWORD written = GetFullPathNameW(path.c_str(), length, buffer.data(), nullptr);
    if (!written || written >= length) return path;
    std::wstring full(buffer.data());
    if (full.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + full.substr(2);
    return L"\\\\?\\" + full;
}

static std::wstring DetectRealFileType(const std::wstring& path, uint64_t& sizeOut,
                                     bool* readable = nullptr)
{
    sizeOut = 0;
    if (readable) *readable = false;

    HANDLE h = CreateFileW(FileCheckIoPath(path).c_str(),
                           GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr,
                           OPEN_EXISTING,
                           // Без FILE_FLAG_EXECUTE и без запуска — только чтение.
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return L""; // нет доступа — молча пропускаем (обработка ошибок)

    LARGE_INTEGER li{};
    if (GetFileSizeEx(h, &li)) sizeOut = static_cast<uint64_t>(li.QuadPart);

    // Read the initial signatures here; distant PE headers are read separately.
    // Never load the whole executable just to determine its type.
    // 64 bytes cover every magic signature and the PE e_lfanew field. If a PE
    // header is farther away, only its 24-byte header is fetched below.
    std::vector<uint8_t> buf(64);
    DWORD read = 0;
    BOOL ok = ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr);
    if (readable) *readable = (ok != FALSE);
    // e_lfanew can point beyond the initial buffer. Read only the PE header
    // at that offset, without allocating memory based on untrusted input.
    if (ok && read >= 64 && buf[0] == 'M' && buf[1] == 'Z')
    {
        uint32_t peOffset = 0;
        memcpy(&peOffset, buf.data() + 0x3C, sizeof(peOffset));
        if (peOffset >= 64 && static_cast<uint64_t>(peOffset) + 24 > read &&
            static_cast<uint64_t>(peOffset) + 24 <= sizeOut)
        {
            LARGE_INTEGER offset{};
            offset.QuadPart = peOffset;
            uint8_t header[24]{};
            DWORD headerRead = 0;
            if (SetFilePointerEx(h, offset, nullptr, FILE_BEGIN) &&
                ReadFile(h, header, sizeof(header), &headerRead, nullptr) &&
                headerRead == sizeof(header))
            {
                // Normalize the small in-memory view for ClassifyPE.
                buf.resize(64 + sizeof(header));
                const uint32_t normalizedOffset = 64;
                memcpy(buf.data() + 0x3C, &normalizedOffset, sizeof(normalizedOffset));
                memcpy(buf.data() + 64, header, sizeof(header));
                read = static_cast<DWORD>(buf.size());
            }
        }
    }
    CloseHandle(h);
    if (!ok) return L"";
    buf.resize(read);
    if (buf.empty()) return L"";

    for (const auto& s : GetFileSignatures())
    {
        if (MatchSignature(buf, s))
        {
            if (s.type == L"PE(MZ)")
                return ClassifyPE(buf); // EXE(PE) / DLL(PE) / DOS/MZ
            return s.type;
        }
    }
    return L""; // неизвестно
}

// -----------------------------------------------------------------------------
//  4. СОПОСТАВЛЕНИЕ РАСШИРЕНИЯ И РЕАЛЬНОГО ТИПА
// -----------------------------------------------------------------------------
// ToLower(std::wstring) уже определён в 02_state_paths_urls.inc — переиспользуем его.

static std::wstring GetExtensionLower(const std::wstring& path)
{
    size_t dot = path.find_last_of(L'.');
    size_t slash = path.find_last_of(L"\\/");
    if (dot == std::wstring::npos || (slash != std::wstring::npos && dot < slash))
        return L""; // нет расширения
    return ToLower(path.substr(dot + 1));
}

// Проверяет, входит ли расширение в список ожидаемых для найденной сигнатуры.
static bool ExtensionMatchesType(const std::wstring& ext, const std::wstring& realType)
{
    for (const auto& s : GetFileSignatures())
    {
        bool typeHit = (s.type == realType) ||
                       (s.type == L"PE(MZ)" &&
                        (realType == L"EXE(PE)" || realType == L"DLL(PE)" || realType == L"DOS/MZ"));
        if (!typeHit) continue;
        for (const auto& e : s.exts)
            if (e == ext) return true;
    }
    return false;
}

// Возвращает предполагаемое исходное расширение исполняемого файла по его
// сигнатуре. Функция нужна в том числе для файлов, переименованных в .zip.
// Сам файл при проверке не переименовывается и никак не изменяется.
static std::wstring ExecutableExtensionFromType(const std::wstring& realType)
{
    if (realType == L"DLL(PE)")
        return L".dll";
    if (realType == L"EXE(PE)")
        return L".exe";
    return L"";
}

// -----------------------------------------------------------------------------
//  Доброкачественные случаи (по требованию): картинка, названная как другая
//  картинка (.png ↔ .jpg), либо как обобщённое/служебное расширение (например
//  файл .file в папке Spotify, который на самом деле png/jpeg) — это нормально
//  и НЕ попадает в вывод.
// -----------------------------------------------------------------------------
static bool IsImageRealType(const std::wstring& realType)
{
    return realType == L"PNG" || realType == L"JPEG" ||
           realType == L"GIF" || realType == L"BMP";
}

static bool IsImageExt(const std::wstring& ext)
{
    static const wchar_t* kImageExts[] = {
        L"png", L"jpg", L"jpeg", L"gif", L"bmp",
        L"webp", L"tif", L"tiff", L"ico", L"heic"
    };
    for (const wchar_t* e : kImageExts)
        if (ext == e) return true;
    return false;
}

static bool IsGenericExt(const std::wstring& ext)
{
    // Обобщённые/служебные расширения, для которых реальный тип не важен.
    static const wchar_t* kGenericExts[] = {
        L"file", L"dat", L"data", L"bin", L"temp", L"tmp",
        L"cache", L"part", L"download", L"old",
        // .winmd — метаданные WinRT: имеют PE/CLI-заголовок и всегда
        // детектятся как DLL, легитимны и штатно не подписаны -> чистый шум
        // (сотни файлов в Windows Kits / Microsoft SDKs).
        L"winmd"
    };
    for (const wchar_t* e : kGenericExts)
        if (ext == e) return true;
    return false;
}

// FileCheck теперь работает по модели allow-by-default:
// проверяем любое расширение, кроме явно перечисленных исключений выше
// (IsGenericExt: .temp/.tmp/.cache/.part/.download и т.п.; .node отдельно).
// Это позволяет находить маскировку PE/JAR под случайные расширения вроде
// .wu91hn41 или .soi14 без поддержки отдельного whitelist.
static bool IsInspectableExtension(const std::wstring& ext)
{
    return !ext.empty();
}

// Результат по одному файлу (колонки как в других вкладках, через '|').
struct FileCheckHit
{
    std::wstring name;
    std::wstring path;
    std::wstring declaredExt;
    std::wstring realType;
    std::wstring status;   // "ВОЗМОЖНО ЧИТ" / "ПОДОЗРИТЕЛЬНО" + состояние подписи
};

// -----------------------------------------------------------------------------
//  4.5 УМНЫЙ АНАЛИЗ СОДЕРЖИМОГО (анти-маскировка читов)
//
//  Задача окна — показывать НЕ любые несовпадения расширения, а именно
//  замаскированные читы/моды Minecraft и подозрительные исполняемые файлы.
//  Поэтому после детекта несовпадения файл анализируется по содержимому:
//
//   - ищем строковые следы чит-клиентов и Minecraft-модов
//     (meteor, liquidbounce, wurst, net/minecraft, fabric.mod.json, ...);
//   - ищем признаки известного легитимного софта (Windhawk, торрент-клиенты,
//     Microsoft, Steam, Discord, ...) — такие файлы НЕ показываем;
//   - JAR-архив (class-файлы/META-INF), переименованный в картинку/документ,
//     считаем типичной маскировкой чит-мода.
//
//  Читается только префикс файла (до 768 КБ) — безопасно и быстро.
// -----------------------------------------------------------------------------

// Признаки читов / Minecraft-модов (нижний регистр, ASCII).
static const std::vector<std::wstring>& GetCheatKeywords()
{
    static const std::vector<std::wstring> k = {
        // чит-клиенты
        L"meteor", L"liquidbounce", L"wurst", L"vape", L"aristois",
        L"huzuni", L"nodus", L"inertia", L"sigma client", L"rusherhack",
        L"thunderhack", L"moonhack", L"neverhook", L"wexside", L"minced",
        L"akrien", L"expensive", L"celestial", L"celka", L"nurik",
        L"nursultan", L"deadcode", L"dreampool", L"excellent", L"bleachhack",
        L"skillclient", L"zamorozka", L"future client", L"delta client",
        L"jex client", L"hakari", L"venus client", L"eclipse client",
        L"winner client", L"nova client", L"doomsday", L"nightware",
        L"troxill", L"arbuz", L"takker", L"xameleon", L"fuzeclient",
        L"wild client", L"konas", L"zeus client", L"ghost client",
        L"rich client", L"squad client", L"infinity client",
        // технические следы Minecraft-модов
        L"net/minecraft", L"net.minecraft", L"fabric.mod.json",
        L"quilt.mod.json", L"mcmod.info", L"me/earthme", L"meteordevelopment",
        L"minecraft", L"killaura", L"xray", L"aimassist", L"baritone",
        L"autototem", L"crystalaura", L"scaffold", L"velocity"
    };
    return k;
}

// Признаки известного легитимного софта — чтобы торренты, Windhawk,
// системные и популярные программы не засоряли вывод.
static const std::vector<std::wstring>& GetLegitSoftwareKeywords()
{
    static const std::vector<std::wstring> k = {
        L"windhawk", L"qbittorrent", L"utorrent", L"bittorrent", L"deluge",
        L"transmission", L"vuze", L"tixati", L"mediaget", L"zona",
        L"microsoft corporation", L"mozilla", L"google llc", L"valve",
        L"steam", L"discord", L"telegram", L"spotify", L"adobe",
        L"nvidia", L"advanced micro devices", L"intel", L"realtek",
        L"oracle", L"jetbrains", L"7-zip", L"winrar", L"obs project",
        L"logitech", L"razer", L"epic games", L"blizzard", L"riot games",
        L"opera", L"yandex", L"node.js", L"python software", L"videolan",
        L"gimp", L"audacity", L"notion", L"slack technologies", L"zoom",
        L"avg", L"avast", L"kaspersky", L"drweb", L"malwarebytes"
    };
    return k;
}

// Читает до maxBytes первых байт файла (только чтение, ничего не исполняет).
static std::vector<uint8_t> ReadFilePrefixBytes(const std::wstring& path, uint64_t maxBytes)
{
    std::vector<uint8_t> out;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return out;

    LARGE_INTEGER li{};
    uint64_t size = 0;
    if (GetFileSizeEx(h, &li)) size = static_cast<uint64_t>(li.QuadPart);
    uint64_t toRead = (size > 0 && size < maxBytes) ? size : maxBytes;
    if (toRead > 0)
    {
        out.resize(static_cast<size_t>(toRead));
        DWORD read = 0;
        if (!ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read, nullptr))
            out.clear();
        else
            out.resize(read);
    }
    CloseHandle(h);
    return out;
}

static wchar_t FileCheckLowerAscii(uint32_t ch)
{
    if (ch >= L'A' && ch <= L'Z') return static_cast<wchar_t>(ch + 32);
    return static_cast<wchar_t>(ch);
}

// Достаёт из бинарника поисковый текст: ASCII-строки + UTF-16LE строки
// (именно в UTF-16 лежат FileDescription/ProductName/CompanyName в PE).
static std::wstring ExtractSearchableTextLower(const std::vector<uint8_t>& bytes)
{
    std::wstring out;
    out.reserve(bytes.size() / 2 + 64);

    for (uint8_t b : bytes)
    {
        if (b >= 0x20 && b < 0x7F)
            out.push_back(FileCheckLowerAscii(b));
        else
            out.push_back(L' ');
    }

    std::wstring wide;
    for (size_t i = 0; i + 1 < bytes.size(); i += 2)
    {
        uint16_t ch = static_cast<uint16_t>(bytes[i]) |
                      (static_cast<uint16_t>(bytes[i + 1]) << 8);
        if (ch >= 0x20 && ch != 0x7F && !(ch >= 0xD800 && ch <= 0xDFFF))
            wide.push_back(FileCheckLowerAscii(ch));
        else
        {
            if (wide.size() >= 4) { out += L' '; out += wide; }
            wide.clear();
        }
    }
    if (wide.size() >= 4) { out += L' '; out += wide; }
    return out;
}

static std::wstring MatchAnyKeyword(const std::wstring& hayLower,
                                    const std::vector<std::wstring>& keywords)
{
    for (const auto& k : keywords)
        if (hayLower.find(k) != std::wstring::npos)
            return k;
    return L"";
}

// CodeMeter stores signed localization resource DLLs under language-specific
// extensions (CodeMeter.lfr, WibuCmTrigger64.ljp, CmRmtAct64.lru, ...). Keep
// this exception deliberately narrow: expected path, known module name, DLL
// type and a valid Authenticode signature must all match.
static bool IsSignedCodeMeterLanguageDll(const std::wstring& path,
                                         const std::wstring& ext,
                                         const std::wstring& realType,
                                         bool signedFile)
{
    if (!signedFile || realType != L"DLL(PE)") return false;

    static const wchar_t* kLanguageExts[] = {
        L"lcn", L"lde", L"les", L"lfr", L"lit", L"ljp", L"lru"
    };
    bool languageExtension = false;
    for (const wchar_t* knownExt : kLanguageExts)
    {
        if (ext == knownExt)
        {
            languageExtension = true;
            break;
        }
    }
    if (!languageExtension) return false;

    std::wstring lowerPath = ToLower(path);
    if (lowerPath.find(L"\\codemeter\\runtime\\bin\\") == std::wstring::npos)
        return false;

    std::wstring name = ToLower(ExtractFileNameOnly(path));
    return name.rfind(L"codemeter.", 0) == 0 ||
           name.rfind(L"wibucmtrigger32.", 0) == 0 ||
           name.rfind(L"wibucmtrigger64.", 0) == 0 ||
           name.rfind(L"cmrmtact64.", 0) == 0;
}

// Several products intentionally store PE DLLs in their own container
// formats. Match both the format and its vendor-owned location so these
// exceptions cannot be used for an arbitrary renamed file elsewhere.
static bool IsKnownLegitimatePeContainer(const std::wstring& path,
                                         const std::wstring& ext,
                                         const std::wstring& realType)
{
    if (realType != L"DLL(PE)") return false;
    const std::wstring lowerPath = ToLower(path);
    const std::wstring name = ToLower(ExtractFileNameOnly(path));

    if (ext == L"ofx" &&
        lowerPath.find(L".ofx.bundle\\contents\\win64\\") != std::wstring::npos)
        return true;

    if (ext == L"mibc" &&
        lowerPath.find(L"\\.nuget\\packages\\microsoft.netcore.app.runtime.win-x64\\") != std::wstring::npos &&
        lowerPath.find(L"\\tools\\") != std::wstring::npos)
        return true;

    if ((ext == L"vdm" || ext == L"lkg") &&
        lowerPath.find(L"\\programdata\\microsoft\\windows defender\\definition updates\\") != std::wstring::npos)
        return true;

    if (ext == L"lmd" && name == L"encoding.lmd" &&
        lowerPath.find(L"\\appdata\\local\\temp\\ir_sf_temp_") != std::wstring::npos)
        return true;

    return false;
}

// Report confirmed PE files with mismatched extensions regardless of vendor.
static bool EvaluateFile(const std::wstring& path, FileCheckHit& out, bool* readable = nullptr)
{
    if (readable) *readable = true; // Intentional exclusions are not read errors.
    std::wstring ext = GetExtensionLower(path);
    if (ext.empty()) return false;

    // Убираем хвостовые '~' (бэкап-копии Forge/OptiFine и т.п.).
    while (!ext.empty() && ext.back() == L'~')
        ext.pop_back();
    if (ext.empty() || ext == L"node" || IsGenericExt(ext) || !IsInspectableExtension(ext))
        return false;
    // This panel reports only disguised PE files. Every normal PE extension
    // is already accepted for both EXE and DLL, regardless of the contents.
    if (ExtensionMatchesType(ext, L"EXE(PE)")) return false;
    uint64_t size = 0;
    std::wstring realType = DetectRealFileType(path, size, readable);
    if (realType.empty())
        return false; // тип не определён — не шумим

    if (ExtensionMatchesType(ext, realType))
        return false; // всё совпадает — не подозрительно (в т.ч. .pyd → DLL)

    // Картинка, названная как другая картинка (.png ↔ .jpg) — это норма.
    if (IsImageRealType(realType) && IsImageExt(ext))
        return false;

    // Показываем ТОЛЬКО реальный тип .exe/.dll (PE). ELF, DOS/MZ, JAR/ZIP
    // и прочие несовпадения в этом окне не выводим по требованию.
    bool peMismatch = (realType == L"EXE(PE)" || realType == L"DLL(PE)");
    if (!peMismatch)
        return false;

    if (IsKnownLegitimatePeContainer(path, ext, realType))
        return false;

    // Vendor names and ordinary strings inside a PE are not evidence that
    // its extension is correct. Always report a confirmed PE mismatch.

    // Проверка цифровой подписи (Authenticode) — неподписанные exe/dll
    // подсвечиваются красным в UI. Проверка только для уже найденных файлов,
    // поэтому на общую скорость сканирования почти не влияет.
    bool signedFile = IsFileAuthenticodeSigned(FileCheckIoPath(path));

    if (IsSignedCodeMeterLanguageDll(path, ext, realType, signedFile))
        return false;

    std::wstring status;
    // Файл с реальным типом .exe/.dll найден под чужим расширением. Красный
    // «ВОЗМОЖНО ЧИТ» ставим, если этот реальный тип НЕ подписан; подписанный —
    // просто «ПОДОЗРИТЕЛЬНО» (без подсветки).
    if (!signedFile)
        status = L"ВОЗМОЖНО ЧИТ";
    else
        status = L"ПОДОЗРИТЕЛЬНО";
    status += signedFile ? L", подписан" : L", не подписан";

    std::wstring originalExecutableExt = ExecutableExtensionFromType(realType);

    out.path        = path;
    out.name        = ExtractFileNameOnly(path);
    out.declaredExt = ext.empty() ? L"(нет)" : (L"." + ext);
    out.realType    = originalExecutableExt; // только реальный тип: .dll / .exe
    out.status      = status;
    return true;
}

// -----------------------------------------------------------------------------
//  5. Iterative traversal: no time, file-count or depth limits.
//  Keep the configured exclusions and cooperative cancellation.
// -----------------------------------------------------------------------------
struct FileCheckScanState
{
    std::vector<FileCheckHit>              hits;
    std::set<std::wstring>                  visitedDirectories;
    uint64_t                               scanned = 0;
    uint64_t                               unreadableFiles = 0;
    uint64_t                               unreadableDirectories = 0;
    std::chrono::steady_clock::time_point  lastProgress{};
    std::chrono::steady_clock::time_point  workSliceStart = std::chrono::steady_clock::now();
    uint32_t                               paceCountdown = 256;
    uint32_t                               progressCountdown = 256;
};

// Yield briefly so the UI remains responsive, but do not idle for most of the
// scan. The worker already runs below normal priority, so a 1 ms yield after a
// 25 ms work slice is enough without the former ~90% duty-cycle penalty.
static bool FileCheckContinue(FileCheckScanState& st)
{
    using namespace std::chrono;
    if (!g_automationFileCheckWorking.load() || g_scanCancelRequested.load()) return false;
    if (st.paceCountdown > 1)
    {
        --st.paceCountdown;
        return true;
    }
    st.paceCountdown = 256;
    if (steady_clock::now() - st.workSliceStart >= milliseconds(25))
    {
        std::this_thread::sleep_for(milliseconds(1));
        if (!g_automationFileCheckWorking.load() || g_scanCancelRequested.load()) return false;
        st.workSliceStart = steady_clock::now();
    }
    return true;
}

static std::vector<std::wstring> FileCheckResultLines(const FileCheckScanState& st,
                                                     const std::wstring& phase)
{
    std::vector<std::wstring> lines;
    lines.reserve(st.hits.size() + 2);
    lines.push_back(phase + L" Обработано файлов: " + std::to_wstring(st.scanned) +
                    L"; найдено: " + std::to_wstring(st.hits.size()) +
                    L"; недоступно файлов/папок: " + std::to_wstring(st.unreadableFiles) +
                    L"/" + std::to_wstring(st.unreadableDirectories) + L".");
    if (!st.hits.empty()) lines.push_back(L"Название | Путь | Тип | Реальный тип | Статус");
    for (const auto& h : st.hits)
        lines.push_back(h.name + L" | " + h.path + L" | " + h.declaredExt + L" | " +
                        h.realType + L" | " + h.status);
    return lines;
}

static void PublishFileCheckProgress(FileCheckScanState& st, bool force = false)
{
    if (!force && st.progressCountdown > 1)
    {
        --st.progressCountdown;
        return;
    }
    st.progressCountdown = 256;
    auto now = std::chrono::steady_clock::now();
    if (!g_hMain || now - st.lastProgress < std::chrono::seconds(1)) return;
    st.lastProgress = now;
    auto lines = FileCheckResultLines(st, L"Сканирование...");
    {
        std::lock_guard<std::mutex> lock(g_automationMutex);
        g_fileCheckLines = std::move(lines);
    }
    InvalidateAutomationPanel(AUTOMATION_OUTPUT_FILECHECK);
}

// Каталоги, которые пропускаем для скорости и чтобы не лезть в системные папки.
// По требованию исключаем C:\\Windows (и системный каталог из %SystemRoot%).
static bool ShouldSkipScanDirectory(const std::wstring& fullPath, const std::wstring& name)
{
    std::wstring lname = ToLower(name);
    if (lname == L"windows" || lname == L"windows.old" ||
        lname == L"$recycle.bin" || lname == L"system volume information" ||
        lname == L"perflogs" ||
        // SDK-каталоги: тысячи легитимных неподписанных .winmd/.dll —
        // сплошной ложный шум и лишние часы сканирования.
        lname == L"windows kits" || lname == L"microsoft sdks" ||
        // высокообъёмные шумные каталоги (код/VCS/кеш) — ради скорости
        lname == L"node_modules" || lname == L".git" ||
        lname == L".svn" || lname == L"__pycache__")
        return true;

    // Абсолютный системный каталог (%SystemRoot%, обычно C:\\Windows).
    static const std::wstring sysRoot = []() -> std::wstring {
        wchar_t buf[MAX_PATH];
        DWORD n = GetEnvironmentVariableW(L"SystemRoot", buf, MAX_PATH);
        return (n > 0 && n < MAX_PATH) ? ToLower(std::wstring(buf)) : std::wstring();
    }();
    if (!sysRoot.empty())
    {
        std::wstring lfull = ToLower(fullPath);
        if (lfull == sysRoot || lfull.rfind(sysRoot + L"\\", 0) == 0)
            return true;
    }
    return false;
}

static void ScanDirectoryTree(const std::wstring& root, FileCheckScanState& st)
{
    std::vector<std::wstring> pending{root};
    while (!pending.empty())
    {
        if (!FileCheckContinue(st)) break;
        std::wstring dir = std::move(pending.back());
        pending.pop_back();
        std::wstring ioDir = FileCheckIoPath(dir);
        while (ioDir.size() > 7 && ioDir.back() == L'\\') ioDir.pop_back();
        if (!st.visitedDirectories.insert(ToLower(ioDir)).second) continue;
        PublishFileCheckProgress(st, true);

        WIN32_FIND_DATAW fd{};
        std::wstring pattern = ioDir;
        if (pattern.back() != L'\\') pattern += L'\\';
        pattern += L'*';
        HANDLE hFind = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &fd,
                                       FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
        if (hFind == INVALID_HANDLE_VALUE)
        {
            if (GetLastError() != ERROR_FILE_NOT_FOUND) ++st.unreadableDirectories;
            continue;
        }
        for (;;)
        {
            if (!FileCheckContinue(st)) break;
            const wchar_t* name = fd.cFileName;
            if (wcscmp(name, L".") != 0 && wcscmp(name, L"..") != 0 &&
                !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            {
                std::wstring full = dir;
                if (!full.empty() && full.back() != L'\\') full += L'\\';
                full += name;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    if (!ShouldSkipScanDirectory(full, name)) pending.push_back(std::move(full));
                }
                else
                {
                    ++st.scanned;
                    FileCheckHit hit;
                    bool readable = true;
                    if (EvaluateFile(full, hit, &readable)) st.hits.push_back(std::move(hit));
                    if (!readable) ++st.unreadableFiles;
                }
                PublishFileCheckProgress(st);
            }
            if (!FindNextFileW(hFind, &fd))
            {
                if (GetLastError() != ERROR_NO_MORE_FILES) ++st.unreadableDirectories;
                break;
            }
        }
        FindClose(hFind);
    }
}

// Корни сканирования по умолчанию: все доступные диски (фиксированные,
// съёмные и сетевые). CD/DVD и неизвестные типы не трогаем, чтобы не зависать.
static std::vector<std::wstring> GetDefaultScanRoots()
{
    std::vector<std::wstring> roots;
    // Check likely user locations first. The visited set prevents duplicates.
    wchar_t executablePath[32768]{};
    DWORD executableLength = GetModuleFileNameW(nullptr, executablePath, ARRAYSIZE(executablePath));
    if (executableLength > 0 && executableLength < ARRAYSIZE(executablePath))
    {
        std::wstring path(executablePath);
        size_t slash = path.find_last_of(L"\\/");
        if (slash != std::wstring::npos) roots.push_back(path.substr(0, slash + 1));
    }
    const KNOWNFOLDERID* userFolders[] = { &FOLDERID_Desktop, &FOLDERID_Downloads, &FOLDERID_Documents };
    for (const auto* folder : userFolders)
    {
        PWSTR path = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(*folder, KF_FLAG_DONT_VERIFY, nullptr, &path)))
            roots.push_back(path);
        CoTaskMemFree(path);
    }
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i)
    {
        if ((mask & (1u << i)) == 0)
            continue;

        wchar_t root[] = L"A:\\";
        root[0] = static_cast<wchar_t>(L'A' + i);
        UINT type = GetDriveTypeW(root);
        if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE || type == DRIVE_REMOTE)
            roots.push_back(root);
    }

    if (roots.empty())
    {
        wchar_t buf[MAX_PATH];
        DWORD n = GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH);
        if (n > 0 && n < MAX_PATH) roots.push_back(buf);
    }
    return roots;
}

// -----------------------------------------------------------------------------
//  6. РАБОЧИЙ ПОТОК СКАНИРОВАНИЯ (по образцу StartAutomationScan)
//
//  Формирует pipe-разделённые строки: name | path | declaredExt | realType | status
//  и кладёт их через SetAutomationLines(AUTOMATION_OUTPUT_FILECHECK, ...),
//  затем шлёт WM_APP_AUTOMATION_DONE, как это делают остальные вкладки.
// -----------------------------------------------------------------------------
static void FileCheckScanWorker()
{
    // Leave CPU scheduling preference to the UI and foreground applications.
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    FileCheckScanState st;

    for (const auto& root : GetDefaultScanRoots())
    {
        if (!g_automationFileCheckWorking.load() || g_scanCancelRequested.load()) break;
        ScanDirectoryTree(root, st);
    }

    bool cancelled = g_scanCancelRequested.load() || !g_automationFileCheckWorking.load();
    SetAutomationLines(AUTOMATION_OUTPUT_FILECHECK,
        FileCheckResultLines(st, cancelled ? L"Сканирование отменено." : L"Сканирование завершено."));

    g_automationFileCheckWorking.store(false);
    // Уведомляем UI-поток так же, как это делают прочие сканы.
    PostMessageW(g_hMain, WM_APP_AUTOMATION_DONE,
                 static_cast<WPARAM>(AUTOMATION_OUTPUT_FILECHECK), 0);
}

// Точка входа по кнопке. Не запускает второй скан, если уже идёт.
static void StartFileCheckScan()
{
    // Снимаем оба флага отмены (см. StartAutomationScan в 02).
    g_scanCancelRequested = false;
    g_cancelRequested = false;

    bool expected = false;
    if (!g_automationFileCheckWorking.compare_exchange_strong(expected, true))
        return; // уже сканируем

    SetAutomationStatusLine(AUTOMATION_OUTPUT_FILECHECK, L"Сканирование...");
    InvalidateAutomationPanel(AUTOMATION_OUTPUT_FILECHECK);

    std::thread(FileCheckScanWorker).detach();
}

// =============================================================================
//  7. БУФЕР ОБМЕНА — ТОЛЬКО БЕЗОПАСНЫЕ ФУНКЦИИ
// =============================================================================

// 7.1. Текущий текст буфера обмена (CF_UNICODETEXT). Ничего не логирует и не
//      сохраняет — просто возвращает строку для показа в UI.
static std::wstring GetCurrentClipboardText()
{
    if (!OpenClipboard(nullptr))
        return L"(не удалось открыть буфер обмена)";

    std::wstring result;
    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (hData)
    {
        const wchar_t* p = static_cast<const wchar_t*>(GlobalLock(hData));
        if (p)
        {
            result.assign(p);
            GlobalUnlock(hData);
        }
    }
    CloseClipboard();
    if (result.empty())
        result = L"(в буфере обмена нет текста)";
    return result;
}

// 7.2. Перечисление процессов, связанных с Clipboard User Service (cbdhsvc).
//      Только чтение списка процессов через Toolhelp — никакого доступа к памяти.
#include <tlhelp32.h>
static std::vector<std::wstring> EnumerateClipboardServiceProcesses()
{
    std::vector<std::wstring> found;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return found;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            std::wstring name = ToLower(pe.szExeFile);
            // cbdhsvc обычно хостится в svchost.exe; отдельного exe нет, поэтому
            // отмечаем svchost как возможного хоста службы буфера.
            if (name.find(L"cbdhsvc") != std::wstring::npos ||
                name == L"svchost.exe")
            {
                found.push_back(std::to_wstring(pe.th32ProcessID) + L" | " + pe.szExeFile);
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// 7.3. ОФИЦИАЛЬНАЯ история буфера обмена Windows (Win+V).
//      Использует документированный WinRT API Clipboard.GetHistoryItemsAsync.
//      Возвращает только то, что ОС сама сохранила, и только если пользователь
//      включил историю. Намеренно очищенные записи здесь не появляются — это
//      корректное поведение, а не ограничение.
//
//      Требуется компиляция с поддержкой C++/WinRT. Если проект её не
//      использует, оставьте функцию как есть — она вернёт пояснение.
//
//      Реализация-ориентир (включить при наличии C++/WinRT):
//
//      #include <winrt/Windows.Foundation.h>
//      #include <winrt/Windows.Foundation.Collections.h>
//      #include <winrt/Windows.ApplicationModel.DataTransfer.h>
//      using namespace winrt::Windows::ApplicationModel::DataTransfer;
//
//      static std::wstring ReadClipboardHistoryOfficial() {
//          try {
//              if (!Clipboard::IsHistoryEnabled())
//                  return L"История буфера обмена отключена (включите Win+V).";
//              auto res = Clipboard::GetHistoryItemsAsync().get();
//              if (res.Status() != ClipboardHistoryItemsResultStatus::Success)
//                  return L"Не удалось получить историю буфера обмена.";
//              std::wstring out;
//              for (auto const& item : res.Items()) {
//                  auto content = item.Content();
//                  if (content.Contains(StandardDataFormats::Text())) {
//                      auto text = content.GetTextAsync().get();
//                      out += std::wstring(text.c_str()) + L"\r\n----\r\n";
//                  }
//              }
//              return out.empty() ? L"(история буфера пуста)" : out;
//          } catch (...) {
//              return L"(ошибка доступа к истории буфера обмена)";
//          }
//      }
//
//      NB: Я сознательно НЕ реализую восстановление уже очищённого буфера через
//          чтение памяти процесса cbdhsvc — это техника кражи данных
//          (пароли/2FA/seed-фразы). Используйте только официальный API выше.

// =============================================================================
//  8. UI-ОБЁРТКИ ДЛЯ КНОПОК ВКЛАДКИ (вызываются из 09_window_main.inc)
//  Пишут в AUTOMATION_OUTPUT_CLIPBOARD и перерисовывают нижнюю панель page 5.
// =============================================================================

// Кноп��а "буфер: текст" — показать текущее текстовое содержимое буфера.
static void ShowCurrentClipboardTextUI()
{
    std::wstring text = GetCurrentClipboardText();
    std::vector<std::wstring> lines;
    lines.push_back(L"Текущий текст буфера обмена:");
    lines.push_back(L"");

    // Разбиваем многострочный текст на отдельные строки для табличного вывода.
    size_t start = 0;
    while (start <= text.size())
    {
        size_t nl = text.find(L'\n', start);
        std::wstring piece = (nl == std::wstring::npos)
            ? text.substr(start)
            : text.substr(start, nl - start);
        while (!piece.empty() && piece.back() == L'\r') piece.pop_back();
        lines.push_back(piece);
        if (nl == std::wstring::npos) break;
        start = nl + 1;
    }

    SetAutomationLines(AUTOMATION_OUTPUT_CLIPBOARD, std::move(lines));
    InvalidateAutomationPanel(AUTOMATION_OUTPUT_CLIPBOARD);
}

// Кнопка "cbdhsvc" — перечислить процессы, связанные со службой буфера.
static void ShowClipboardProcessesUI()
{
    std::vector<std::wstring> procs = EnumerateClipboardServiceProcesses();
    std::vector<std::wstring> lines;
    lines.push_back(L"PID | процесс (возможный хост службы буфера cbdhsvc)");
    if (procs.empty())
        lines.push_back(L"Процессы cbdhsvc / svchost не найдены.");
    else
        for (auto& p : procs) lines.push_back(p);

    lines.push_back(L"");
    lines.push_back(L"Примечание: намеренно очищенный буфер НЕ восстанавливается из памяти (см. комментарий в модуле).");
    lines.push_back(L"Для истории буфера используйте официальный Win+V (ReadClipboardHistoryOfficial).");

    SetAutomationLines(AUTOMATION_OUTPUT_CLIPBOARD, std::move(lines));
    InvalidateAutomationPanel(AUTOMATION_OUTPUT_CLIPBOARD);
}
