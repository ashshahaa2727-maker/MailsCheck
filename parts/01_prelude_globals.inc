#ifndef UNICODE
#define UNICODE
#endif

#ifndef _WIN32_IE
#define _WIN32_IE 0x0600
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <shlwapi.h>
#ifdef __MINGW32__
// MinGW declares these WinHTTP and WinINet types independently.
#include <wininet.h>
#define INTERNET_SCHEME WinHttpScheme
#define LPINTERNET_SCHEME WinHttpSchemePtr
#define URL_COMPONENTS WinHttpUrlComponents
#define LPURL_COMPONENTS WinHttpUrlComponentsPtr
#define URL_COMPONENTSW WinHttpUrlComponentsW
#define LPURL_COMPONENTSW WinHttpUrlComponentsWPtr
#define HTTP_VERSION_INFO WinHttpVersionInfo
#define LPHTTP_VERSION_INFO WinHttpVersionInfoPtr
#include <winhttp.h>
#undef INTERNET_SCHEME
#undef LPINTERNET_SCHEME
#undef URL_COMPONENTS
#undef LPURL_COMPONENTS
#undef URL_COMPONENTSW
#undef LPURL_COMPONENTSW
#undef HTTP_VERSION_INFO
#undef LPHTTP_VERSION_INFO
#undef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(parameter) (void)(parameter)
#else
#include <winhttp.h>
#include <wininet.h>
using WinHttpUrlComponents = URL_COMPONENTS;
#endif
#include <urlmon.h>
#include <servprov.h>
#include <ole2.h>
#include <shldisp.h>
#include <dwmapi.h>
#include <gdiplus.h>
#include <tlhelp32.h>
#include <winevt.h>
#include <wintrust.h>
#include <softpub.h>
#include <psapi.h>

#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <regex>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <cctype>
#include <iterator>
#include <memory>
#include <initializer_list>
#include <new>
#include <climits>
#include <sstream>
#include <iomanip>
#include <utility>
#include <cstddef>
#include <cmath>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")

using namespace Gdiplus;

#include "11_mailscheck_theme.inc"

#define IDC_DOWNLOAD_ALL    2100
#define IDC_POWERSHELL      2104
#define IDC_ENABLE_SERVICES 2105
#define IDC_DELETE_HOLYCHECK 2106
#define IDC_CANCEL_DOWNLOAD 2107
#define IDC_SEARCH_CHEATS 2108
#define IDC_SEARCH_CONFIGS 2109
#define IDC_COPY_POWERSHELL 2110
#define IDC_COPY_SITES      2111
#define IDC_REFRESH_BOOT    2116
#define IDC_AUTOMATION_NAV  2112
#define IDC_AUTOMATION_BAM  2113
#define IDC_AUTOMATION_EVENTVWR 2114
#define IDC_AUTOMATION_BAM_UNSIGNED_ONLY 2115
#define IDC_AUTOMATION_JAR_PAGE 2117
#define IDC_JAR_ACTIV 2118
#define IDC_EVENTVWR_EDIT 2134
#define IDC_EXE_DELETED 2120
#define IDC_PF_DELETED 2121
#define IDC_MC_LOGS 2122
#define IDC_PAGE4_NAV 2123
#define IDC_MOD_HASH 2124
#define IDC_DLL_UNSIGNED 2125
#define IDC_MOD_FULLSCAN 2135
#define IDC_DLL_ACTIVITY 2127
#define IDC_PAGE5_NAV 2126
#define IDC_INJGEN_CHECK 2128
#define IDC_HOME_NAV 2129
#define IDC_JAR_EDIT 2130
#define IDC_EXE_EDIT 2131
#define IDC_PF_EDIT 2132
#define IDC_MC_EDIT 2133
// --- Вкладка "file check" (page 5) ---
#define IDC_FILECHECK_SCAN 2140
#define IDC_CLIP_SHOW 2141
#define IDC_CLIP_PROC 2142
#define IDC_OPEN_DOWNLOADS 2143

#define IDC_TILE_BASE       3000


#define WM_APP_PROGRESS     (WM_APP + 2)
#define WM_APP_DONE         (WM_APP + 3)
#define WM_APP_LOG          (WM_APP + 4)
#define WM_APP_ITEM_DONE    (WM_APP + 5)
#define WM_APP_REFRESH      (WM_APP + 6)
#define WM_APP_AUTOMATION_DONE (WM_APP + 7)
#define WM_APP_AUTOMATION_BATCH_DONE (WM_APP + 8)

#define WM_APP_DOWNLOAD_CARD (WM_APP + 9)
#define TIMER_UI_TRANSITION 9001

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1 0x00000080
#endif

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 0x00000200
#endif

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 0x00000800
#endif

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif

struct DownloadItem
{
    std::wstring name;
    std::wstring url;
    std::wstring file;
    int tab;
    std::wstring description;
};

struct ParsedUrl
{
    std::wstring host;
    INTERNET_PORT port = 0;
    std::wstring pathAndQuery;
    bool https = false;
};


enum class DownloadError
{
    None,
    Cancelled,
    InvalidUrl,
    OpenSessionFailed,
    ConnectFailed,
    OpenRequestFailed,
    SendFailed,
    ReceiveFailed,
    HttpStatus,
    HtmlInsteadOfFile,
    HtmlLinkNotFound,
    ReadFailed,
    FileOpenFailed,
    FileWriteFailed,
    MoveFailed,
    SizeMismatch,
    TooManyRedirects,
    Stalled
};

struct DownloadResult
{
    bool ok = false;
    DownloadError error = DownloadError::None;
    DWORD httpStatus = 0;
    DWORD win32Error = 0;
    unsigned long long contentLength = 0;
    unsigned long long bytesWritten = 0;
    unsigned long long resumeFrom = 0;
    bool resumed = false;
    bool retryable = false;
    std::wstring finalUrl;
    std::wstring message;
};

static DownloadResult MakeDownloadError(DownloadError error, DWORD win32Error = 0, bool retryable = true)
{
    DownloadResult result;
    result.ok = false;
    result.error = error;
    result.win32Error = win32Error;
    result.retryable = retryable;
    return result;
}

static DownloadResult MakeDownloadOk()
{
    DownloadResult result;
    result.ok = true;
    result.error = DownloadError::None;
    return result;
}

struct ActiveDownloadInfo
{
    std::wstring name;
    std::wstring method;
    size_t linkIndex = 0;
    size_t linkTotal = 0;
    unsigned long long bytes = 0;
    unsigned long long totalBytes = 0;
    unsigned long long speedBps = 0;
    ULONGLONG startedTick = 0;
    ULONGLONG updatedTick = 0;
};

HINSTANCE g_hInst = nullptr;
HWND g_hMain = nullptr;
HWND g_hDownloadAll = nullptr;
HWND g_hPowerShell = nullptr;
HWND g_hEnableServices = nullptr;
HWND g_hDeleteHolyCheck = nullptr;
HWND g_hCancelDownload = nullptr;
struct DownloadItem;
HWND g_hSearchCheats = nullptr;
HWND g_hSearchConfigs = nullptr;
HWND g_hOpenDownloads = nullptr;
HWND g_hCopyPowerShell = nullptr;
HWND g_hCopySites = nullptr;
HWND g_hRefreshBoot = nullptr;
HWND g_hAutomationNav = nullptr;
HWND g_hHomeNav = nullptr;
HWND g_hAutomationBam = nullptr;
HWND g_hAutomationEventVwr = nullptr;
HWND g_hAutomationBamUnsignedOnly = nullptr;
HWND g_hAutomationJarPage = nullptr;

// --- Вкладка "file check" (page 5): кнопки, буферы вывода и флаг работы ---
HWND g_hFileCheckScan = nullptr;   // кнопка запуска сканирования ф��йлов
HWND g_hClipShow = nullptr;        // кнопка "показать текущий текст буфера"
HWND g_hClipProc = nullptr;        // кнопка "процессы cbdhsvc"
std::vector<std::wstring> g_fileCheckLines;   // строки результатов file check
std::vector<std::wstring> g_clipboardLines;   // строки блока буфера обмена
int g_fileCheckScrollOffset = 0;
int g_clipboardScrollOffset = 0;
std::atomic_bool g_automationFileCheckWorking{false};
HWND g_hJarActiv = nullptr;
HWND g_hExeDeleted = nullptr;
HWND g_hPfDeleted = nullptr;
HWND g_hMcLogs = nullptr;
HWND g_hPage4Nav = nullptr;
HWND g_hModHash = nullptr;
HWND g_hModFullScan = nullptr;
HWND g_hDllUnsigned = nullptr;
HWND g_hDllActivity = nullptr;
HWND g_hPage5Nav = nullptr;
HWND g_hInjGenCheck = nullptr;
HWND g_hEventEdit = nullptr;
HWND g_hJarEdit = nullptr;
HWND g_hExeEdit = nullptr;
HWND g_hPfEdit = nullptr;
HWND g_hMcEdit = nullptr;

HFONT g_hFont = nullptr;
HFONT g_hSmallFont = nullptr;
HFONT g_hTinyFont = nullptr;
HFONT g_hAutomationTextFont = nullptr;
HBRUSH g_hAutomationEditBrush = nullptr;

std::vector<HWND> g_tileButtons;
HDC g_sceneBufferDc = nullptr;
HBITMAP g_sceneBufferBitmap = nullptr;
HGDIOBJ g_sceneBufferOldBitmap = nullptr;
int g_sceneBufferWidth = 0;
int g_sceneBufferHeight = 0;

std::atomic_bool g_working(false);
std::atomic_bool g_cancelRequested(false);
std::atomic_bool g_scanCancelRequested(false);
 
std::atomic_bool g_deleteInProgress(false);
std::atomic_bool g_destroying(false);
std::atomic_int g_activeSingleDownloads(0);
int g_singleTotal = 0;
int g_singleDone = 0;
std::atomic_bool g_automationBamWorking(false);
std::atomic_bool g_automationEventWorking(false);
std::atomic_bool g_automationJarWorking(false);
std::atomic_bool g_automationJarModifiedWorking(false);
std::atomic_bool g_automationExeWorking(false);
std::atomic_bool g_automationPfWorking(false);
std::atomic_bool g_automationMcLogsWorking(false);
std::atomic_bool g_automationPage4Working(false);
std::atomic_bool g_automationDllWorking(false);
std::atomic_bool g_automationDllActivityWorking(false);
std::atomic_bool g_automationInjGenWorking(false);
std::atomic_int g_activityScanMode(0);
std::atomic_int g_page4ScanMode(0);
std::atomic_bool g_bamUnsignedOnly(true);

static bool AnyAutomationScanWorking()
{
    return g_automationBamWorking.load() ||
        g_automationEventWorking.load() ||
        g_automationJarWorking.load() ||
        g_automationJarModifiedWorking.load() ||
        g_automationExeWorking.load() ||
        g_automationPfWorking.load() ||
        g_automationMcLogsWorking.load() ||
        g_automationPage4Working.load() ||
        g_automationDllWorking.load() ||
        g_automationDllActivityWorking.load() ||
        g_automationInjGenWorking.load();
}

static thread_local bool g_lastTransferStalled = false;
static thread_local bool g_lastDownloadedPayloadInvalid = false;
static thread_local std::wstring g_lastDownloadMethod;
static thread_local unsigned long long g_lastDownloadSpeedBps = 0;
static thread_local bool g_lastHiddenProcessTimedOut = false;
static thread_local DWORD g_lastHiddenProcessExitCode = 0;
static thread_local DWORD g_lastHiddenProcessCreateError = 0;

static void ClearTransferStalledFlag()
{
    g_lastTransferStalled = false;
}

static void MarkTransferStalled()
{
    g_lastTransferStalled = true;
}

static bool DidLastTransferStall()
{
    return g_lastTransferStalled;
}

static void ClearDownloadedPayloadInvalidFlag()
{
    g_lastDownloadedPayloadInvalid = false;
}

static void MarkDownloadedPayloadInvalid()
{
    g_lastDownloadedPayloadInvalid = true;
}

static bool DidLastDownloadedPayloadInvalid()
{
    return g_lastDownloadedPayloadInvalid;
}

std::mutex g_zipMutex;
std::mutex g_logMutex;
std::mutex g_automationMutex;
std::mutex g_automationCacheMutex;
std::mutex g_activeDownloadsMutex;
std::mutex g_itemBusyMutex;
std::mutex g_httpHandlesMutex;
std::mutex g_ericDownloadMutex;
std::mutex g_debugLogMutex;

struct HttpHandleSlot
{
    HINTERNET handle = nullptr;
    bool closed = false;
};

std::vector<std::shared_ptr<HttpHandleSlot>> g_httpHandles;
std::vector<BYTE> g_itemBusy;
struct DownloadLogEntry
{
    std::wstring time;
    std::wstring message;
};

enum class DownloadCardPhase { Idle, Queued, Downloading, Extracting, Ready, Error, Cancelled };

std::vector<DownloadLogEntry> g_logLines;
std::vector<std::wstring> g_bamLines;
std::vector<std::wstring> g_eventVwrLines;
std::vector<std::wstring> g_jarActivityLines;
std::vector<std::wstring> g_jarModifiedLines;
std::vector<std::wstring> g_exeDeletedLines;
std::vector<std::wstring> g_pfDeletedLines;
std::vector<std::wstring> g_mcLogsLines;
std::vector<std::wstring> g_page4Lines;
std::vector<std::wstring> g_dllUnsignedLines;
std::vector<std::wstring> g_dllActivityLines;
std::vector<std::wstring> g_injGenLines;

struct AutomationCacheEntry
{
    ULONGLONG tick = 0;
    std::vector<std::wstring> lines;
};

std::map<int, AutomationCacheEntry> g_automationCache;
std::vector<ActiveDownloadInfo> g_activeDownloads;

std::atomic<bool> g_systemInformerInstalling(false);
std::atomic<int> g_systemInformerTileIndex(-1);
std::atomic<bool> g_recuvaInstalling(false);
std::atomic<int> g_recuvaTileIndex(-1);
std::atomic<bool> g_ftkImagerInstalling(false);
std::atomic<int> g_ftkImagerTileIndex(-1);
int g_logScrollOffset = 0;
int g_bamScrollOffset = 0;
int g_eventVwrScrollOffset = 0;
int g_jarActivityScrollOffset = 0;
int g_jarModifiedScrollOffset = 0;
int g_exeDeletedScrollOffset = 0;
int g_pfDeletedScrollOffset = 0;
int g_mcLogsScrollOffset = 0;
int g_page4ScrollOffset = 0;
int g_dllUnsignedScrollOffset = 0;
int g_dllActivityScrollOffset = 0;
int g_injGenScrollOffset = 0;
bool g_automationScrollDragging = false;
int g_automationScrollDragTarget = 0;
std::map<int, std::vector<float>> g_automationColumnWidthOverrides;
bool g_automationColumnResizing = false;
int g_automationColumnResizeTarget = 0;
size_t g_automationColumnResizeIndex = static_cast<size_t>(-1);
int g_automationColumnResizeStartX = 0;
float g_automationColumnResizeStartW = 0.0f;
int g_automationCopyHighlightTarget = 0;
size_t g_automationCopyHighlightIndex = static_cast<size_t>(-1);

int g_currentPage = 0;
WNDPROC g_oldAutomationEditProc = nullptr;
int g_progressPercent = 0;
ULONG_PTR g_gdiplusToken = 0;
DWORD g_uiThreadId = 0;

static const size_t HTML_READ_LIMIT = 4 * 1024 * 1024;
static const DWORD ZIP_EXTRACT_TIMEOUT_MS = 120000;
static const DWORD ZIP_EXTRACT_POLL_MS = 250;

const COLORREF BG = MailsTheme::Canvas;
const COLORREF TEXT = MailsTheme::Text;
static const wchar_t* g_homeFontFace = L"Segoe UI";
static const wchar_t* g_homeMonoFace = L"Consolas";

static constexpr int HOME_MARGIN = 3 * MailsTheme::Grid;
static constexpr int HOME_HEADER = 8 * MailsTheme::Grid;
static constexpr int HOME_RAIL_RIGHT = 32 * MailsTheme::Grid;
static constexpr int HOME_MAIN_X = HOME_RAIL_RIGHT + HOME_MARGIN;
static constexpr int HOME_TILE_TOP = 17 * MailsTheme::Grid;
static constexpr int HOME_TILE_HEIGHT = 8 * MailsTheme::Grid;
static constexpr int HOME_TILE_GAP = MailsTheme::Grid;
static constexpr int HOME_FOOTER_HEIGHT = 9 * MailsTheme::Grid;
static constexpr int LOG_HEADER_HEIGHT = 5 * MailsTheme::Grid;
static constexpr int LOG_COLUMN_HEIGHT = 3 * MailsTheme::Grid;
static constexpr int LOG_ROW_HEIGHT = 3 * MailsTheme::Grid;
static constexpr size_t LOG_MAX_LINES = 200;
static size_t g_logVisibleLines = 3;
static constexpr int CANCEL_BUTTON_W = 14 * MailsTheme::Grid;

static std::vector<DownloadCardPhase> g_downloadCardPhases;
static std::vector<size_t> g_operationItems;
static bool g_operationBatch = false;
static bool g_operationFinished = false;
static bool g_operationCancelled = false;
static bool g_operationHadError = false;
static bool g_reduceMotion = false;

static const int AUTOMATION_LEFT_X = 28;
static const int AUTOMATION_PANEL_X = 145;
static const int AUTOMATION_BUTTON_W = 104;
static const int AUTOMATION_BUTTON_H = MailsTheme::Target;
static const int AUTOMATION_PANEL_MIN_W = 520;
static const int AUTOMATION_PANEL_H = 156;
static const int AUTOMATION_SERVICE_PANEL_W = 360;
static const int AUTOMATION_SERVICE_PANEL_H = 210;
static const int AUTOMATION_SERVICE_PANEL_MARGIN = 24;
static const size_t AUTOMATION_MAX_LINES = 5000;
static const size_t AUTOMATION_VISIBLE_LINES = 10;
static const DWORD AUTOMATION_CACHE_TTL_MS = 45000;
static const DWORD AUTOMATION_EVENT_MAX_PER_CHANNEL = 160;

enum AutomationOutputKind
{
    AUTOMATION_OUTPUT_BAM = 1,
    AUTOMATION_OUTPUT_EVENTVWR = 2,
    AUTOMATION_OUTPUT_JAR_ACTIVITY = 4,
    AUTOMATION_OUTPUT_PAGE4 = 5,
    AUTOMATION_OUTPUT_EXE_DELETED = 6,
    AUTOMATION_OUTPUT_PF_DELETED = 7,
    AUTOMATION_OUTPUT_MC_LOGS = 8,
    AUTOMATION_OUTPUT_DLL_UNSIGNED = 9,
    AUTOMATION_OUTPUT_INJGEN = 10,
    AUTOMATION_OUTPUT_JAR_MODIFIED = 11,
    AUTOMATION_OUTPUT_DLL_ACTIVITY = 12,
    // Новая вкладка file check: результаты проверки файлов и блок буфера обмена.
    AUTOMATION_OUTPUT_FILECHECK = 20,
    AUTOMATION_OUTPUT_CLIPBOARD = 21
};

struct AutomationResult
{
    int target = 0;
    std::vector<std::wstring> lines;
};

struct AutomationBatchItem
{
    int target = 0;
    std::vector<std::wstring> lines;
};

struct AutomationBatchResult
{
    std::vector<AutomationBatchItem> items;
};

static RECT MakeAutomationButtonRect(int top)
{
    RECT out{};
    out.left = AUTOMATION_LEFT_X;
    out.top = top;
    out.right = out.left + AUTOMATION_BUTTON_W;
    out.bottom = out.top + AUTOMATION_BUTTON_H;
    return out;
}

static RECT GetAutomationBamButtonRect(const RECT&)
{
    return MakeAutomationButtonRect(84);
}

static RECT GetModFullScanButtonRect(const RECT&)
{
    return MakeAutomationButtonRect(124);
}

static RECT GetAutomationEventButtonRect(const RECT&)
{
    return MakeAutomationButtonRect(254);
}


static RECT GetAutomationJarPageButtonRect(const RECT& rc)
{
    const int topButtonH = MailsTheme::Target;
    const int topGap = MailsTheme::Grid;
    const int topY = 12;
    const int navButtonW = 116;
    int navX = rc.right - 24 - navButtonW;

    RECT out{};
    out.left = navX - topGap - navButtonW;
    out.top = topY;
    out.right = out.left + navButtonW;
    out.bottom = out.top + topButtonH;

    if (out.left < AUTOMATION_PANEL_X)
        return MakeAutomationButtonRect(590);

    return out;
}

static RECT GetJarActivButtonRect(const RECT&)
{
    // Keep the JT scan button higher so it does not visually sit on the same
    // vertical band as the first result panel.
    return MakeAutomationButtonRect(76);
}

static RECT GetExeDeletedButtonRect(const RECT&)
{
    return MakeAutomationButtonRect(132);
}

static RECT GetPfDeletedButtonRect(const RECT&)
{
    return MakeAutomationButtonRect(174);
}

static RECT GetMcLogsButtonRect(const RECT&)
{
    return MakeAutomationButtonRect(216);
}

static RECT GetModHashButtonRect(const RECT&)
{
    return MakeAutomationButtonRect(90);
}

static RECT GetDllUnsignedButtonRect(const RECT&)
{
    return MakeAutomationButtonRect(132);
}

static RECT GetDllActivityButtonRect(const RECT&)
{
    return MakeAutomationButtonRect(174);
}

static RECT GetInjGenButtonRect(const RECT&)
{
    return MakeAutomationButtonRect(90);
}

static RECT GetAutomationBamUnsignedOnlyRect(const RECT&)
{
    RECT out{};
    out.left = AUTOMATION_LEFT_X;
    out.top = 124;
    out.right = out.left + AUTOMATION_BUTTON_W;
    out.bottom = out.top + MailsTheme::Target;
    return out;
}

static RECT MakeAutomationPanelRect(const RECT& rc, int top, int height)
{
    RECT out{};
    out.left = AUTOMATION_PANEL_X;
    out.top = top;
    out.right = rc.right - AUTOMATION_SERVICE_PANEL_MARGIN;

    if (out.right - out.left < AUTOMATION_PANEL_MIN_W)
        out.right = out.left + AUTOMATION_PANEL_MIN_W;

    out.bottom = out.top + height;

    if (out.bottom > rc.bottom - 70)
    {
        out.bottom = rc.bottom - 70;
        out.top = std::max<int>(70, static_cast<int>(out.bottom) - height);
    }

    return out;
}

static RECT MakePage3PanelRect(const RECT& rc, int index);

static RECT GetAutomationServicesPanelRect(const RECT& rc)
{
    RECT out{};
    out.right = rc.right - AUTOMATION_SERVICE_PANEL_MARGIN;
    out.left = out.right - AUTOMATION_SERVICE_PANEL_W;
    out.bottom = rc.bottom - 48;
    out.top = out.bottom - AUTOMATION_SERVICE_PANEL_H;

    if (out.top < 470)
        out.top = 470;

    if (out.left < AUTOMATION_PANEL_X + 360)
        out.left = AUTOMATION_PANEL_X + 360;

    return out;
}

static int GetAutomationMainPanelRight(const RECT& rc)
{
    RECT services = GetAutomationServicesPanelRect(rc);
    int right = services.left - 12;
    int hardRight = rc.right - AUTOMATION_SERVICE_PANEL_MARGIN;

    if (right <= AUTOMATION_PANEL_X + 360)
        right = hardRight;

    if (right > hardRight)
        right = hardRight;

    return right;
}

// Вкладка check использует ту же вертикальную сетку и ту же область, что dll | jar:
// верхняя половина — checkmods, нижняя половина — eventvwr + службы/Вкл ПК.
static RECT GetAutomationBamPanelRect(const RECT& rc)
{
    return MakePage3PanelRect(rc, 0);
}

static RECT GetAutomationEventPanelRect(const RECT& rc)
{
    RECT out = MakePage3PanelRect(rc, 1);
    out.right = GetAutomationMainPanelRight(rc);
    if (out.right - out.left < 360)
        out.right = out.left + 360;
    return out;
}

static RECT MakePage3PanelRect(const RECT& rc, int index)
{
    int left = AUTOMATION_PANEL_X;
    int right = rc.right - AUTOMATION_SERVICE_PANEL_MARGIN;
    // dll | jar: две панели — .jar activity и .dll activity.
    // Панель unsigned dll перенесена на вкладку file check.
    int top = HOME_HEADER;
    int gap = 8;
    const int count = 2;
    if (index < 0) index = 0;
    if (index >= count) index = count - 1;
    int bottomLimit = rc.bottom - 48;
    int totalH = bottomLimit - top;
    int h = std::max<int>(145, (totalH - gap * (count - 1)) / count);
    RECT out{};
    out.left = left;
    out.right = right;
    out.top = top + index * (h + gap);
    out.bottom = (index == count - 1) ? bottomLimit : (out.top + h);
    if (out.right - out.left < AUTOMATION_PANEL_MIN_W)
        out.right = out.left + AUTOMATION_PANEL_MIN_W;
    if (out.bottom <= out.top + 110)
        out.bottom = out.top + 110;
    return out;
}

static RECT GetJarActivityPanelRect(const RECT& rc) { return MakePage3PanelRect(rc, 0); }
static RECT GetJarModifiedPanelRect(const RECT& rc) { return MakePage3PanelRect(rc, 1); }
static RECT GetExeDeletedPanelRect(const RECT& rc) { return MakePage3PanelRect(rc, 1); }
static RECT GetMcLogsPanelRect(const RECT& rc) { return MakePage3PanelRect(rc, 1); }
static RECT GetPfDeletedPanelRect(const RECT& rc) { return MakePage3PanelRect(rc, 0); }
static RECT GetDllActivityPanelRect(const RECT& rc) { return MakePage3PanelRect(rc, 1); }

// --- Разметка вкладки "file check" (page 5) ---
// Кнопки слева (тот же столбец, что и у scan на других вкладках).
static RECT GetFileCheckButtonRect(const RECT&) { return MakeAutomationButtonRect(84); }
static RECT GetClipShowButtonRect(const RECT&)  { return MakeAutomationButtonRect(126); }
static RECT GetClipProcButtonRect(const RECT&)  { return MakeAutomationButtonRect(168); }

// Вкладка file check содержит две панели: сверху — проверка совпадения
// типа с расширением, снизу — unsigned dll.
static void MakeFileCheckPanelRects(const RECT& rc, RECT& top, RECT& bottom)
{
    const int left = AUTOMATION_PANEL_X;
    int right = rc.right - AUTOMATION_SERVICE_PANEL_MARGIN;
    if (right - left < AUTOMATION_PANEL_MIN_W)
        right = left + AUTOMATION_PANEL_MIN_W;

    const int areaTop = 48;
    const int gap = 8;
    int areaBottom = rc.bottom - 48;
    if (areaBottom <= areaTop + 260)
        areaBottom = areaTop + 260;

    int h = std::max<int>(120, (areaBottom - areaTop - gap) / 2);

    top.left = left;
    top.right = right;
    top.top = areaTop;
    top.bottom = areaTop + h;

    bottom.left = left;
    bottom.right = right;
    bottom.top = top.bottom + gap;
    bottom.bottom = areaBottom;
    if (bottom.bottom <= bottom.top + 110)
        bottom.bottom = bottom.top + 110;
}

static RECT GetFileCheckPanelRect(const RECT& rc)
{
    RECT top{}, bottom{};
    MakeFileCheckPanelRects(rc, top, bottom);
    return top;
}

// Нижняя панель вкладки file check — unsigned dll.
static RECT GetDllUnsignedPanelRect(const RECT& rc)
{
    RECT top{}, bottom{};
    MakeFileCheckPanelRects(rc, top, bottom);
    return bottom;
}

// Нижняя панель — буфер обмена / cbdhsvc.
static RECT GetClipPanelRect(const RECT& rc)
{
    RECT top = GetFileCheckPanelRect(rc);
    RECT out{};
    out.left = AUTOMATION_PANEL_X;
    out.right = rc.right - AUTOMATION_SERVICE_PANEL_MARGIN;
    out.top = top.bottom + 8;
    out.bottom = rc.bottom - 48;
    if (out.right - out.left < AUTOMATION_PANEL_MIN_W)
        out.right = out.left + AUTOMATION_PANEL_MIN_W;
    if (out.bottom <= out.top + 110)
        out.bottom = out.top + 110;
    return out;
}

static RECT GetFullAutomationPanelRect(const RECT& rc)
{
    RECT out{};
    out.left = AUTOMATION_PANEL_X;
    out.top = 78;
    out.right = rc.right - AUTOMATION_SERVICE_PANEL_MARGIN;
    out.bottom = rc.bottom - 68;
    if (out.right - out.left < AUTOMATION_PANEL_MIN_W)
        out.right = out.left + AUTOMATION_PANEL_MIN_W;
    if (out.bottom - out.top < 220)
        out.bottom = out.top + 220;
    return out;
}

static RECT MakeSplitAutomationPanelRect(const RECT& rc, int index)
{
    RECT full = GetFullAutomationPanelRect(rc);
    const int gap = 12;
    int total = full.bottom - full.top;
    int h = std::max(180, (total - gap) / 2);
    RECT out = full;
    out.top = full.top + index * (h + gap);
    out.bottom = (index == 0) ? (out.top + h) : full.bottom;
    if (out.bottom <= out.top + 120)
        out.bottom = out.top + 120;
    return out;
}

static RECT GetPage4PanelRect(const RECT& rc)
{
    return MakeSplitAutomationPanelRect(rc, 0);
}

static RECT GetPage4DllPanelRect(const RECT& rc)
{
    return MakeSplitAutomationPanelRect(rc, 1);
}

static RECT GetPage5PanelRect(const RECT& rc)
{
    return MakeSplitAutomationPanelRect(rc, 0);
}

static RECT GetPage5InjGenPanelRect(const RECT& rc)
{
    return GetFullAutomationPanelRect(rc);
}

static bool PointInRect(const RECT& rc, POINT pt)
{
    return pt.x >= rc.left && pt.x < rc.right && pt.y >= rc.top && pt.y < rc.bottom;
}

static int GetMaxLogScrollOffsetLocked()
{
    if (g_logLines.size() <= g_logVisibleLines)
        return 0;

    return static_cast<int>(g_logLines.size() - g_logVisibleLines);
}

static void ClampLogScrollOffsetLocked()
{
    int maxOffset = GetMaxLogScrollOffsetLocked();

    if (g_logScrollOffset < 0)
        g_logScrollOffset = 0;

    if (g_logScrollOffset > maxOffset)
        g_logScrollOffset = maxOffset;
}

static bool ScrollDownloadLog(int wheelDelta)
{
    std::lock_guard<std::mutex> lock(g_logMutex);

    int maxOffset = GetMaxLogScrollOffsetLocked();

    if (maxOffset <= 0)
        return false;

    int oldOffset = g_logScrollOffset;
    int step = std::max(1, std::abs(wheelDelta) / WHEEL_DELTA);

    if (wheelDelta > 0)
        g_logScrollOffset += step;
    else if (wheelDelta < 0)
        g_logScrollOffset -= step;

    ClampLogScrollOffsetLocked();
    return g_logScrollOffset != oldOffset;
}

static std::vector<DownloadItem> g_items =
{
    { L"Everything",           L"https://www.voidtools.com/Everything-1.5.0.1404a.x64.zip", L"Everything-1.5.0.1404a.x64.zip", 0, L"Мгновенный поиск файлов" },
    { L"ShellBag Analyzer",    L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/shellbag_analyzer_cleaner.exe", L"shellbag_analyzer_cleaner.exe", 0, L"История открытых папок" },
    { L"RecentFilesView",      L"https://www.nirsoft.net/utils/recentfilesview.zip", L"recentfilesview.zip", 0, L"Недавние файлы" },
    { L"SystemInformer",       L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/systeminformer-build-canary-setup.exe", L"systeminformer-build-canary-setup.exe", 0, L"Процессы и службы" },
    { L"LastActivityView",     L"https://www.nirsoft.net/utils/lastactivityview.zip", L"lastactivityview.zip", 0, L"Действия в Windows" },
    { L"ExecutedProgramsList", L"https://www.nirsoft.net/utils/executedprogramslist.zip", L"executedprogramslist.zip", 0, L"История запуска программ" },
    { L"RegScanner",           L"https://www.nirsoft.net/utils/regscanner.zip", L"regscanner.zip", 0, L"Поиск в реестре" },
    { L"ProcessHacker",        L"https://github.com/processhacker/processhacker/releases/download/v2.39/processhacker-2.39-setup.exe", L"processhacker-2.39-setup.exe", 3, L"Просмотр процессов Windows" },
    { L"BrowserDownloadsView", L"https://www.nirsoft.net/utils/browserdownloadsview.zip", L"browserdownloadsview.zip", 0, L"Загрузки из браузеров" },
    { L"MinecraftVersionChecker", L"https://github.com/HolyWorldWEB/VersionChecker/releases/download/v1.0.0/MinecraftVersionChecker.exe", L"MinecraftVersionChecker.exe", 0, L"Версии и профили Minecraft" },
    { L"USBDriveLog",          L"https://www.nirsoft.net/utils/usbdrivelog.zip", L"usbdrivelog.zip", 0, L"Подключения USB-дисков" },
    { L"USBDeview",            L"https://usbdeview.com/wp-content/uploads/2025/02/usbdeview-x64.zip", L"usbdeview-x64.zip", 3, L"История USB-устройств" },
    { L"JournalTrace",         L"https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTrace.exe", L"JournalTrace.exe", 0, L"Изменения файлов в NTFS" },
    { L"WinRAR",               L"https://www.rarlab.com/rar/winrar-x64-722ru.exe", L"winrar-x64-722ru.exe", 0, L"Работа с архивами" },

    { L"BAMParser",            L"https://github.com/spokwn/BAM-parser/releases/download/v1.2.8/BAMParser.exe", L"BAMParser.exe", 1, L"Запуски по данным BAM" },
    { L"RegistryExplorer",     L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/RegistryExplorer.zip", L"RegistryExplorer.zip", 1, L"Анализ файлов реестра" },
    { L"JumpListExplorer",     L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/JumpListExplorer.zip", L"JumpListExplorer.zip", 1, L"Документы из списков переходов" },
    { L"SimpleUnlocker",       L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/simpleunlocker_release.zip", L"simpleunlocker_release.zip", 1, L"Снятие блокировки с файлов" },
    { L"WinPrefetchView",      L"https://www.nirsoft.net/utils/winprefetchview.zip", L"winprefetchview.zip", 1, L"Запуски по данным Prefetch" },
    { L"Recuva",               L"https://download.ccleaner.com/rcsetup155.exe", L"rcsetup155.exe", 1, L"Восстановление файлов" },

    { L"PathsParser",          L"https://github.com/spokwn/PathsParser/releases/download/v1.1/PathsParser.exe", L"PathsParser.exe", 2, L"Извлечение путей к файлам" },
    { L"Detect It Easy",       L"https://github.com/horsicq/Detect-It-Easy/releases/download/Beta/die_win64_portable_3.10_x64.zip", L"die_win64_portable_3.10_x64.zip", 2, L"Тип и упаковщик файла" },
    { L"Recaf CLI",            L"https://github.com/Col-E/Recaf-Launcher/releases/download/0.8.8/recaf-cli-0.8.8.jar", L"recaf-cli-0.8.8.jar", 2, L"Анализ байткода Java" },

    { L"BrowsingHistoryView",  L"https://www.nirsoft.net/utils/browsinghistoryview.zip", L"browsinghistoryview.zip", 3, L"История посещений в браузерах" },
    { L"AlternateStreamView",  L"https://www.nirsoft.net/utils/alternatestreamview-x64.zip", L"alternatestreamview-x64.zip", 3, L"Потоки данных NTFS" },
    { L"WinDefLogView",        L"https://www.nirsoft.net/utils/windeflogview.zip", L"windeflogview.zip", 3, L"Журнал Защитника Windows" },
    { L"VolatilityWorkbench",  L"https://www.osforensics.com/downloads/VolatilityWorkbench.zip", L"VolatilityWorkbench.zip", 3, L"Анализ дампов памяти" },
    { L"KernelLiveDumpTool",   L"https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe", L"KernelLiveDumpTool.exe", 3, L"Создание дампа ядра" },
    { L"FTK Imager",           L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/FTK.Imager.8.3.0.27.zip", L"FTK.Imager.8.3.0.27.zip", 3, L"Образы дисков и файлов" }
};
