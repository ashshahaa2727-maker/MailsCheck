static std::wstring EscapePowerShellSingleQuoted(std::wstring s);
static std::wstring QuoteProcessArgument(const std::wstring& arg);
static std::wstring GetSystemToolPath(const wchar_t* relativePath);

struct DirectoryStats
{
    unsigned long long files = 0;
    unsigned long long dirs = 0;
    unsigned long long bytes = 0;
};

static bool GetDirectoryStatsRecursive(const std::wstring& dir, DirectoryStats& stats)
{
    std::wstring mask = CombinePath(dir, L"*");
    WIN32_FIND_DATAW data{};
    HANDLE hFind = FindFirstFileW(mask.c_str(), &data);

    if (hFind == INVALID_HANDLE_VALUE)
        return false;

    do
    {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
            continue;

        std::wstring child = CombinePath(dir, data.cFileName);

        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            ++stats.dirs;

            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                GetDirectoryStatsRecursive(child, stats);
        }
        else
        {
            ++stats.files;
            ULARGE_INTEGER size{};
            size.HighPart = data.nFileSizeHigh;
            size.LowPart = data.nFileSizeLow;
            stats.bytes += size.QuadPart;
        }
    }
    while (FindNextFileW(hFind, &data));

    FindClose(hFind);
    return true;
}

static bool DirectoryHasAnyEntry(const std::wstring& dir)
{
    DirectoryStats stats{};
    return GetDirectoryStatsRecursive(dir, stats) && (stats.files > 0 || stats.dirs > 0);
}

static bool DirectoryHasAnyEntryShallow(const std::wstring& dir)
{
    std::wstring mask = CombinePath(dir, L"*");
    WIN32_FIND_DATAW data{};
    HANDLE hFind = FindFirstFileW(mask.c_str(), &data);

    if (hFind == INVALID_HANDLE_VALUE)
        return false;

    bool found = false;

    do
    {
        if (wcscmp(data.cFileName, L".") != 0 && wcscmp(data.cFileName, L"..") != 0)
        {
            found = true;
            break;
        }
    }
    while (FindNextFileW(hFind, &data));

    FindClose(hFind);
    return found;
}

static bool WaitForDirectoryToStabilize(const std::wstring& dir, DWORD timeoutMs, DWORD stableMs)
{
    ULONGLONG started = GetTickCount64();
    ULONGLONG lastChanged = started;
    DirectoryStats last{};
    bool haveLast = false;

    while (!IsCancelRequested() && GetTickCount64() - started < timeoutMs)
    {
        DirectoryStats current{};
        bool ok = GetDirectoryStatsRecursive(dir, current);
        ULONGLONG now = GetTickCount64();

        if (ok && (current.files > 0 || current.dirs > 0))
        {
            if (!haveLast || current.files != last.files || current.dirs != last.dirs || current.bytes != last.bytes)
            {
                last = current;
                haveLast = true;
                lastChanged = now;
            }
            else if (now - lastChanged >= stableMs)
            {
                return true;
            }
        }

        Sleep(ZIP_EXTRACT_POLL_MS);
    }

    return false;
}

static DWORD RunHiddenProcessAndWait(std::wstring commandLine, DWORD timeoutMs)
{
    DebugLogLine(L"process", L"RunHiddenProcessAndWait start timeout=" + std::to_wstring(timeoutMs) + L" command=" + commandLine);
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};

    if (!CreateProcessW(
        nullptr,
        mutableCommand.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi))
    {
        DebugLogLine(L"process", L"RunHiddenProcessAndWait CreateProcess failed error=" + FormatWin32ErrorForLog(GetLastError()) + L" command=" + commandLine);
        return static_cast<DWORD>(-1);
    }

    DWORD wait = WaitForSingleObject(pi.hProcess, timeoutMs);
    DWORD exitCode = static_cast<DWORD>(-1);

    if (wait == WAIT_TIMEOUT)
    {
        TerminateProcess(pi.hProcess, ERROR_TIMEOUT);
        exitCode = ERROR_TIMEOUT;
    }
    else if (wait == WAIT_OBJECT_0)
    {
        GetExitCodeProcess(pi.hProcess, &exitCode);
    }

    DebugLogLine(L"process", L"RunHiddenProcessAndWait finish wait=" + std::to_wstring(wait) + L" exit=" + std::to_wstring(exitCode));
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return exitCode;
}

static bool ExtractZipWithPowerShell(const std::wstring& zipPath, const std::wstring& destDir)
{
    std::wstring powershell = GetSystemToolPath(L"WindowsPowerShell\\v1.0\\powershell.exe");

    std::wstring script =
        L"try { "
        L"Expand-Archive -LiteralPath '" + EscapePowerShellSingleQuoted(zipPath) +
        L"' -DestinationPath '" + EscapePowerShellSingleQuoted(destDir) +
        L"' -Force -ErrorAction Stop; exit 0 } catch { exit 1 }";

    std::wstring command = QuoteProcessArgument(powershell) +
        L" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " +
        QuoteProcessArgument(script);

    return RunHiddenProcessAndWait(command, ZIP_EXTRACT_TIMEOUT_MS) == 0 &&
        DirectoryHasAnyEntryShallow(destDir) &&
        !IsCancelRequested();
}

static bool ExtractZipWithTar(const std::wstring& zipPath, const std::wstring& destDir)
{
    std::wstring tar = GetSystemToolPath(L"tar.exe");
    std::wstring command = QuoteProcessArgument(tar) +
        L" -xf " + QuoteProcessArgument(zipPath) +
        L" -C " + QuoteProcessArgument(destDir);

    return RunHiddenProcessAndWait(command, ZIP_EXTRACT_TIMEOUT_MS) == 0 &&
        DirectoryHasAnyEntryShallow(destDir) &&
        !IsCancelRequested();
}

static bool ExtractZipWithShellFallback(const std::wstring& zipPath, const std::wstring& destDir)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool needUninit = SUCCEEDED(hr);

    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
        return false;

    IShellDispatch* shell = nullptr;
    hr = CoCreateInstance(CLSID_Shell, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&shell));

    if (FAILED(hr) || !shell)
    {
        if (needUninit)
            CoUninitialize();

        return false;
    }

    VARIANT vZip;
    VARIANT vDest;

    VariantInit(&vZip);
    VariantInit(&vDest);

    vZip.vt = VT_BSTR;
    vZip.bstrVal = SysAllocString(zipPath.c_str());

    vDest.vt = VT_BSTR;
    vDest.bstrVal = SysAllocString(destDir.c_str());

    if (!vZip.bstrVal || !vDest.bstrVal)
    {
        VariantClear(&vZip);
        VariantClear(&vDest);
        shell->Release();

        if (needUninit)
            CoUninitialize();

        return false;
    }

    Folder* zipFolder = nullptr;
    Folder* destFolder = nullptr;

    shell->NameSpace(vZip, &zipFolder);
    shell->NameSpace(vDest, &destFolder);

    if (!zipFolder || !destFolder)
    {
        if (zipFolder) zipFolder->Release();
        if (destFolder) destFolder->Release();

        VariantClear(&vZip);
        VariantClear(&vDest);
        shell->Release();

        if (needUninit)
            CoUninitialize();

        return false;
    }

    FolderItems* items = nullptr;
    zipFolder->Items(&items);

    if (!items)
    {
        destFolder->Release();
        zipFolder->Release();
        VariantClear(&vZip);
        VariantClear(&vDest);
        shell->Release();

        if (needUninit)
            CoUninitialize();

        return false;
    }

    VARIANT vItems;
    VARIANT vOptions;

    VariantInit(&vItems);
    VariantInit(&vOptions);

    vItems.vt = VT_DISPATCH;
    vItems.pdispVal = items;

    vOptions.vt = VT_I4;
    vOptions.lVal = 4 | 16 | 512 | 1024;

    hr = destFolder->CopyHere(vItems, vOptions);
    bool stable = SUCCEEDED(hr) && WaitForDirectoryToStabilize(destDir, ZIP_EXTRACT_TIMEOUT_MS, 2500);

    items->Release();
    destFolder->Release();
    zipFolder->Release();

    VariantClear(&vZip);
    VariantClear(&vDest);
    shell->Release();

    if (needUninit)
        CoUninitialize();

    return SUCCEEDED(hr) && stable && !IsCancelRequested();
}

static bool ExtractZip(const std::wstring& zipPath, const std::wstring& destDir)
{
    std::lock_guard<std::mutex> lock(g_zipMutex);
    DebugLogLine(L"extract", L"ExtractZip start zip=" + zipPath + L" dest=" + destDir);

    if (!FileExists(zipPath))
    {
        DebugLogLine(L"extract", L"ExtractZip missing zip=" + zipPath);
        return false;
    }

    if (!EnsureDirectory(destDir))
    {
        DebugLogLine(L"extract", L"ExtractZip cannot create dest=" + destDir);
        return false;
    }

    if (ExtractZipWithTar(zipPath, destDir))
    {
        DebugLogLine(L"extract", L"ExtractZip ok via tar zip=" + zipPath);
        return true;
    }

    DebugLogLine(L"extract", L"ExtractZip tar failed zip=" + zipPath);

    if (ExtractZipWithPowerShell(zipPath, destDir))
    {
        DebugLogLine(L"extract", L"ExtractZip ok via PowerShell zip=" + zipPath);
        return true;
    }

    DebugLogLine(L"extract", L"ExtractZip PowerShell failed zip=" + zipPath);
    bool shellOk = ExtractZipWithShellFallback(zipPath, destDir);
    DebugLogLine(L"extract", L"ExtractZip shell result=" + std::to_wstring(shellOk ? 1 : 0) + L" zip=" + zipPath);
    return shellOk;
}

static std::wstring EscapePowerShellSingleQuoted(std::wstring s)
{
    size_t pos = 0;

    while ((pos = s.find(L'\'', pos)) != std::wstring::npos)
    {
        s.insert(pos, L"'");
        pos += 2;
    }

    return s;
}
static std::wstring QuoteProcessArgument(const std::wstring& arg)
{
    if (arg.empty())
        return L"\"\"";

    bool needQuotes = false;

    for (wchar_t ch : arg)
    {
        if (iswspace(ch) || ch == L'\"')
        {
            needQuotes = true;
            break;
        }
    }

    if (!needQuotes)
        return arg;

    std::wstring out = L"\"";
    size_t backslashes = 0;

    for (wchar_t ch : arg)
    {
        if (ch == L'\\')
        {
            ++backslashes;
        }
        else if (ch == L'\"')
        {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(ch);
            backslashes = 0;
        }
        else
        {
            out.append(backslashes, L'\\');
            backslashes = 0;
            out.push_back(ch);
        }
    }

    out.append(backslashes * 2, L'\\');
    out.push_back(L'\"');
    return out;
}

static std::wstring GetSystemToolPath(const wchar_t* relativePath)
{
    wchar_t systemDir[MAX_PATH * 2]{};
    UINT len = GetSystemDirectoryW(systemDir, ARRAYSIZE(systemDir));

    if (len == 0 || len >= ARRAYSIZE(systemDir))
        return relativePath ? relativePath : L"";

    std::wstring path = CombinePath(systemDir, relativePath ? relativePath : L"");
    return FileExists(path) ? path : std::wstring(relativePath ? relativePath : L"");
}

static std::wstring Base64EncodeBytes(const unsigned char* data, size_t len)
{
    static const wchar_t alphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::wstring out;
    out.reserve(((len + 2) / 3) * 4);

    for (size_t i = 0; i < len; i += 3)
    {
        unsigned int value = data[i] << 16;
        bool has2 = i + 1 < len;
        bool has3 = i + 2 < len;

        if (has2)
            value |= data[i + 1] << 8;

        if (has3)
            value |= data[i + 2];

        out.push_back(alphabet[(value >> 18) & 0x3F]);
        out.push_back(alphabet[(value >> 12) & 0x3F]);
        out.push_back(has2 ? alphabet[(value >> 6) & 0x3F] : L'=');
        out.push_back(has3 ? alphabet[value & 0x3F] : L'=');
    }

    return out;
}

static std::wstring Base64EncodePowerShellCommand(const std::wstring& command)
{
    return Base64EncodeBytes(reinterpret_cast<const unsigned char*>(command.data()), command.size() * sizeof(wchar_t));
}



static bool DownloadWithCurlFallback(
    const std::wstring& url,
    const std::wstring& targetPath,
    DWORD timeoutMs = 18000,
    const std::wstring& itemName = L"",
    size_t linkIndex = 0,
    size_t linkTotal = 0);
static bool DownloadWithPowerShellFallback(
    const std::wstring& url,
    const std::wstring& targetPath,
    DWORD timeoutMs = 22000,
    unsigned long long minBytesPerSecond = 1ull * 1024ull,
    DWORD lowSpeedWindowMs = 60000,
    DWORD noProgressAbortMs = 45000,
    const std::wstring& itemName = L"",
    size_t linkIndex = 0,
    size_t linkTotal = 0);
static bool DownloadRecursiveValidated(const DownloadItem& item, const std::wstring& url, const std::wstring& targetPath);
static bool DownloadCurlValidated(const DownloadItem& item, const std::wstring& url, const std::wstring& targetPath);
static bool DownloadPowerShellValidated(const DownloadItem& item, const std::wstring& url, const std::wstring& targetPath);

