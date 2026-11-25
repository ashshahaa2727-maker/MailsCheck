static const unsigned long long MIN_ACCEPTABLE_DOWNLOAD_SPEED_BPS = 14ull * 1024ull;
static const unsigned long long FAST_SWITCH_DOWNLOAD_SPEED_BPS = 96ull * 1024ull;

static bool ReadFilePrefix(const std::wstring& path, std::vector<unsigned char>& out, DWORD maxBytes);
static bool StartsWithBytes(const std::vector<unsigned char>& data, std::initializer_list<unsigned char> bytes);
static bool LooksLikeDownloadedHtml(const std::vector<unsigned char>& data);
static bool IsZipArchiveStructurallyValid(const std::wstring& path);
static bool IsRecuvaItem(const DownloadItem& item);

static unsigned long long GetMinCompleteExeSizeForName(const std::wstring& itemName)
{
    std::wstring lower = ToLower(itemName);

    if (lower.find(L"systeminformer") != std::wstring::npos ||
        (lower.find(L"system") != std::wstring::npos && lower.find(L"informer") != std::wstring::npos))
        return 10ull * 1024ull * 1024ull;

    if (lower.find(L"processhacker") != std::wstring::npos ||
        (lower.find(L"process") != std::wstring::npos && lower.find(L"hacker") != std::wstring::npos))
        return 1024ull * 1024ull;

    if (lower.find(L"bamparser") != std::wstring::npos || lower.find(L"bam parser") != std::wstring::npos)
        return 200ull * 1024ull;

    if (lower.find(L"journaltrace") != std::wstring::npos ||
        (lower.find(L"journal") != std::wstring::npos && lower.find(L"trace") != std::wstring::npos))
        return 100ull * 1024ull;

    if (lower.find(L"recuva") != std::wstring::npos)
        return 2ull * 1024ull * 1024ull;

    return 4096ull;
}

static bool TryFinalizeAbortedPartFile(
    const std::wstring& itemName,
    const std::wstring& partPath,
    const std::wstring& targetPath)
{
    if (!FileExists(partPath) || IsCancelRequested())
        return false;

    unsigned long long partSize = 0;
    if (!GetFileSizeBytes(partPath, partSize) || partSize == 0)
        return false;

    std::vector<unsigned char> head;
    if (!ReadFilePrefix(partPath, head, 32) || LooksLikeDownloadedHtml(head))
        return false;

    std::wstring lowerTarget = ToLower(targetPath);

    if (EndsWithI(lowerTarget, L".exe") || EndsWithI(lowerTarget, L".msi"))
    {
        return false;
    }
    else if (EndsWithI(lowerTarget, L".zip") || EndsWithI(lowerTarget, L".jar"))
    {
        if (!StartsWithBytes(head, { 0x50, 0x4B }) || !IsZipArchiveStructurallyValid(partPath))
            return false;
    }
    else if (EndsWithI(lowerTarget, L".rar"))
    {
        if (!StartsWithBytes(head, { 0x52, 0x61, 0x72, 0x21 }))
            return false;
    }
    else if (EndsWithI(lowerTarget, L".7z"))
    {
        if (!StartsWithBytes(head, { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }))
            return false;
    }

    DeleteFileW(targetPath.c_str());
    if (!MoveFileExW(partPath.c_str(), targetPath.c_str(), MOVEFILE_REPLACE_EXISTING))
        return false;

    return true;
}

static bool IsFastSpeedSwitchItem(const DownloadItem& item)
{
    std::wstring lower = ToLower(item.name);

    return IsSystemInformerItem(item) ||
        IsProcessHackerItem(item) ||
        IsBamParserItem(item) ||
        IsJumpListExplorerItem(item) ||
        IsRegistryExplorerItem(item) ||
        IsSimpleUnlockerItem(item) ||
        lower.find(L"journaltrace") != std::wstring::npos ||
        (lower.find(L"journal") != std::wstring::npos && lower.find(L"trace") != std::wstring::npos);
}

static bool IsProblemDownloadName(const std::wstring& name)
{
    std::wstring lower = ToLower(name);

    return lower.find(L"systeminformer") != std::wstring::npos ||
        (lower.find(L"system") != std::wstring::npos && lower.find(L"informer") != std::wstring::npos) ||
        lower.find(L"processhacker") != std::wstring::npos ||
        (lower.find(L"process") != std::wstring::npos && lower.find(L"hacker") != std::wstring::npos) ||
        lower.find(L"bamparser") != std::wstring::npos ||
        lower.find(L"bam parser") != std::wstring::npos ||
        lower.find(L"registryexplorer") != std::wstring::npos ||
        (lower.find(L"registry") != std::wstring::npos && lower.find(L"explorer") != std::wstring::npos) ||
        lower.find(L"jumplistexplorer") != std::wstring::npos ||
        (lower.find(L"jumplist") != std::wstring::npos && lower.find(L"explorer") != std::wstring::npos) ||
        lower.find(L"simpleunlocker") != std::wstring::npos ||
        (lower.find(L"simple") != std::wstring::npos && lower.find(L"unlocker") != std::wstring::npos) ||
        lower.find(L"journaltrace") != std::wstring::npos ||
        (lower.find(L"journal") != std::wstring::npos && lower.find(L"trace") != std::wstring::npos);
}

static bool IsProblemDownloadItem(const DownloadItem& item)
{
    return IsProblemDownloadName(item.name);
}

static bool ShouldUseWinHttpFirst(const DownloadItem& item)
{
    return IsProblemDownloadItem(item);
}

static unsigned long long GetMethodMinSpeedBps(const DownloadItem& item)
{
    if (IsFastSpeedSwitchItem(item))
        return FAST_SWITCH_DOWNLOAD_SPEED_BPS; // меньше ~96 КБ/сек -> другой метод/ссылка

    return MIN_ACCEPTABLE_DOWNLOAD_SPEED_BPS;
}

static DWORD GetMethodLowSpeedWindowMs(const DownloadItem& item)
{
    if (IsFastSpeedSwitchItem(item))
        return 2500;

    return 3000;
}

static DWORD GetMethodNoProgressAbortMs(const DownloadItem& item)
{
    if (IsFastSpeedSwitchItem(item))
        return 3000;

    return 3500;
}

static unsigned long long GetPowerShellMinSpeedBps(const DownloadItem& item)
{
    return GetMethodMinSpeedBps(item);
}

static DWORD GetPowerShellLowSpeedWindowMs(const DownloadItem& item)
{
    return GetMethodLowSpeedWindowMs(item);
}

static DWORD GetPowerShellNoProgressAbortMs(const DownloadItem& item)
{
    return GetMethodNoProgressAbortMs(item);
}

static std::wstring BuildCurlLowSpeedArgs(
    unsigned long long minBytesPerSecond,
    DWORD lowSpeedWindowMs)
{
    if (minBytesPerSecond == 0 || lowSpeedWindowMs == 0)
        return L"";

    DWORD seconds = std::max<DWORD>(2, lowSpeedWindowMs / 1000);
    return L" --speed-limit " + std::to_wstring(minBytesPerSecond) +
        L" --speed-time " + std::to_wstring(seconds);
}

static bool WaitForDownloadProcessWithInstantFallback(
    PROCESS_INFORMATION& pi,
    const std::wstring& partPath,
    DWORD timeoutMs,
    DWORD noProgressAbortMs,
    DWORD lowSpeedWindowMs,
    unsigned long long minBytesPerSecond,
    const std::wstring& itemName = L"",
    const std::wstring& methodName = L"",
    size_t linkIndex = 0,
    size_t linkTotal = 0)
{
    ULONGLONG started = GetTickCount64();
    ULONGLONG lastProgress = started;
    ULONGLONG lowWindowStarted = started;
    ULONGLONG speedWindowStarted = started;
    ULONGLONG lastUiUpdate = 0;
    unsigned long long lastSize = GetFileSizeBytesOrZero(partPath);
    unsigned long long lowWindowSize = lastSize;
    unsigned long long speedWindowSize = lastSize;
    g_lastDownloadSpeedBps = 0;
    DebugLogLine(L"download", L"wait process start item=" + itemName + L" method=" + methodName +
        L" link=" + std::to_wstring(linkIndex) + L"/" + std::to_wstring(linkTotal) +
        L" timeout=" + std::to_wstring(timeoutMs) +
        L" noProgress=" + std::to_wstring(noProgressAbortMs) +
        L" lowSpeedWindow=" + std::to_wstring(lowSpeedWindowMs) +
        L" minBps=" + std::to_wstring(minBytesPerSecond) +
        L" part=" + partPath);

    if (!itemName.empty())
        UpdateActiveDownloadStatus(itemName, methodName, linkIndex, linkTotal, lastSize, 0);

    auto abortProcess = [&](const std::wstring& reason) -> bool
    {
        MarkTransferStalled();
        DebugLogLine(L"download", L"wait process abort item=" + itemName + L" method=" + methodName +
            L" reason=" + reason + L" partBytes=" + std::to_wstring(GetFileSizeBytesOrZero(partPath)) +
            L" speed=" + std::to_wstring(g_lastDownloadSpeedBps));
        if (!itemName.empty())
            UpdateActiveDownloadStatus(itemName, methodName, linkIndex, linkTotal, GetFileSizeBytesOrZero(partPath), g_lastDownloadSpeedBps);
        KillProcessTreeById(pi.dwProcessId);
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 1000);
        return false;
    };

    for (;;)
    {
        DWORD waitResult = WaitForSingleObject(pi.hProcess, 250);
        ULONGLONG now = GetTickCount64();
        unsigned long long currentSize = GetFileSizeBytesOrZero(partPath);

        if (now - speedWindowStarted >= 1000)
        {
            unsigned long long delta = currentSize >= speedWindowSize ? currentSize - speedWindowSize : 0;
            g_lastDownloadSpeedBps = (delta * 1000ull) / std::max<ULONGLONG>(1, now - speedWindowStarted);
            speedWindowStarted = now;
            speedWindowSize = currentSize;
        }

        if (!itemName.empty() && now - lastUiUpdate >= 500)
        {
            UpdateActiveDownloadStatus(itemName, methodName, linkIndex, linkTotal, currentSize, g_lastDownloadSpeedBps);
            lastUiUpdate = now;
        }

        if (waitResult == WAIT_OBJECT_0)
        {
            if (!itemName.empty())
                UpdateActiveDownloadStatus(itemName, methodName, linkIndex, linkTotal, currentSize, g_lastDownloadSpeedBps);
            DebugLogLine(L"download", L"wait process finished item=" + itemName + L" method=" + methodName +
                L" bytes=" + std::to_wstring(currentSize) + L" speed=" + std::to_wstring(g_lastDownloadSpeedBps));
            return true;
        }

        if (waitResult == WAIT_FAILED)
            return abortProcess(L"WaitForSingleObject failed");

        if (IsCancelRequested())
            return abortProcess(L"cancel requested");

        if (now - started > timeoutMs)
            return abortProcess(L"timeout");

        if (currentSize > lastSize)
        {
            lastSize = currentSize;
            lastProgress = now;
        }

        if (noProgressAbortMs > 0 && now - lastProgress >= noProgressAbortMs)
            return abortProcess(L"no progress");

        if (lowSpeedWindowMs > 0 && minBytesPerSecond > 0)
        {
            ULONGLONG windowMs = now - lowWindowStarted;
            if (windowMs >= lowSpeedWindowMs)
            {
                unsigned long long delta = currentSize >= lowWindowSize ? currentSize - lowWindowSize : 0;
                unsigned long long bytesPerSecond = (delta * 1000ull) / std::max<ULONGLONG>(1, windowMs);

                if (bytesPerSecond < minBytesPerSecond)
                    return abortProcess(L"low speed " + std::to_wstring(bytesPerSecond) + L" < " + std::to_wstring(minBytesPerSecond));

                lowWindowStarted = now;
                lowWindowSize = currentSize;
            }
        }
    }
}

static bool WaitForProcessOrCancel(PROCESS_INFORMATION& pi, DWORD timeoutMs)
{
    ULONGLONG started = GetTickCount64();
    DebugLogLine(L"process", L"wait external process start timeout=" + std::to_wstring(timeoutMs));

    for (;;)
    {
        DWORD waitResult = WaitForSingleObject(pi.hProcess, 250);

        if (waitResult == WAIT_OBJECT_0)
        {
            DebugLogLine(L"process", L"wait external process done");
            return true;
        }

        ULONGLONG now = GetTickCount64();

        if (waitResult == WAIT_FAILED || IsCancelRequested() || now - started > timeoutMs)
        {
            MarkTransferStalled();
            DebugLogLine(L"process", L"wait external process abort waitResult=" + std::to_wstring(waitResult) +
                L" cancel=" + std::to_wstring(IsCancelRequested() ? 1 : 0) +
                L" elapsed=" + std::to_wstring(now - started));
            KillProcessTreeById(pi.dwProcessId);
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 1000);
            return false;
        }
    }
}

static bool DownloadWithCurlFallback(
    const std::wstring& url,
    const std::wstring& targetPath,
    DWORD timeoutMs,
    unsigned long long minBytesPerSecond,
    DWORD lowSpeedWindowMs,
    DWORD noProgressAbortMs,
    const std::wstring& itemName,
    size_t linkIndex,
    size_t linkTotal)
{
    ClearTransferStalledFlag();

    if (IsCancelRequested())
        return false;

    std::wstring partPath = targetPath + L".part";

    std::wstring curlExe = GetSystemToolPath(L"curl.exe");
    DWORD maxTimeSeconds = std::max<DWORD>(180, timeoutMs / 1000);
    DWORD connectTimeoutSeconds = 5;

    std::wstring command =
        QuoteProcessArgument(curlExe) +
        L" -L --fail --silent --show-error --ssl-no-revoke --tcp-nodelay"
        L" -C -"
        L" --retry 1 --retry-delay 1 --retry-connrefused" +
        BuildCurlLowSpeedArgs(minBytesPerSecond, lowSpeedWindowMs) +
        L" --connect-timeout " + std::to_wstring(connectTimeoutSeconds) +
        L" --max-time " + std::to_wstring(maxTimeSeconds) +
        L" -A " + QuoteProcessArgument(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36") +
        L" -H " + QuoteProcessArgument(L"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,application/octet-stream,*/*;q=0.8") +
        L" -H " + QuoteProcessArgument(L"Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.7,en;q=0.6") +
        L" -H " + QuoteProcessArgument(L"Accept-Encoding: identity") +
        L" -o " + QuoteProcessArgument(partPath) +
        L" " + QuoteProcessArgument(url);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> cmd(command.begin(), command.end());
    cmd.push_back(L'\0');

    const wchar_t* appName = FileExists(curlExe) ? curlExe.c_str() : nullptr;

    if (!CreateProcessW(appName, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    {
        DebugLogLine(L"download", L"CreateProcess failed command=" + command + L" error=" + FormatWin32ErrorForLog(GetLastError()));
        return false;
    }

    if (!WaitForDownloadProcessWithInstantFallback(
        pi, partPath, timeoutMs,
        noProgressAbortMs, lowSpeedWindowMs, minBytesPerSecond,
        itemName, L"curl", linkIndex, linkTotal))
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return TryFinalizeAbortedPartFile(itemName, partPath, targetPath);
    }

    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    DebugLogLine(L"download", L"process exit command=" + command + L" exit=" + std::to_wstring(exitCode) +
        L" partSize=" + std::to_wstring(GetFileSizeBytesOrZero(partPath)));

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (exitCode == 28)
        MarkTransferStalled();

    if (exitCode != 0 || !FileExists(partPath) || IsCancelRequested())
        return TryFinalizeAbortedPartFile(itemName, partPath, targetPath);

    DeleteFileW(targetPath.c_str());

    if (!MoveFileW(partPath.c_str(), targetPath.c_str()))
    {
        DebugLogLine(L"download", L"curl MoveFile failed item=" + itemName + L" error=" + FormatWin32ErrorForLog(GetLastError()));
        return false;
    }

    DebugLogLine(L"download", L"curl success item=" + itemName + L" bytes=" + std::to_wstring(GetFileSizeBytesOrZero(targetPath)));
    return true;
}


static bool DownloadWithCurlBrowserLike(
    const std::wstring& url,
    const std::wstring& targetPath,
    DWORD timeoutMs,
    unsigned long long minBytesPerSecond,
    DWORD lowSpeedWindowMs,
    DWORD noProgressAbortMs,
    const std::wstring& itemName = L"",
    size_t linkIndex = 0,
    size_t linkTotal = 0)
{
    ClearTransferStalledFlag();

    if (IsCancelRequested())
        return false;

    std::wstring partPath = targetPath + L".part";

    std::wstring curlExe = GetSystemToolPath(L"curl.exe");
    DWORD maxTimeSeconds = std::max<DWORD>(300, timeoutMs / 1000);

    std::wstring command =
        QuoteProcessArgument(curlExe) +
        L" -L --fail --silent --show-error --ssl-no-revoke --tcp-nodelay"
        L" -C -"
        L" --retry 1 --retry-delay 1 --retry-connrefused" +
        BuildCurlLowSpeedArgs(minBytesPerSecond, lowSpeedWindowMs) +
        L" --connect-timeout 6"
        L" --max-time " + std::to_wstring(maxTimeSeconds) +
        L" -A " + QuoteProcessArgument(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36") +
        L" -H " + QuoteProcessArgument(L"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,application/octet-stream,*/*;q=0.8") +
        L" -H " + QuoteProcessArgument(L"Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.7,en;q=0.6") +
        L" -H " + QuoteProcessArgument(L"Accept-Encoding: identity") +
        L" -e " + QuoteProcessArgument(L"https://ericzimmerman.github.io/") +
        L" -o " + QuoteProcessArgument(partPath) +
        L" " + QuoteProcessArgument(url);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> cmd(command.begin(), command.end());
    cmd.push_back(L'\0');

    const wchar_t* appName = FileExists(curlExe) ? curlExe.c_str() : nullptr;

    if (!CreateProcessW(appName, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    {
        DebugLogLine(L"download", L"CreateProcess failed command=" + command + L" error=" + FormatWin32ErrorForLog(GetLastError()));
        return false;
    }

    if (!WaitForDownloadProcessWithInstantFallback(
        pi, partPath, timeoutMs,
        noProgressAbortMs, lowSpeedWindowMs, minBytesPerSecond,
        itemName, L"curl", linkIndex, linkTotal))
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return TryFinalizeAbortedPartFile(itemName, partPath, targetPath);
    }

    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    DebugLogLine(L"download", L"process exit command=" + command + L" exit=" + std::to_wstring(exitCode) +
        L" partSize=" + std::to_wstring(GetFileSizeBytesOrZero(partPath)));

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (exitCode != 0 || !FileExists(partPath) || IsCancelRequested())
        return TryFinalizeAbortedPartFile(itemName, partPath, targetPath);

    DeleteFileW(targetPath.c_str());

    if (!MoveFileW(partPath.c_str(), targetPath.c_str()))
        return false;

    return true;
}


static bool DownloadWithCurlGitHubFast(
    const std::wstring& url,
    const std::wstring& targetPath,
    DWORD timeoutMs,
    unsigned long long minBytesPerSecond,
    DWORD lowSpeedWindowMs,
    DWORD noProgressAbortMs,
    const std::wstring& itemName = L"",
    size_t linkIndex = 0,
    size_t linkTotal = 0)
{
    ClearTransferStalledFlag();

    if (IsCancelRequested())
        return false;

    std::wstring partPath = targetPath + L".part";

    std::wstring curlExe = GetSystemToolPath(L"curl.exe");
    DWORD maxTimeSeconds = std::max<DWORD>(600, timeoutMs / 1000);

    std::wstring command =
        QuoteProcessArgument(curlExe) +
        L" -L --fail --silent --show-error --ssl-no-revoke --tcp-nodelay"
        L" -C -"
        L" --retry 1 --retry-delay 1 --retry-connrefused" +
        BuildCurlLowSpeedArgs(minBytesPerSecond, lowSpeedWindowMs) +
        L" --connect-timeout 6"
        L" --max-time " + std::to_wstring(maxTimeSeconds) +
        L" -A " + QuoteProcessArgument(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36") +
        L" -H " + QuoteProcessArgument(L"Accept: application/octet-stream,application/x-msdownload,application/zip,*/*") +
        L" -H " + QuoteProcessArgument(L"Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.7,en;q=0.6") +
        L" -H " + QuoteProcessArgument(L"Accept-Encoding: identity") +
        L" -e " + QuoteProcessArgument(L"https://github.com/") +
        L" -o " + QuoteProcessArgument(partPath) +
        L" " + QuoteProcessArgument(url);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> cmd(command.begin(), command.end());
    cmd.push_back(L'\0');

    const wchar_t* appName = FileExists(curlExe) ? curlExe.c_str() : nullptr;

    if (!CreateProcessW(appName, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    {
        DebugLogLine(L"download", L"CreateProcess failed command=" + command + L" error=" + FormatWin32ErrorForLog(GetLastError()));
        return false;
    }

    if (!WaitForDownloadProcessWithInstantFallback(
        pi, partPath, timeoutMs,
        noProgressAbortMs, lowSpeedWindowMs, minBytesPerSecond,
        itemName, L"curl", linkIndex, linkTotal))
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return TryFinalizeAbortedPartFile(itemName, partPath, targetPath);
    }

    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    DebugLogLine(L"download", L"process exit command=" + command + L" exit=" + std::to_wstring(exitCode) +
        L" partSize=" + std::to_wstring(GetFileSizeBytesOrZero(partPath)));

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (exitCode == 28)
        MarkTransferStalled();

    if (exitCode != 0 || !FileExists(partPath) || IsCancelRequested())
        return TryFinalizeAbortedPartFile(itemName, partPath, targetPath);

    DeleteFileW(targetPath.c_str());

    if (!MoveFileW(partPath.c_str(), targetPath.c_str()))
        return false;

    return true;
}

static bool DownloadWithPowerShellFallback(
    const std::wstring& url,
    const std::wstring& targetPath,
    DWORD timeoutMs,
    unsigned long long minBytesPerSecond,
    DWORD lowSpeedWindowMs,
    DWORD noProgressAbortMs,
    const std::wstring& itemName,
    size_t linkIndex,
    size_t linkTotal)
{
    ClearTransferStalledFlag();

    if (IsCancelRequested())
        return false;

    std::wstring partPath = targetPath + L".part";
    DeleteFileW(partPath.c_str());

    DWORD timeoutSec = std::max<DWORD>(30, timeoutMs / 1000);
    timeoutSec = std::min<DWORD>(timeoutSec, 900);

    std::wstring psUrl = EscapePowerShellSingleQuoted(url);
    std::wstring psPart = EscapePowerShellSingleQuoted(partPath);
    std::wstring psTimeout = std::to_wstring(timeoutSec);

    std::wstring script =
        L"$ProgressPreference='SilentlyContinue'; "
        L"$ErrorActionPreference='Stop'; "
        L"try { Add-Type -AssemblyName System.Net.Http } catch {}; "
        L"try { [Net.ServicePointManager]::SecurityProtocol = "
        L"[Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls } catch {}; "
        L"$url='" + psUrl + L"'; "
        L"$out='" + psPart + L"'; "
        L"$ua='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'; "
        L"try { "
        L"$handler=New-Object System.Net.Http.HttpClientHandler; "
        L"$handler.AllowAutoRedirect=$true; "
        L"$client=New-Object System.Net.Http.HttpClient -ArgumentList $handler; "
        L"$client.Timeout=[TimeSpan]::FromSeconds(" + psTimeout + L"); "
        L"$client.DefaultRequestHeaders.UserAgent.ParseAdd($ua); "
        L"$client.DefaultRequestHeaders.Accept.ParseAdd('application/octet-stream'); "
        L"$client.DefaultRequestHeaders.Accept.ParseAdd('application/zip'); "
        L"$client.DefaultRequestHeaders.Accept.ParseAdd('*/*'); "
        L"$resp=$client.GetAsync($url,[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult(); "
        L"$resp.EnsureSuccessStatusCode() | Out-Null; "
        L"$stream=$resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult(); "
        L"$file=[IO.File]::Open($out,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None); "
        L"$buf=New-Object byte[] 1048576; "
        L"try { while (($read=$stream.Read($buf,0,$buf.Length)) -gt 0) { $file.Write($buf,0,$read) } } "
        L"finally { $file.Close(); $stream.Close(); $client.Dispose(); if ($resp) { $resp.Dispose() } } "
        L"exit 0 "
        L"} catch { "
        L"try { "
        L"$wc=New-Object Net.WebClient; "
        L"$wc.Headers.Add('User-Agent',$ua); "
        L"$wc.Headers.Add('Accept','application/octet-stream,application/zip,*/*'); "
        L"$wc.Headers.Add('Accept-Language','ru-RU,ru;q=0.9,en-US;q=0.7,en;q=0.6'); "
        L"$wc.DownloadFile($url,$out); "
        L"exit 0 "
        L"} catch { exit 1 } "
        L"}";

    std::wstring powerShellExe = GetSystemToolPath(L"WindowsPowerShell\\v1.0\\powershell.exe");
    std::wstring encoded = Base64EncodePowerShellCommand(script);
    std::wstring command =
        QuoteProcessArgument(powerShellExe) +
        L" -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + encoded;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> cmd(command.begin(), command.end());
    cmd.push_back(L'\0');

    const wchar_t* appName = FileExists(powerShellExe) ? powerShellExe.c_str() : nullptr;

    if (!CreateProcessW(appName, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    {
        DebugLogLine(L"download", L"CreateProcess failed command=" + command + L" error=" + FormatWin32ErrorForLog(GetLastError()));
        return false;
    }

    if (!WaitForDownloadProcessWithInstantFallback(
        pi, partPath, timeoutMs,
        noProgressAbortMs, lowSpeedWindowMs, minBytesPerSecond,
        itemName, L"PowerShell", linkIndex, linkTotal))
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return TryFinalizeAbortedPartFile(itemName, partPath, targetPath);
    }

    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    DebugLogLine(L"download", L"process exit command=" + command + L" exit=" + std::to_wstring(exitCode) +
        L" partSize=" + std::to_wstring(GetFileSizeBytesOrZero(partPath)));

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (exitCode != 0 || !FileExists(partPath) || IsCancelRequested())
        return TryFinalizeAbortedPartFile(itemName, partPath, targetPath);

    DeleteFileW(targetPath.c_str());

    if (!MoveFileW(partPath.c_str(), targetPath.c_str()))
        return false;

    return true;
}


static bool DownloadWithWinInetFallback(
    const std::wstring& url,
    const std::wstring& targetPath,
    DWORD timeoutMs,
    unsigned long long minBytesPerSecond,
    DWORD lowSpeedWindowMs,
    DWORD noProgressAbortMs,
    const std::wstring& itemName,
    size_t linkIndex,
    size_t linkTotal)
{
    ClearTransferStalledFlag();

    if (IsCancelRequested())
        return false;

    std::wstring partPath = targetPath + L".part";
    DeleteFileW(partPath.c_str());
    DebugLogLine(L"download", L"WinINet start item=" + itemName + L" url=" + url + L" target=" + targetPath +
        L" timeout=" + std::to_wstring(timeoutMs));

    HINTERNET session = InternetOpenW(
        L"Mozilla/5.0 HolyCheckDownloader/WinINet",
        INTERNET_OPEN_TYPE_PRECONFIG,
        nullptr,
        nullptr,
        0
    );

    if (!session)
    {
        DebugLogLine(L"download", L"WinINet InternetOpen failed item=" + itemName + L" error=" + FormatWin32ErrorForLog(GetLastError()));
        return false;
    }

    DWORD connectTimeout = timeoutMs >= 300000 ? 6000 : 5000;
    DWORD receiveTimeout = IsProblemDownloadName(itemName) ? 7000 : 9000;
    DWORD sendTimeout = 5000;

    InternetSetOptionW(session, INTERNET_OPTION_CONNECT_TIMEOUT, &connectTimeout, sizeof(connectTimeout));
    InternetSetOptionW(session, INTERNET_OPTION_RECEIVE_TIMEOUT, &receiveTimeout, sizeof(receiveTimeout));
    InternetSetOptionW(session, INTERNET_OPTION_SEND_TIMEOUT, &sendTimeout, sizeof(sendTimeout));

    std::wstring headers =
        L"Accept: application/octet-stream,application/zip,application/x-msdownload,*/*\r\n"
        L"Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.7,en;q=0.6\r\n"
        L"Accept-Encoding: identity\r\n"
        L"Cache-Control: no-cache\r\n"
        L"Pragma: no-cache\r\n";

    DWORD flags = INTERNET_FLAG_RELOAD |
        INTERNET_FLAG_NO_CACHE_WRITE |
        INTERNET_FLAG_PRAGMA_NOCACHE |
        INTERNET_FLAG_NO_UI |
        INTERNET_FLAG_KEEP_CONNECTION;

    HINTERNET handle = InternetOpenUrlW(
        session,
        url.c_str(),
        headers.c_str(),
        static_cast<DWORD>(headers.size()),
        flags,
        0
    );

    if (!handle)
    {
        DebugLogLine(L"download", L"WinINet InternetOpenUrl failed item=" + itemName + L" error=" + FormatWin32ErrorForLog(GetLastError()) + L" url=" + url);
        InternetCloseHandle(session);
        return false;
    }

    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    if (HttpQueryInfoW(handle, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &statusSize, nullptr))
    {
        if (status < 200 || status >= 300)
        {
            DebugLogLine(L"download", L"WinINet HTTP status failed item=" + itemName + L" status=" + std::to_wstring(status));
            InternetCloseHandle(handle);
            InternetCloseHandle(session);
            return false;
        }
    }

    HANDLE file = CreateFileW(
        partPath.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );

    if (file == INVALID_HANDLE_VALUE)
    {
        DebugLogLine(L"download", L"WinINet part open failed item=" + itemName + L" part=" + partPath + L" error=" + FormatWin32ErrorForLog(GetLastError()));
        InternetCloseHandle(handle);
        InternetCloseHandle(session);
        return false;
    }

    DWORD expectedSize = 0;
    DWORD expectedSizeBytes = sizeof(expectedSize);
    if (!HttpQueryInfoW(handle, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
        &expectedSize, &expectedSizeBytes, nullptr))
        expectedSize = 0;

    const DWORD BUFFER_SIZE = 1024 * 1024;
    std::vector<unsigned char> buffer(BUFFER_SIZE);
    unsigned long long totalBytes = 0;

    ULONGLONG started = GetTickCount64();
    ULONGLONG lastProgress = started;
    ULONGLONG speedWindowStarted = started;
    unsigned long long speedWindowBytes = 0;
    ULONGLONG lowSpeedWindowStarted = started;
    unsigned long long lowSpeedWindowBytes = 0;
    ULONGLONG lastUiUpdate = 0;

    UpdateActiveDownloadStatus(itemName, L"WinINet", linkIndex, linkTotal, 0, 0, expectedSize);

    bool ok = true;

    for (;;)
    {
        if (IsCancelRequested() || GetTickCount64() - started > timeoutMs)
        {
            ok = false;
            MarkTransferStalled();
            break;
        }

        DWORD read = 0;
        if (!InternetReadFile(handle, buffer.data(), BUFFER_SIZE, &read))
        {
            ok = false;
            MarkTransferStalled();
            break;
        }

        if (read == 0)
            break;

        DWORD written = 0;
        if (!WriteFile(file, buffer.data(), read, &written, nullptr) || written != read)
        {
            ok = false;
            break;
        }

        totalBytes += written;
        lastProgress = GetTickCount64();

        ULONGLONG now = lastProgress;

        if (now - speedWindowStarted >= 1000)
        {
            unsigned long long delta = totalBytes >= speedWindowBytes ? totalBytes - speedWindowBytes : 0;
            g_lastDownloadSpeedBps = (delta * 1000ull) / std::max<ULONGLONG>(1, now - speedWindowStarted);
            speedWindowStarted = now;
            speedWindowBytes = totalBytes;
        }

        if (now - lastUiUpdate >= 500)
        {
            UpdateActiveDownloadStatus(itemName, L"WinINet", linkIndex, linkTotal, totalBytes, g_lastDownloadSpeedBps, expectedSize);
            lastUiUpdate = now;
        }

        if (noProgressAbortMs > 0 && now - lastProgress >= noProgressAbortMs)
        {
            ok = false;
            MarkTransferStalled();
            break;
        }

        if (lowSpeedWindowMs > 0 && minBytesPerSecond > 0)
        {
            ULONGLONG windowMs = now - lowSpeedWindowStarted;
            if (windowMs >= lowSpeedWindowMs)
            {
                unsigned long long delta = totalBytes >= lowSpeedWindowBytes ? totalBytes - lowSpeedWindowBytes : 0;
                unsigned long long bytesPerSecond = (delta * 1000ull) / std::max<ULONGLONG>(1, windowMs);

                if (bytesPerSecond < minBytesPerSecond)
                {
                    ok = false;
                    MarkTransferStalled();
                    break;
                }

                lowSpeedWindowStarted = now;
                lowSpeedWindowBytes = totalBytes;
            }
        }
    }

    CloseHandle(file);
    InternetCloseHandle(handle);
    InternetCloseHandle(session);

    if (!ok || !FileExists(partPath) || IsCancelRequested())
    {
        DebugLogLine(L"download", L"WinINet failed item=" + itemName + L" ok=" + std::to_wstring(ok ? 1 : 0) +
            L" partExists=" + std::to_wstring(FileExists(partPath) ? 1 : 0) +
            L" cancelled=" + std::to_wstring(IsCancelRequested() ? 1 : 0) +
            L" bytes=" + std::to_wstring(GetFileSizeBytesOrZero(partPath)));
        return TryFinalizeAbortedPartFile(itemName, partPath, targetPath);
    }

    DeleteFileW(targetPath.c_str());
    if (!MoveFileW(partPath.c_str(), targetPath.c_str()))
    {
        DebugLogLine(L"download", L"WinINet MoveFile failed item=" + itemName + L" error=" + FormatWin32ErrorForLog(GetLastError()));
        return false;
    }

    DebugLogLine(L"download", L"WinINet success item=" + itemName + L" bytes=" + std::to_wstring(GetFileSizeBytesOrZero(targetPath)));
    return true;
}

static bool FindFileRecursiveByName(const std::wstring& folder, const std::wstring& fileName, std::wstring& outPath)
{
    std::wstring mask = CombinePath(folder, L"*");

    WIN32_FIND_DATAW data{};
    HANDLE hFind = FindFirstFileW(mask.c_str(), &data);

    if (hFind == INVALID_HANDLE_VALUE)
        return false;

    std::vector<std::wstring> subFolders;

    do
    {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
            continue;

        std::wstring path = CombinePath(folder, data.cFileName);

        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            subFolders.push_back(path);
        }
        else if (_wcsicmp(data.cFileName, fileName.c_str()) == 0)
        {
            outPath = path;
            FindClose(hFind);
            return true;
        }
    }
    while (FindNextFileW(hFind, &data));

    FindClose(hFind);

    for (const auto& subFolder : subFolders)
    {
        if (FindFileRecursiveByName(subFolder, fileName, outPath))
            return true;
    }

    return false;
}


static bool FindFirstExeRecursive(const std::wstring& folder, std::wstring& outPath)
{
    std::wstring mask = CombinePath(folder, L"*");

    WIN32_FIND_DATAW data{};
    HANDLE hFind = FindFirstFileW(mask.c_str(), &data);

    if (hFind == INVALID_HANDLE_VALUE)
        return false;

    std::vector<std::wstring> subFolders;

    do
    {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
            continue;

        std::wstring path = CombinePath(folder, data.cFileName);

        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            subFolders.push_back(path);
        }
        else if (EndsWithI(path, L".exe"))
        {
            outPath = path;
            FindClose(hFind);
            return true;
        }
    }
    while (FindNextFileW(hFind, &data));

    FindClose(hFind);

    for (const auto& subFolder : subFolders)
    {
        if (FindFirstExeRecursive(subFolder, outPath))
            return true;
    }

    return false;
}


static std::wstring MakeSafeFileStem(std::wstring name)
{
    for (wchar_t& ch : name)
    {
        if (ch == L'\\' || ch == L'/' || ch == L':' || ch == L'*' || ch == L'?' ||
            ch == L'\"' || ch == L'<' || ch == L'>' || ch == L'|')
        {
            ch = L'_';
        }
    }

    while (!name.empty() && (name.back() == L' ' || name.back() == L'.'))
        name.pop_back();

    if (name.empty())
        name = L"program";

    return name;
}

static std::wstring GetItemFinalExePath(const DownloadItem& item, const std::wstring& baseFolder)
{
    std::wstring tabFolder = CombinePath(baseFolder, GetTabFolderName(item.tab));

    if (EndsWithI(item.file, L".zip"))
        return CombinePath(tabFolder, MakeSafeFileStem(item.name) + L".exe");

    return CombinePath(tabFolder, item.file);
}

static std::wstring GetItemTargetPath(const DownloadItem& item, const std::wstring& baseFolder)
{
    std::wstring tabFolder = CombinePath(baseFolder, GetTabFolderName(item.tab));
    return CombinePath(tabFolder, item.file);
}

static std::wstring GetItemExtractDir(const DownloadItem& item, const std::wstring& baseFolder)
{
    std::wstring tabFolder = CombinePath(baseFolder, GetTabFolderName(item.tab));
    return CombinePath(tabFolder, RemoveExtension(item.file));
}

static bool IsFtkImagerItem(const DownloadItem& item)
{
    return _wcsicmp(item.name.c_str(), L"FTK Imager") == 0;
}

// Locate only the real FTK Imager executable. Do not fall back to the first
// .exe in the archive because FTK packages may also contain setup/helper EXEs.
// Search the expected extraction folder first, then the whole Extra programs
// folder to stay compatible with folders created by older HolyCheck builds.
static std::wstring FindFtkImagerLaunchPath(const DownloadItem& item, const std::wstring& baseFolder)
{
    if (!IsFtkImagerItem(item))
        return L"";

    std::wstring tabFolder = CombinePath(baseFolder, GetTabFolderName(item.tab));
    std::wstring extractDir = GetItemExtractDir(item, baseFolder);
    std::wstring exePath;

    std::wstring directPath = CombinePath(extractDir, L"FTK Imager.exe");
    if (FileExists(directPath))
        return directPath;

    if (FindFileRecursiveByName(extractDir, L"FTK Imager.exe", exePath) && FileExists(exePath))
        return exePath;

    directPath = CombinePath(tabFolder, L"FTK Imager.exe");
    if (FileExists(directPath))
        return directPath;

    exePath.clear();
    if (FindFileRecursiveByName(tabFolder, L"FTK Imager.exe", exePath) && FileExists(exePath))
        return exePath;

    return L"";
}

// FTK 8.3 package used by HolyCheck contains the Exterro installer rather than
// a portable FTK Imager.exe. Always select this exact installer name so a
// helper executable from the archive can never be launched by mistake.
static std::wstring FindFtkImagerInstallerPath(const DownloadItem& item, const std::wstring& baseFolder)
{
    if (!IsFtkImagerItem(item))
        return L"";

    const wchar_t* installerName = L"Exterro_FTK_Imager_(x64).exe";
    std::wstring extractDir = GetItemExtractDir(item, baseFolder);
    std::wstring direct = CombinePath(extractDir, installerName);
    if (FileExists(direct))
        return direct;

    std::wstring found;
    if (FindFileRecursiveByName(extractDir, installerName, found) && FileExists(found))
        return found;

    std::wstring tabFolder = CombinePath(baseFolder, GetTabFolderName(item.tab));
    direct = CombinePath(tabFolder, installerName);
    if (FileExists(direct))
        return direct;

    found.clear();
    if (FindFileRecursiveByName(tabFolder, installerName, found) && FileExists(found))
        return found;

    return L"";
}

static std::wstring TrimLaunchString(std::wstring value)
{
    while (!value.empty() && iswspace(value.front()))
        value.erase(value.begin());

    while (!value.empty() && iswspace(value.back()))
        value.pop_back();

    while (!value.empty() && (value.front() == L'\"' || value.front() == L'\''))
        value.erase(value.begin());

    while (!value.empty() && (value.back() == L'\"' || value.back() == L'\'' || value.back() == L','))
        value.pop_back();

    while (!value.empty() && iswspace(value.back()))
        value.pop_back();

    return value;
}

static std::wstring ExtractExecutablePathFromRegistryValue(std::wstring value)
{
    value = TrimLaunchString(value);

    if (value.empty())
        return L"";

    if (value.front() == L'\"')
    {
        size_t endQuote = value.find(L'\"', 1);
        if (endQuote != std::wstring::npos)
            return TrimLaunchString(value.substr(1, endQuote - 1));
    }

    std::wstring lower = ToLower(value);
    size_t exePos = lower.find(L".exe");

    if (exePos != std::wstring::npos)
        return TrimLaunchString(value.substr(0, exePos + 4));

    size_t commaPos = value.find(L',');
    if (commaPos != std::wstring::npos)
        value = value.substr(0, commaPos);

    return TrimLaunchString(value);
}

static bool LaunchRegistryGetString(HKEY key, const wchar_t* valueName, std::wstring& out)
{
    DWORD type = 0;
    DWORD cb = 0;

    if (RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &cb) != ERROR_SUCCESS)
        return false;

    if ((type != REG_SZ && type != REG_EXPAND_SZ) || cb == 0)
        return false;

    std::wstring value(cb / sizeof(wchar_t), L'\0');

    if (RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(&value[0]), &cb) != ERROR_SUCCESS)
        return false;

    while (!value.empty() && value.back() == L'\0')
        value.pop_back();

    if (type == REG_EXPAND_SZ)
    {
        wchar_t expanded[4096]{};
        DWORD expandedLen = ExpandEnvironmentStringsW(value.c_str(), expanded, ARRAYSIZE(expanded));

        if (expandedLen > 0 && expandedLen < ARRAYSIZE(expanded))
            value = expanded;
    }

    out = value;
    return !out.empty();
}


static void AddUniqueFtkLaunchCandidate(std::vector<std::wstring>& candidates, const std::wstring& rawPath)
{
    std::wstring path = ExtractExecutablePathFromRegistryValue(rawPath);
    if (path.empty())
        path = TrimLaunchString(rawPath);

    if (path.empty())
        return;

    std::wstring lower = ToLower(path);
    if (!EndsWithI(lower, L".exe") || lower.find(L"ftk imager") == std::wstring::npos)
        return;

    for (const auto& existing : candidates)
    {
        if (ToLower(existing) == lower)
            return;
    }
    candidates.push_back(path);
}

static void AddFtkCandidateFromEnv(std::vector<std::wstring>& candidates, const wchar_t* envName, const wchar_t* relativePath)
{
    wchar_t base[MAX_PATH * 4]{};
    DWORD len = GetEnvironmentVariableW(envName, base, ARRAYSIZE(base));
    if (len == 0 || len >= ARRAYSIZE(base))
        return;
    AddUniqueFtkLaunchCandidate(candidates, CombinePath(base, relativePath));
}

static void AddFtkRootFromEnv(std::vector<std::wstring>& roots, const wchar_t* envName)
{
    wchar_t base[MAX_PATH * 4]{};
    DWORD len = GetEnvironmentVariableW(envName, base, ARRAYSIZE(base));
    if (len == 0 || len >= ARRAYSIZE(base) || !DirectoryExists(base))
        return;

    std::wstring key = ToLower(base);
    for (const auto& existing : roots)
        if (ToLower(existing) == key)
            return;
    roots.push_back(base);
}

// Full Program Files scan used only from the background worker. Reparse points
// are skipped so junctions cannot create loops or unexpectedly leave the tree.
static bool FindFtkImagerInProgramFilesTree(const std::wstring& root, std::wstring& outPath)
{
    if (root.empty() || !DirectoryExists(root))
        return false;

    std::queue<std::wstring> q;
    q.push(root);

    while (!q.empty())
    {
        std::wstring dir = std::move(q.front());
        q.pop();

        WIN32_FIND_DATAW data{};
        HANDLE h = FindFirstFileW(CombinePath(dir, L"*").c_str(), &data);
        if (h == INVALID_HANDLE_VALUE)
            continue;

        do
        {
            if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
                continue;

            std::wstring full = CombinePath(dir, data.cFileName);
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
                    q.push(full);
            }
            else if (_wcsicmp(data.cFileName, L"FTK Imager.exe") == 0)
            {
                outPath = full;
                FindClose(h);
                return true;
            }
        }
        while (FindNextFileW(h, &data));

        FindClose(h);
    }

    return false;
}

static void AddFtkAppPathRegistryCandidate(std::vector<std::wstring>& candidates, HKEY root, REGSAM wowFlags)
{
    HKEY key{};
    if (RegOpenKeyExW(root,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\FTK Imager.exe",
        0, KEY_READ | wowFlags, &key) != ERROR_SUCCESS)
        return;

    std::wstring value;
    if (LaunchRegistryGetString(key, nullptr, value))
        AddUniqueFtkLaunchCandidate(candidates, value);
    RegCloseKey(key);
}

static void AddFtkUninstallRegistryCandidates(std::vector<std::wstring>& candidates, HKEY root, REGSAM wowFlags)
{
    HKEY uninstall{};
    if (RegOpenKeyExW(root,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        0, KEY_READ | wowFlags, &uninstall) != ERROR_SUCCESS)
        return;

    DWORD index = 0;
    wchar_t subName[512]{};
    DWORD subLen = ARRAYSIZE(subName);
    while (RegEnumKeyExW(uninstall, index++, subName, &subLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
    {
        HKEY sub{};
        if (RegOpenKeyExW(uninstall, subName, 0, KEY_READ | wowFlags, &sub) == ERROR_SUCCESS)
        {
            std::wstring displayName;
            if (LaunchRegistryGetString(sub, L"DisplayName", displayName) &&
                ToLower(displayName).find(L"ftk imager") != std::wstring::npos)
            {
                std::wstring installLocation;
                if (LaunchRegistryGetString(sub, L"InstallLocation", installLocation))
                    AddUniqueFtkLaunchCandidate(candidates, CombinePath(TrimLaunchString(installLocation), L"FTK Imager.exe"));

                std::wstring displayIcon;
                if (LaunchRegistryGetString(sub, L"DisplayIcon", displayIcon))
                    AddUniqueFtkLaunchCandidate(candidates, displayIcon);
            }
            RegCloseKey(sub);
        }
        subLen = ARRAYSIZE(subName);
    }
    RegCloseKey(uninstall);
}

static std::wstring FindInstalledFtkImagerPath(bool deepProgramFilesScan)
{
    std::vector<std::wstring> candidates;

    // Current/default AccessData layout plus Exterro-branded layouts that can
    // appear on newer/custom packages. Check all Windows Program Files views.
    const wchar_t* envs[] = { L"ProgramW6432", L"ProgramFiles", L"ProgramFiles(x86)" };
    const wchar_t* rels[] = {
        L"AccessData\\FTK Imager\\FTK Imager.exe",
        L"AccessData\\AccessData FTK Imager\\FTK Imager.exe",
        L"AccessData\\FTK Imager.exe",
        L"Exterro\\FTK Imager\\FTK Imager.exe",
        L"Exterro\\FTK Imager.exe"
    };
    for (const auto* env : envs)
        for (const auto* rel : rels)
            AddFtkCandidateFromEnv(candidates, env, rel);

    AddFtkAppPathRegistryCandidate(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY);
    AddFtkAppPathRegistryCandidate(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY);
    AddFtkAppPathRegistryCandidate(candidates, HKEY_CURRENT_USER, 0);
    AddFtkUninstallRegistryCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY);
    AddFtkUninstallRegistryCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY);
    AddFtkUninstallRegistryCandidates(candidates, HKEY_CURRENT_USER, 0);

    for (const auto& path : candidates)
        if (FileExists(path))
            return path;

    if (!deepProgramFilesScan)
        return L"";

    std::vector<std::wstring> roots;
    AddFtkRootFromEnv(roots, L"ProgramW6432");
    AddFtkRootFromEnv(roots, L"ProgramFiles");
    AddFtkRootFromEnv(roots, L"ProgramFiles(x86)");

    for (const auto& root : roots)
    {
        std::wstring found;
        if (FindFtkImagerInProgramFilesTree(root, found) && FileExists(found))
            return found;
    }

    return L"";
}

static bool IsNonEmptyRegularFile(const std::wstring& path)
{
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data))
        return false;
    if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        return false;
    return data.nFileSizeHigh != 0 || data.nFileSizeLow != 0;
}

// Do not treat FTK Imager as launchable merely because FTK Imager.exe has
// appeared. InstallShield/MSI can create the EXE before its private DLLs are
// copied, which causes errors such as "dongle.dll was not found". These are
// direct FTK dependencies that are installed beside the executable.
static bool IsFtkImagerLaunchReady(const std::wstring& exePath)
{
    if (exePath.empty() || !FileExists(exePath) ||
        _wcsicmp(ExtractFileNameOnly(exePath).c_str(), L"FTK Imager.exe") != 0)
        return false;

    size_t slash = exePath.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
        return false;
    std::wstring dir = exePath.substr(0, slash);
    if (dir.empty() || !DirectoryExists(dir))
        return false;

    const wchar_t* requiredFiles[] = {
        L"dongle.dll",
        L"LMS.dll",
        L"adlib.dll",
        L"adshared.dll"
    };

    for (const wchar_t* file : requiredFiles)
    {
        if (!IsNonEmptyRegularFile(CombinePath(dir, file)))
            return false;
    }

    return true;
}

static std::wstring FindReadyInstalledFtkImagerPath(bool deepProgramFilesScan)
{
    std::wstring path = FindInstalledFtkImagerPath(deepProgramFilesScan);
    return IsFtkImagerLaunchReady(path) ? path : L"";
}

static void AddUniqueSystemInformerLaunchCandidate(std::vector<std::wstring>& candidates, const std::wstring& rawPath)
{
    std::wstring path = ExtractExecutablePathFromRegistryValue(rawPath);

    if (path.empty())
        return;

    std::wstring lower = ToLower(path);
    bool systemInformerName = lower.find(L"systeminformer") != std::wstring::npos ||
        (lower.find(L"system") != std::wstring::npos && lower.find(L"informer") != std::wstring::npos);

    if (!EndsWithI(lower, L".exe") || !systemInformerName)
        return;

    for (const std::wstring& existing : candidates)
    {
        if (ToLower(existing) == lower)
            return;
    }

    candidates.push_back(path);
}

static void AddSystemInformerCandidateFromEnv(std::vector<std::wstring>& candidates, const wchar_t* envName, const wchar_t* relativePath)
{
    wchar_t base[MAX_PATH * 4]{};
    DWORD len = GetEnvironmentVariableW(envName, base, ARRAYSIZE(base));

    if (len == 0 || len >= ARRAYSIZE(base))
        return;

    AddUniqueSystemInformerLaunchCandidate(candidates, CombinePath(base, relativePath));
}

static void AddSystemInformerAppPathRegistryCandidates(std::vector<std::wstring>& candidates, HKEY root, REGSAM wowFlags)
{
    HKEY key{};
    if (RegOpenKeyExW(root,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\SystemInformer.exe",
            0, KEY_READ | wowFlags, &key) != ERROR_SUCCESS)
    {
        return;
    }

    std::wstring value;
    if (LaunchRegistryGetString(key, nullptr, value))
        AddUniqueSystemInformerLaunchCandidate(candidates, value);

    RegCloseKey(key);
}

static void AddSystemInformerUninstallRegistryCandidates(std::vector<std::wstring>& candidates, HKEY root, REGSAM wowFlags)
{
    HKEY uninstallKey{};
    if (RegOpenKeyExW(root,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            0, KEY_READ | wowFlags, &uninstallKey) != ERROR_SUCCESS)
    {
        return;
    }

    for (DWORD index = 0;; ++index)
    {
        wchar_t subName[512]{};
        DWORD subNameLen = ARRAYSIZE(subName);

        if (RegEnumKeyExW(uninstallKey, index, subName, &subNameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        HKEY itemKey{};
        if (RegOpenKeyExW(uninstallKey, subName, 0, KEY_READ | wowFlags, &itemKey) != ERROR_SUCCESS)
            continue;

        std::wstring displayName;
        if (LaunchRegistryGetString(itemKey, L"DisplayName", displayName))
        {
            std::wstring lowerDisplayName = ToLower(displayName);
            if (lowerDisplayName.find(L"systeminformer") != std::wstring::npos ||
                (lowerDisplayName.find(L"system") != std::wstring::npos && lowerDisplayName.find(L"informer") != std::wstring::npos))
            {
                std::wstring installLocation;
                if (LaunchRegistryGetString(itemKey, L"InstallLocation", installLocation))
                {
                    installLocation = TrimLaunchString(installLocation);
                    if (!installLocation.empty())
                    {
                        AddUniqueSystemInformerLaunchCandidate(candidates, CombinePath(installLocation, L"SystemInformer.exe"));
                        AddUniqueSystemInformerLaunchCandidate(candidates, CombinePath(installLocation, L"System Informer.exe"));
                    }
                }

                std::wstring displayIcon;
                if (LaunchRegistryGetString(itemKey, L"DisplayIcon", displayIcon))
                    AddUniqueSystemInformerLaunchCandidate(candidates, displayIcon);
            }
        }

        RegCloseKey(itemKey);
    }

    RegCloseKey(uninstallKey);
}

static std::wstring FindInstalledSystemInformerPath()
{
    std::vector<std::wstring> candidates;

    AddSystemInformerAppPathRegistryCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY);
    AddSystemInformerAppPathRegistryCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY);
    AddSystemInformerAppPathRegistryCandidates(candidates, HKEY_CURRENT_USER, 0);

    AddSystemInformerUninstallRegistryCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY);
    AddSystemInformerUninstallRegistryCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY);
    AddSystemInformerUninstallRegistryCandidates(candidates, HKEY_CURRENT_USER, 0);

    AddSystemInformerCandidateFromEnv(candidates, L"ProgramFiles", L"SystemInformer\\SystemInformer.exe");
    AddSystemInformerCandidateFromEnv(candidates, L"ProgramFiles", L"System Informer\\SystemInformer.exe");
    AddSystemInformerCandidateFromEnv(candidates, L"ProgramFiles(x86)", L"SystemInformer\\SystemInformer.exe");
    AddSystemInformerCandidateFromEnv(candidates, L"ProgramFiles(x86)", L"System Informer\\SystemInformer.exe");
    AddSystemInformerCandidateFromEnv(candidates, L"LOCALAPPDATA", L"Programs\\SystemInformer\\SystemInformer.exe");
    AddSystemInformerCandidateFromEnv(candidates, L"LOCALAPPDATA", L"Programs\\System Informer\\SystemInformer.exe");

    for (const std::wstring& path : candidates)
    {
        if (FileExists(path))
            return path;
    }

    return L"";
}

static void AddUniqueRecuvaLaunchCandidate(std::vector<std::wstring>& candidates, const std::wstring& rawPath)
{
    std::wstring path = ExtractExecutablePathFromRegistryValue(rawPath);

    if (path.empty())
        return;

    std::wstring lower = ToLower(path);
    bool recuvaName = lower.find(L"recuva64.exe") != std::wstring::npos ||
        lower.find(L"recuva.exe") != std::wstring::npos;

    if (!recuvaName)
        return;

    for (const std::wstring& existing : candidates)
    {
        if (ToLower(existing) == lower)
            return;
    }

    candidates.push_back(path);
}

static void AddRecuvaCandidateFromEnv(std::vector<std::wstring>& candidates, const wchar_t* envName, const wchar_t* relativePath)
{
    wchar_t base[MAX_PATH * 4]{};
    DWORD len = GetEnvironmentVariableW(envName, base, ARRAYSIZE(base));

    if (len == 0 || len >= ARRAYSIZE(base))
        return;

    AddUniqueRecuvaLaunchCandidate(candidates, CombinePath(base, relativePath));
}

static void AddRecuvaUninstallRegistryCandidates(std::vector<std::wstring>& candidates, HKEY root, REGSAM wowFlags)
{
    HKEY uninstallKey{};
    if (RegOpenKeyExW(root,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            0, KEY_READ | wowFlags, &uninstallKey) != ERROR_SUCCESS)
    {
        return;
    }

    for (DWORD index = 0;; ++index)
    {
        wchar_t subName[512]{};
        DWORD subNameLen = ARRAYSIZE(subName);

        if (RegEnumKeyExW(uninstallKey, index, subName, &subNameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        HKEY itemKey{};
        if (RegOpenKeyExW(uninstallKey, subName, 0, KEY_READ | wowFlags, &itemKey) != ERROR_SUCCESS)
            continue;

        std::wstring displayName;
        if (LaunchRegistryGetString(itemKey, L"DisplayName", displayName) &&
            ToLower(displayName).find(L"recuva") != std::wstring::npos)
        {
            std::wstring installLocation;
            if (LaunchRegistryGetString(itemKey, L"InstallLocation", installLocation))
            {
                installLocation = TrimLaunchString(installLocation);
                if (!installLocation.empty())
                {
                    AddUniqueRecuvaLaunchCandidate(candidates, CombinePath(installLocation, L"recuva64.exe"));
                    AddUniqueRecuvaLaunchCandidate(candidates, CombinePath(installLocation, L"recuva.exe"));
                }
            }

            std::wstring displayIcon;
            if (LaunchRegistryGetString(itemKey, L"DisplayIcon", displayIcon))
                AddUniqueRecuvaLaunchCandidate(candidates, displayIcon);
        }

        RegCloseKey(itemKey);
    }

    RegCloseKey(uninstallKey);
}

static std::wstring FindInstalledRecuvaPath()
{
    std::vector<std::wstring> candidates;

    AddRecuvaUninstallRegistryCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY);
    AddRecuvaUninstallRegistryCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY);
    AddRecuvaUninstallRegistryCandidates(candidates, HKEY_CURRENT_USER, 0);

    AddRecuvaCandidateFromEnv(candidates, L"ProgramFiles", L"Recuva\\recuva64.exe");
    AddRecuvaCandidateFromEnv(candidates, L"ProgramFiles", L"Recuva\\recuva.exe");
    AddRecuvaCandidateFromEnv(candidates, L"ProgramFiles(x86)", L"Recuva\\recuva64.exe");
    AddRecuvaCandidateFromEnv(candidates, L"ProgramFiles(x86)", L"Recuva\\recuva.exe");

    for (const std::wstring& path : candidates)
    {
        if (FileExists(path))
            return path;
    }

    return L"";
}

static std::wstring FindLaunchPathForItem(const DownloadItem& item, const std::wstring& baseFolder)
{
    std::wstring target = GetItemTargetPath(item, baseFolder);

    if (IsSystemInformerItem(item))
    {
        std::wstring installedPath = FindInstalledSystemInformerPath();
        if (!installedPath.empty())
            return installedPath;
    }

    if (IsRecuvaItem(item))
    {
        std::wstring installedPath = FindInstalledRecuvaPath();
        if (!installedPath.empty())
            return installedPath;
    }

    if (IsFtkImagerItem(item))
    {
        // The button worker has already done the expensive Program Files scan.
        // Here only re-check fast locations/registry, then fall back to the
        // freshly extracted HolyCheck copy below.
        std::wstring installedPath = FindReadyInstalledFtkImagerPath(false);
        if (!installedPath.empty())
            return installedPath;
    }

    if (EndsWithI(target, L".zip"))
    {
        std::wstring extractDir = GetItemExtractDir(item, baseFolder);
        std::wstring exePath;

        // FTK 8.3 archive contains Exterro_FTK_Imager_(x64).exe. The installer
        // is handled by OpenItemPath on a background worker; after installation
        // subsequent clicks resolve directly to Program Files above.
        if (IsFtkImagerItem(item))
            return FindFtkImagerInstallerPath(item, baseFolder);

        if (FindFirstExeRecursive(extractDir, exePath))
            return exePath;

        return L"";
    }

    if (FileExists(target))
        return target;

    return L"";
}

static bool OpenPath(const std::wstring& path)
{
    if (path.empty())
        return false;

    HINSTANCE result = ShellExecuteW(
        g_hMain,
        L"open",
        path.c_str(),
        nullptr,
        nullptr,
        SW_SHOWNORMAL
    );

    return reinterpret_cast<INT_PTR>(result) > 32;
}

static bool OpenPathElevated(const std::wstring& path)
{
    if (path.empty())
        return false;

    HINSTANCE result = ShellExecuteW(
        g_hMain,
        L"runas",
        path.c_str(),
        nullptr,
        nullptr,
        SW_SHOWNORMAL
    );

    return reinterpret_cast<INT_PTR>(result) > 32;
}


static bool IsEverythingItem(const DownloadItem& item)
{
    std::wstring name = ToLower(item.name);
    return name.find(L"everything") != std::wstring::npos;
}

static std::wstring QuotePowerShellSingleArgLocal(std::wstring value)
{
    std::wstring out;
    for (wchar_t ch : value)
        out += (ch == L'\'') ? L"''" : std::wstring(1, ch);
    return out;
}

static bool EnsureRegistryExplorerDotNetRuntime(const std::wstring& registryExplorerExe)
{
    if (registryExplorerExe.empty())
        return false;

    std::wstring exeDir;
    size_t slash = registryExplorerExe.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
        exeDir = registryExplorerExe.substr(0, slash);

    std::wstring script;
    script.reserve(8192);
    script += L"$ErrorActionPreference='Stop'\n";
    // Ускорение скачивания рантайма: без прогресс-бара Invoke-WebRequest
    // в Windows PowerShell 5.1 (Win10/11) работает в десятки раз быстрее.
    script += L"$ProgressPreference='SilentlyContinue'\n";
    script += L"$exe='" + QuotePowerShellSingleArgLocal(registryExplorerExe) + L"'\n";
    script += L"$dir='" + QuotePowerShellSingleArgLocal(exeDir) + L"'\n";
    script += LR"HCPS(
function Out($s){[Console]::WriteLine([string]$s)}
$runtimeName='Microsoft.WindowsDesktop.App'
$major='8'
try{
  $runtimeConfig=Get-ChildItem -LiteralPath $dir -Filter '*.runtimeconfig.json' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*RegistryExplorer*' } | Select-Object -First 1
  if($runtimeConfig){
    $json=Get-Content -LiteralPath $runtimeConfig.FullName -Raw | ConvertFrom-Json
    $fx=@($json.runtimeOptions.frameworks)+@($json.runtimeOptions.framework) | Where-Object { $_ }
    $desktop=$fx | Where-Object { $_.name -eq 'Microsoft.WindowsDesktop.App' } | Select-Object -First 1
    if($desktop -and $desktop.version){ $major=([string]$desktop.version).Split('.')[0] }
  }
}catch{}
try{
  $runtimes=& dotnet --list-runtimes 2>$null
  if($LASTEXITCODE -eq 0 -and ($runtimes -match ('^' + [regex]::Escape($runtimeName) + '\s+' + [regex]::Escape($major) + '\.'))){ Out 'runtime-ok'; exit 0 }
}catch{}
$temp=Join-Path ([IO.Path]::GetTempPath()) 'HolyCheck\RegistryExplorerRuntime'
New-Item -ItemType Directory -Force -Path $temp | Out-Null
$installer=Join-Path $temp ('windowsdesktop-runtime-' + $major + '.0-win-x64.exe')
$url='https://aka.ms/dotnet/' + $major + '.0/windowsdesktop-runtime-win-x64.exe'
Out ('runtime-missing: ' + $runtimeName + ' ' + $major + '.x')
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing -TimeoutSec 120
$sig=Get-AuthenticodeSignature -LiteralPath $installer
if($sig.Status -ne 'Valid'){ throw 'Installer signature is not valid: ' + $sig.Status }
$p=Start-Process -FilePath $installer -ArgumentList '/install','/quiet','/norestart' -Wait -PassThru
if($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010){ throw 'Installer exit code: ' + $p.ExitCode }
Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
Out 'runtime-installed'
)HCPS";

    std::wstring output;
    bool ok = RunHiddenPowerShellScriptCapture(script, output, 180000);
    if (!ok)
    {
        PostLog(L"RegistryExplorer: не удалось проверить .NET Desktop Runtime");
        return false;
    }

    std::wstring lower = ToLower(output);
    if (lower.find(L"runtime-ok") != std::wstring::npos || lower.find(L"runtime-installed") != std::wstring::npos)
        return true;

    PostLog(L"RegistryExplorer: не удалось установить Microsoft.WindowsDesktop.App Runtime");
    if (!output.empty())
        DebugLogLine(L"registryexplorer", L"runtime output=" + output);
    return false;
}

// Everything открывается как обычная программа: без параметров командной строки.
static bool OpenEverythingPath(const std::wstring& path)
{
    return OpenPath(path);
}

static bool ShouldOpenItemElevated(const DownloadItem& item)
{
    std::wstring name = ToLower(item.name);

    return name.find(L"registryexplorer") != std::wstring::npos ||
        (name.find(L"registry") != std::wstring::npos && name.find(L"explorer") != std::wstring::npos) ||
        name.find(L"recuva") != std::wstring::npos;
}

// Setup wizard automation. The System Informer installer has no working silent
// switch, so its dialog is driven directly through window messages. HolyCheck
// always runs elevated, so UIPI does not block messages to the setup.
static std::wstring NormalizeSetupButtonText(const std::wstring& raw)
{
    std::wstring text;
    text.reserve(raw.size());

    for (wchar_t ch : raw)
    {
        if (ch == L'&')
            continue;

        text.push_back(ch);
    }

    while (!text.empty() && (text.front() == L' ' || text.front() == L'\t'))
        text.erase(text.begin());

    while (!text.empty() && (text.back() == L' ' || text.back() == L'\t' || text.back() == L'.'))
        text.pop_back();

    if (!text.empty())
        CharLowerBuffW(&text[0], static_cast<DWORD>(text.size()));

    return text;
}

struct SetupButtonInfo
{
    HWND hwnd;
    std::wstring text;
};

static BOOL CALLBACK CollectSetupButtonsProc(HWND hwnd, LPARAM lParam)
{
    auto* buttons = reinterpret_cast<std::vector<SetupButtonInfo>*>(lParam);

    if (!buttons)
        return FALSE;

    wchar_t className[64] = {};
    GetClassNameW(hwnd, className, ARRAYSIZE(className));

    if (_wcsicmp(className, L"Button") != 0)
        return TRUE;

    if (!IsWindowEnabled(hwnd))
        return TRUE;

    wchar_t caption[256] = {};
    GetWindowTextW(hwnd, caption, ARRAYSIZE(caption));

    SetupButtonInfo info;
    info.hwnd = hwnd;
    info.text = NormalizeSetupButtonText(caption);
    buttons->push_back(info);
    return TRUE;
}

struct SetupWindowSearch
{
    DWORD pid;
    std::vector<HWND> windows;
};

static BOOL CALLBACK CollectSetupWindowsProc(HWND hwnd, LPARAM lParam)
{
    auto* search = reinterpret_cast<SetupWindowSearch*>(lParam);

    if (!search)
        return FALSE;

    DWORD windowPid = 0;
    GetWindowThreadProcessId(hwnd, &windowPid);

    if (windowPid == search->pid)
        search->windows.push_back(hwnd);

    return TRUE;
}

static std::vector<HWND> CollectProcessWindows(DWORD pid)
{
    SetupWindowSearch search;
    search.pid = pid;
    EnumWindows(CollectSetupWindowsProc, reinterpret_cast<LPARAM>(&search));
    return search.windows;
}

static HWND FindSetupButton(const std::vector<SetupButtonInfo>& buttons, const std::vector<std::wstring>& names)
{
    for (const auto& button : buttons)
    {
        for (const auto& name : names)
        {
            if (button.text == name)
                return button.hwnd;
        }
    }

    return nullptr;
}

static HWND FindSetupButtonContaining(const std::vector<SetupButtonInfo>& buttons, const std::vector<std::wstring>& parts)
{
    for (const auto& button : buttons)
    {
        for (const auto& part : parts)
        {
            if (button.text.find(part) != std::wstring::npos)
                return button.hwnd;
        }
    }

    return nullptr;
}

static void ClickSetupButton(HWND button)
{
    if (button && IsWindow(button))
        SendMessageW(button, BM_CLICK, 0, 0);
}

static bool StartElevatedProcessHidden(const std::wstring& file, const std::wstring& params, HANDLE& processOut, DWORD& pidOut)
{
    processOut = nullptr;
    pidOut = 0;

    if (file.empty())
        return false;

    // Self-extracting installers (including FTK Imager) may resolve embedded
    // payloads relative to their own folder. Give ShellExecute an explicit
    // working directory instead of inheriting whatever directory launched
    // HolyCheck. This is safe on both Windows 10 and Windows 11.
    std::wstring workingDir;
    size_t slash = file.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
        workingDir = file.substr(0, slash);

    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.hwnd = nullptr;
    sei.lpVerb = L"runas";
    sei.lpFile = file.c_str();
    sei.lpParameters = params.empty() ? nullptr : params.c_str();
    sei.lpDirectory = workingDir.empty() ? nullptr : workingDir.c_str();
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei))
    {
        DebugLogLine(L"systeminformer", L"elevated start failed error=" + FormatWin32ErrorForLog(GetLastError()));
        return false;
    }

    processOut = sei.hProcess;

    if (processOut)
        pidOut = GetProcessId(processOut);

    return true;
}

// Install -> Next -> Close, exactly the sequence of the visible wizard.
static bool DriveSystemInformerSetupWizard(DWORD pid, DWORD timeoutMs)
{
    if (pid == 0)
        return false;

    const std::vector<std::wstring> installNames = { L"install", L"\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c" };
    const std::vector<std::wstring> nextNames = { L"next", L"\u0434\u0430\u043b\u0435\u0435", L"\u0434\u0430\u043b\u044c\u0448\u0435" };
    const std::vector<std::wstring> closeNames = { L"close", L"finish", L"\u0437\u0430\u043a\u0440\u044b\u0442\u044c", L"\u0433\u043e\u0442\u043e\u0432\u043e" };
    const std::vector<std::wstring> autoStartParts = { L"start program", L"\u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u044c" };

    DWORD startTick = GetTickCount();
    bool clickedInstall = false;
    bool clickedNext = false;
    std::vector<HWND> lastWindows;

    while (GetTickCount() - startTick < timeoutMs)
    {
        std::vector<HWND> windows = CollectProcessWindows(pid);

        if (!windows.empty())
            lastWindows = windows;

        for (HWND window : windows)
        {
            if (IsWindowVisible(window))
                ShowWindow(window, SW_HIDE);

            std::vector<SetupButtonInfo> buttons;
            EnumChildWindows(window, CollectSetupButtonsProc, reinterpret_cast<LPARAM>(&buttons));

            if (buttons.empty())
                continue;

            HWND installButton = FindSetupButton(buttons, installNames);

            if (installButton && !clickedInstall)
            {
                DebugLogLine(L"systeminformer", L"setup wizard: click Install");
                ClickSetupButton(installButton);
                clickedInstall = true;
                Sleep(200);
                continue;
            }

            HWND nextButton = FindSetupButton(buttons, nextNames);

            if (nextButton)
            {
                DebugLogLine(L"systeminformer", L"setup wizard: click Next");
                ClickSetupButton(nextButton);
                clickedNext = true;
                Sleep(200);
                continue;
            }

            // Closing the first page would cancel the install, so the close
            // button is only used after Install or Next was pressed.
            if (!clickedInstall && !clickedNext)
                continue;

            HWND autoStart = FindSetupButtonContaining(buttons, autoStartParts);

            if (autoStart && SendMessageW(autoStart, BM_GETCHECK, 0, 0) == BST_CHECKED)
                ClickSetupButton(autoStart);

            HWND closeButton = FindSetupButton(buttons, closeNames);

            if (closeButton)
            {
                DebugLogLine(L"systeminformer", L"setup wizard: click Close");
                ClickSetupButton(closeButton);
                Sleep(200);
            }
        }

        if (!FindInstalledSystemInformerPath().empty() && CollectProcessWindows(pid).empty())
            return true;

        Sleep(120);
    }

    // Do not leave an invisible stuck setup behind.
    for (HWND window : lastWindows)
    {
        if (IsWindow(window))
            ShowWindow(window, SW_SHOWNORMAL);
    }

    return !FindInstalledSystemInformerPath().empty();
}

// The uninstaller has the same problem as the setup: no silent switch, so it
// pops the "Are you sure you want to uninstall" dialog. Drive it directly:
// Uninstall -> Close. "Cancel" is never in the lists, so it cannot be clicked.
static bool DriveSystemInformerUninstallWizard(DWORD pid, DWORD timeoutMs)
{
    if (pid == 0)
        return false;

    const std::vector<std::wstring> uninstallNames = { L"uninstall", L"\u0443\u0434\u0430\u043b\u0438\u0442\u044c" };
    const std::vector<std::wstring> closeNames = { L"close", L"finish", L"\u0437\u0430\u043a\u0440\u044b\u0442\u044c", L"\u0433\u043e\u0442\u043e\u0432\u043e" };

    DWORD startTick = GetTickCount();
    bool clickedUninstall = false;
    std::vector<HWND> lastWindows;

    while (GetTickCount() - startTick < timeoutMs)
    {
        std::vector<HWND> windows = CollectProcessWindows(pid);

        if (!windows.empty())
            lastWindows = windows;

        for (HWND window : windows)
        {
            if (IsWindowVisible(window))
                ShowWindow(window, SW_HIDE);

            std::vector<SetupButtonInfo> buttons;
            EnumChildWindows(window, CollectSetupButtonsProc, reinterpret_cast<LPARAM>(&buttons));

            if (buttons.empty())
                continue;

            HWND uninstallButton = FindSetupButton(buttons, uninstallNames);

            if (uninstallButton && !clickedUninstall)
            {
                DebugLogLine(L"systeminformer", L"uninstall wizard: click Uninstall");
                ClickSetupButton(uninstallButton);
                clickedUninstall = true;
                Sleep(200);
                continue;
            }

            if (!clickedUninstall)
                continue;

            HWND closeButton = FindSetupButton(buttons, closeNames);

            if (closeButton)
            {
                DebugLogLine(L"systeminformer", L"uninstall wizard: click Close");
                ClickSetupButton(closeButton);
                Sleep(200);
            }
        }

        if (FindInstalledSystemInformerPath().empty() && CollectProcessWindows(pid).empty())
            return true;

        Sleep(120);
    }

    if (!FindInstalledSystemInformerPath().empty())
    {
        for (HWND window : lastWindows)
        {
            if (IsWindow(window))
                ShowWindow(window, SW_SHOWNORMAL);
        }

        return false;
    }

    return true;
}

static bool InstallSystemInformerSilently(const std::wstring& setupPath)
{
    std::wstring installed = FindInstalledSystemInformerPath();

    if (!installed.empty())
    {
        DebugLogLine(L"systeminformer", L"install skipped: already installed " + installed);
        return true;
    }

    if (setupPath.empty() || !FileExists(setupPath))
    {
        DebugLogLine(L"systeminformer", L"install skipped: setup missing " + setupPath);
        return false;
    }

    HANDLE process = nullptr;
    DWORD pid = 0;

    if (!StartElevatedProcessHidden(setupPath, L"", process, pid))
        return false;

    DebugLogLine(L"systeminformer", L"setup started pid=" + std::to_wstring(pid));

    bool ok = DriveSystemInformerSetupWizard(pid, 240000);

    if (process)
    {
        WaitForSingleObject(process, ok ? 10000 : 0);
        CloseHandle(process);
    }

    ok = ok && !FindInstalledSystemInformerPath().empty();
    DebugLogLine(L"systeminformer", ok ? L"install ok" : L"install failed");
    return ok;
}

static void SystemInformerInstallWorker(std::wstring setupPath)
{
    HRESULT comInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    try
    {
        bool launched = false;

        if (InstallSystemInformerSilently(setupPath))
        {
            std::wstring installed = FindInstalledSystemInformerPath();

            if (!installed.empty())
            {
                PostLog(L"System Informer: \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d");
                launched = OpenPathElevated(installed) || OpenPath(installed);
            }
        }

        if (!launched)
        {
            // Silent install did not go through (for example the elevation
            // prompt was declined). Fall back to opening the setup normally so
            // the button always produces a visible result.
            PostLog(L"System Informer: \u043e\u0442\u043a\u0440\u044b\u0432\u0430\u044e \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u0449\u0438\u043a");

            if (!setupPath.empty() && FileExists(setupPath))
                OpenPathElevated(setupPath);
        }
    }
    catch (...)
    {
        DebugLogLine(L"systeminformer", L"background install failed with exception");
    }

    if (SUCCEEDED(comInit))
        CoUninitialize();

    g_systemInformerInstalling.store(false);

    // Re-enable the tile that was locked for the duration of the install.
    int tileIndex = g_systemInformerTileIndex.exchange(-1);

    if (tileIndex >= 0)
    {
        SetItemBusyIndex(tileIndex, false);
        SetTileEnabledByIndex(tileIndex, true);
    }
}

static bool InstallRecuvaSilently(const std::wstring& setupPath)
{
    std::wstring installed = FindInstalledRecuvaPath();

    if (!installed.empty())
        return true;

    if (setupPath.empty() || !FileExists(setupPath))
        return false;

    HANDLE process = nullptr;
    DWORD pid = 0;

    // Official Recuva setup supports the NSIS /S switch. The process is
    // launched hidden and elevated, so only the Windows UAC prompt can appear.
    if (!StartElevatedProcessHidden(setupPath, L"/S", process, pid))
        return false;

    bool ok = false;
    if (process)
    {
        DWORD waitResult = WaitForSingleObject(process, 240000);
        DWORD exitCode = 1;
        ok = waitResult == WAIT_OBJECT_0 && GetExitCodeProcess(process, &exitCode) && exitCode == 0;
        CloseHandle(process);
    }

    for (int attempt = 0; attempt < 20 && FindInstalledRecuvaPath().empty(); ++attempt)
        Sleep(250);

    return ok && !FindInstalledRecuvaPath().empty();
}

static void RecuvaInstallWorker(std::wstring setupPath)
{
    HRESULT comInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    try
    {
        if (InstallRecuvaSilently(setupPath))
        {
            std::wstring installed = FindInstalledRecuvaPath();
            bool launched = false;

            // The installation has fully completed at this point. Try a normal
            // launch first to avoid a second UAC prompt, then use elevation as
            // a fallback. A few retries cover delayed antivirus/file unlocks.
            for (int attempt = 0; attempt < 3 && !launched && !installed.empty(); ++attempt)
            {
                launched = OpenPath(installed) || OpenPathElevated(installed);

                if (!launched)
                    Sleep(500);
            }

            PostLog(launched
                ? L"Recuva: установлена и открыта"
                : L"Recuva: установлена, но не открылась");
        }
        else
        {
            PostLog(L"Recuva: ошибка фоновой установки");
        }
    }
    catch (...)
    {
        DebugLogLine(L"recuva", L"background install failed with exception");
    }

    if (SUCCEEDED(comInit))
        CoUninitialize();

    g_recuvaInstalling.store(false);

    int tileIndex = g_recuvaTileIndex.exchange(-1);
    if (tileIndex >= 0)
    {
        SetItemBusyIndex(tileIndex, false);
        SetTileEnabledByIndex(tileIndex, true);
    }
}

static bool OpenFtkImagerExecutable(const std::wstring& path);

static std::wstring FindInstalledFtkImagerFastPath()
{
    // Hot path used while the installer is running. Avoid enumerating every
    // Uninstall registry subkey or recursively scanning Program Files on each
    // poll; those operations made FTK installation feel much slower.
    std::vector<std::wstring> candidates;
    const wchar_t* envs[] = { L"ProgramW6432", L"ProgramFiles", L"ProgramFiles(x86)" };
    const wchar_t* rels[] = {
        L"AccessData\\FTK Imager\\FTK Imager.exe",
        L"AccessData\\AccessData FTK Imager\\FTK Imager.exe",
        L"AccessData\\FTK Imager.exe",
        L"Exterro\\FTK Imager\\FTK Imager.exe",
        L"Exterro\\FTK Imager.exe"
    };

    for (const auto* env : envs)
        for (const auto* rel : rels)
            AddFtkCandidateFromEnv(candidates, env, rel);

    // App Paths is cheap to query and covers installations that register an
    // explicit executable path without using the default AccessData folder.
    AddFtkAppPathRegistryCandidate(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY);
    AddFtkAppPathRegistryCandidate(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY);
    AddFtkAppPathRegistryCandidate(candidates, HKEY_CURRENT_USER, 0);

    for (const auto& path : candidates)
        if (IsFtkImagerLaunchReady(path))
            return path;

    return L"";
}

static bool WaitForFtkImagerInstall(HANDLE process, DWORD maxWaitMs, bool& processFinished, DWORD& exitCode)
{
    processFinished = false;
    exitCode = STILL_ACTIVE;

    const ULONGLONG started = GetTickCount64();
    ULONGLONG lastRegistryProbe = 0;
    ULONGLONG finishedAt = 0;
    ULONGLONG readySince = 0;

    for (;;)
    {
        const ULONGLONG now = GetTickCount64();
        const ULONGLONG elapsed = now - started;

        if (process && !processFinished)
        {
            DWORD waitResult = WaitForSingleObject(process, 0);
            if (waitResult == WAIT_OBJECT_0)
            {
                processFinished = true;
                finishedAt = elapsed;
                GetExitCodeProcess(process, &exitCode);
            }
        }

        // A visible FTK Imager.exe is not enough. Wait until its private DLLs
        // (especially dongle.dll) are present and non-empty, then keep that
        // state stable for a short interval before declaring installation ready.
        std::wstring readyPath = FindInstalledFtkImagerFastPath();
        if (readyPath.empty() && (elapsed == 0 || elapsed - lastRegistryProbe >= 2000))
        {
            lastRegistryProbe = elapsed;
            readyPath = FindReadyInstalledFtkImagerPath(false);
        }

        if (!readyPath.empty())
        {
            if (readySince == 0)
                readySince = now;

            // Give MSI/InstallShield a little time to finish replacing/copying
            // neighboring DLLs. This prevents the first automatic launch from
            // racing the installer while keeping the delay barely noticeable.
            if (now - readySince >= 2000)
                return true;
        }
        else
        {
            readySince = 0;
        }

        // InstallShield can exit before the child Windows Installer finishes.
        // A successful bootstrapper therefore gets a grace period in which we
        // continue waiting for a fully launchable FTK installation.
        if (processFinished)
        {
            const ULONGLONG graceMs = (exitCode == ERROR_SUCCESS || exitCode == 3010) ? 60000ULL : 8000ULL;
            if (elapsed >= finishedAt + graceMs)
                break;
        }

        if (elapsed >= maxWaitMs)
            break;

        Sleep(250);
    }

    std::wstring readyPath = FindReadyInstalledFtkImagerPath(true);
    if (readyPath.empty())
        return false;

    // Final stabilization after a deep lookup as well.
    Sleep(1500);
    return IsFtkImagerLaunchReady(readyPath);
}

static bool RunFtkInstallerSilentAttempt(
    const std::wstring& setupPath,
    const std::wstring& args,
    DWORD maxWaitMs,
    bool& processFinished,
    DWORD& exitCode)
{
    HANDLE process = nullptr;
    DWORD pid = 0;

    processFinished = false;
    exitCode = STILL_ACTIVE;

    if (!StartElevatedProcessHidden(setupPath, args, process, pid))
        return false;

    DebugLogLine(L"ftk", L"silent setup started pid=" + std::to_wstring(pid) + L" args=" + args);

    bool installed = WaitForFtkImagerInstall(process, maxWaitMs, processFinished, exitCode);

    if (process)
        CloseHandle(process);

    DebugLogLine(L"ftk", L"silent setup state exit=" + std::to_wstring(exitCode) +
        L" finished=" + std::to_wstring(processFinished ? 1 : 0) +
        L" installed=" + std::to_wstring(installed ? 1 : 0));
    return installed;
}

static bool InstallFtkImagerSilently(const std::wstring& setupPath)
{
    if (!FindReadyInstalledFtkImagerPath(false).empty())
        return true;

    if (setupPath.empty() || !FileExists(setupPath))
    {
        DebugLogLine(L"ftk", L"installer missing: " + setupPath);
        return false;
    }

    // FTK Imager uses an InstallShield bootstrapper around Windows Installer.
    // The FTK-specific unattended form used by deployment scripts is /s /v/qn;
    // keep the first attempt minimal so InstallShield forwards it cleanly on
    // both Windows 10 and Windows 11. A quoted MSI form remains below as the
    // single compatibility fallback.
    bool processFinished = false;
    DWORD exitCode = STILL_ACTIVE;
    if (RunFtkInstallerSilentAttempt(
        setupPath,
        L"/s /v/qn",
        300000,
        processFinished,
        exitCode))
    {
        return true;
    }

    // Some InstallShield bootstrappers return 0 as soon as they hand work to
    // Windows Installer. A zero bootstrapper exit code therefore is not proof
    // that FTK was installed. If the bootstrapper really ended and FTK still
    // cannot be found after the grace period, retry once with the alternate
    // MSI quiet spelling. Never start the fallback while the first bootstrapper
    // is still alive.
    if (processFinished && exitCode != STILL_ACTIVE && FindReadyInstalledFtkImagerPath(false).empty())
    {
        bool fallbackFinished = false;
        DWORD fallbackExit = STILL_ACTIVE;
        return RunFtkInstallerSilentAttempt(
            setupPath,
            L"/s /v\"/qn /norestart REBOOT=ReallySuppress\"",
            180000,
            fallbackFinished,
            fallbackExit);
    }

    return !FindReadyInstalledFtkImagerPath(false).empty();
}

static void FtkImagerInstallWorker(std::wstring setupPath)
{
    HRESULT comInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    try
    {
        if (InstallFtkImagerSilently(setupPath))
        {
            std::wstring installed = FindInstalledFtkImagerFastPath();
            if (installed.empty())
                installed = FindReadyInstalledFtkImagerPath(false);
            if (installed.empty())
                installed = FindReadyInstalledFtkImagerPath(true);
            bool launched = false;
            if (!g_deleteInProgress.load() && !g_destroying.load())
                launched = !installed.empty() && OpenFtkImagerExecutable(installed);

            PostLog(g_deleteInProgress.load() || g_destroying.load()
                ? L"FTK Imager: установка завершена, запуск отменён из-за удаления"
                : (launched ? L"FTK Imager: установлен и открыт" : L"FTK Imager: установлен, но не открылся"));
        }
        else
        {
            PostLog(L"FTK Imager: ошибка фоновой установки");
        }
    }
    catch (...)
    {
        DebugLogLine(L"ftk", L"background install failed with exception");
        PostLog(L"FTK Imager: ошибка фоновой установки");
    }

    if (SUCCEEDED(comInit))
        CoUninitialize();

    g_ftkImagerInstalling.store(false);
    int tileIndex = g_ftkImagerTileIndex.exchange(-1);
    if (tileIndex >= 0)
    {
        SetItemBusyIndex(tileIndex, false);
        SetTileEnabledByIndex(tileIndex, true);
    }
}

static std::wstring GetLaunchWorkingDirectory(const std::wstring& path)
{
    size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
        return L"";

    return path.substr(0, slash);
}

static bool OpenFtkImagerExecutable(const std::wstring& path)
{
    if (!IsFtkImagerLaunchReady(path))
    {
        DebugLogLine(L"ftk", L"launch blocked: FTK dependencies are not ready beside " + path);
        return false;
    }

    std::wstring workingDir = GetLaunchWorkingDirectory(path);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    if (CreateProcessW(
        path.c_str(),
        nullptr,
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        workingDir.empty() ? nullptr : workingDir.c_str(),
        &si,
        &pi))
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        DebugLogLine(L"ftk", L"launched existing FTK Imager: " + path);
        return true;
    }

    DWORD createError = GetLastError();
    DebugLogLine(L"ftk", L"CreateProcess failed path=" + path + L" error=" + FormatWin32ErrorForLog(createError));

    // Fallback through ShellExecute. If elevation is required, request it
    // explicitly; HolyCheck normally already runs elevated, so this is mostly
    // for systems with a different launch policy.
    const wchar_t* verb = (createError == ERROR_ELEVATION_REQUIRED) ? L"runas" : L"open";
    HINSTANCE result = ShellExecuteW(
        g_hMain,
        verb,
        path.c_str(),
        nullptr,
        workingDir.empty() ? nullptr : workingDir.c_str(),
        SW_SHOWNORMAL
    );

    return reinterpret_cast<INT_PTR>(result) > 32;
}

static bool OpenItemPath(const DownloadItem& item, const std::wstring& path)
{
    if (IsFtkImagerItem(item))
    {
        std::wstring installed = FindReadyInstalledFtkImagerPath(false);
        if (!installed.empty())
            return OpenFtkImagerExecutable(installed);

        std::wstring fileName = ToLower(ExtractFileNameOnly(path));
        if (fileName == L"ftk imager.exe")
            return IsFtkImagerLaunchReady(path) && OpenFtkImagerExecutable(path);

        if (path.empty() || !FileExists(path) ||
            _wcsicmp(ExtractFileNameOnly(path).c_str(), L"Exterro_FTK_Imager_(x64).exe") != 0)
        {
            DebugLogLine(L"ftk", L"exact installer not found: " + path);
            return false;
        }

        bool expected = false;
        if (!g_ftkImagerInstalling.compare_exchange_strong(expected, true))
            return true;

        try
        {
            std::thread(FtkImagerInstallWorker, path).detach();
        }
        catch (...)
        {
            g_ftkImagerInstalling.store(false);
            return false;
        }

        return true;
    }

    if (IsEverythingItem(item))
        return OpenEverythingPath(path);

    if (IsRecuvaItem(item))
    {
        std::wstring installed = FindInstalledRecuvaPath();

        // If Recuva is already installed, never open the downloaded setup.
        if (!installed.empty())
            return OpenPath(installed) || OpenPathElevated(installed);

        if (path.empty() || !FileExists(path))
            return false;

        bool expected = false;
        if (!g_recuvaInstalling.compare_exchange_strong(expected, true))
            return true;

        try
        {
            std::thread(RecuvaInstallWorker, path).detach();
        }
        catch (...)
        {
            g_recuvaInstalling.store(false);
            return false;
        }

        return true;
    }

    if (IsSystemInformerItem(item))
    {
        std::wstring installed = FindInstalledSystemInformerPath();

        if (installed.empty() && !EndsWithI(path, L"setup.exe") && FileExists(path))
            installed = path;

        // Already installed: just launch it.
        if (!installed.empty())
        {
            DebugLogLine(L"systeminformer", L"launch installed copy: " + installed);
            return OpenPathElevated(installed) || OpenPath(installed);
        }

        if (path.empty() || !FileExists(path))
        {
            DebugLogLine(L"systeminformer", L"setup not found, nothing to install: " + path);
            return false;
        }

        bool expected = false;

        if (!g_systemInformerInstalling.compare_exchange_strong(expected, true))
        {
            DebugLogLine(L"systeminformer", L"install already running");
            return true;
        }

        // The install runs on its own thread. Previously it ran synchronously,
        // including from the click handler, which froze the window for the
        // whole duration of the setup.
        DebugLogLine(L"systeminformer", L"start background install: " + path);

        try
        {
            std::thread(SystemInformerInstallWorker, path).detach();
        }
        catch (...)
        {
            g_systemInformerInstalling.store(false);
            DebugLogLine(L"systeminformer", L"failed to start background install thread");
            return false;
        }

        return true;
    }

    if (IsRegistryExplorerItem(item) && !EnsureRegistryExplorerDotNetRuntime(path))
        return false;

    if (ShouldOpenItemElevated(item))
        return OpenPathElevated(path);

    return OpenPath(path);
}

static bool CopyTextToClipboard(const wchar_t* text)
{
    if (!text || !g_hMain)
        return false;

    size_t len = wcslen(text);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, (len + 1) * sizeof(wchar_t));

    if (!memory)
        return false;

    wchar_t* target = static_cast<wchar_t*>(GlobalLock(memory));

    if (!target)
    {
        GlobalFree(memory);
        return false;
    }

    memcpy(target, text, (len + 1) * sizeof(wchar_t));
    GlobalUnlock(memory);

    if (!OpenClipboard(g_hMain))
    {
        GlobalFree(memory);
        return false;
    }

    const bool copied = EmptyClipboard() && SetClipboardData(CF_UNICODETEXT, memory) != nullptr;
    CloseClipboard();
    if (!copied)
        GlobalFree(memory);
    return copied;
}

static void CopyHelperText(const wchar_t* text, const std::wstring& name)
{
    UNREFERENCED_PARAMETER(name);

    if (CopyTextToClipboard(text))
        PostLog(L"текст скопирован");
    else
        PostLog(L"текст не скопирован");
}

static constexpr wchar_t EVERYTHING_CHEATS_QUERY[] = LR"HCEV(file: ext:exe;jar;zip;rar regex:"(impact|wurst|bleach[-_]?hack|aristois|huzuni|skill[-_]?client|nodus|inertia|ares|sigma|meteor|atomic|zamorozka|liquid[-_]?bounce|nurik|nursultan|celestial|calestial|celka|expensive|neverhook|excellent|wexside|wild|minced|deadcode|akrien|future|dreampool|vape|infinity|squad|no[-_]?rules|konas|zeus[-_]?client|rich[-_]?client|ghost[-_]?client|rusher[-_]?hack|thunder[-_]?hack|moon[-_]?hack|winner|nova|exire|doomsday|nightware|ricardo|extazyy|troxill|arbuz|dauntiblyat|rename[-_]?me[-_]?please|edit[-_]?me|takker|faker|xameleon|fuze[-_]?client|wise[-_]?folder|net[-_]?limiter|feather|delta|eclipse|venus|jex|hakari|hush|hach|rogalik|catlavan|haruka|wissend|fluger|sperma|vortex|newcode|astra|britva|bariton|bot|player|freecam|bedrock|hotbar|swap|chest|gumball|tweak|entity|crystal|lowdurabilityswitcher|optimizer|viabackwards|viaforge|viaproxy|hitbox|elytra|through|mob|auto|place|inventory|x[-_]?ray|clean[-_]?cut|smart[-_]?moving|save[-_]?searcher|world[-_]?downloader|trade[-_]?finder|chorus[-_]?find|inv[-_]?move|chunk[-_]?copy|seed[-_]?cracker|diamond[-_]?sim|forge[-_]?hax|step[-_]?up|client[-_]?commands|camera[-_]?utils|cheat[-_]?utils|universal[-_]?mod|swing[-_]?through[-_]?grass|luminex|wissend|nuclear)")HCEV";

static constexpr wchar_t EVERYTHING_CONFIGS_QUERY[] = LR"HCEV(<ext:txt;json;toml;yml;cfg;properties;ini|folder:> dm:14days regex:"(shellbag|bariton|bot|player|freecam|bedrock|hotbar|swap|chest|gumball|tweak|entity|crystal|optimizer|viabackwards|viaforge|viaproxy|hitbox|elytra|through|mob|auto|place|inventory|x[-_]?ray|clean[-_]?cut|smart[-_]?moving|save[-_]?searcher|world[-_]?downloader|trade[-_]?finder|chorus[-_]?find|inv[-_]?move|chunk[-_]?copy|seed[-_]?cracker|diamond[-_]?sim|forge[-_]?hax|step[-_]?up|client[-_]?commands|camera[-_]?utils|cheat[-_]?utils|universal[-_]?mod|swing[-_]?through[-_]?grass)")HCEV";

static const wchar_t* JOURNAL_TRACE_TXT = LR"HCJOURNAL(1
directory:.mineceaft;name:!!.
2
directory:.minecraft;directory:config||mods||logs||addons
3
directory::;name:.jar||.zip||.rar;name:!!.lnk
4
directory:Downloads||Desktop
5
directory:prefetch)HCJOURNAL";


static const wchar_t* SYSTEM_INFORMER_TXT = LR"HCSYSTEM(Regex (case-insensetive) | javaw.exe:

(ASM:|H\(q=Zf@wDLF\?/d\?D&|x/fC5K<;i/f6I\-w\[|SMe;8#xj0s<\+pyE&bEZ|cR_A\^yvDVSXDYPQp\]|cortex|r\|\~\}Xnpo\>\]_\^'@BA|WYX\-gih\>rssK\{\|\|\[|net\/minecraft\/client\/renderer\/RenderState\$\$Lambda\+0x000001e7d29d9930|7ba\{vsdkvhd\}o\}w|Hba\{vsdkvhduy\{q|Fba\{vsdkvhdpxhz|Aba\{vsdkvhdnxhv|x\/mo\/c|Self Destruct|blessed|stubborn\.website|cortex|E S P|Hitbox:|Reach:|chs\/Main|chs\/Profiler|net\.minecraftforge\.ASMEventHandler\.31\.wait\(long, int\)|magicthein|radioegor146|BaoBab:|b\/time|chs\/90|by\.kayn|ZDCoder|dreampool|TriggerBOT|forge\.commons\.|sjuuOiqotmus|<!+CJR|GUI Blur)


Regex (case-insensetive) | DPS:

(?:2023\/03\/09:17:11:30|2023\/07\/03:22:01:11|2023\/10\/04:16:07:05|2024\/04\/05:11:43:39|2025\/05\/28:23:57:12|2076\/05\/18:04:53:15|2024\/05\/02:22:48|2024\/09\/06:09:35:50|2023\/08\/13:13:09:58|2025\/01\/20:21:37:53|2025\/01\/16:14:21:21|2022\/06\/07:07:45:55)

> Список dps для справки (НЕ ДЛЯ БАНА!)

2023/03/09:17:11:30 - stubborn
2023/07/03:22:01:11 - синий авалон
2023/10/04:16:07:05 - зелёный авалон
2024/04/05:11:43:39 - красный авалон
2025/05/28:23:57:12 - cortex
2076/05/18:04:53:15 - unicorn
2024/05/02:22:48 - niobium
2024/09/06:09:35:50 - ocean bypass
2023/08/13:13:09:58 - rockstar
2025/01/20:21:37:53 - troxill
2025/01/16:14:21:21 - nemezida
2022/06/07:07:45:55 - mp3)HCSYSTEM";

static const wchar_t* POWERSHELL_TXT =
    LR"HCPS($ErrorActionPreference="SilentlyContinue";$out="$PWD\check.txt";$twinksOut="$PWD\checktwinks.txt";$mac = (Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'} | Sort-Object -Property InterfaceIndex | Select-Object -First 1).MacAddress;if (-not $mac) { $mac = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Virtual|WireGuard|TAP'} | Sort-Object -Property InterfaceIndex | Select-Object -First 1).MacAddress };"1. Модель системы: $((Get-CimInstance Win32_ComputerSystem).Model)`n2. Серийный BIOS: $((Get-CimInstance Win32_BIOS).SerialNumber)`n3. Реестр: $((Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS').SystemProductName)`n4. Модель диска: $((Get-CimInstance Win32_DiskDrive | ForEach-Object { "$($_.Model) ($([math]::Round($_.Size/1GB, 2)) GB)" }) -join ', ')`n5. Видеоадаптеры: $(($(Get-CimInstance Win32_PnPSignedDriver | Where-Object {$_.DeviceClass -eq 'DISPLAY'} | ForEach-Object { "$($_.DeviceName) | $($_.Manufacturer) | $($_.DriverProviderName)" }) -join '; '))`n6. Виртуальные устройства: $((Get-CimInstance Win32_PnPEntity | Where-Object {$_.Name -match 'VMware|Virtual|VBox|Hyper-V|QEMU|Xen|KVM|VirtIO|VirtualBox|VMCI|SVGA|VMBus'}).Name -join ', ')`n7. Mac: $mac">$out;$bootTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime;function f($t){$p=(' '*((45-$t.Length)/2));"${p}${t}${p}"+(' '*(45-$p.Length*2-$t.Length))};"`n`n=============================================`n$(f 'ИНФОРМАЦИЯ О ВКЛЮЧЕНИИ ПК')`n=============================================`nПоследнее включение ПК: $($bootTime.ToString('yyyy-MM-dd HH:mm:ss'))">>$out;"`n`n`n=============================================`n$(f 'СОСТОЯНИЕ СЛУЖБ')`n=============================================">>$out;$services=@("PcaSvc","DPS","SysMain","EventLog","bam")|%{$s=Get-Service $_ -ea 0;if($s){$t=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$_" -n Start -ea 0).Start;$n=switch($t){2{'Авто'}3{'Вручную'}4{'Отключена'}default{'Неизвестно'}};$p=if($s.Status-eq'Running'){try{$procId=(Get-CimInstance Win32_Service -Filter "Name='$_'").ProcessID;(Get-Process -Id $procId -ea 0).StartTime.ToString('yyyy-MM-dd HH:mm:ss')}catch{'Не удалось получить'}}else{'Не запущена'};[PSCustomObject]@{'Служба'=$_.PadRight(8);'Состояние'=$s.Status.ToString().PadRight(10);'Тип запуска'=$n.PadRight(9);'Время запуска'=$p.PadRight(20)}}};($services|ft -AutoSize -Wrap|Out-String -Width 4096|%{$_.Trim()})>>$out;"`n`n`n=============================================`n$(f 'СОБЫТИЯ ОЧИСТКИ ЖУРНАЛОВ (ID 104)')`n=============================================">>$out;$e=Get-WinEvent -LogName System -FilterXPath "*[System[(EventID=104)]]" -ea 0;if($e){$e|%{$d=($_.Message-split"`n")[0];"ID $($_.Id) | $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | $d">>$out}};"`n`n`n=============================================`n$(f 'СОБЫТИЯ ПРИЛОЖЕНИЯ (ID 3079)')`n=============================================">>$out;Get-WinEvent -LogName Application -FilterXPath "*[System[(EventID=3079)]]" -MaxEvents 5 -ea 0|%{$m=($_.Message-split"Подробности:")[-1].Trim()-replace"`n|`r|\s+"," ";"ID $($_.Id) | $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | $m">>$out};"`n`n`n=============================================`n$(f 'СПИСОК ТВИНКОВ ИГРОКА')`n=============================================">>$out;$r=@{};$err=@();$scanFiles=@(Get-ChildItem -LiteralPath . -File -Recurse -ea 0);)HCPS"
    LR"HCPS($scanFiles|?{$_.Name -like '*.log' -or $_.Name -like '*.log.gz'}|%{try{if($_.Extension-eq'.gz'){$c=[System.IO.Compression.GzipStream]::new([System.IO.File]::OpenRead($_.FullName),[System.IO.Compression.CompressionMode]::Decompress);$s=[System.IO.StreamReader]::new($c);while(-not$s.EndOfStream){$l=$s.ReadLine();if($l-match'setting user:\s*(.+)$'){$r[$matches[1].Trim()]=1}};$s.Close()}else{Get-Content $_.FullName|?{$_-match'setting user:\s*(.+)$'}|%{$r[$matches[1].Trim()]=1}}}catch{$err+="Ошибка логов $($_.Name): $_"}};if(Test-Path "$env:APPDATA\.iasx"){try{[System.Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes("$env:APPDATA\.iasx")) -split '[\0-\x1F\x7F-\x9F]'|%{$_.TrimEnd('t')}|?{$_-match '^[\p{IsCyrillic}\p{IsBasicLatin}_]{3,20}$'-and$_-notmatch'=$'-and$_-notmatch'(java|alias|user|pass|field|object|count|list|data|xp|sr|lastused|premium|obj|q$|\[)'}|%{$r[$_]=1}}catch{$err+="Ошибка appdata iasx: $_"}};$scanFiles|?{$_.Extension -eq'.iasx'}|%{try{[System.Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($_.FullName)) -split '[\0-\x1F\x7F-\x9F]'|%{$_.TrimEnd('t')}|?{$_-match '^[\p{IsCyrillic}\p{IsBasicLatin}_]{3,20}$'-and$_-notmatch'=$'-and$_-notmatch'(java|alias|user|pass|field|object|count|list|data|xp|sr|lastused|premium|obj|q$|\[)'}|%{$r[$_]=1}}catch{$err+="Ошибка iasx $($_.Name): $_"}};$scanFiles|?{$_.Name -eq'accounts_v1.do_not_send_to_anyone'}|%{try{$b=[System.IO.File]::ReadAllBytes($_.FullName);$ms=New-Object System.IO.MemoryStream(,$b[2..($b.Length-1)]);$ds=New-Object System.IO.Compression.DeflateStream($ms,[System.IO.Compression.CompressionMode]::Decompress);$sr=New-Object System.IO.StreamReader($ds);$c=$sr.ReadToEnd();$sr.Close();$ds.Close();$ms.Close();$c-split'[\x00-\x1F]'|?{$_-match'^[a-zA-Z0-9_]{3,}$'}|%{$r[$_]=1}}catch{$err+="Ошибка accounts_v1 $($_.Name): $_"}};if(Test-Path "$PWD\usercache.json"){try{Get-Content "$PWD\usercache.json" -Raw|ConvertFrom-Json|Select-Object -ExpandProperty name|%{$r[$_]=1}}catch{$err+="Ошибка usercache.json: $_"}};if(Test-Path "$PWD\TlauncherProfiles.json"){try{Get-Content "$PWD\TlauncherProfiles.json" -Raw|ConvertFrom-Json|%{$_.accounts.PSObject.Properties.Value|Select-Object -Expand username}|%{$r[$_]=1}}catch{$err+="Ошибка TlauncherProfiles.json: $_"}};if(Test-Path "$PWD\LabyMod\accounts.json"){try{Get-Content "$PWD\LabyMod\accounts.json" -Raw|ConvertFrom-Json|%{$_.accounts.PSObject.Properties.Value.username}|%{$r[$_]=1}}catch{$err+="Ошибка LabyMod/accounts.json: $_"}};if(Test-Path "$PWD\labymod-neo\accounts.json"){try{Get-Content "$PWD\labymod-neo\accounts.json" -Raw|ConvertFrom-Json|%{$_.accounts.PSObject.Properties.Value.username}|%{$r[$_]=1}}catch{$err+="Ошибка labymod-neo/accounts.json: $_"}};$scanFiles|?{$_.Name -eq'ias.json'}|%{try{$j=Get-Content $_.FullName -Raw|ConvertFrom-Json;if($j.accounts){$j.accounts|%{if($_.name){$r[$_.name]=1}elseif($_.data.username){$r[$_.data.username]=1}}}}catch{$err+="Ошибка ias.json $($_.Name): $_"}};if(Test-Path "$PWD\usernamecache.json"){try{Get-Content "$PWD\usernamecache.json" -Raw|ConvertFrom-Json|%{$_.PSObject.Properties.Value}|%{$r[$_]=1}}catch{$err+="Ошибка usernamecache.json: $_"}};if(Test-Path "$env:APPDATA\.lunarclient"){try{Get-ChildItem "$env:APPDATA\.lunarclient" -Recurse -Filter *.json -ea 0|%{try{$c=Get-Content $_.FullName -Raw;)HCPS"
    LR"HCPS(if($c -match'"username"\s*:\s*"([^"]+)"'){$matches[1]|%{$r[$_]=1}}if($c -match'"displayName"\s*:\s*"([^"]+)"'){$matches[1]|%{$r[$_]=1}}}catch{$err+="Ошибка Lunar Client $($_.Name): $_"}}}catch{$err+="Ошибка доступа к Lunar Client: $_"}};if(Test-Path "$env:APPDATA\lunarclient"){try{Get-ChildItem "$env:APPDATA\lunarclient" -Recurse -Filter *.json -ea 0|%{try{$c=Get-Content $_.FullName -Raw;if($c -match'"username"\s*:\s*"([^"]+)"'){$matches[1]|%{$r[$_]=1}}if($c -match'"displayName"\s*:\s*"([^"]+)"'){$matches[1]|%{$r[$_]=1}}}catch{$err+="Ошибка Lunar Client $($_.Name): $_"}}}catch{$err+="Ошибка доступа к Lunar Client: $_"}};if($r.Count-gt0){($r.Keys-join' ')>$twinksOut;$r.Keys>>$out}else{"Нет данных о твинках">>$out};if($err){"Ошибки:`n$($err-join"`n")">>$out};$pwdPath=(Get-Location).ProviderPath;try{[System.IO.File]::WriteAllText((Join-Path $env:TEMP 'HolyChecker_last_check_dir.txt'),$pwdPath,[System.Text.Encoding]::UTF8)}catch{};try{Start-Process explorer.exe -ArgumentList $pwdPath}catch{})HCPS"
    ;

static const wchar_t* POWERSHELL_SITES_TXT = LR"HCSITES($sites="anticheat.ac","github.com","voidtools.com","privazer.com","nirsoft.net","download.ericzimmermanstools.com","win-rar.com","simpleunlocker.ds1nc.ru"; function Test-Site($u){ $r=@(); if(Select-String -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Pattern "(?mi)^\s*?\d.+?$($u.Replace('.','\.'))\s*$"){$r+="HOSTS"}; try{if((Resolve-DnsName $u -ErrorAction Stop -Type A|% IPAddress)-like'127.*'){$r+="DNS_LOOPBACK"}}catch{}; $regPath="HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($u.Replace('.','\\'))";if(Test-Path $regPath){$r+="REGISTRY_ZONE"}elseif(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$u"){$r+="REGISTRY_ZONE"}; if(Get-NetFirewallRule|?{$_.DisplayName-like"*$u*"-and$_.Action-eq"Block"}){$r+="FIREWALL"}; try{iwr "https://$u"-TimeoutSec 5 -UseBasicParsing -DisableKeepAlive -ErrorAction Stop|Out-Null}catch{if($_.Exception.Response.StatusCode-eq407){$r+="PROXY_BLOCK"}elseif(-not$_.Exception.Response){try{iwr "http://$u"-TimeoutSec 3 -UseBasicParsing -DisableKeepAlive -ErrorAction Stop|Out-Null}catch{$r+="WEB_BLOCKED"}}}; $tcp80=Test-NetConnection $u -Port 80 -WarningAction SilentlyContinue; $tcp443=Test-NetConnection $u -Port 443 -WarningAction SilentlyContinue; if(-not$tcp80.TcpTestSucceeded-and$u-ne'anticheat.ac'){$r+="PORT_80_BLOCKED"};if(-not$tcp443.TcpTestSucceeded-and$u-ne'anticheat.ac'){$r+="PORT_443_BLOCKED"}; if($r.Count-gt0){"$u → БЛОКИРОВКА: $($r-join', ')"}else{"$u → OK"}}; $sites|%{Test-Site $_}
)HCSITES";


static bool WriteUtf8TextFile(const std::wstring& path, const wchar_t* text)
{
    if (!text)
        return false;

    int size = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);

    if (size <= 1)
        return false;

    std::string utf8(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, &utf8[0], size, nullptr, nullptr);

    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file == INVALID_HANDLE_VALUE)
        return false;

    const BYTE bom[] = { 0xEF, 0xBB, 0xBF };
    DWORD written = 0;
    bool ok = WriteFile(file, bom, sizeof(bom), &written, nullptr) && written == sizeof(bom);

    if (ok)
    {
        written = 0;
        ok = WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size() - 1), &written, nullptr) &&
            written == static_cast<DWORD>(utf8.size() - 1);
    }

    CloseHandle(file);
    return ok;
}

static bool ItemNameEquals(const DownloadItem& item, const std::wstring& name)
{
    return ToLower(item.name) == ToLower(name);
}

static bool ReadFilePrefix(const std::wstring& path, std::vector<unsigned char>& out, DWORD maxBytes = 16)
{
    out.clear();

    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file == INVALID_HANDLE_VALUE)
        return false;

    out.resize(maxBytes);
    DWORD read = 0;
    bool ok = ReadFile(file, out.data(), maxBytes, &read, nullptr) != FALSE;
    CloseHandle(file);

    if (!ok || read == 0)
    {
        out.clear();
        return false;
    }

    out.resize(read);
    return true;
}

static bool StartsWithBytes(const std::vector<unsigned char>& data, std::initializer_list<unsigned char> bytes)
{
    if (data.size() < bytes.size())
        return false;

    size_t i = 0;
    for (unsigned char b : bytes)
    {
        if (data[i++] != b)
            return false;
    }

    return true;
}

static bool LooksLikeDownloadedHtml(const std::vector<unsigned char>& data)
{
    if (data.empty())
        return false;

    std::string head;
    for (unsigned char c : data)
    {
        if (c >= 32 && c <= 126)
            head.push_back(static_cast<char>(tolower(c)));
    }

    return head.find("html") != std::string::npos ||
        head.find("doctype") != std::string::npos ||
        head.find("<head") != std::string::npos ||
        head.find("<body") != std::string::npos;
}


static bool IsZipArchiveStructurallyValid(const std::wstring& path)
{
    unsigned long long totalSize = 0;
    if (!GetFileSizeBytes(path, totalSize) || totalSize < 22)
        return false;

    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file == INVALID_HANDLE_VALUE)
        return false;

    DWORD tailSize = static_cast<DWORD>(std::min<unsigned long long>(totalSize, 65557));
    LARGE_INTEGER offset{};
    offset.QuadPart = static_cast<LONGLONG>(totalSize - tailSize);

    if (!SetFilePointerEx(file, offset, nullptr, FILE_BEGIN))
    {
        CloseHandle(file);
        return false;
    }

    std::vector<unsigned char> tail(tailSize);
    DWORD read = 0;
    bool ok = ReadFile(file, tail.data(), tailSize, &read, nullptr) != FALSE;
    CloseHandle(file);

    if (!ok || read < 22)
        return false;

    tail.resize(read);

    for (size_t i = tail.size() - 22; i != static_cast<size_t>(-1); --i)
    {
        if (i + 4 <= tail.size() &&
            tail[i] == 0x50 && tail[i + 1] == 0x4B && tail[i + 2] == 0x05 && tail[i + 3] == 0x06)
        {
            return true;
        }

        if (i == 0)
            break;
    }

    for (size_t i = 0; i + 4 <= tail.size(); ++i)
    {
        if (tail[i] == 0x50 && tail[i + 1] == 0x4B &&
            ((tail[i + 2] == 0x06 && tail[i + 3] == 0x06) ||
             (tail[i + 2] == 0x06 && tail[i + 3] == 0x07)))
        {
            return true;
        }
    }

    return false;
}

static bool IsValidDownloadedPayload(const DownloadItem& item, const std::wstring& path)
{
    if (!FileExists(path))
        return false;

    LARGE_INTEGER size{};
    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file == INVALID_HANDLE_VALUE)
        return false;

    bool gotSize = GetFileSizeEx(file, &size) != FALSE;
    CloseHandle(file);

    if (!gotSize || size.QuadPart <= 0)
        return false;

    std::wstring fileLowerForSize = ToLower(item.file);

    if (EndsWithI(fileLowerForSize, L".exe"))
    {
        unsigned long long minExeSize = GetMinCompleteExeSizeForName(item.name);
        if (static_cast<unsigned long long>(size.QuadPart) < minExeSize)
            return false;
    }

    if ((EndsWithI(fileLowerForSize, L".zip") || EndsWithI(fileLowerForSize, L".jar")) && size.QuadPart < 22)
        return false;


    if (EndsWithI(fileLowerForSize, L".rar") && size.QuadPart < 7)
        return false;

    if (EndsWithI(fileLowerForSize, L".7z") && size.QuadPart < 6)
        return false;

    if (EndsWithI(fileLowerForSize, L".msi") && size.QuadPart < 512)
        return false;

    std::vector<unsigned char> head;
    if (!ReadFilePrefix(path, head, 32))
        return false;

    if (LooksLikeDownloadedHtml(head))
        return false;

    std::wstring fileLower = fileLowerForSize;

    if (EndsWithI(fileLower, L".exe"))
        return StartsWithBytes(head, { 0x4D, 0x5A });

    if (EndsWithI(fileLower, L".zip") || EndsWithI(fileLower, L".jar"))
        return StartsWithBytes(head, { 0x50, 0x4B }) && IsZipArchiveStructurallyValid(path);

    if (EndsWithI(fileLower, L".rar"))
        return StartsWithBytes(head, { 0x52, 0x61, 0x72, 0x21 });

    if (EndsWithI(fileLower, L".7z"))
        return StartsWithBytes(head, { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C });

    if (EndsWithI(fileLower, L".msi"))
        return StartsWithBytes(head, { 0xD0, 0xCF, 0x11, 0xE0 });

    return true;
}

static bool ValidateDownloadedFileOrDelete(const DownloadItem& item, const std::wstring& targetPath)
{
    bool valid = IsValidDownloadedPayload(item, targetPath);
    DebugLogLine(L"download", L"validate payload item=" + item.name + L" path=" + targetPath +
        L" valid=" + std::to_wstring(valid ? 1 : 0) +
        L" size=" + std::to_wstring(GetFileSizeBytesOrZero(targetPath)));
    if (valid)
        return true;

    DeleteFileW(targetPath.c_str());
    DeleteFileW((targetPath + L".part").c_str());
    MarkDownloadedPayloadInvalid();
    return false;
}

static bool DownloadRecursiveValidated(const DownloadItem& item, const std::wstring& url, const std::wstring& targetPath);
static bool DownloadCurlValidated(const DownloadItem& item, const std::wstring& url, const std::wstring& targetPath);
static bool DownloadPowerShellValidated(const DownloadItem& item, const std::wstring& url, const std::wstring& targetPath)
{
    if (!DownloadWithPowerShellFallback(
            url, targetPath, GetDirectDownloadTimeoutMs(item),
            0, 0, GetPowerShellNoProgressAbortMs(item), item.name, 1, 1))
        return false;

    return ValidateDownloadedFileOrDelete(item, targetPath);
}

static bool IsPrimaryUrlOnlyItem(const DownloadItem& item)
{
    return IsRegistryExplorerItem(item) || IsJumpListExplorerItem(item) || IsSimpleUnlockerItem(item);
}

static bool IsJournalTraceItem(const DownloadItem& item)
{
    std::wstring name = ToLower(item.name);
    return name.find(L"journaltrace") != std::wstring::npos ||
        (name.find(L"journal") != std::wstring::npos && name.find(L"trace") != std::wstring::npos);
}

static bool IsRecuvaItem(const DownloadItem& item)
{
    return ToLower(item.name).find(L"recuva") != std::wstring::npos;
}

static bool ShouldTryPowerShellBeforeCurl(const DownloadItem& item)
{
    return IsRegistryExplorerItem(item) ||
        IsJumpListExplorerItem(item) ||
        IsDetectItEasyItem(item) ||
        IsSimpleUnlockerItem(item) ||
        IsJournalTraceItem(item);
}

static DWORD GetPrimaryUrlOnlyTimeoutMs(const DownloadItem& item)
{
    if (IsRegistryExplorerItem(item) || IsJumpListExplorerItem(item))
        return 900000;

    if (IsSimpleUnlockerItem(item))
        return 300000;

    return GetDirectDownloadTimeoutMs(item);
}

static std::vector<std::wstring> GetDirectDownloadUrls(const DownloadItem& item)
{
    std::vector<std::wstring> urls;
    AddUniqueString(urls, item.url);

    std::wstring name = ToLower(item.name);

    if (IsSystemInformerItem(item))
    {
        AddUniqueString(urls, L"https://github.com/winsiderss/systeminformer/releases/download/v3.2.25011.2103/systeminformer-3.2.25011-release-setup.exe");
        AddUniqueString(urls, L"https://downloads.sourceforge.net/project/systeminformer/systeminformer-3.2.25011-release-setup.exe");
        AddUniqueString(urls, L"https://sourceforge.net/projects/systeminformer/files/systeminformer-3.2.25011-release-setup.exe/download");
        AddUniqueString(urls, L"https://systeminformer.sourceforge.io/canary/systeminformer-3.2.25011-setup.exe");
    }
    else if (IsWinRarItem(item))
    {
        AddUniqueString(urls, L"https://www.rarlab.com/rar/winrar-x64-722ru.exe");
        AddUniqueString(urls, L"https://www.rarlab.com/rar/winrar-x64-722.exe");
        AddUniqueString(urls, L"https://www.rarlab.com/rar/winrar-x64-721ru.exe");
        AddUniqueString(urls, L"https://www.rarlab.com/rar/winrar-x64-721.exe");
    }
    else if (IsSimpleUnlockerItem(item))
    {
        AddUniqueString(urls, L"https://simpleunlocker.ds1nc.ru/release/simpleunlocker_release.zip");
        AddUniqueString(urls, L"https://simpleunlocker.ds1nc.ru/release/simpleunlocker_release-u.zip");
    }
    else if (name.find(L"recuva") != std::wstring::npos)
    {
        AddUniqueString(urls, L"https://download.ccleaner.com/rcsetup155.exe");
    }
    else if (name == L"everything")
    {
        AddUniqueString(urls, L"https://www.voidtools.com/Everything-1.5.0.1404a.x64.zip");
    }

    return urls;
}


enum class DownloadMethodChoice
{
    PowerShell,
    Curl,
    WinHttp,
    WinInet,
    Bits
};

static const wchar_t* GetDownloadMethodDisplayName(DownloadMethodChoice method)
{
    switch (method)
    {
    case DownloadMethodChoice::PowerShell:
        return L"PowerShell";
    case DownloadMethodChoice::Curl:
        return L"curl";
    case DownloadMethodChoice::WinHttp:
        return L"WinHTTP";
    case DownloadMethodChoice::WinInet:
        return L"WinINet";
    case DownloadMethodChoice::Bits:
        return L"BITS";
    }

    return L"загрузка";
}

static bool DownloadWithWinHttpValidated(
    const DownloadItem& item,
    const std::wstring& url,
    const std::wstring& targetPath,
    size_t linkIndex,
    size_t linkTotal)
{
    if (IsCancelRequested())
        return false;

    ClearDownloadedPayloadInvalidFlag();
    ClearTransferStalledFlag();
    g_lastDownloadMethod.clear();
    g_lastDownloadSpeedBps = 0;

    DeleteFileW(targetPath.c_str());
    DeleteFileW((targetPath + L".part").c_str());

    UpdateActiveDownloadStatus(item.name, L"WinHTTP", linkIndex, linkTotal, 0, 0);

    if (DownloadRecursive(url, targetPath, item.name, 0) &&
        ValidateDownloadedFileOrDelete(item, targetPath))
    {
        g_lastDownloadMethod = L"WinHTTP";
        UpdateActiveDownloadStatus(item.name, L"готово WinHTTP", linkIndex, linkTotal, GetFileSizeBytesOrZero(targetPath), g_lastDownloadSpeedBps);
        return true;
    }

    DebugLogLine(L"download", L"WinHTTP validated failed item=" + item.name +
        L" stalled=" + std::to_wstring(DidLastTransferStall() ? 1 : 0) +
        L" invalidPayload=" + std::to_wstring(DidLastDownloadedPayloadInvalid() ? 1 : 0) +
        L" targetSize=" + std::to_wstring(GetFileSizeBytesOrZero(targetPath)) +
        L" partSize=" + std::to_wstring(GetFileSizeBytesOrZero(targetPath + L".part")));
    DeleteFileW(targetPath.c_str());
    DeleteFileW((targetPath + L".part").c_str());
    return false;
}

static bool DownloadWithBitsAdminFallback(
    const std::wstring& url,
    const std::wstring& targetPath,
    DWORD timeoutMs,
    const std::wstring& itemName,
    size_t linkIndex,
    size_t linkTotal)
{
    ClearTransferStalledFlag();

    if (IsCancelRequested())
        return false;

    std::wstring partPath = targetPath + L".part";
    DeleteFileW(partPath.c_str());

    std::wstring bitsExe = GetSystemToolPath(L"bitsadmin.exe");
    std::wstring jobName = L"HolyCheck_" + std::to_wstring(GetTickCount64()) + L"_" + std::to_wstring(linkIndex);

    std::wstring command =
        QuoteProcessArgument(bitsExe) +
        L" /transfer " + QuoteProcessArgument(jobName) +
        L" /download /priority FOREGROUND " +
        QuoteProcessArgument(url) + L" " + QuoteProcessArgument(partPath);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> cmd(command.begin(), command.end());
    cmd.push_back(L'\0');

    const wchar_t* appName = FileExists(bitsExe) ? bitsExe.c_str() : nullptr;

    if (!CreateProcessW(appName, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    {
        DebugLogLine(L"download", L"CreateProcess failed command=" + command + L" error=" + FormatWin32ErrorForLog(GetLastError()));
        return false;
    }

    UpdateActiveDownloadStatus(itemName, L"BITS", linkIndex, linkTotal, 0, 0);

    bool waited = WaitForProcessOrCancel(pi, timeoutMs);

    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    DebugLogLine(L"download", L"process exit command=" + command + L" exit=" + std::to_wstring(exitCode) +
        L" partSize=" + std::to_wstring(GetFileSizeBytesOrZero(partPath)));

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (!waited || exitCode != 0 || !FileExists(partPath) || IsCancelRequested())
    {
        DeleteFileW(partPath.c_str());
        return false;
    }

    DeleteFileW(targetPath.c_str());

    if (!MoveFileW(partPath.c_str(), targetPath.c_str()))
        return false;

    return true;
}

static bool DownloadBitsValidated(
    const DownloadItem& item,
    const std::wstring& url,
    const std::wstring& targetPath,
    DWORD timeoutMs,
    size_t linkIndex,
    size_t linkTotal)
{
    if (IsCancelRequested())
        return false;

    ClearDownloadedPayloadInvalidFlag();
    ClearTransferStalledFlag();
    g_lastDownloadMethod.clear();
    g_lastDownloadSpeedBps = 0;

    DeleteFileW(targetPath.c_str());
    DeleteFileW((targetPath + L".part").c_str());

    if (DownloadWithBitsAdminFallback(url, targetPath, timeoutMs, item.name, linkIndex, linkTotal) &&
        ValidateDownloadedFileOrDelete(item, targetPath))
    {
        g_lastDownloadMethod = L"BITS";
        UpdateActiveDownloadStatus(item.name, L"готово BITS", linkIndex, linkTotal, GetFileSizeBytesOrZero(targetPath), g_lastDownloadSpeedBps);
        return true;
    }

    DeleteFileW(targetPath.c_str());
    DeleteFileW((targetPath + L".part").c_str());
    return false;
}


static bool TryDirectDownloadCandidate(
    const DownloadItem& item,
    const std::wstring& url,
    const std::wstring& targetPath,
    DWORD timeoutMs,
    size_t linkIndex,
    size_t linkTotal,
    DownloadMethodChoice method,
    bool relaxedSpeedGuard = false)
{
    std::wstring methodName = GetDownloadMethodDisplayName(method);
    DebugLogLine(L"download", L"candidate start item=" + item.name +
        L" method=" + methodName + L" link=" + std::to_wstring(linkIndex) + L"/" + std::to_wstring(linkTotal) +
        L" timeout=" + std::to_wstring(timeoutMs) + L" relaxed=" + std::to_wstring(relaxedSpeedGuard ? 1 : 0) +
        L" target=" + targetPath + L" url=" + url);

    if (IsCancelRequested())
    {
        DebugLogLine(L"download", L"candidate cancelled before start item=" + item.name + L" method=" + methodName);
        return false;
    }

    ClearDownloadedPayloadInvalidFlag();
    ClearTransferStalledFlag();
    g_lastDownloadMethod.clear();
    g_lastDownloadSpeedBps = 0;
    DeleteFileW(targetPath.c_str());
    DeleteFileW((targetPath + L".part").c_str());

    bool githubUrl = IsGitHubUrl(url);
    bool ericLarge = IsEricZimmermanLargeItem(item) || IsEricZimmermanUrl(url);
    unsigned long long curlMinSpeed = relaxedSpeedGuard ? 0ull : GetMethodMinSpeedBps(item);
    DWORD curlLowSpeedWindowMs = relaxedSpeedGuard ? 0 : GetMethodLowSpeedWindowMs(item);
    DWORD curlNoProgressAbortMs = relaxedSpeedGuard ? 90000 : GetMethodNoProgressAbortMs(item);
    unsigned long long powerShellMinSpeed = relaxedSpeedGuard ? 0ull : GetPowerShellMinSpeedBps(item);
    DWORD powerShellLowSpeedWindowMs = relaxedSpeedGuard ? 0 : GetPowerShellLowSpeedWindowMs(item);
    DWORD powerShellNoProgressAbortMs = relaxedSpeedGuard ? 90000 : GetPowerShellNoProgressAbortMs(item);

    if (method == DownloadMethodChoice::WinHttp)
    {
        bool ok = DownloadWithWinHttpValidated(item, url, targetPath, linkIndex, linkTotal);
        DebugLogLine(L"download", L"candidate finish item=" + item.name + L" method=" + methodName +
            L" ok=" + std::to_wstring(ok ? 1 : 0) + L" stalled=" + std::to_wstring(DidLastTransferStall() ? 1 : 0) +
            L" invalidPayload=" + std::to_wstring(DidLastDownloadedPayloadInvalid() ? 1 : 0) +
            L" size=" + std::to_wstring(GetFileSizeBytesOrZero(targetPath)));
        return ok;
    }

    if (method == DownloadMethodChoice::WinInet)
    {
        UpdateActiveDownloadStatus(item.name, L"WinINet", linkIndex, linkTotal, 0, 0);

        if (DownloadWithWinInetFallback(
                url, targetPath, timeoutMs,
                relaxedSpeedGuard ? 0ull : GetMethodMinSpeedBps(item),
                relaxedSpeedGuard ? 0 : GetMethodLowSpeedWindowMs(item),
                relaxedSpeedGuard ? 90000 : GetMethodNoProgressAbortMs(item),
                item.name, linkIndex, linkTotal) &&
            ValidateDownloadedFileOrDelete(item, targetPath))
        {
            g_lastDownloadMethod = L"WinINet";
            UpdateActiveDownloadStatus(item.name, L"готово WinINet", linkIndex, linkTotal, GetFileSizeBytesOrZero(targetPath), g_lastDownloadSpeedBps);
            DebugLogLine(L"download", L"candidate success item=" + item.name + L" method=" + methodName + L" size=" + std::to_wstring(GetFileSizeBytesOrZero(targetPath)));
            return true;
        }
    }

    if (method == DownloadMethodChoice::Bits)
    {
        bool ok = DownloadBitsValidated(item, url, targetPath, timeoutMs, linkIndex, linkTotal);
        DebugLogLine(L"download", L"candidate finish item=" + item.name + L" method=" + methodName +
            L" ok=" + std::to_wstring(ok ? 1 : 0) + L" stalled=" + std::to_wstring(DidLastTransferStall() ? 1 : 0) +
            L" invalidPayload=" + std::to_wstring(DidLastDownloadedPayloadInvalid() ? 1 : 0) +
            L" size=" + std::to_wstring(GetFileSizeBytesOrZero(targetPath)));
        return ok;
    }

    if (method == DownloadMethodChoice::PowerShell)
    {
        UpdateActiveDownloadStatus(item.name, L"PowerShell", linkIndex, linkTotal, 0, 0);

        if (DownloadWithPowerShellFallback(
                url, targetPath, timeoutMs,
                powerShellMinSpeed,
                powerShellLowSpeedWindowMs,
                powerShellNoProgressAbortMs,
                item.name, linkIndex, linkTotal) &&
            ValidateDownloadedFileOrDelete(item, targetPath))
        {
            g_lastDownloadMethod = L"PowerShell";
            UpdateActiveDownloadStatus(item.name, L"готово PowerShell", linkIndex, linkTotal, GetFileSizeBytesOrZero(targetPath), g_lastDownloadSpeedBps);
            DebugLogLine(L"download", L"candidate success item=" + item.name + L" method=" + methodName + L" size=" + std::to_wstring(GetFileSizeBytesOrZero(targetPath)));
            return true;
        }
    }
    else
    {
        bool curlOk = false;
        UpdateActiveDownloadStatus(item.name, L"curl", linkIndex, linkTotal, 0, 0);

        if (githubUrl)
            curlOk = DownloadWithCurlGitHubFast(url, targetPath, timeoutMs, curlMinSpeed, curlLowSpeedWindowMs, curlNoProgressAbortMs, item.name, linkIndex, linkTotal);
        else if (ericLarge)
            curlOk = DownloadWithCurlBrowserLike(url, targetPath, timeoutMs, curlMinSpeed, curlLowSpeedWindowMs, curlNoProgressAbortMs, item.name, linkIndex, linkTotal);
        else
            curlOk = DownloadWithCurlFallback(url, targetPath, timeoutMs, curlMinSpeed, curlLowSpeedWindowMs, curlNoProgressAbortMs, item.name, linkIndex, linkTotal);

        if (curlOk && ValidateDownloadedFileOrDelete(item, targetPath))
        {
            g_lastDownloadMethod = L"curl";
            UpdateActiveDownloadStatus(item.name, L"готово curl", linkIndex, linkTotal, GetFileSizeBytesOrZero(targetPath), g_lastDownloadSpeedBps);
            DebugLogLine(L"download", L"candidate success item=" + item.name + L" method=" + methodName + L" size=" + std::to_wstring(GetFileSizeBytesOrZero(targetPath)));
            return true;
        }
    }

    DebugLogLine(L"download", L"candidate failed item=" + item.name + L" method=" + methodName +
        L" stalled=" + std::to_wstring(DidLastTransferStall() ? 1 : 0) +
        L" invalidPayload=" + std::to_wstring(DidLastDownloadedPayloadInvalid() ? 1 : 0) +
        L" targetSize=" + std::to_wstring(GetFileSizeBytesOrZero(targetPath)) +
        L" partSize=" + std::to_wstring(GetFileSizeBytesOrZero(targetPath + L".part")));
    DeleteFileW(targetPath.c_str());
    DeleteFileW((targetPath + L".part").c_str());
    return false;
}


static std::vector<DownloadMethodChoice> GetOptimizedProblemMethods(const DownloadItem& item, const std::wstring& url)
{
    std::vector<DownloadMethodChoice> methods;

    if (IsGitHubUrl(url) || IsSystemInformerItem(item) || IsProcessHackerItem(item) ||
        IsBamParserItem(item) || IsJournalTraceItem(item))
    {
        methods.push_back(DownloadMethodChoice::WinInet);
        methods.push_back(DownloadMethodChoice::Curl);
        methods.push_back(DownloadMethodChoice::PowerShell);
        methods.push_back(DownloadMethodChoice::WinHttp);
    }
    else if (IsEricZimmermanUrl(url) || IsRegistryExplorerItem(item) || IsJumpListExplorerItem(item) || IsSimpleUnlockerItem(item))
    {
        methods.push_back(DownloadMethodChoice::WinInet);
        methods.push_back(DownloadMethodChoice::PowerShell);
        methods.push_back(DownloadMethodChoice::Curl);
        methods.push_back(DownloadMethodChoice::WinHttp);
    }
    else if (ShouldTryPowerShellBeforeCurl(item))
    {
        methods.push_back(DownloadMethodChoice::Curl);
        methods.push_back(DownloadMethodChoice::WinInet);
        methods.push_back(DownloadMethodChoice::PowerShell);
        methods.push_back(DownloadMethodChoice::WinHttp);
    }
    else
    {
        methods.push_back(DownloadMethodChoice::Curl);
        methods.push_back(DownloadMethodChoice::WinInet);
        methods.push_back(DownloadMethodChoice::PowerShell);
        methods.push_back(DownloadMethodChoice::WinHttp);
    }

    std::vector<DownloadMethodChoice> uniqueMethods;
    for (DownloadMethodChoice method : methods)
    {
        if (std::find(uniqueMethods.begin(), uniqueMethods.end(), method) == uniqueMethods.end())
            uniqueMethods.push_back(method);
    }

    return uniqueMethods;
}

static bool DownloadPrimaryUrlOnlyValidated(const DownloadItem& item, const std::wstring& targetPath)
{
    if (IsCancelRequested())
        return false;

    DWORD timeoutMs = GetPrimaryUrlOnlyTimeoutMs(item);
    std::vector<std::wstring> urls = GetDirectDownloadUrls(item);
    DebugLogLine(L"download", L"direct download start item=" + item.name + L" target=" + targetPath +
        L" urls=" + std::to_wstring(urls.size()) + L" timeout=" + std::to_wstring(timeoutMs));

    auto tryOne = [&](size_t i, DownloadMethodChoice method, bool relaxedSpeedGuard = false) -> bool
    {
        if (IsCancelRequested())
            return false;

        return TryDirectDownloadCandidate(item, urls[i], targetPath, timeoutMs, i + 1, urls.size(), method, relaxedSpeedGuard);
    };

    if (IsProblemDownloadItem(item))
    {
        for (size_t i = 0; i < urls.size(); ++i)
        {
            std::vector<DownloadMethodChoice> methods = GetOptimizedProblemMethods(item, urls[i]);

            for (DownloadMethodChoice method : methods)
            {
                if (tryOne(i, method, false))
                    return true;

                if (IsCancelRequested())
                    return false;
            }
        }

        DebugLogLine(L"download", L"direct download failed item=" + item.name + L" all problem methods exhausted");
        return false;
    }

    auto tryAllLinksWithMethod = [&](DownloadMethodChoice method) -> bool
    {
        for (size_t i = 0; i < urls.size(); ++i)
        {
            if (IsCancelRequested())
                return false;

            if (tryOne(i, method, false))
                return true;
        }

        return false;
    };

    if (tryAllLinksWithMethod(DownloadMethodChoice::Curl))
        return true;

    if (tryAllLinksWithMethod(DownloadMethodChoice::WinInet))
        return true;

    bool ok = tryAllLinksWithMethod(DownloadMethodChoice::PowerShell);
    if (!ok)
        DebugLogLine(L"download", L"direct download failed item=" + item.name + L" all methods exhausted");
    return ok;
}

static void AddEricZimmermanKnownUrls(const DownloadItem& item, std::vector<std::wstring>& urls)
{
    AddUniqueString(urls, item.url);
}

static std::vector<std::wstring> GetEricZimmermanInstallUrls(const DownloadItem& item)
{
    std::vector<std::wstring> urls;
    AddEricZimmermanKnownUrls(item, urls);
    return urls;
}


static bool TryInstallDownloadUrl(const DownloadItem& item, const std::wstring& url, const std::wstring& targetPath, DWORD timeoutMs)
{
    if (IsCancelRequested())
        return false;

    ClearDownloadedPayloadInvalidFlag();
    ClearTransferStalledFlag();
    DeleteFileW(targetPath.c_str());
    DeleteFileW((targetPath + L".part").c_str());

    if (DownloadWithCurlBrowserLike(url, targetPath, timeoutMs,
            0, 0, 0, item.name, 1, 1) &&
        ValidateDownloadedFileOrDelete(item, targetPath))
    {
        return true;
    }

    DeleteFileW(targetPath.c_str());
    DeleteFileW((targetPath + L".part").c_str());
    return false;
}

static bool DownloadEricZimmermanLargeValidated(const DownloadItem& item, const std::wstring& targetPath)
{
    std::lock_guard<std::mutex> lock(g_ericDownloadMutex);

    const DWORD perUrlTimeoutMs = 900000;
    std::vector<std::wstring> urls = GetEricZimmermanInstallUrls(item);

    if (urls.empty())
    {
        PostLog(L"Eric: нет ссылок " + item.name);
        return false;
    }

    for (size_t i = 0; i < urls.size(); ++i)
    {
        if (IsCancelRequested())
            return false;

        PostLog(L"Eric " + std::to_wstring(i + 1) + L"/" + std::to_wstring(urls.size()) + L": " + item.name);

        if (TryInstallDownloadUrl(item, urls[i], targetPath, perUrlTimeoutMs))
            return true;
    }

    PostLog(L"Eric: установка не удалась " + item.name);
    return false;
}

