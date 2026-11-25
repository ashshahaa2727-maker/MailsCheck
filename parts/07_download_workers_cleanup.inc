static bool DeleteDirectoryTree(const std::wstring& folder);

static bool WaitForExtractedExe(const std::wstring& extractDir, std::wstring& exePath, DWORD timeoutMs = ZIP_EXTRACT_TIMEOUT_MS)
{
    ULONGLONG started = GetTickCount64();

    do
    {
        if (IsCancelRequested())
            return false;

        if (FindFirstExeRecursive(extractDir, exePath))
            return true;

        Sleep(ZIP_EXTRACT_POLL_MS);
    }
    while (GetTickCount64() - started < timeoutMs);

    return false;
}


static std::wstring GetExtractionMarkerPath(const std::wstring& extractDir)
{
    return CombinePath(extractDir, L".extract.ok");
}

static void RemoveExtractionMarker(const std::wstring& extractDir)
{
    DeleteFileW(GetExtractionMarkerPath(extractDir).c_str());
}

static bool WriteExtractionMarker(const std::wstring& extractDir)
{
    std::wstring marker = GetExtractionMarkerPath(extractDir);
    HANDLE file = CreateFileW(
        marker.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN,
        nullptr
    );

    if (file == INVALID_HANDLE_VALUE)
        return false;

    const char text[] = "ok\r\n";
    DWORD written = 0;
    bool ok = WriteFile(file, text, static_cast<DWORD>(sizeof(text) - 1), &written, nullptr) &&
        written == sizeof(text) - 1;
    CloseHandle(file);
    return ok;
}

static bool HasCompletedExtraction(const std::wstring& extractDir)
{
    return DirectoryExists(extractDir) && FileExists(GetExtractionMarkerPath(extractDir));
}



static bool ProcessItem(const DownloadItem& item, const std::wstring& baseFolder)
{
    DebugLogLine(L"download", L"process item start name=" + item.name + L" file=" + item.file +
        L" tab=" + std::to_wstring(item.tab) + L" base=" + baseFolder +
        L" url=" + item.url);

    if (IsCancelRequested())
    {
        DebugLogLine(L"download", L"process item cancelled before start name=" + item.name);
        return false;
    }

    std::wstring tabFolder = CombinePath(baseFolder, GetTabFolderName(item.tab));

    if (!EnsureDirectory(tabFolder))
    {
        DebugLogLine(L"download", L"process item failed ensure tab folder name=" + item.name + L" folder=" + tabFolder);
        return false;
    }

    std::wstring target = CombinePath(tabFolder, item.file);
    bool zipItem = EndsWithI(target, L".zip");
    bool hadFileBefore = FileExists(target);
    bool downloadedThisRun = false;

    DebugLogLine(L"download", L"process item target=" + target + L" hadFileBefore=" + std::to_wstring(hadFileBefore ? 1 : 0));
    if (hadFileBefore && !ValidateDownloadedFileOrDelete(item, target))
    {
        DebugLogLine(L"download", L"existing file validation failed name=" + item.name + L" target=" + target);
        hadFileBefore = false;
    }

    if (!hadFileBefore)
    {
        ReportDownloadCard(item, DownloadCardPhase::Downloading);
        AddActiveDownload(item.name);

        bool downloaded = DownloadPrimaryUrlOnlyValidated(item, target);

        RemoveActiveDownload(item.name);

        if (!downloaded)
        {
            DebugLogLine(L"download", L"download failed name=" + item.name + L" target=" + target);
            return false;
        }

        DebugLogLine(L"download", L"download ok name=" + item.name + L" target=" + target + L" size=" + std::to_wstring(GetFileSizeBytesOrZero(target)));
        downloadedThisRun = true;
    }

    if (IsCancelRequested())
    {
        DebugLogLine(L"download", L"process item cancelled after download name=" + item.name);
        return false;
    }

    if (zipItem)
    {
        std::wstring extractDir = CombinePath(tabFolder, RemoveExtension(item.file));
        std::wstring exePath;
        bool alreadyExtracted = false;

        if (!downloadedThisRun && HasCompletedExtraction(extractDir))
        {
            if (IsFtkImagerItem(item))
            {
                exePath = FindFtkImagerInstallerPath(item, baseFolder);
                alreadyExtracted = !exePath.empty() && FileExists(exePath);
            }
            else
            {
                alreadyExtracted = FindFirstExeRecursive(extractDir, exePath);
            }
        }

        if (!alreadyExtracted)
        {
            ReportDownloadCard(item, DownloadCardPhase::Extracting);
            RemoveExtractionMarker(extractDir);
            DeleteDirectoryTree(extractDir);
            EnsureDirectory(extractDir);

            DebugLogLine(L"download", L"extract start name=" + item.name + L" zip=" + target + L" dir=" + extractDir);
            if (!ExtractZip(target, extractDir))
            {
                DebugLogLine(L"download", L"extract failed name=" + item.name + L" zip=" + target + L" dir=" + extractDir);
                return false;
            }

            if (!WaitForExtractedExe(extractDir, exePath))
            {
                DebugLogLine(L"download", L"extract exe wait failed name=" + item.name + L" dir=" + extractDir);
                return false;
            }
            DebugLogLine(L"download", L"extract ok name=" + item.name + L" exe=" + exePath);

            WriteExtractionMarker(extractDir);
        }
    }

    {
        bool ok = FileExists(target) && !IsCancelRequested();
        DebugLogLine(L"download", L"process item finish name=" + item.name + L" ok=" + std::to_wstring(ok ? 1 : 0) +
            L" target=" + target + L" size=" + std::to_wstring(GetFileSizeBytesOrZero(target)));
        return ok;
    }
}


static void PostDownloadSummaryLine(const std::wstring& prefix, const std::vector<std::wstring>& names)
{
    if (names.empty())
    {
        PostLog(prefix + L"нет");
        return;
    }

    const size_t maxLineLen = 150;
    std::wstring line = prefix;

    for (const auto& name : names)
    {
        std::wstring part = name;

        if (line.size() > prefix.size())
            part = L", " + part;

        if (line.size() + part.size() > maxLineLen && line.size() > prefix.size())
        {
            PostLog(line);
            line = prefix + name;
        }
        else
        {
            line += part;
        }
    }

    if (line.size() > prefix.size())
        PostLog(line);
}

static void PostDownloadSummary(const std::vector<std::wstring>& downloaded, const std::vector<std::wstring>& failed)
{
    PostLog(L"Сохранено программ: " + std::to_wstring(downloaded.size()));
    if (!failed.empty())
        PostDownloadSummaryLine(L"Не удалось сохранить: ", failed);
}


static unsigned long long GetEstimatedDownloadOrderBytes(const DownloadItem& item)
{
    std::wstring name = ToLower(item.name);
    std::wstring file = ToLower(item.file);
    std::wstring url = ToLower(item.url);

    if (name.find(L"recentfilesview") != std::wstring::npos) return 90ull * 1024ull;
    if (name.find(L"lastactivityview") != std::wstring::npos) return 120ull * 1024ull;
    if (name.find(L"executedprogramslist") != std::wstring::npos) return 120ull * 1024ull;
    if (name.find(L"browserdownloadsview") != std::wstring::npos) return 200ull * 1024ull;
    if (name.find(L"browsinghistoryview") != std::wstring::npos) return 220ull * 1024ull;
    if (name.find(L"regscanner") != std::wstring::npos) return 250ull * 1024ull;
    if (name.find(L"winprefetchview") != std::wstring::npos) return 350ull * 1024ull;
    if (name.find(L"alternatestreamview") != std::wstring::npos) return 450ull * 1024ull;
    if (name.find(L"windeflogview") != std::wstring::npos) return 500ull * 1024ull;
    if (name.find(L"everything") != std::wstring::npos) return 6ull * 1024ull * 1024ull;
    if (name.find(L"recuva") != std::wstring::npos) return 25ull * 1024ull * 1024ull;
    if (name.find(L"detect") != std::wstring::npos) return 30ull * 1024ull * 1024ull;
    if (name.find(L"winrar") != std::wstring::npos) return 4ull * 1024ull * 1024ull;
    if (name.find(L"systeminformer") != std::wstring::npos) return 20ull * 1024ull * 1024ull;
    if (name.find(L"processhacker") != std::wstring::npos) return 4ull * 1024ull * 1024ull;
    if (name.find(L"registryexplorer") != std::wstring::npos) return 75ull * 1024ull * 1024ull;
    if (name.find(L"jumplistexplorer") != std::wstring::npos) return 70ull * 1024ull * 1024ull;
    if (name.find(L"volatility") != std::wstring::npos) return 80ull * 1024ull * 1024ull;
    if (name.find(L"simpleunlocker") != std::wstring::npos) return 20ull * 1024ull * 1024ull;

    if (EndsWithI(file, L".zip")) return 2ull * 1024ull * 1024ull;
    if (EndsWithI(file, L".exe")) return 8ull * 1024ull * 1024ull;
    if (EndsWithI(file, L".msi")) return 12ull * 1024ull * 1024ull;

    return 1024ull * 1024ull;
}

static void DownloadWorker(std::vector<DownloadItem> items)
{
    DebugLogSeparator(L"download batch worker start");
    DebugLogLine(L"download", L"worker start items=" + std::to_wstring(items.size()));
    g_working = true;

    std::stable_sort(items.begin(), items.end(), [](const DownloadItem& a, const DownloadItem& b)
    {
        unsigned long long as = GetEstimatedDownloadOrderBytes(a);
        unsigned long long bs = GetEstimatedDownloadOrderBytes(b);

        if (as != bs)
            return as < bs;

        if (a.tab != b.tab)
            return a.tab < b.tab;

        return ToLower(a.name) < ToLower(b.name);
    });

    std::wstring folder = GetHolyCheckFolder();

    if (!EnsureDirectory(folder))
    {
        DebugLogLine(L"download", L"worker failed ensure holycheck folder=" + folder);
        PostLog(L"Не создана папка holycheck");
        PostProgress(0);

        if (g_hMain && !g_destroying.load())
            PostMessageW(g_hMain, WM_APP_DONE, 0, 0);
        else
            g_working = false;

        return;
    }

    for (const auto& item : items)
    {
        if (!EnsureDirectory(CombinePath(folder, GetTabFolderName(item.tab))))
            PostLog(L"Не создана папка: " + GetTabFolderName(item.tab));
    }

    int done = 0;
    std::mutex resultMutex;
    std::vector<std::wstring> downloadedItems;
    std::vector<std::wstring> failedItems;

    int totalOriginal = static_cast<int>(items.size());

    auto runDownloadBatch = [&](const std::vector<DownloadItem>& batch)
    {
        if (batch.empty() || IsCancelRequested())
            return;

        std::atomic<int> batchIndex = 0;
        int remaining = static_cast<int>(batch.size());
        int workers = static_cast<int>(std::thread::hardware_concurrency());

        if (workers < 4) workers = 4;
        if (workers > 8) workers = 8;

        if (workers > remaining) workers = remaining;
        if (workers < 1) workers = remaining > 0 ? 1 : 0;

        std::vector<std::thread> threads;

        for (int i = 0; i < workers; ++i)
        {
            threads.emplace_back([&]()
            {
                for (;;)
                {
                    int n = batchIndex.fetch_add(1);

                    if (n >= remaining || IsCancelRequested())
                        break;

                    bool ok = ProcessItem(batch[n], folder);
                    ReportDownloadCard(batch[n], IsCancelRequested() ? DownloadCardPhase::Cancelled :
                        (ok ? DownloadCardPhase::Ready : DownloadCardPhase::Error));

                    {
                        std::lock_guard<std::mutex> resultLock(resultMutex);

                        if (ok)
                            downloadedItems.push_back(batch[n].name);
                        else
                            failedItems.push_back(batch[n].name);
                        ++done;
                        PostProgress(done * 100 / totalOriginal);
                    }
                }
            });
        }

        for (auto& t : threads)
        {
            if (t.joinable())
                t.join();
        }
    };

    runDownloadBatch(items);

    DebugLogLine(L"download", L"worker downloads done downloaded=" + std::to_wstring(downloadedItems.size()) +
        L" failed=" + std::to_wstring(failedItems.size()) + L" cancelled=" + std::to_wstring(IsCancelRequested() ? 1 : 0));

    ClearActiveDownloads();
    InvalidateBottomPanel();

    if (!IsCancelRequested())
        PostDownloadSummary(downloadedItems, failedItems);

    if (IsCancelRequested())
    {
        PostProgress(0);
    }
    else
    {
        PostProgress(100);
    }

    HWND hwnd = g_hMain;

    if (hwnd && !g_destroying.load())
        PostMessageW(hwnd, WM_APP_DONE, 0, 0);
    else
        g_working = false;
}

static void SetDownloadControlsEnabled(bool enabled)
{
    if (g_hDownloadAll)
    {
        EnableWindow(g_hDownloadAll, enabled ? TRUE : FALSE);
        InvalidateRect(g_hDownloadAll, nullptr, FALSE);
    }


    if (g_hDeleteHolyCheck)
    {
        EnableWindow(g_hDeleteHolyCheck, enabled ? TRUE : FALSE);
        InvalidateRect(g_hDeleteHolyCheck, nullptr, FALSE);
    }

    if (g_hCancelDownload)
        InvalidateRect(g_hCancelDownload, nullptr, FALSE);

    for (HWND button : g_tileButtons)
    {
        EnableWindow(button, enabled ? TRUE : FALSE);
        InvalidateRect(button, nullptr, FALSE);
    }
}

static void StartDownload(const std::vector<DownloadItem>& items)
{
    DebugLogLine(L"download", L"start download request items=" + std::to_wstring(items.size()) + L" working=" + std::to_wstring(g_working.load() ? 1 : 0));
    if (items.empty())
        return;

    if (g_working)
        return;

    if (g_activeSingleDownloads.load() > 0)
    {
        PostLog(L"Сейчас идут одиночные загрузки");
        return;
    }

    g_cancelRequested = false;
    AbortActiveHttpHandles();
    g_working = true;
    BeginDownloadPresentation(items, true, true);
    SetDownloadControlsEnabled(false);
    g_progressPercent = 0;
    ClearDownloadLog();
    ClearActiveDownloads();
    InvalidateBottomPanel();

    std::thread(DownloadWorker, items).detach();
}

static void DownloadSingleWorker(int itemIndex, DownloadItem item)
{
    DebugLogSeparator(L"single download worker start");
    DebugLogLine(L"download", L"single worker start index=" + std::to_wstring(itemIndex) + L" item=" + item.name);
    bool processed = ProcessItem(item, GetHolyCheckFolder());
    RemoveActiveDownload(item.name);
    ReportDownloadCard(item, IsCancelRequested() ? DownloadCardPhase::Cancelled :
        (processed ? DownloadCardPhase::Ready : DownloadCardPhase::Error));
    if (processed && !IsCancelRequested())
        PostLog(L"Сохранено: " + item.name);
    else if (IsCancelRequested())
    {
        PostLog(L"Отменено: " + item.name);
    }
    else
    {
        PostLog(L"Не удалось: " + item.name);
    }

    if (g_hMain && !g_destroying.load())
        PostMessageW(g_hMain, WM_APP_ITEM_DONE, static_cast<WPARAM>(itemIndex), 0);
}

static void DownloadSingleById(int id)
{
    DebugLogLine(L"download", L"single request id=" + std::to_wstring(id));
    int index = id - IDC_TILE_BASE;

    if (index < 0 || index >= static_cast<int>(g_items.size()))
        return;

    if (g_working || IsCancelRequested() || IsItemBusyIndex(index))
        return;

    const DownloadItem& item = g_items[index];

    int previousActive = g_activeSingleDownloads.fetch_add(1);

    if (previousActive == 0)
    {
        g_cancelRequested = false;
        AbortActiveHttpHandles();
        g_singleTotal = 0;
        g_singleDone = 0;
        g_progressPercent = 0;
        ClearDownloadLog();
        ClearActiveDownloads();
    }

    BeginDownloadPresentation({ item }, false, previousActive == 0);
    ++g_singleTotal;

    SetItemBusyIndex(index, true);
    SetTileEnabledByIndex(index, false);

    AddActiveDownload(item.name);
    UpdateActiveDownloadStatus(item.name, L"старт", 1, 1, 0, 0);
    g_progressPercent = g_singleDone * 100 / g_singleTotal;
    InvalidateBottomPanel();

    std::thread(DownloadSingleWorker, index, item).detach();
}

static void CloseProcessesFromFolder(const std::wstring& folder);

static bool DeleteFileOrFolderPermanent(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());

    if (attr == INVALID_FILE_ATTRIBUTES)
        return true;

    if (attr & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
    {
        DWORD cleanAttr = attr & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

        if (cleanAttr == 0)
            cleanAttr = FILE_ATTRIBUTE_NORMAL;

        SetFileAttributesW(path.c_str(), cleanAttr);
    }

    if (!(attr & FILE_ATTRIBUTE_DIRECTORY))
        return DeleteFileW(path.c_str()) || GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES;

    std::wstring mask = CombinePath(path, L"*");

    WIN32_FIND_DATAW data{};
    HANDLE hFind = FindFirstFileW(mask.c_str(), &data);

    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
                continue;

            DeleteFileOrFolderPermanent(CombinePath(path, data.cFileName));
        }
        while (FindNextFileW(hFind, &data));

        FindClose(hFind);
    }

    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
    return RemoveDirectoryW(path.c_str()) || GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES;
}

static bool DeleteDirectoryTree(const std::wstring& folder)
{
    if (!IsSafeHolyCheckDeletionTarget(folder))
    {
        PostLog(L"Небезопасный путь удаления");
        return false;
    }

    if (!DirectoryExists(folder))
        return true;

    for (int attempt = 0; attempt < 6; ++attempt)
    {
        CloseProcessesFromFolder(folder);

        if (DeleteFileOrFolderPermanent(folder))
            return true;

        Sleep(120);
    }

    return !DirectoryExists(folder);
}

static bool RegistryGetString(HKEY key, const wchar_t* valueName, std::wstring& out)
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

        if (ExpandEnvironmentStringsW(value.c_str(), expanded, ARRAYSIZE(expanded)) > 0)
            value = expanded;
    }

    out = value;
    return !out.empty();
}

static bool RunElevatedCommandAndWait(const std::wstring& command)
{
    if (command.empty())
        return false;

    std::wstring params = L"/c " + command;

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = L"cmd.exe";
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei))
        return false;

    bool ok = true;

    if (sei.hProcess)
    {
        DWORD waitResult = WaitForSingleObject(sei.hProcess, 60000);
        DWORD exitCode = 1;

        if (waitResult != WAIT_OBJECT_0 || !GetExitCodeProcess(sei.hProcess, &exitCode) || exitCode != 0)
            ok = false;

        CloseHandle(sei.hProcess);
    }

    return ok;
}

static std::wstring MakeUninstallCommand(std::wstring command, bool addNsisSilent)
{
    std::wstring lower = ToLower(command);

    if (lower.find(L"msiexec") != std::wstring::npos)
    {
        size_t pos = lower.find(L"/i");

        if (pos != std::wstring::npos)
            command.replace(pos, 2, L"/X");

        pos = ToLower(command).find(L"-i");

        if (pos != std::wstring::npos)
            command.replace(pos, 2, L"/X");

        if (ToLower(command).find(L"/qn") == std::wstring::npos)
            command += L" /qn";

        if (ToLower(command).find(L"/norestart") == std::wstring::npos)
            command += L" /norestart";
    }
    else if (addNsisSilent)
    {
        std::wstring updatedLower = ToLower(command);

        if (updatedLower.find(L" /s") == std::wstring::npos &&
            updatedLower.find(L" -s") == std::wstring::npos &&
            updatedLower.find(L"/silent") == std::wstring::npos &&
            updatedLower.find(L"/verysilent") == std::wstring::npos &&
            updatedLower.find(L"/quiet") == std::wstring::npos)
        {
            // /S — NSIS, /VERYSILENT /SUPPRESSMSGBOXES — Inno Setup.
            // Вместе они гасят и окно удаления, и подтверждающие диалоги.
            command += L" /S /VERYSILENT /SUPPRESSMSGBOXES /NORESTART";
        }
    }

    return command;
}

static bool DisplayNameMatchesAny(const std::wstring& displayName, const std::vector<std::wstring>& needles)
{
    std::wstring lowerName = ToLower(displayName);

    for (const auto& needle : needles)
    {
        if (lowerName.find(ToLower(needle)) != std::wstring::npos)
            return true;
    }

    return false;
}

static bool FindUninstallCommandInRoot(
    HKEY root,
    REGSAM viewFlags,
    const std::vector<std::wstring>& displayNameNeedles,
    bool addNsisSilent,
    std::wstring& out)
{
    const wchar_t* uninstallPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

    HKEY hUninstall = nullptr;

    if (RegOpenKeyExW(root, uninstallPath, 0, KEY_READ | viewFlags, &hUninstall) != ERROR_SUCCESS)
        return false;

    bool found = false;

    for (DWORD i = 0; !found; ++i)
    {
        wchar_t subKeyName[512]{};
        DWORD subKeyLen = ARRAYSIZE(subKeyName);

        if (RegEnumKeyExW(hUninstall, i, subKeyName, &subKeyLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        HKEY hApp = nullptr;

        if (RegOpenKeyExW(hUninstall, subKeyName, 0, KEY_READ | viewFlags, &hApp) != ERROR_SUCCESS)
            continue;

        std::wstring displayName;

        if (RegistryGetString(hApp, L"DisplayName", displayName) &&
            DisplayNameMatchesAny(displayName, displayNameNeedles))
        {
            std::wstring quietUninstall;
            std::wstring uninstall;

            if (RegistryGetString(hApp, L"QuietUninstallString", quietUninstall))
                out = MakeUninstallCommand(quietUninstall, addNsisSilent);
            else if (RegistryGetString(hApp, L"UninstallString", uninstall))
                out = MakeUninstallCommand(uninstall, addNsisSilent);

            found = !out.empty();
        }

        RegCloseKey(hApp);
    }

    RegCloseKey(hUninstall);
    return found;
}

static bool FindUninstallCommand(
    const std::vector<std::wstring>& displayNameNeedles,
    bool addNsisSilent,
    std::wstring& out)
{
    return
        FindUninstallCommandInRoot(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, displayNameNeedles, addNsisSilent, out) ||
        FindUninstallCommandInRoot(HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, displayNameNeedles, addNsisSilent, out) ||
        FindUninstallCommandInRoot(HKEY_CURRENT_USER, 0, displayNameNeedles, addNsisSilent, out);
}

static void SplitCommandLineExeAndArgs(const std::wstring& command, std::wstring& exe, std::wstring& args);

static bool UninstallProgramIfPresent(
    const std::wstring& logName,
    const std::vector<std::wstring>& displayNameNeedles,
    bool addNsisSilent)
{
    std::wstring command;

    if (!FindUninstallCommand(displayNameNeedles, addNsisSilent, command))
    {
        PostLog(logName + L": не установлен");
        return true;
    }

    PostLog(logName + L": удаление");

    // Execute the registered uninstaller directly. The old implementation
    // wrapped every uninstall command in cmd.exe /c, which could leave a
    // console/conhost process behind after FTK removal. MSI and normal EXE
    // uninstallers can be launched directly with their registered arguments.
    std::wstring exe;
    std::wstring args;
    SplitCommandLineExeAndArgs(command, exe, args);
    if (exe.empty())
    {
        PostLog(logName + L": ошибка удаления");
        return false;
    }

    HANDLE process = nullptr;
    DWORD pid = 0;
    if (!StartElevatedProcessHidden(exe, args, process, pid))
    {
        PostLog(logName + L": ошибка удаления");
        return false;
    }

    bool ok = true;
    if (process)
    {
        DWORD waitResult = WaitForSingleObject(process, 120000);
        DWORD exitCode = 1;
        if (waitResult != WAIT_OBJECT_0 || !GetExitCodeProcess(process, &exitCode) ||
            (exitCode != ERROR_SUCCESS && exitCode != 3010 && exitCode != 1641))
            ok = false;
        CloseHandle(process);
    }

    PostLog(ok ? logName + L": команда выполнена" : logName + L": ошибка удаления");
    return ok;
}

static void SplitCommandLineExeAndArgs(const std::wstring& command, std::wstring& exe, std::wstring& args)
{
    exe.clear();
    args.clear();

    size_t start = command.find_first_not_of(L" \t");

    if (start == std::wstring::npos)
        return;

    if (command[start] == L'"')
    {
        size_t end = command.find(L'"', start + 1);

        if (end == std::wstring::npos)
        {
            exe = command.substr(start + 1);
            return;
        }

        exe = command.substr(start + 1, end - start - 1);
        start = end + 1;
    }
    else
    {
        size_t end = command.find(L' ', start);

        if (end == std::wstring::npos)
        {
            exe = command.substr(start);
            return;
        }

        exe = command.substr(start, end - start);
        start = end;
    }

    size_t argsStart = command.find_first_not_of(L" \t", start);

    if (argsStart != std::wstring::npos)
        args = command.substr(argsStart);
}

static bool UninstallSystemInformerIfPresent()
{
    std::wstring command;

    // addNsisSilent=false: this uninstaller ignores /S and /VERYSILENT and still
    // shows the confirmation dialog, so the wizard is clicked through instead.
    if (!FindUninstallCommand({ L"system informer", L"systeminformer" }, false, command))
    {
        PostLog(L"SystemInformer: \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d");
        return true;
    }

    std::wstring exe;
    std::wstring args;
    SplitCommandLineExeAndArgs(command, exe, args);

    if (exe.empty())
    {
        PostLog(L"SystemInformer: \u043e\u0448\u0438\u0431\u043a\u0430 \u0443\u0434\u0430\u043b\u0435\u043d\u0438\u044f");
        return false;
    }

    PostLog(L"SystemInformer: \u0443\u0434\u0430\u043b\u0435\u043d\u0438\u0435");

    HANDLE process = nullptr;
    DWORD pid = 0;

    if (!StartElevatedProcessHidden(exe, args, process, pid))
    {
        PostLog(L"SystemInformer: \u043e\u0448\u0438\u0431\u043a\u0430 \u0443\u0434\u0430\u043b\u0435\u043d\u0438\u044f");
        return false;
    }

    bool ok = DriveSystemInformerUninstallWizard(pid, 60000);

    if (process)
    {
        WaitForSingleObject(process, ok ? 10000 : 0);
        CloseHandle(process);
    }

    PostLog(ok
        ? L"SystemInformer: \u0443\u0434\u0430\u043b\u0451\u043d"
        : L"SystemInformer: \u043e\u0448\u0438\u0431\u043a\u0430 \u0443\u0434\u0430\u043b\u0435\u043d\u0438\u044f");
    return ok;
}

static void CloseProcessesByName(const std::vector<std::wstring>& processNames);

static bool UninstallRecuvaIfPresent()
{
    // Close the installed copy first; otherwise the silent uninstaller can
    // leave locked files behind. The actual uninstall runs hidden in the
    // already detached delete worker.
    CloseProcessesByName({ L"recuva.exe", L"recuva64.exe" });

    return UninstallProgramIfPresent(
        L"Recuva",
        { L"recuva", L"piriform recuva", L"ccleaner recuva" },
        true);
}

static bool UninstallFtkImagerIfPresent()
{
    // FTK may keep evidence handles/drivers open while the GUI is running.
    // Close the GUI first, then use the registered uninstall command (usually
    // MSI, converted by MakeUninstallCommand to /X /qn /norestart).
    CloseProcessesByName({ L"FTK Imager.exe", L"Exterro_FTK_Imager_(x64).exe" });
    Sleep(200);

    std::wstring installExe = FindInstalledFtkImagerPath(false);
    std::wstring installDir = GetLaunchWorkingDirectory(installExe);

    bool ok = UninstallProgramIfPresent(
        L"FTK Imager",
        { L"exterro ftk imager", L"accessdata ftk imager", L"ftk imager" },
        false);

    // MSI normally removes everything. Clean a leftover product directory only
    // when its path itself contains "FTK Imager"; never delete AccessData or
    // Exterro parent folders that may contain other forensic tools.
    if (ok && !installDir.empty())
    {
        std::wstring lower = ToLower(installDir);
        if (lower.find(L"ftk imager") != std::wstring::npos && DirectoryExists(installDir))
        {
            // HolyCheck is already elevated. Remove the leftover product folder
            // directly instead of spawning cmd.exe /c rmdir; this avoids a
            // console process/window being left behind at the end of deletion.
            CloseProcessesFromFolder(installDir);
            DeleteDirectoryTree(installDir);
        }
    }

    return ok;
}

static bool IsPathInsideFolder(const std::wstring& path, const std::wstring& folder)
{
    std::wstring p = ToLower(path);
    std::wstring f = ToLower(folder);

    while (!f.empty() && (f.back() == L'\\' || f.back() == L'/'))
        f.pop_back();

    if (p.size() <= f.size())
        return false;

    if (p.compare(0, f.size(), f) != 0)
        return false;

    return p[f.size()] == L'\\' || p[f.size()] == L'/';
}


static bool IsProcessNameEqual(const wchar_t* processName, const wchar_t* wantedName)
{
    if (!processName || !wantedName)
        return false;
    return _wcsicmp(processName, wantedName) == 0;
}

static void TerminateAndWaitHandles(std::vector<HANDLE>& handles, DWORD timeoutMs)
{
    if (handles.empty())
        return;

    // Wait on the whole batch at once (chunked to the API limit) instead of
    // blocking on each process one after another. TerminateProcess was already
    // issued for every handle, so this only waits for the kernel to finish.
    size_t offset = 0;
    while (offset < handles.size())
    {
        DWORD count = static_cast<DWORD>(
            (std::min<size_t>)(MAXIMUM_WAIT_OBJECTS, handles.size() - offset));
        WaitForMultipleObjects(count, handles.data() + offset, TRUE, timeoutMs);
        offset += count;
    }

    for (HANDLE h : handles)
        CloseHandle(h);

    handles.clear();
}

static void CloseProcessesByName(const std::vector<std::wstring>& names)
{
    if (names.empty())
        return;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return;

    DWORD currentPid = GetCurrentProcessId();
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    std::vector<HANDLE> killed;

    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            if (pe.th32ProcessID == currentPid)
                continue;

            bool matched = false;
            for (const std::wstring& name : names)
            {
                if (IsProcessNameEqual(pe.szExeFile, name.c_str()))
                {
                    matched = true;
                    break;
                }
            }

            if (!matched)
                continue;

            HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
            if (!process)
                continue;

            PostLog(L"Закрывается: " + std::wstring(pe.szExeFile));
            TerminateProcess(process, 0);
            killed.push_back(process);
        }
        while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);

    // Every process was signalled to die already; wait for the whole set once.
    TerminateAndWaitHandles(killed, 1500);
}

static void CloseProcessesFromFolder(const std::wstring& folder)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE)
        return;

    DWORD currentPid = GetCurrentProcessId();
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    std::vector<HANDLE> killed;

    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            if (pe.th32ProcessID == currentPid)
                continue;

            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pe.th32ProcessID);

            if (!process)
                continue;

            wchar_t imagePath[MAX_PATH * 4]{};
            DWORD size = ARRAYSIZE(imagePath);

            bool killedThis = false;

            if (QueryFullProcessImageNameW(process, 0, imagePath, &size))
            {
                if (IsPathInsideFolder(imagePath, folder))
                {
                    PostLog(L"Закрывается: " + std::wstring(pe.szExeFile));
                    TerminateProcess(process, 0);
                    killed.push_back(process);
                    killedThis = true;
                }
            }

            if (!killedThis)
                CloseHandle(process);
        }
        while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);

    // Wait for the whole batch of folder processes to exit in one shot.
    TerminateAndWaitHandles(killed, 1500);
}


static std::wstring GetHolyCheckerLastCheckDirMarkerPath()
{
    wchar_t tempPath[MAX_PATH * 4]{};
    DWORD len = GetTempPathW(ARRAYSIZE(tempPath), tempPath);

    if (len == 0 || len >= ARRAYSIZE(tempPath))
        return L"";

    return CombinePath(tempPath, L"HolyChecker_last_check_dir.txt");
}

static std::wstring TrimText(std::wstring text)
{
    while (!text.empty() && (text.front() == static_cast<wchar_t>(0xFEFF) || iswspace(text.front())))
        text.erase(text.begin());

    while (!text.empty() && iswspace(text.back()))
        text.pop_back();

    return text;
}

static std::wstring ReadSmallUtf8TextFile(const std::wstring& path)
{
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (file == INVALID_HANDLE_VALUE)
        return L"";

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 32768)
    {
        CloseHandle(file);
        return L"";
    }

    std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    BOOL ok = ReadFile(file, &bytes[0], static_cast<DWORD>(bytes.size()), &read, nullptr);
    CloseHandle(file);

    if (!ok || read == 0)
        return L"";

    bytes.resize(read);

    int wideLen = MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (wideLen <= 0)
        return L"";

    std::wstring text(wideLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), &text[0], wideLen);
    return TrimText(text);
}

static bool IsSafeCheckOutputFolder(const std::wstring& folder)
{
    if (folder.empty() || !DirectoryExists(folder))
        return false;

    std::wstring profile = GetCurrentUserProfilePath();
    std::wstring holyCheck = GetHolyCheckFolderPathOnly();

    if (!profile.empty() && IsPathUnderFolder(folder, profile))
        return true;

    if (!holyCheck.empty() && IsPathUnderFolder(folder, holyCheck))
        return true;

    if (IsPathUnderFolder(folder, L"C:\\PulseVisuals\\game"))
        return true;

    return false;
}

static void DeleteCheckOutputFilesInFolder(const std::wstring& folder, int& deletedCount)
{
    if (!IsSafeCheckOutputFolder(folder))
        return;

    const wchar_t* names[] = { L"check.txt", L"checktwinks.txt" };

    for (const wchar_t* name : names)
    {
        std::wstring path = CombinePath(folder, name);
        if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
            continue;

        if (DeleteFileOrFolderPermanent(path))
            ++deletedCount;
    }
}

// check.txt / checktwinks.txt are written into the working directory of every
// scanned game folder, so under .lunarclient they end up spread across many
// profile subfolders. Walk the tree (bounded depth) and delete them all.
static void DeleteCheckOutputFilesRecursive(const std::wstring& folder, int depth, int& deletedCount)
{
    if (depth < 0 || !DirectoryExists(folder))
        return;

    DeleteCheckOutputFilesInFolder(folder, deletedCount);

    WIN32_FIND_DATAW data = {};
    std::wstring mask = CombinePath(folder, L"*");
    HANDLE hFind = FindFirstFileW(mask.c_str(), &data);

    if (hFind == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;

        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
            continue;

        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;

        DeleteCheckOutputFilesRecursive(CombinePath(folder, data.cFileName), depth - 1, deletedCount);
    }
    while (FindNextFileW(hFind, &data));

    FindClose(hFind);
}

static void DeletePowerShellCheckOutputFiles()
{
    std::vector<std::wstring> folders;

    std::wstring marker = GetHolyCheckerLastCheckDirMarkerPath();
    if (!marker.empty())
    {
        std::wstring lastFolder = ReadSmallUtf8TextFile(marker);
        if (!lastFolder.empty())
            AddUniquePath(folders, lastFolder);
    }

    AddUniquePath(folders, GetHolyCheckFolderPathOnly());

    std::wstring profile = GetCurrentUserProfilePath();
    if (!profile.empty())
    {
        AddUniquePath(folders, CombinePath(CombinePath(profile, L"AppData\\Roaming"), L".minecraft"));
        AddUniquePath(folders, CombinePath(CombinePath(profile, L"AppData\\Roaming"), L".tlauncher\\legacy\\Minecraft\\game"));
        AddUniquePath(folders, CombinePath(profile, L"Desktop"));
        AddUniquePath(folders, CombinePath(profile, L"Downloads"));
    }

    AddUniquePath(folders, L"C:\\PulseVisuals\\game");

    int deletedCount = 0;
    for (const std::wstring& folder : folders)
        DeleteCheckOutputFilesInFolder(folder, deletedCount);

    // .lunarclient keeps per-profile working dirs, so recurse a bounded depth.
    if (!profile.empty())
    {
        DeleteCheckOutputFilesRecursive(CombinePath(profile, L".lunarclient"), 6, deletedCount);
        DeleteCheckOutputFilesRecursive(
            CombinePath(CombinePath(profile, L"AppData\\Roaming"), L".minecraft"), 6, deletedCount);
    }

    if (!marker.empty())
        DeleteFileW(marker.c_str());

    if (deletedCount > 0)
        PostLog(L"Удалены check.txt/checktwinks.txt: " + std::to_wstring(deletedCount));
}



static std::wstring QuoteCmdArgument(const std::wstring& value)
{
    std::wstring out = L"\"";
    for (wchar_t ch : value)
    {
        if (ch == L'\"')
            out += L"\\\"";
        else
            out += ch;
    }
    out += L"\"";
    return out;
}

static bool IsHolyCheckLikeFolderName(const std::wstring& folder)
{
    std::wstring full = GetFullPathSafe(folder);
    size_t slash = full.find_last_of(L"\\/");
    std::wstring leaf = (slash == std::wstring::npos) ? full : full.substr(slash + 1);
    std::wstring lower = ToLower(leaf);
    return lower == L"holycheck" || lower == L"holycxheker" || lower.find(L"holycheck") != std::wstring::npos;
}

static bool WriteUtf8TextFileLocal(const std::wstring& path, const std::wstring& text)
{
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;

    std::string bytes;
    if (!text.empty())
    {
        int need = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (need > 1)
        {
            bytes.resize(static_cast<size_t>(need - 1));
            WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, bytes.data(), need, nullptr, nullptr);
        }
    }

    DWORD written = 0;
    BOOL ok = TRUE;
    if (!bytes.empty())
        ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    CloseHandle(file);
    return ok != FALSE;
}

static std::wstring BatchSetValue(std::wstring value)
{
    for (wchar_t& ch : value)
    {
        if (ch == L'"')
            ch = L'\'';
    }
    return value;
}

static std::wstring EscapePowerShellSingleQuotedLocal(const std::wstring& value)
{
    std::wstring out;
    out.reserve(value.size() + 8);
    for (wchar_t ch : value)
    {
        if (ch == L'\'')
            out += L"''";
        else
            out += ch;
    }
    return out;
}

static void ScheduleSelfDeleteAndCloseProgram()
{
    wchar_t exePath[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, exePath, ARRAYSIZE(exePath)))
        return;

    std::wstring exe = exePath;
    std::wstring folder;
    size_t slash = exe.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
        folder = exe.substr(0, slash);

    wchar_t tempDir[MAX_PATH]{};
    std::wstring tempRoot = L"C:\\Windows\\Temp";
    DWORD tempLen = GetTempPathW(ARRAYSIZE(tempDir), tempDir);
    if (tempLen > 0 && tempLen < ARRAYSIZE(tempDir))
        tempRoot = tempDir;
    while (!tempRoot.empty() && (tempRoot.back() == L'\\' || tempRoot.back() == L'/'))
        tempRoot.pop_back();

    std::wstring scriptPath = CombinePath(tempRoot,
        L"HolyCheck_self_delete_" + std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(GetTickCount64()) + L".bat");

    std::wstring script;
    script += L"@echo off\r\n";
    script += L"setlocal enableextensions\r\n";
    script += L"set \"HC_EXE=" + BatchSetValue(exe) + L"\"\r\n";
    if (!folder.empty())
        script += L"set \"HC_DIR=" + BatchSetValue(folder) + L"\"\r\n";
    script += L"for /l %%i in (1,1,30) do (\r\n";
    script += L"  if not exist \"%HC_EXE%\" goto cleanup_dir\r\n";
    script += L"  attrib -r -s -h \"%HC_EXE%\" >nul 2>nul\r\n";
    script += L"  del /f /q \"%HC_EXE%\" >nul 2>nul\r\n";
    script += L"  if not exist \"%HC_EXE%\" goto cleanup_dir\r\n";
    script += L"  timeout /t 1 /nobreak >nul\r\n";
    script += L")\r\n";
    script += L":cleanup_dir\r\n";
    if (!folder.empty())
    {
        script += L"for /l %%i in (1,1,10) do (\r\n";
        script += L"  if not exist \"%HC_DIR%\" goto self_remove\r\n";
        script += L"  rmdir /s /q \"%HC_DIR%\" >nul 2>nul\r\n";
        script += L"  if not exist \"%HC_DIR%\" goto self_remove\r\n";
        script += L"  timeout /t 1 /nobreak >nul\r\n";
        script += L")\r\n";
    }
    script += L":self_remove\r\n";
    script += L"(goto) 2>nul & del /f /q \"%~f0\"\r\n";

    if (!WriteUtf8TextFileLocal(scriptPath, script))
    {
        DebugLogLine(L"delete", L"self-delete bat write failed path=" + scriptPath + L" error=" + FormatWin32ErrorForLog(GetLastError()));
        return;
    }

    wchar_t sysDir[MAX_PATH]{};
    std::wstring cmdExe = L"cmd.exe";
    if (GetSystemDirectoryW(sysDir, ARRAYSIZE(sysDir)))
        cmdExe = CombinePath(sysDir, L"cmd.exe");

    // Run the batch directly inside a no-console cmd process. Using `start`
    // creates a second command interpreter for .bat files and on some systems
    // that minimized console can remain visible after FTK/HolyCheck deletion.
    std::wstring commandLine = QuoteCmdArgument(cmdExe) + L" /D /Q /C \"" + scriptPath + L"\"";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buffer(commandLine.begin(), commandLine.end());
    buffer.push_back(L'\0');

    std::vector<wchar_t> cwd(tempRoot.begin(), tempRoot.end());
    cwd.push_back(L'\0');

    if (CreateProcessW(nullptr, buffer.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                       nullptr, cwd.data(), &si, &pi))
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        DebugLogLine(L"delete", L"self-delete bat started path=" + scriptPath);
    }
    else
    {
        DebugLogLine(L"delete", L"self-delete bat start failed path=" + scriptPath + L" error=" + FormatWin32ErrorForLog(GetLastError()));
        DeleteFileW(scriptPath.c_str());
    }
}




static void DeleteHolyCheckByNameInDesktopDownloads()
{
    std::wstring script;
    script.reserve(8000);
    script += LR"HCPS(
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
function Out($s){[Console]::WriteLine([string]$s)}
function IsHolyExeName([string]$path){
  try{ return ([IO.Path]::GetFileName($path) -ieq 'holycheck.exe') }catch{return $false}
}
function RemovePermanent([string]$path){
  try{
    if([IO.File]::Exists($path)){[IO.File]::Delete($path); return (-not [IO.File]::Exists($path))}
  }catch{}
  return $false
}
function DeleteHolyExeFile([string]$path){
  if(-not (IsHolyExeName $path)){return 0}
  if(RemovePermanent $path){Out ('deleted exe: ' + $path); return 1}
  Out ('delete exe failed: ' + $path)
  return 0
}
function GetScanRoots(){
  $roots=New-Object System.Collections.Generic.List[string]
  foreach($drive in [IO.DriveInfo]::GetDrives()){
    try{
      if(-not $drive.IsReady){continue}
      $users=Join-Path $drive.RootDirectory.FullName 'Users'
      if(-not (Test-Path -LiteralPath $users)){continue}
      foreach($profile in @(Get-ChildItem -LiteralPath $users -Directory -Force -ErrorAction SilentlyContinue)){
        foreach($leaf in @('Desktop','Downloads')){
          $root=Join-Path $profile.FullName $leaf
          if(Test-Path -LiteralPath $root){[void]$roots.Add($root)}
        }
      }
    }catch{}
  }
  return @($roots)
}
$deleted=0
foreach($root in @(GetScanRoots)){
  try{
    foreach($f in @(Get-ChildItem -LiteralPath $root -Filter 'holycheck.exe' -File -Recurse -Depth 6 -Force -ErrorAction SilentlyContinue)){
      $deleted += (DeleteHolyExeFile $f.FullName)
    }
  }catch{}
}
Out ('deleted-exe-count: ' + $deleted)
)HCPS";

    std::wstring output;
    if (RunHiddenPowerShellScriptCapture(script, output, 60000))
    {
        DebugLogLine(L"delete", L"holycheck.exe cleanup output=" + output);
        PostLog(L"Удаление holycheck.exe завершено");
    }
    else
    {
        PostLog(L"Удаление holycheck.exe не выполнено");
    }
}


// Anything still locked after the retry passes (an antivirus scan, a driver
// handle) is queued for removal on the next boot. Needs admin rights;
// failing is harmless because the folder is already mostly gone.
static void ScheduleFolderDeleteOnReboot(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());

    if (attr == INVALID_FILE_ATTRIBUTES)
        return;

    if (attr & FILE_ATTRIBUTE_DIRECTORY)
    {
        std::wstring mask = CombinePath(path, L"*");

        WIN32_FIND_DATAW data{};
        HANDLE hFind = FindFirstFileW(mask.c_str(), &data);

        if (hFind != INVALID_HANDLE_VALUE)
        {
            do
            {
                if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
                    continue;

                // Children must be queued before their parent directory.
                ScheduleFolderDeleteOnReboot(CombinePath(path, data.cFileName));
            }
            while (FindNextFileW(hFind, &data));

            FindClose(hFind);
        }
    }

    MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
}


static void DeleteHolyCheckWorker()
{
    RequestCancelDownloads();

    AbortActiveHttpHandles();

    std::wstring folder = GetHolyCheckFolderPathOnly();

    // SystemInformer/Recuva/FTK Imager live in Program Files, not the HolyCheck
    // folder, so their uninstalls do not block the folder wipe. Kick them off
    // first and let them run while we close processes and delete HolyCheck.
    std::thread siThread(UninstallSystemInformerIfPresent);
    std::thread recuvaThread(UninstallRecuvaIfPresent);
    std::thread ftkThread(UninstallFtkImagerIfPresent);

    // Cancel already fired above; don't sit around waiting on in-flight work.
    for (int i = 0; i < 6 && (g_working.load() || g_activeSingleDownloads.load() > 0); ++i)
        Sleep(50);

    DeletePowerShellCheckOutputFiles();
    DeleteHolyCheckByNameInDesktopDownloads();

    PostLog(L"Закрываю программы");

    // Everything 1.5 ставится службой прямо из нашей папки: после убийства
    // процесса диспетчер служб поднимает его снова, и папка не удаляется
    // (на части ПК из-за этого удаление подолгу висело). Если служба ссылается
    // на наш exe — штатно останавливаем и снимаем её ДО удаления папки.
    // Чужая служба Everything (например, из Program Files) не трогается.
    auto stopEverythingServiceIfOurs = [&folder](const wchar_t* serviceName)
    {
        std::wstring qcOut;
        std::wstring qcCmd = L"sc.exe qc \"" + std::wstring(serviceName) + L"\" 4096";

        if (!RunHiddenCommandCapture(qcCmd, qcOut, 8000))
            return;

        std::wstring lowerOut = ToLower(qcOut);
        std::wstring lowerFolder = ToLower(folder);

        if (lowerFolder.size() < 4 || lowerOut.find(lowerFolder) == std::wstring::npos)
            return; // служба чужая — не наша папка, оставляем в покое

        std::wstring svcOut;
        RunHiddenCommandCapture(L"sc.exe stop \"" + std::wstring(serviceName) + L"\"", svcOut, 10000);
        RunHiddenCommandCapture(L"sc.exe delete \"" + std::wstring(serviceName) + L"\"", svcOut, 8000);
        PostLog(L"Служба Everything остановлена и снята");
    };

    stopEverythingServiceIfOurs(L"Everything");
    stopEverythingServiceIfOurs(L"Everything (1.5a)");

    // Kill anything holding a lock up front: the HolyCheck helpers, the shells
    // that launched them, and the download/extract tools. Releasing the locks
    // first makes the folder deletion below succeed on the first pass.
    CloseProcessesByName({
        L"powershell.exe", L"pwsh.exe", L"conhost.exe",
        L"curl.exe", L"7z.exe", L"7za.exe", L"7zg.exe", L"WinRAR.exe", L"Rar.exe",
        L"recuva.exe", L"recuva64.exe", L"FTK Imager.exe", L"Exterro_FTK_Imager_(x64).exe" });

    // DeleteDirectoryTree re-kills folder processes and retries internally, so
    // one call already clears freshly released locks. A single extra kill+retry
    // covers the rare straggler without the old multi-second retry storm.
    CloseProcessesFromFolder(folder);
    bool removed = DeleteDirectoryTree(folder);

    if (!removed)
    {
        CloseProcessesFromFolder(folder);
        removed = DeleteDirectoryTree(folder);
    }

    if (removed)
    {
        PostLog(L"Папка удалена полностью");
    }
    else
    {
        if (IsSafeHolyCheckDeletionTarget(folder))
            ScheduleFolderDeleteOnReboot(folder);

        PostLog(L"Остатки удалятся после перезагрузки, завершаю HolyCheck");
    }

    // Не ждём фоновые деинсталляторы бесконечно: ожидание join() здесь могло
    // зависить самоудаление, если внешний uninstall/процесс не завершался.
    // Потоки отделяем, а основной процесс закрывается; Windows 10/11 корректно
    // завершит их вместе с процессом без зависания UI.
    if (siThread.joinable())
        siThread.detach();
    if (recuvaThread.joinable())
        recuvaThread.detach();
    if (ftkThread.joinable())
        ftkThread.detach();

    ClearActiveDownloads();
    g_deleteInProgress = false;
    PostProgress(0);

    ScheduleSelfDeleteAndCloseProgram();

    if (g_hMain && !g_destroying.load())
        PostMessageW(g_hMain, WM_CLOSE, 0, 0);

    Sleep(300);
    ExitProcess(0);
}


static void DeleteHolyCheckFolder()
{
    if (g_deleteInProgress.exchange(true))
        return;

    g_cancelRequested = true;
    SetDownloadControlsEnabled(false);
    g_progressPercent = 0;
    ClearDownloadLog();
    PostLog(L"Удаление holycheck");
    InvalidateBottomPanel();

    std::thread(DeleteHolyCheckWorker).detach();
}

