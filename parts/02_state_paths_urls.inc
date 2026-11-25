static void PostProgress(int value)
{
    HWND hwnd = g_hMain;

    if (!hwnd || g_destroying.load())
        return;

    PostMessageW(hwnd, WM_APP_PROGRESS, static_cast<WPARAM>(value), 0);
}

static std::wstring ShortLogLine(std::wstring line)
{
    const size_t maxLen = 124;

    for (wchar_t& ch : line)
    {
        if (ch == L'\r' || ch == L'\n' || ch == L'\t')
            ch = L' ';
    }

    if (line.size() > maxLen)
        line = line.substr(0, maxLen - 3) + L"...";

    return line;
}

static std::wstring SanitizeDebugLogText(std::wstring text)
{
    for (wchar_t& ch : text)
    {
        if (ch == L'\r' || ch == L'\n' || ch == L'\t')
            ch = L' ';
    }
    return text;
}

static std::wstring FormatWin32ErrorForLog(DWORD err)
{
    if (err == 0)
        return L"0";

    wchar_t* buffer = nullptr;
    DWORD len = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        err,
        0,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    std::wstring text = std::to_wstring(err);
    if (len > 0 && buffer)
    {
        text += L" (";
        text += buffer;
        while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ' || text.back() == L'\t'))
            text.pop_back();
        text += L")";
    }

    if (buffer)
        LocalFree(buffer);

    return text;
}

static void DebugLogLine(const std::wstring& scope, const std::wstring& message)
{
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    wchar_t stamp[64] = {};
    swprintf(stamp, 64, L"%04d-%02d-%02d %02d:%02d:%02d.%03d ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    std::wstring line = std::wstring(stamp) + L"[" + SanitizeDebugLogText(scope) + L"] " +
        SanitizeDebugLogText(message) + L"\r\n";

    OutputDebugStringW(line.c_str());
}

static void DebugLogSeparator(const std::wstring& title)
{
    DebugLogLine(L"----", L"==== " + title + L" ====");
}

static std::wstring EscapePowerShellSingleQuotedForDebug(std::wstring s)
{
    size_t pos = 0;
    while ((pos = s.find(L"'", pos)) != std::wstring::npos)
    {
        s.replace(pos, 1, L"''");
        pos += 2;
    }
    return s;
}

static void PushLogLine(const std::wstring& line)
{
    std::lock_guard<std::mutex> lock(g_logMutex);

    bool wasAtBottom = g_logScrollOffset == 0;

    SYSTEMTIME now{};
    GetLocalTime(&now);
    wchar_t time[9]{};
    swprintf(time, std::size(time), L"%02u:%02u:%02u", now.wHour, now.wMinute, now.wSecond);
    g_logLines.push_back({ time, ShortLogLine(line) });

    while (g_logLines.size() > LOG_MAX_LINES)
    {
        g_logLines.erase(g_logLines.begin());

        if (g_logScrollOffset > 0)
            --g_logScrollOffset;
    }

    if (!wasAtBottom)
        ++g_logScrollOffset;

    ClampLogScrollOffsetLocked();
}

static void ClearDownloadLog()
{
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_logLines.clear();
    g_logScrollOffset = 0;
}


static bool IsRunningAsAdministrator()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup))
    {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin == TRUE;
}

static std::wstring QuoteShellArgument(const std::wstring& arg)
{
    if (arg.empty())
        return L"\"\"";

    bool needsQuotes = arg.find_first_of(L" \t\"") != std::wstring::npos;

    if (!needsQuotes)
        return arg;

    std::wstring out = L"\"";
    size_t slashCount = 0;

    for (wchar_t ch : arg)
    {
        if (ch == L'\\')
        {
            ++slashCount;
            continue;
        }

        if (ch == L'\"')
        {
            out.append(slashCount * 2 + 1, L'\\');
            out.push_back(ch);
            slashCount = 0;
            continue;
        }

        if (slashCount > 0)
        {
            out.append(slashCount, L'\\');
            slashCount = 0;
        }

        out.push_back(ch);
    }

    if (slashCount > 0)
        out.append(slashCount * 2, L'\\');

    out.push_back(L'\"');
    return out;
}

static std::wstring BuildRelaunchParameters()
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (!argv)
        return L"";

    std::wstring params;

    for (int i = 1; i < argc; ++i)
    {
        if (!params.empty())
            params += L" ";

        params += QuoteShellArgument(argv[i]);
    }

    LocalFree(argv);
    return params;
}

static bool RelaunchAsAdministrator()
{
    wchar_t exePath[MAX_PATH]{};

    if (!GetModuleFileNameW(nullptr, exePath, static_cast<DWORD>((sizeof(exePath) / sizeof(exePath[0])))))
        return false;

    std::wstring params = BuildRelaunchParameters();

    HINSTANCE result = ShellExecuteW(
        nullptr,
        L"runas",
        exePath,
        params.empty() ? nullptr : params.c_str(),
        nullptr,
        SW_SHOWNORMAL
    );

    return reinterpret_cast<INT_PTR>(result) > 32;
}

static std::wstring ToLowerCopy(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch)
    {
        return static_cast<wchar_t>(towlower(ch));
    });

    return value;
}

static std::wstring TrimXmlText(std::wstring value)
{
    for (wchar_t& ch : value)
    {
        if (ch == L'\r' || ch == L'\n' || ch == L'\t')
            ch = L' ';
    }

    while (!value.empty() && iswspace(value.front()))
        value.erase(value.begin());

    while (!value.empty() && iswspace(value.back()))
        value.pop_back();

    return value;
}

static std::wstring ExtractFileNameOnly(const std::wstring& path)
{
    size_t pos = path.find_last_of(L"\\/");

    if (pos == std::wstring::npos || pos + 1 >= path.size())
        return path;

    return path.substr(pos + 1);
}

static bool IsLikelySystemExecutable(const std::wstring& path)
{
    std::wstring lower = ToLowerCopy(path);
    std::replace(lower.begin(), lower.end(), L'/', L'\\');
    std::wstring file = ExtractFileNameOnly(lower);

    if (lower.empty())
        return true;

    wchar_t winDirBuf[MAX_PATH * 4]{};
    std::wstring winDir;
    UINT winLen = GetWindowsDirectoryW(winDirBuf, ARRAYSIZE(winDirBuf));
    if (winLen > 0 && winLen < ARRAYSIZE(winDirBuf))
    {
        winDir = ToLowerCopy(winDirBuf);
        std::replace(winDir.begin(), winDir.end(), L'/', L'\\');
        while (!winDir.empty() && winDir.back() == L'\\')
            winDir.pop_back();
    }

    std::wstring winLeafNeedle;
    if (!winDir.empty())
        winLeafNeedle = L"\\" + ExtractFileNameOnly(winDir) + L"\\";

    auto has = [&](const wchar_t* needle) -> bool
    {
        return lower.find(needle) != std::wstring::npos;
    };

    // а не пропускать Windows/SystemRoot/WinSxS/WindowsApps/Microsoft системные пути.
    // Хеши без локальной базы эталонных системных хешей не дают 100% результата и сильно тормозят скан.
    if ((!winDir.empty() && (lower.rfind(winDir + L"\\", 0) == 0 || (!winLeafNeedle.empty() && lower.find(winLeafNeedle) != std::wstring::npos))) ||
        has(L"\\windows\\") ||
        has(L"\\systemroot\\") ||
        has(L"\\winsxs\\") ||
        has(L"\\system32\\") ||
        has(L"\\syswow64\\") ||
        has(L"\\microsoft.net\\framework") ||
        has(L"\\$windows.~bt\\") ||
        has(L"\\$windows.~ws\\") ||
        has(L"\\program files\\windowsapps\\") ||
        has(L"\\program files (x86)\\windowsapps\\") ||
        has(L"\\windowsapps\\microsoft.") ||
        has(L"\\windowsapps\\windows.") ||
        has(L"\\programdata\\microsoft\\windows\\") ||
        has(L"\\microsoft\\windows\\") ||
        has(L"microsoft.windows.") ||
        has(L"windows.client.") ||
        has(L"startmenuexperiencehost") ||
        has(L"client.cbs") ||
        has(L"_cw5n1h2txyewy") ||
        has(L"_8wekyb3d8bbwe") ||
        has(L"__8wekyb3d8bbwe"))
    {
        return true;
    }

    if (lower.rfind(L"c:\\windows\\", 0) == 0 ||
        lower.rfind(L"c:\\programdata\\microsoft\\windows\\", 0) == 0 ||
        (lower.rfind(L"\\device\\harddiskvolume", 0) == 0 && lower.find(L"\\windows\\") != std::wstring::npos))
    {
        return true;
    }

    static const wchar_t* systemNames[] =
    {
        L"svchost.exe", L"conhost.exe", L"dllhost.exe", L"rundll32.exe", L"regsvr32.exe",
        L"taskhostw.exe", L"taskhost.exe", L"taskeng.exe", L"explorer.exe", L"sihost.exe",
        L"searchindexer.exe", L"searchhost.exe", L"searchprotocolhost.exe", L"runtimebroker.exe",
        L"audiodg.exe", L"csrss.exe", L"winlogon.exe", L"services.exe", L"lsass.exe",
        L"smss.exe", L"fontdrvhost.exe", L"wmiprvse.exe", L"werfault.exe", L"wermgr.exe",
        L"dwm.exe", L"ctfmon.exe", L"securityhealthsystray.exe", L"startmenuexperiencehost.exe",
        L"shellexperiencehost.exe", L"applicationframehost.exe", L"lockapp.exe", L"textinputhost.exe",
        L"backgroundtaskhost.exe", L"systemsettings.exe", L"trustedinstaller.exe", L"tiworker.exe",
        L"mousocoreworker.exe", L"wuauclt.exe", L"musnotification.exe", L"musnotificationux.exe",
        L"usocoreworker.exe", L"compattelrunner.exe", L"devicecensus.exe", L"consent.exe",
        L"smartscreen.exe", L"securityhealthservice.exe", L"securityhealthhost.exe",
        L"sppsvc.exe", L"vssvc.exe", L"spoolsv.exe", L"wscript.exe", L"cscript.exe",
        L"msiexec.exe", L"msedgewebview2.exe", L"client.cbs", L"searchapp.exe",
        L"widgets.exe", L"widgetservice.exe", L"onedrivesetup.exe", L"setuphost.exe",
        L"backgrounddownload.exe", L"aggregatorhost.exe", L"systemsettingsbroker.exe",
        L"yourphone.exe", L"phoneexperiencehost.exe", L"gamebar.exe", L"gamebarftserver.exe",
        L"gamebarpresencewriter.exe", L"xboxgamebarwidgets.exe"
    };

    for (const wchar_t* name : systemNames)
    {
        std::wstring n = ToLowerCopy(name);
        if (file == n || file.find(n) != std::wstring::npos)
            return true;
    }

    // чем хешировать каждый exe без локальной базы эталонных системных хешей.
    if (has(L"\\program files\\microsoft\\") ||
        has(L"\\program files (x86)\\microsoft\\") ||
        has(L"\\program files\\windows defender\\") ||
        has(L"\\program files\\windows security\\") ||
        has(L"\\program files\\windows nt\\") ||
        has(L"\\program files\\internet explorer\\") ||
        has(L"\\program files (x86)\\internet explorer\\") ||
        has(L"\\program files\\common files\\microsoft shared\\") ||
        has(L"\\program files (x86)\\common files\\microsoft shared\\") ||
        has(L"\\appdata\\local\\microsoft\\windows\\") ||
        has(L"\\appdata\\roaming\\microsoft\\windows\\") ||
        has(L"\\appdata\\local\\packages\\microsoft.") ||
        has(L"\\appdata\\local\\packages\\windows."))
    {
        return true;
    }

    // Prefetch-файлы часто дают только имя exe. Если это типичное системное имя — не выводим вообще.
    if (lower.find(L"\\") == std::wstring::npos && lower.find(L"/") == std::wstring::npos)
    {
        if (file.rfind(L"microsoft.", 0) == 0 || file.rfind(L"windows.", 0) == 0 ||
            file.find(L"setup") != std::wstring::npos || file.find(L"update") != std::wstring::npos)
            return true;
    }

    return false;
}

static std::wstring DevicePathToDosPath(const std::wstring& path)
{
    if (path.empty() || path[0] != L'\\')
        return path;

    wchar_t drives[512]{};
    DWORD len = GetLogicalDriveStringsW(static_cast<DWORD>((sizeof(drives) / sizeof(drives[0])) - 1), drives);

    if (len == 0 || len >= (sizeof(drives) / sizeof(drives[0])))
        return path;

    for (wchar_t* drive = drives; *drive; drive += wcslen(drive) + 1)
    {
        wchar_t letter[] = { drive[0], L':', L'\0' };
        wchar_t deviceName[1024]{};

        if (!QueryDosDeviceW(letter, deviceName, static_cast<DWORD>((sizeof(deviceName) / sizeof(deviceName[0])))))
            continue;

        std::wstring device = deviceName;

        if (path.size() > device.size() && _wcsnicmp(path.c_str(), device.c_str(), device.size()) == 0 && path[device.size()] == L'\\')
        {
            return std::wstring(letter) + path.substr(device.size());
        }
    }

    return path;
}

static bool IsPlausibleFileTime(const FILETIME& ft)
{
    ULARGE_INTEGER value{};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;

    if (value.QuadPart == 0)
        return false;

    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&ft, &st))
        return false;

    return st.wYear >= 2000 && st.wYear <= 2100;
}

static bool TryReadBamFileTime(const BYTE* data, DWORD dataLen, FILETIME& out)
{
    if (!data || dataLen < sizeof(FILETIME))
        return false;

    const DWORD offsets[] = { 0, 8, 16 };

    for (DWORD offset : offsets)
    {
        if (dataLen < offset + sizeof(FILETIME))
            continue;

        FILETIME ft{};
        std::memcpy(&ft, data + offset, sizeof(FILETIME));

        if (IsPlausibleFileTime(ft))
        {
            out = ft;
            return true;
        }
    }

    return false;
}

static std::wstring FileTimeToLocalText(const FILETIME& ft)
{
    SYSTEMTIME utc{};
    SYSTEMTIME local{};

    if (!FileTimeToSystemTime(&ft, &utc) || !SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local))
        return L"дата неизвестна";

    wchar_t buffer[64]{};
    swprintf_s(
        buffer,
        L"%02u.%02u.%04u %02u:%02u:%02u",
        local.wDay,
        local.wMonth,
        local.wYear,
        local.wHour,
        local.wMinute,
        local.wSecond
    );

    return buffer;
}

static bool IsoUtcTextToLocalText(const std::wstring& iso, std::wstring& out)
{
    if (iso.size() < 19)
        return false;

    SYSTEMTIME st{};
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;

    if (swscanf_s(iso.c_str(), L"%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second) != 6)
        return false;

    st.wYear = static_cast<WORD>(year);
    st.wMonth = static_cast<WORD>(month);
    st.wDay = static_cast<WORD>(day);
    st.wHour = static_cast<WORD>(hour);
    st.wMinute = static_cast<WORD>(minute);
    st.wSecond = static_cast<WORD>(second);

    FILETIME ft{};
    if (!SystemTimeToFileTime(&st, &ft))
        return false;

    out = FileTimeToLocalText(ft);
    return true;
}

static std::wstring ExtractXmlAttribute(const std::wstring& xml, const std::wstring& tag, const std::wstring& attr)
{
    size_t tagPos = xml.find(L"<" + tag);

    if (tagPos == std::wstring::npos)
        return L"";

    size_t tagEnd = xml.find(L'>', tagPos);

    if (tagEnd == std::wstring::npos)
        tagEnd = xml.size();

    std::wstring key = attr + L"=";
    size_t attrPos = xml.find(key, tagPos);

    if (attrPos == std::wstring::npos || attrPos > tagEnd)
        return L"";

    attrPos += key.size();

    if (attrPos >= xml.size())
        return L"";

    wchar_t quote = xml[attrPos];

    if (quote != L'\'' && quote != L'\"')
        return L"";

    size_t valueStart = attrPos + 1;
    size_t valueEnd = xml.find(quote, valueStart);

    if (valueEnd == std::wstring::npos)
        return L"";

    return xml.substr(valueStart, valueEnd - valueStart);
}

static std::wstring ExtractFirstXmlDataText(const std::wstring& xml)
{
    size_t dataPos = xml.find(L"<Data");

    if (dataPos == std::wstring::npos)
        return L"";

    size_t start = xml.find(L'>', dataPos);
    size_t end = xml.find(L"</Data>", start == std::wstring::npos ? dataPos : start);

    if (start == std::wstring::npos || end == std::wstring::npos || end <= start + 1)
        return L"";

    return TrimXmlText(xml.substr(start + 1, end - start - 1));
}

static std::wstring ExtractAllXmlDataText(const std::wstring& xml)
{
    std::wstring out;
    size_t pos = 0;

    while (true)
    {
        size_t dataPos = xml.find(L"<Data", pos);

        if (dataPos == std::wstring::npos)
            break;

        size_t start = xml.find(L'>', dataPos);
        size_t end = xml.find(L"</Data>", start == std::wstring::npos ? dataPos : start);

        if (start == std::wstring::npos || end == std::wstring::npos)
            break;

        if (end > start + 1)
        {
            std::wstring value = TrimXmlText(xml.substr(start + 1, end - start - 1));

            if (!value.empty())
            {
                if (!out.empty())
                    out += L"; ";

                out += value;
            }
        }

        pos = end + 7;
    }

    if (out.empty())
        out = ExtractFirstXmlDataText(xml);

    if (out.size() > 260)
        out = out.substr(0, 257) + L"...";

    return out;
}


static std::wstring ExtractXmlDataTextByName(const std::wstring& xml, const std::wstring& name)
{
    size_t pos = 0;

    while (true)
    {
        size_t dataPos = xml.find(L"<Data", pos);
        if (dataPos == std::wstring::npos)
            break;

        size_t tagEnd = xml.find(L'>', dataPos);
        if (tagEnd == std::wstring::npos)
            break;

        std::wstring nameAttr = ExtractXmlAttribute(xml.substr(dataPos, tagEnd - dataPos + 1), L"Data", L"Name");
        if (_wcsicmp(nameAttr.c_str(), name.c_str()) == 0)
        {
            size_t end = xml.find(L"</Data>", tagEnd);
            if (end == std::wstring::npos)
                return L"";
            return TrimXmlText(xml.substr(tagEnd + 1, end - tagEnd - 1));
        }

        pos = tagEnd + 1;
    }

    return L"";
}

static std::vector<std::wstring> ExtractXmlDataValues(const std::wstring& xml)
{
    std::vector<std::wstring> values;
    size_t pos = 0;

    while (true)
    {
        size_t dataPos = xml.find(L"<Data", pos);
        if (dataPos == std::wstring::npos)
            break;

        size_t start = xml.find(L'>', dataPos);
        size_t end = xml.find(L"</Data>", start == std::wstring::npos ? dataPos : start);
        if (start == std::wstring::npos || end == std::wstring::npos)
            break;

        std::wstring value = TrimXmlText(xml.substr(start + 1, end - start - 1));
        if (!value.empty())
            values.push_back(value);

        pos = end + 7;
    }

    return values;
}

static std::wstring CleanEventDetailText(std::wstring detail);

static std::wstring DecodeXmlEntities(std::wstring value)
{
    struct EntityPair
    {
        const wchar_t* from;
        const wchar_t* to;
    };

    const EntityPair entities[] =
    {
        { L"&amp;", L"&" },
        { L"&lt;", L"<" },
        { L"&gt;", L">" },
        { L"&quot;", L"\"" },
        { L"&apos;", L"'" }
    };

    for (const EntityPair& entity : entities)
    {
        size_t pos = 0;
        while ((pos = value.find(entity.from, pos)) != std::wstring::npos)
        {
            value.replace(pos, wcslen(entity.from), entity.to);
            pos += wcslen(entity.to);
        }
    }

    return value;
}

static std::vector<std::pair<std::wstring, std::wstring>> ExtractXmlDataPairs(const std::wstring& xml)
{
    std::vector<std::pair<std::wstring, std::wstring>> values;
    size_t pos = 0;
    size_t index = 1;

    while (true)
    {
        size_t dataPos = xml.find(L"<Data", pos);
        if (dataPos == std::wstring::npos)
            break;

        size_t tagEnd = xml.find(L'>', dataPos);
        size_t end = xml.find(L"</Data>", tagEnd == std::wstring::npos ? dataPos : tagEnd);
        if (tagEnd == std::wstring::npos || end == std::wstring::npos)
            break;

        std::wstring tag = xml.substr(dataPos, tagEnd - dataPos + 1);
        std::wstring name = ExtractXmlAttribute(tag, L"Data", L"Name");
        std::wstring value = DecodeXmlEntities(TrimXmlText(xml.substr(tagEnd + 1, end - tagEnd - 1)));

        if (!value.empty())
        {
            if (name.empty())
                name = L"Data" + std::to_wstring(index);
            values.emplace_back(name, value);
        }

        ++index;
        pos = end + 7;
    }

    return values;
}

static std::wstring FindNamedEventValue(const std::vector<std::pair<std::wstring, std::wstring>>& values, std::initializer_list<const wchar_t*> names)
{
    for (const wchar_t* wanted : names)
    {
        for (const auto& item : values)
        {
            if (_wcsicmp(item.first.c_str(), wanted) == 0 && !item.second.empty())
                return item.second;
        }
    }

    return L"";
}

static bool LooksLikeExecutableName(const std::wstring& value)
{
    std::wstring lower = ToLowerCopy(value);
    size_t pos = lower.find(L".exe");
    if (pos == std::wstring::npos)
        return false;

    if (pos + 4 < lower.size())
    {
        wchar_t ch = lower[pos + 4];
        if (iswalnum(ch) || ch == L'_' || ch == L'-')
            return false;
    }

    return true;
}

static std::wstring ExtractEventProcessName(const std::wstring& xml)
{
    std::vector<std::pair<std::wstring, std::wstring>> values = ExtractXmlDataPairs(xml);
    std::wstring process = FindNamedEventValue(values,
    {
        L"ProcessName",
        L"Process",
        L"Image",
        L"ImageName",
        L"Application",
        L"Executable",
        L"CallerProcessName",
        L"ClientProcessName"
    });

    if (!process.empty())
        return ExtractFileNameOnly(process);

    for (const auto& item : values)
    {
        if (LooksLikeExecutableName(item.second))
            return ExtractFileNameOnly(item.second);
    }

    return L"";
}

static std::wstring ExtractEventTargetName(const std::wstring& xml)
{
    std::vector<std::pair<std::wstring, std::wstring>> values = ExtractXmlDataPairs(xml);
    std::wstring target = FindNamedEventValue(values,
    {
        L"LogFile",
        L"LogName",
        L"Channel",
        L"TargetLog",
        L"ObjectName",
        L"FileName",
        L"TargetFilename",
        L"Path",
        L"VolumeName",
        L"Volume",
        L"DeviceName",
        L"DeviceInstanceId"
    });

    if (!target.empty())
        return target;

    for (const auto& item : values)
    {
        std::wstring lower = ToLowerCopy(item.second);
        if (lower.find(L"\\") != std::wstring::npos ||
            lower.find(L"volume") != std::wstring::npos ||
            lower.find(L"journal") != std::wstring::npos ||
            lower.find(L"log") != std::wstring::npos)
            return item.second;
    }

    return L"";
}

static std::wstring BuildNamedEventDataSummary(const std::wstring& xml, size_t limit)
{
    std::vector<std::pair<std::wstring, std::wstring>> values = ExtractXmlDataPairs(xml);
    std::wstring out;

    for (const auto& item : values)
    {
        std::wstring name = item.first;
        std::wstring lowerName = ToLowerCopy(name);
        if (lowerName == L"data1" || lowerName == L"data2" || lowerName == L"data3" || lowerName == L"data4")
            name = L"данные";

        std::wstring piece = name + L": " + item.second;
        if (!out.empty())
            piece = L"; " + piece;

        if (out.size() + piece.size() > limit)
            break;

        out += piece;
    }

    return CleanEventDetailText(out);
}

static std::wstring FormatEventMessageFromMetadata(EVT_HANDLE eventHandle, const std::wstring& provider)
{
    if (provider.empty())
        return L"";

    EVT_HANDLE metadata = EvtOpenPublisherMetadata(nullptr, provider.c_str(), nullptr, 0, 0);
    if (!metadata)
        return L"";

    DWORD bufferUsed = 0;
    std::wstring result;

    if (!EvtFormatMessage(metadata, eventHandle, 0, 0, nullptr, EvtFormatMessageEvent, 0, nullptr, &bufferUsed) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        std::vector<wchar_t> buffer(bufferUsed + 2);
        if (EvtFormatMessage(metadata, eventHandle, 0, 0, nullptr, EvtFormatMessageEvent, bufferUsed, buffer.data(), &bufferUsed))
            result = CleanEventDetailText(buffer.data());
    }

    EvtClose(metadata);
    return result;
}

static std::wstring FormatEventMessageFromMetadataCached(EVT_HANDLE eventHandle, const std::wstring& provider, std::map<std::wstring, EVT_HANDLE>& metadataCache)
{
    if (provider.empty())
        return L"";

    EVT_HANDLE metadata = nullptr;
    auto it = metadataCache.find(provider);
    if (it != metadataCache.end())
    {
        metadata = it->second;
    }
    else
    {
        metadata = EvtOpenPublisherMetadata(nullptr, provider.c_str(), nullptr, 0, 0);
        metadataCache[provider] = metadata;
    }

    if (!metadata)
        return L"";

    DWORD bufferUsed = 0;
    std::wstring result;

    if (!EvtFormatMessage(metadata, eventHandle, 0, 0, nullptr, EvtFormatMessageEvent, 0, nullptr, &bufferUsed) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        std::vector<wchar_t> buffer(bufferUsed + 2);
        if (EvtFormatMessage(metadata, eventHandle, 0, 0, nullptr, EvtFormatMessageEvent, bufferUsed, buffer.data(), &bufferUsed))
            result = CleanEventDetailText(buffer.data());
    }

    return result;
}

static bool IsoUtcTextToLocalIsoText(const std::wstring& iso, std::wstring& out)
{
    if (iso.size() < 19)
        return false;

    SYSTEMTIME st{};
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;

    if (swscanf_s(iso.c_str(), L"%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second) != 6)
        return false;

    st.wYear = static_cast<WORD>(year);
    st.wMonth = static_cast<WORD>(month);
    st.wDay = static_cast<WORD>(day);
    st.wHour = static_cast<WORD>(hour);
    st.wMinute = static_cast<WORD>(minute);
    st.wSecond = static_cast<WORD>(second);

    FILETIME ft{};
    SYSTEMTIME utc{};
    SYSTEMTIME local{};
    if (!SystemTimeToFileTime(&st, &ft) || !FileTimeToSystemTime(&ft, &utc) || !SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local))
        return false;

    wchar_t buffer[64]{};
    swprintf_s(buffer, L"%04u-%02u-%02u %02u:%02u:%02u", local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute, local.wSecond);
    out = buffer;
    return true;
}

static long long IsoUtcTextToSortKey(const std::wstring& iso)
{
    if (iso.size() < 19)
        return 0;

    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (swscanf_s(iso.c_str(), L"%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second) != 6)
        return 0;

    return static_cast<long long>(year) * 10000000000LL +
        static_cast<long long>(month) * 100000000LL +
        static_cast<long long>(day) * 1000000LL +
        static_cast<long long>(hour) * 10000LL +
        static_cast<long long>(minute) * 100LL +
        static_cast<long long>(second);
}

static std::wstring ExtractEvent104ClearedLogName(const std::wstring& xml)
{
    const wchar_t* namedFields[] =
    {
        L"LogFileCleared",
        L"LogFile",
        L"LogName",
        L"Channel",
        L"TargetLog",
        L"Name"
    };

    for (const wchar_t* field : namedFields)
    {
        std::wstring value = ExtractXmlDataTextByName(xml, field);
        if (!value.empty())
            return value;
    }

    std::vector<std::wstring> values = ExtractXmlDataValues(xml);
    for (const std::wstring& value : values)
    {
        std::wstring lower = ToLowerCopy(value);
        if (lower.find(L"system") != std::wstring::npos ||
            lower.find(L"application") != std::wstring::npos ||
            lower.find(L"powershell") != std::wstring::npos ||
            lower.find(L"operational") != std::wstring::npos ||
            lower.find(L"windows") != std::wstring::npos)
            return value;
    }

    if (!values.empty())
        return values.back();

    return L"журнала";
}

static std::wstring CleanEventDetailText(std::wstring detail)
{
    for (wchar_t& ch : detail)
    {
        if (ch == L'\r' || ch == L'\n' || ch == L'\t')
            ch = L' ';
    }

    while (detail.find(L"  ") != std::wstring::npos)
        detail.replace(detail.find(L"  "), 2, L" ");

    detail = TrimXmlText(detail);
    if (detail.size() > 260)
        detail = detail.substr(0, 257) + L"...";
    return detail;
}

static std::wstring BuildCompactEventMessage(DWORD eventId, const std::wstring& xml, const std::wstring& provider, const std::wstring& formatted)
{
    std::wstring message = CleanEventDetailText(DecodeXmlEntities(formatted));

    if (message.empty() && eventId == 104)
    {
        std::wstring logName = ExtractEvent104ClearedLogName(xml);
        if (logName.empty())
            logName = L"журнала";
        message = L"Файл журнала " + logName + L" очищен.";
    }

    if (message.empty())
        message = CleanEventDetailText(ExtractAllXmlDataText(xml));

    if (message.empty())
        message = BuildNamedEventDataSummary(xml, 360);

    if (message.empty() && !provider.empty())
        message = provider;

    std::wstring process = ExtractEventProcessName(xml);
    if (!process.empty() && ToLowerCopy(message).find(ToLowerCopy(process)) == std::wstring::npos)
        message = L"процесс: " + process + L" | " + message;

    std::wstring target = ExtractEventTargetName(xml);
    if (!target.empty() && ToLowerCopy(message).find(ToLowerCopy(target)) == std::wstring::npos)
        message += L" | объект: " + target;

    std::wstring dataSummary = BuildNamedEventDataSummary(xml, 420);
    if (!dataSummary.empty() && ToLowerCopy(message).find(ToLowerCopy(dataSummary.substr(0, std::min<size_t>(dataSummary.size(), 32)))) == std::wstring::npos)
        message += L" | данные: " + dataSummary;

    message = CleanEventDetailText(message);
    if (message.size() > 520)
        message = message.substr(0, 517) + L"...";

    return message.empty() ? L"событие найдено" : message;
}

static std::wstring RenderEventXml(EVT_HANDLE eventHandle)
{
    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;

    if (!EvtRender(nullptr, eventHandle, EvtRenderEventXml, 0, nullptr, &bufferUsed, &propertyCount) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return L"";

    std::vector<wchar_t> buffer((bufferUsed / sizeof(wchar_t)) + 2);

    if (!EvtRender(nullptr, eventHandle, EvtRenderEventXml, bufferUsed, buffer.data(), &bufferUsed, &propertyCount))
        return L"";

    return buffer.data();
}

static void LimitAutomationLines(std::vector<std::wstring>& lines)
{
    if (lines.size() <= AUTOMATION_MAX_LINES)
        return;

    size_t removed = lines.size() - AUTOMATION_MAX_LINES;
    lines.erase(lines.begin(), lines.begin() + static_cast<std::ptrdiff_t>(removed));
    lines.insert(lines.begin(), L"показаны последние " + std::to_wstring(AUTOMATION_MAX_LINES) + L" строк, скрыт��: " + std::to_wstring(removed));
}

static size_t GetAutomationVisibleLineCapacity(int target)
{
    HWND hwnd = g_hMain;

    if (!hwnd)
        return AUTOMATION_VISIBLE_LINES;

    RECT rc{};
    GetClientRect(hwnd, &rc);

    RECT panel{};
    if (target == AUTOMATION_OUTPUT_EVENTVWR)
        panel = GetAutomationEventPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_JAR_ACTIVITY)
        panel = GetJarActivityPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_JAR_MODIFIED)
        panel = GetJarModifiedPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_EXE_DELETED)
        panel = GetExeDeletedPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_PF_DELETED)
        panel = GetPfDeletedPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_MC_LOGS)
        panel = GetMcLogsPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_PAGE4)
        panel = (g_currentPage == 1) ? GetAutomationBamPanelRect(rc) : GetPage4PanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_DLL_UNSIGNED)
        panel = GetDllUnsignedPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_DLL_ACTIVITY)
        panel = GetDllActivityPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_INJGEN)
        SetRectEmpty(&panel);
    else if (target == AUTOMATION_OUTPUT_FILECHECK)
        panel = GetFileCheckPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_CLIPBOARD)
        panel = GetClipPanelRect(rc);
    else
        panel = GetAutomationBamPanelRect(rc);

    int h = panel.bottom - panel.top;
    int capacity = std::max(1, (h - 34) / 15);
    return static_cast<size_t>(capacity);
}

static int GetMaxAutomationScrollOffsetLocked(int target, const std::vector<std::wstring>& lines)
{
    size_t visible = GetAutomationVisibleLineCapacity(target);

    if (lines.size() <= visible)
        return 0;

    return static_cast<int>(lines.size() - visible);
}

static int& AutomationScrollRef(int target)
{
    if (target == AUTOMATION_OUTPUT_EVENTVWR)
        return g_eventVwrScrollOffset;
    if (target == AUTOMATION_OUTPUT_JAR_ACTIVITY)
        return g_jarActivityScrollOffset;
    if (target == AUTOMATION_OUTPUT_JAR_MODIFIED)
        return g_jarModifiedScrollOffset;
    if (target == AUTOMATION_OUTPUT_EXE_DELETED)
        return g_exeDeletedScrollOffset;
    if (target == AUTOMATION_OUTPUT_PF_DELETED)
        return g_pfDeletedScrollOffset;
    if (target == AUTOMATION_OUTPUT_MC_LOGS)
        return g_mcLogsScrollOffset;
    if (target == AUTOMATION_OUTPUT_PAGE4)
        return g_page4ScrollOffset;
    if (target == AUTOMATION_OUTPUT_DLL_UNSIGNED)
        return g_dllUnsignedScrollOffset;
    if (target == AUTOMATION_OUTPUT_DLL_ACTIVITY)
        return g_dllActivityScrollOffset;
    if (target == AUTOMATION_OUTPUT_INJGEN)
        return g_injGenScrollOffset;
    if (target == AUTOMATION_OUTPUT_FILECHECK)
        return g_fileCheckScrollOffset;
    if (target == AUTOMATION_OUTPUT_CLIPBOARD)
        return g_clipboardScrollOffset;
    return g_bamScrollOffset;
}

static std::vector<std::wstring>& AutomationLinesRef(int target)
{
    if (target == AUTOMATION_OUTPUT_EVENTVWR)
        return g_eventVwrLines;
    if (target == AUTOMATION_OUTPUT_JAR_ACTIVITY)
        return g_jarActivityLines;
    if (target == AUTOMATION_OUTPUT_JAR_MODIFIED)
        return g_jarModifiedLines;
    if (target == AUTOMATION_OUTPUT_EXE_DELETED)
        return g_exeDeletedLines;
    if (target == AUTOMATION_OUTPUT_PF_DELETED)
        return g_pfDeletedLines;
    if (target == AUTOMATION_OUTPUT_MC_LOGS)
        return g_mcLogsLines;
    if (target == AUTOMATION_OUTPUT_PAGE4)
        return g_page4Lines;
    if (target == AUTOMATION_OUTPUT_DLL_UNSIGNED)
        return g_dllUnsignedLines;
    if (target == AUTOMATION_OUTPUT_DLL_ACTIVITY)
        return g_dllActivityLines;
    if (target == AUTOMATION_OUTPUT_INJGEN)
        return g_injGenLines;
    if (target == AUTOMATION_OUTPUT_FILECHECK)
        return g_fileCheckLines;
    if (target == AUTOMATION_OUTPUT_CLIPBOARD)
        return g_clipboardLines;
    return g_bamLines;
}

static void ClampAutomationScrollOffsetLocked(int target)
{
    std::vector<std::wstring>& lines = AutomationLinesRef(target);
    int& scroll = AutomationScrollRef(target);
    int maxOffset = GetMaxAutomationScrollOffsetLocked(target, lines);

    if (scroll < 0)
        scroll = 0;

    if (scroll > maxOffset)
        scroll = maxOffset;
}

static void SetAutomationLines(int target, std::vector<std::wstring> lines)
{
    if (target != AUTOMATION_OUTPUT_FILECHECK)
        LimitAutomationLines(lines);

    std::lock_guard<std::mutex> lock(g_automationMutex);
    AutomationLinesRef(target) = std::move(lines);
    AutomationScrollRef(target) = 0;
}

static void SetAutomationStatusLine(int target, const std::wstring& status)
{
    std::lock_guard<std::mutex> lock(g_automationMutex);
    AutomationLinesRef(target).assign(1, status);
    AutomationScrollRef(target) = 0;
}

static void GetAutomationSnapshot(int target, std::vector<std::wstring>& lines, int& scrollOffset)
{
    std::lock_guard<std::mutex> lock(g_automationMutex);
    ClampAutomationScrollOffsetLocked(target);
    lines = AutomationLinesRef(target);
    scrollOffset = AutomationScrollRef(target);
}


static std::wstring JoinAutomationLinesForEdit(const std::vector<std::wstring>& lines)
{
    std::wstring text;
    for (const std::wstring& line : lines)
    {
        text += line;
        text += L"\r\n";
    }
    return text;
}

static void SyncAutomationEditScrollToState(int target);

static void UpdateHistoryEditWindow();

static HWND AutomationEditForTarget(int target)
{
    if (target == AUTOMATION_OUTPUT_EVENTVWR) return g_hEventEdit;
    if (target == AUTOMATION_OUTPUT_JAR_ACTIVITY) return g_hJarEdit;
    if (target == AUTOMATION_OUTPUT_JAR_MODIFIED) return nullptr;
    if (target == AUTOMATION_OUTPUT_EXE_DELETED) return g_hExeEdit;
    if (target == AUTOMATION_OUTPUT_PF_DELETED) return g_hPfEdit;
    if (target == AUTOMATION_OUTPUT_MC_LOGS) return g_hMcEdit;
    return nullptr;
}


static void SyncAutomationEditScrollToState(int target)
{
    HWND edit = AutomationEditForTarget(target);
    if (!edit)
        return;

    int wanted = 0;
    {
        std::lock_guard<std::mutex> lock(g_automationMutex);
        wanted = AutomationScrollRef(target);
    }

    int current = static_cast<int>(SendMessageW(edit, EM_GETFIRSTVISIBLELINE, 0, 0));
    int diff = wanted - current;
    if (diff != 0)
        SendMessageW(edit, EM_LINESCROLL, 0, diff);
}

static void UpdateAutomationEditWindow(int target)
{
    HWND edit = AutomationEditForTarget(target);
    if (!edit || g_destroying.load())
        return;
    std::vector<std::wstring> lines;
    {
        std::lock_guard<std::mutex> lock(g_automationMutex);
        lines = AutomationLinesRef(target);
    }
    std::wstring text = JoinAutomationLinesForEdit(lines);
    SetWindowTextW(edit, text.c_str());
    if (target == AUTOMATION_OUTPUT_EVENTVWR)
        ShowScrollBar(edit, SB_BOTH, FALSE);
    SyncAutomationEditScrollToState(target);
}

static void UpdateHistoryEditWindow()
{
    UpdateAutomationEditWindow(AUTOMATION_OUTPUT_EVENTVWR);
}

static HWND AutomationEditForTarget(int target);
static void SyncAutomationEditScrollToState(int target);

static bool ScrollAutomationOutput(int target, int wheelDelta)
{
    std::lock_guard<std::mutex> lock(g_automationMutex);

    std::vector<std::wstring>& lines = AutomationLinesRef(target);
    int maxOffset = GetMaxAutomationScrollOffsetLocked(target, lines);

    if (maxOffset <= 0)
        return false;

    int& scroll = AutomationScrollRef(target);
    int oldOffset = scroll;
    int step = std::max(1, std::abs(wheelDelta) / WHEEL_DELTA) * 3;

    if (wheelDelta > 0)
        scroll -= step;
    else if (wheelDelta < 0)
        scroll += step;

    ClampAutomationScrollOffsetLocked(target);
    bool changed = scroll != oldOffset;
    if (changed)
    {
    }
    return changed;
}

static RECT GetAutomationPanelRectForTarget(int target, const RECT& rc)
{
    if (target == AUTOMATION_OUTPUT_EVENTVWR) return GetAutomationEventPanelRect(rc);
    if (target == AUTOMATION_OUTPUT_JAR_ACTIVITY) return GetJarActivityPanelRect(rc);
    if (target == AUTOMATION_OUTPUT_JAR_MODIFIED) return GetJarModifiedPanelRect(rc);
    if (target == AUTOMATION_OUTPUT_EXE_DELETED) return GetExeDeletedPanelRect(rc);
    if (target == AUTOMATION_OUTPUT_PF_DELETED) return GetPfDeletedPanelRect(rc);
    if (target == AUTOMATION_OUTPUT_MC_LOGS) return GetMcLogsPanelRect(rc);
    if (target == AUTOMATION_OUTPUT_PAGE4) return (g_currentPage == 1) ? GetAutomationBamPanelRect(rc) : GetPage4PanelRect(rc);
    if (target == AUTOMATION_OUTPUT_DLL_UNSIGNED) return GetDllUnsignedPanelRect(rc);
    if (target == AUTOMATION_OUTPUT_DLL_ACTIVITY) return GetDllActivityPanelRect(rc);
    if (target == AUTOMATION_OUTPUT_FILECHECK) return GetFileCheckPanelRect(rc);
    if (target == AUTOMATION_OUTPUT_CLIPBOARD) return GetClipPanelRect(rc);
    if (target == AUTOMATION_OUTPUT_INJGEN) { RECT empty{}; return empty; }
    return GetAutomationBamPanelRect(rc);
}

static bool GetAutomationScrollGeometryLocked(int target, const RECT& panel, float& trackX, float& trackY, float& trackH, float& thumbH, int& maxOffset)
{
    std::vector<std::wstring>& lines = AutomationLinesRef(target);
    size_t visible = GetAutomationVisibleLineCapacity(target);
    if (lines.size() <= visible)
        return false;

    maxOffset = std::max<int>(1, static_cast<int>(lines.size()) - static_cast<int>(visible));
    float panelW = static_cast<float>(panel.right - panel.left);
    float panelH = static_cast<float>(panel.bottom - panel.top);
    trackX = static_cast<float>(panel.left) + panelW - 10.0f;
    trackY = static_cast<float>(panel.top) + 28.0f;
    trackH = panelH - 40.0f;
    if (trackH < 24.0f)
        return false;
    thumbH = std::max(22.0f, trackH * (static_cast<float>(visible) / static_cast<float>(lines.size())));
    if (thumbH > trackH)
        thumbH = trackH;
    return true;
}

static bool HitAutomationScrollTrack(int target, POINT pt)
{
    if (!g_hMain)
        return false;
    RECT rc{};
    GetClientRect(g_hMain, &rc);
    RECT panel = GetAutomationPanelRectForTarget(target, rc);

    std::lock_guard<std::mutex> lock(g_automationMutex);
    float trackX = 0.0f, trackY = 0.0f, trackH = 0.0f, thumbH = 0.0f;
    int maxOffset = 0;
    if (!GetAutomationScrollGeometryLocked(target, panel, trackX, trackY, trackH, thumbH, maxOffset))
        return false;

    return pt.x >= static_cast<int>(trackX - 18.0f) && pt.x <= static_cast<int>(trackX + 18.0f) &&
        pt.y >= static_cast<int>(trackY) && pt.y <= static_cast<int>(trackY + trackH);
}

static bool SetAutomationScrollFromPoint(int target, POINT pt)
{
    if (!g_hMain)
        return false;

    RECT rc{};
    GetClientRect(g_hMain, &rc);
    RECT panel = GetAutomationPanelRectForTarget(target, rc);

    std::lock_guard<std::mutex> lock(g_automationMutex);
    float trackX = 0.0f, trackY = 0.0f, trackH = 0.0f, thumbH = 0.0f;
    int maxOffset = 0;
    if (!GetAutomationScrollGeometryLocked(target, panel, trackX, trackY, trackH, thumbH, maxOffset))
        return false;

    int& scroll = AutomationScrollRef(target);
    int oldScroll = scroll;
    float usable = std::max(1.0f, trackH - thumbH);
    float pos = static_cast<float>(pt.y) - trackY - thumbH * 0.5f;
    if (pos < 0.0f) pos = 0.0f;
    if (pos > usable) pos = usable;

    float ratio = pos / usable;
    scroll = static_cast<int>(ratio * static_cast<float>(maxOffset) + 0.5f);
    ClampAutomationScrollOffsetLocked(target);
    return scroll != oldScroll;
}

static int AutomationScrollTargetAtPoint(POINT pt)
{
    if (!g_hMain)
        return 0;

    RECT rc{};
    GetClientRect(g_hMain, &rc);

    int targetsPage1[] = { AUTOMATION_OUTPUT_PAGE4, AUTOMATION_OUTPUT_EVENTVWR };
    int targetsPage2[] = { AUTOMATION_OUTPUT_JAR_ACTIVITY, AUTOMATION_OUTPUT_DLL_ACTIVITY };
    int targetsPage3[] = { AUTOMATION_OUTPUT_PAGE4 };
    int targetsPage5[] = { AUTOMATION_OUTPUT_FILECHECK, AUTOMATION_OUTPUT_DLL_UNSIGNED };
    const int* targets = nullptr;
    int count = 0;
    if (g_currentPage == 1) { targets = targetsPage1; count = 2; }
    else if (g_currentPage == 2) { targets = targetsPage2; count = 2; }
    else if (g_currentPage == 3) { targets = targetsPage3; count = 1; }
    else if (g_currentPage == 5) { targets = targetsPage5; count = 2; }

    for (int i = 0; i < count; ++i)
    {
        RECT panel = GetAutomationPanelRectForTarget(targets[i], rc);
        if (PointInRect(panel, pt) && HitAutomationScrollTrack(targets[i], pt))
            return targets[i];
    }

    return 0;
}

static void InvalidateAutomationPanel(int target)
{
    HWND hwnd = g_hMain;

    if (!hwnd || g_destroying.load())
        return;

    RECT rc{};
    GetClientRect(hwnd, &rc);
    RECT panel{};
    if (target == AUTOMATION_OUTPUT_EVENTVWR)
        panel = GetAutomationEventPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_JAR_ACTIVITY)
        panel = GetJarActivityPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_JAR_MODIFIED)
        panel = GetJarModifiedPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_EXE_DELETED)
        panel = GetExeDeletedPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_PF_DELETED)
        panel = GetPfDeletedPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_MC_LOGS)
        panel = GetMcLogsPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_PAGE4)
        panel = (g_currentPage == 1) ? GetAutomationBamPanelRect(rc) : GetPage4PanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_DLL_UNSIGNED)
        panel = GetDllUnsignedPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_DLL_ACTIVITY)
        panel = GetDllActivityPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_INJGEN)
        SetRectEmpty(&panel);
    else if (target == AUTOMATION_OUTPUT_FILECHECK)
        panel = GetFileCheckPanelRect(rc);
    else if (target == AUTOMATION_OUTPUT_CLIPBOARD)
        panel = GetClipPanelRect(rc);
    else
        panel = GetAutomationBamPanelRect(rc);
    InflateRect(&panel, 10, 10);
    InvalidateRect(hwnd, &panel, FALSE);
}

static void PostAutomationDone(int target, std::vector<std::wstring>&& lines)
{
    HWND hwnd = g_hMain;

    if (!hwnd || g_destroying.load())
        return;

    AutomationResult* result = new (std::nothrow) AutomationResult();

    if (!result)
        return;

    result->target = target;
    result->lines = std::move(lines);

    if (!PostMessageW(hwnd, WM_APP_AUTOMATION_DONE, 0, reinterpret_cast<LPARAM>(result)))
        delete result;
}

static std::atomic_bool& AutomationWorkingRef(int target)
{
    if (target == AUTOMATION_OUTPUT_EVENTVWR)
        return g_automationEventWorking;
    if (target == AUTOMATION_OUTPUT_JAR_ACTIVITY)
        return g_automationJarWorking;
    if (target == AUTOMATION_OUTPUT_JAR_MODIFIED)
        return g_automationJarModifiedWorking;
    if (target == AUTOMATION_OUTPUT_EXE_DELETED)
        return g_automationExeWorking;
    if (target == AUTOMATION_OUTPUT_PF_DELETED)
        return g_automationPfWorking;
    if (target == AUTOMATION_OUTPUT_MC_LOGS)
        return g_automationMcLogsWorking;
    if (target == AUTOMATION_OUTPUT_PAGE4)
        return g_automationPage4Working;
    if (target == AUTOMATION_OUTPUT_DLL_UNSIGNED)
        return g_automationDllWorking;
    if (target == AUTOMATION_OUTPUT_DLL_ACTIVITY)
        return g_automationDllActivityWorking;
    if (target == AUTOMATION_OUTPUT_INJGEN)
        return g_automationInjGenWorking;
    if (target == AUTOMATION_OUTPUT_FILECHECK)
        return g_automationFileCheckWorking;
    return g_automationBamWorking;
}

enum class BamSignatureState
{
    Deleted,
    Signed,
    NotSigned
};

struct BamEntry
{
    std::wstring exeName;
    std::wstring path;
    std::wstring when;
    std::wstring sid;
    BamSignatureState signature = BamSignatureState::NotSigned;
    ULONGLONG fileTimeValue = 0;
};

static bool PathExistsAndIsFile(const std::wstring& path)
{
    if (path.empty() || path.rfind(L"\\Device\\", 0) == 0)
        return false;

    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static bool IsFileAuthenticodeSigned(const std::wstring& path)
{
    if (!PathExistsAndIsFile(path))
        return false;

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policyGuid, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &trustData);

    return status == ERROR_SUCCESS;
}

static BamSignatureState GetBamSignatureState(const std::wstring& path)
{
    if (!PathExistsAndIsFile(path))
        return BamSignatureState::Deleted;

    return IsFileAuthenticodeSigned(path) ? BamSignatureState::Signed : BamSignatureState::NotSigned;
}

static std::wstring BamSignatureStateText(BamSignatureState state)
{
    switch (state)
    {
    case BamSignatureState::Signed:
        return L"Signed";
    case BamSignatureState::Deleted:
        return L"Deleted";
    case BamSignatureState::NotSigned:
    default:
        return L"Not signed";
    }
}

static ULONGLONG FileTimeToUInt64(const FILETIME& ft)
{
    ULARGE_INTEGER value{};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

static std::wstring ShortSidTail(const std::wstring& sid)
{
    size_t pos = sid.find_last_of(L'-');
    if (pos == std::wstring::npos || pos + 1 >= sid.size())
        return sid;

    return L"...-" + sid.substr(pos + 1);
}

static void AppendBamRegistryKey(const wchar_t* subPath, bool unsignedOnly, std::vector<BamEntry>& rows, std::vector<std::wstring>& notes)
{
    HKEY root = nullptr;
    LONG openResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath, 0, KEY_READ | KEY_WOW64_64KEY, &root);
    if (openResult != ERROR_SUCCESS)
        openResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath, 0, KEY_READ | KEY_WOW64_32KEY, &root);
    if (openResult != ERROR_SUCCESS)
        openResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath, 0, KEY_READ, &root);

    if (openResult != ERROR_SUCCESS)
    {
        notes.push_back(L"BAM: не удалось открыть HKLM\\" + std::wstring(subPath) + L".");
        return;
    }

    DWORD subKeyCount = 0;
    DWORD maxSubKeyLen = 0;
    if (RegQueryInfoKeyW(root, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKeyLen, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
    {
        notes.push_back(L"BAM: не удалось прочитать список SID в HKLM\\" + std::wstring(subPath) + L".");
        RegCloseKey(root);
        return;
    }

    for (DWORD i = 0; i < subKeyCount; ++i)
    {
        std::vector<wchar_t> sid(maxSubKeyLen + 2, L'\0');
        DWORD sidLen = static_cast<DWORD>(sid.size());

        if (RegEnumKeyExW(root, i, sid.data(), &sidLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            continue;

        std::wstring sidText(sid.data(), sidLen);
        HKEY userKey = nullptr;

        if (RegOpenKeyExW(root, sidText.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &userKey) != ERROR_SUCCESS)
            continue;

        DWORD valueCount = 0;
        DWORD maxValueNameLen = 0;
        DWORD maxValueDataLen = 0;
        if (RegQueryInfoKeyW(userKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valueCount, &maxValueNameLen, &maxValueDataLen, nullptr, nullptr) != ERROR_SUCCESS)
        {
            RegCloseKey(userKey);
            continue;
        }

        for (DWORD valueIndex = 0; valueIndex < valueCount; ++valueIndex)
        {
            std::vector<wchar_t> valueName(maxValueNameLen + 2, L'\0');
            std::vector<BYTE> valueData(std::max<DWORD>(maxValueDataLen + 2, sizeof(FILETIME)));
            DWORD valueNameLen = static_cast<DWORD>(valueName.size());
            DWORD valueDataLen = static_cast<DWORD>(valueData.size());
            DWORD type = 0;

            LONG enumResult = RegEnumValueW(userKey, valueIndex, valueName.data(), &valueNameLen, nullptr, &type, valueData.data(), &valueDataLen);

            if (enumResult != ERROR_SUCCESS || valueNameLen == 0 || type != REG_BINARY)
                continue;

            std::wstring rawPath(valueName.data(), valueNameLen);
            std::wstring displayPath = DevicePathToDosPath(rawPath);

            FILETIME ft{};
            std::wstring when = L"дата неизвестна";
            ULONGLONG ftValue = 0;

            if (TryReadBamFileTime(valueData.data(), valueDataLen, ft))
            {
                when = FileTimeToLocalText(ft);
                ftValue = FileTimeToUInt64(ft);
            }

            BamSignatureState signature = GetBamSignatureState(displayPath);

            // unsignedOnly означает строго только unsigned/not signed.
            // Deleted/отсутствующие файлы и signed в BAM не выводим.
            if (unsignedOnly && signature != BamSignatureState::NotSigned)
                continue;

            BamEntry entry;
            entry.exeName = ExtractFileNameOnly(displayPath);
            entry.path = displayPath;
            entry.when = when;
            entry.sid = ShortSidTail(sidText);
            entry.signature = signature;
            entry.fileTimeValue = ftValue;
            rows.push_back(std::move(entry));
        }

        RegCloseKey(userKey);
    }

    RegCloseKey(root);
}

static std::vector<std::wstring> ScanBamRegistry(bool unsignedOnly)
{
    // BAM в интерфейсе всегда выводит только unsigned/not signed файлы.
    unsignedOnly = true;

    std::vector<std::wstring> lines;
    std::vector<std::wstring> notes;
    std::vector<BamEntry> rows;

    const wchar_t* subPaths[] =
    {
        L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
        L"SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings",
        L"SYSTEM\\ControlSet001\\Services\\bam\\UserSettings",
        L"SYSTEM\\ControlSet002\\Services\\bam\\State\\UserSettings",
        L"SYSTEM\\ControlSet002\\Services\\bam\\UserSettings"
    };

    for (const wchar_t* subPath : subPaths)
        AppendBamRegistryKey(subPath, unsignedOnly, rows, notes);

    std::sort(rows.begin(), rows.end(), [](const BamEntry& a, const BamEntry& b)
    {
        if (a.fileTimeValue == 0 && b.fileTimeValue != 0)
            return false;

        if (a.fileTimeValue != 0 && b.fileTimeValue == 0)
            return true;

        if (a.fileTimeValue != b.fileTimeValue)
            return a.fileTimeValue < b.fileTimeValue;

        return ToLowerCopy(a.path) < ToLowerCopy(b.path);
    });

    rows.erase(std::unique(rows.begin(), rows.end(), [](const BamEntry& a, const BamEntry& b)
    {
        return ToLowerCopy(a.path) == ToLowerCopy(b.path) && a.fileTimeValue == b.fileTimeValue;
    }), rows.end());

    lines.push_back(L"дата | программа | путь | подпись");

    if (rows.empty())
    {
        if (unsignedOnly)
            lines.push_back(L"unsigned записей не найдено или все записи похожи на системные.");
        else
            lines.push_back(L"пользовательских запусков не найдено или все найденные записи похожи на системные.");

        return lines;
    }

    for (const BamEntry& entry : rows)
    {
        lines.push_back(entry.when + L" | " + entry.exeName + L" | " + entry.path + L" | " + BamSignatureStateText(entry.signature));
    }

    return lines;
}


static bool IsSearchIndexerEventText(const std::wstring& text)
{
    std::wstring lower = ToLowerCopy(text);
    return lower.find(L"searchindexer") != std::wstring::npos ||
        lower.find(L"searchindexer.exe") != std::wstring::npos;
}

struct CompactEventRow
{
    DWORD eventId = 0;
    std::wstring timeText;
    std::wstring message;
    long long sortKey = 0;
};

static void AppendEventLogMatches(std::vector<CompactEventRow>& rows, const wchar_t* channel, DWORD eventId, DWORD maxRows)
{
    std::wstring query = L"*[System[(EventID=" + std::to_wstring(eventId) + L")]]";
    EVT_HANDLE queryHandle = EvtQuery(nullptr, channel, query.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection);

    if (!queryHandle)
        return;

    EVT_HANDLE events[16]{};
    DWORD returned = 0;
    DWORD collected = 0;
    DWORD scanned = 0;
    const DWORD scanLimit = std::max<DWORD>(maxRows * 4, maxRows + 32);
    std::map<std::wstring, EVT_HANDLE> metadataCache;

    while (collected < maxRows && scanned < scanLimit && EvtNext(queryHandle, static_cast<DWORD>((sizeof(events) / sizeof(events[0]))), events, 0, 0, &returned))
    {
        for (DWORD i = 0; i < returned && collected < maxRows && scanned < scanLimit; ++i)
        {
            ++scanned;
            std::wstring xml = RenderEventXml(events[i]);
            std::wstring provider = ExtractXmlAttribute(xml, L"Provider", L"Name");
            std::wstring isoTime = ExtractXmlAttribute(xml, L"TimeCreated", L"SystemTime");
            std::wstring localTime;

            if (!IsoUtcTextToLocalIsoText(isoTime, localTime))
                localTime = isoTime.empty() ? L"дата неизвестна" : isoTime;

            std::wstring detail = ExtractAllXmlDataText(xml);

            if (IsSearchIndexerEventText(xml) || IsSearchIndexerEventText(provider) || IsSearchIndexerEventText(detail))
            {
                EvtClose(events[i]);
                events[i] = nullptr;
                continue;
            }

            CompactEventRow row;
            row.eventId = eventId;
            row.timeText = localTime;
            std::wstring formatted = FormatEventMessageFromMetadataCached(events[i], provider, metadataCache);
            row.message = BuildCompactEventMessage(eventId, xml, provider, formatted);
            row.sortKey = IsoUtcTextToSortKey(isoTime);
            rows.push_back(std::move(row));
            ++collected;

            EvtClose(events[i]);
            events[i] = nullptr;
        }
    }

    for (EVT_HANDLE& eventHandle : events)
    {
        if (eventHandle)
        {
            EvtClose(eventHandle);
            eventHandle = nullptr;
        }
    }

    for (auto& item : metadataCache)
    {
        if (item.second)
            EvtClose(item.second);
    }

    EvtClose(queryHandle);
}

static std::vector<std::wstring> ScanEventViewerLogs()
{
    std::vector<CompactEventRow> rows;
    rows.reserve(128);

    AppendEventLogMatches(rows, L"System", 104, AUTOMATION_EVENT_MAX_PER_CHANNEL);
    AppendEventLogMatches(rows, L"Microsoft-Windows-Ntfs/Operational", 501, AUTOMATION_EVENT_MAX_PER_CHANNEL);
    AppendEventLogMatches(rows, L"Application", 3079, AUTOMATION_EVENT_MAX_PER_CHANNEL);

    std::stable_sort(rows.begin(), rows.end(), [](const CompactEventRow& a, const CompactEventRow& b)
    {
        if (a.sortKey != b.sortKey)
            return a.sortKey > b.sortKey;
        return a.eventId < b.eventId;
    });

    std::vector<std::wstring> lines;
    for (const CompactEventRow& row : rows)
    {
        lines.push_back(L"ID " + std::to_wstring(row.eventId) + L" | " + row.timeText + L" | " + row.message);
    }

    if (lines.empty())
        lines.push_back(L"не найдено");

    return lines;
}

static std::wstring DecodeAutomationTextBytes(const std::vector<BYTE>& bytes)
{
    if (bytes.empty())
        return L"";

    const BYTE* data = bytes.data();
    int size = static_cast<int>(bytes.size());

    if (size >= 2 && data[0] == 0xFF && data[1] == 0xFE)
        return std::wstring(reinterpret_cast<const wchar_t*>(data + 2), (size - 2) / 2);

    if (size >= 2 && data[0] == 0xFE && data[1] == 0xFF)
    {
        std::wstring out;
        for (int i = 2; i + 1 < size; i += 2)
            out.push_back(static_cast<wchar_t>((data[i] << 8) | data[i + 1]));
        return out;
    }

    UINT cp = CP_UTF8;
    int offset = 0;
    DWORD flags = MB_ERR_INVALID_CHARS;

    if (size >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
        offset = 3;

    int needed = MultiByteToWideChar(cp, flags, reinterpret_cast<const char*>(data + offset), size - offset, nullptr, 0);

    if (needed <= 0)
    {
        cp = CP_OEMCP;
        flags = 0;
        offset = 0;
        needed = MultiByteToWideChar(cp, flags, reinterpret_cast<const char*>(data), size, nullptr, 0);
    }

    if (needed <= 0)
        return L"";

    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(cp, flags, reinterpret_cast<const char*>(data + offset), size - offset, &out[0], needed);
    return out;
}

static std::vector<std::wstring> SplitAutomationTextLines(const std::wstring& text)
{
    std::vector<std::wstring> lines;
    std::wstring current;

    for (wchar_t ch : text)
    {
        if (ch == L'\r')
            continue;

        if (ch == L'\n')
        {
            for (wchar_t& c : current)
            {
                if (c == L'\t')
                    c = L' ';
            }
            lines.push_back(current);
            current.clear();
            continue;
        }

        current.push_back(ch);
    }

    if (!current.empty())
    {
        for (wchar_t& c : current)
        {
            if (c == L'\t')
                c = L' ';
        }
        lines.push_back(current);
    }

    return lines;
}

static void AppendWrappedAutomationLine(std::vector<std::wstring>& lines, const std::wstring& line, size_t maxChars = 150)
{
    if (line.size() <= maxChars)
    {
        lines.push_back(line);
        return;
    }

    size_t pos = 0;
    while (pos < line.size())
    {
        size_t take = std::min(maxChars, line.size() - pos);
        size_t breakAt = std::wstring::npos;

        if (take == maxChars)
        {
            size_t end = pos + take;
            for (size_t i = end; i > pos + maxChars / 2; --i)
            {
                wchar_t ch = line[i - 1];
                if (ch == L' ' || ch == L'|' || ch == L',' || ch == L';' || ch == L'\\' || ch == L'/')
                {
                    breakAt = i;
                    break;
                }
            }
        }

        if (breakAt != std::wstring::npos && breakAt > pos)
            take = breakAt - pos;

        std::wstring part = line.substr(pos, take);
        if (pos != 0)
            part = L"  " + part;
        lines.push_back(part);
        pos += take;
    }
}

static void AppendWrappedAutomationLines(std::vector<std::wstring>& out, const std::vector<std::wstring>& src, size_t maxChars = 150)
{
    for (const std::wstring& line : src)
        AppendWrappedAutomationLine(out, line, maxChars);
}

static std::mutex g_childProcessMutex;
static std::vector<HANDLE> g_childProcesses;

// Every hidden child process (curl / powershell / bitsadmin / 7z) is tracked
// so cancelling can kill it immediately instead of waiting out its full
// timeout, which is what used to make cancel look frozen.
static void RegisterChildProcess(HANDLE process)
{
    if (!process || process == INVALID_HANDLE_VALUE)
        return;

    std::lock_guard<std::mutex> lock(g_childProcessMutex);
    g_childProcesses.push_back(process);
}

// Must run before the owner closes the handle, otherwise a cancel could
// terminate a recycled handle value.
static void UnregisterChildProcess(HANDLE process)
{
    if (!process || process == INVALID_HANDLE_VALUE)
        return;

    std::lock_guard<std::mutex> lock(g_childProcessMutex);
    g_childProcesses.erase(
        std::remove(g_childProcesses.begin(), g_childProcesses.end(), process),
        g_childProcesses.end());
}

// Убивает процесс и всех его потомков (powershell -> 7z/fsutil/curl и т.д.).
// Раньше отмена убивала только зарегистрированный корневой процесс, а его дети
// оставались работать сиротами и держали пайпы/файлы — отмена выглядела зависшей.
static void KillProcessTreeById(DWORD rootPid)
{
    if (rootPid == 0 || rootPid == GetCurrentProcessId())
        return;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE)
    {
        HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, rootPid);

        if (process)
        {
            TerminateProcess(process, 1);
            CloseHandle(process);
        }

        return;
    }

    std::vector<std::pair<DWORD, DWORD>> processes;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            processes.push_back(std::make_pair(pe.th32ProcessID, pe.th32ParentProcessID));
        }
        while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);

    // BFS по дереву потомков.
    std::vector<DWORD> tree;
    tree.push_back(rootPid);

    for (size_t i = 0; i < tree.size(); ++i)
    {
        for (const auto& entry : processes)
        {
            if (entry.second != tree[i] || entry.first == 0)
                continue;

            if (std::find(tree.begin(), tree.end(), entry.first) == tree.end())
                tree.push_back(entry.first);
        }
    }

    // Убиваем с конца списка: сначала самых глубоких потомков, корень — последним.
    for (auto it = tree.rbegin(); it != tree.rend(); ++it)
    {
        if (*it == GetCurrentProcessId())
            continue;

        HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, *it);

        if (process)
        {
            TerminateProcess(process, 1);
            CloseHandle(process);
        }
    }
}

static void TerminateTrackedChildProcesses()
{
    std::vector<HANDLE> processes;

    {
        std::lock_guard<std::mutex> lock(g_childProcessMutex);
        processes = g_childProcesses;
    }

    for (HANDLE process : processes)
    {
        DWORD pid = GetProcessId(process);

        if (pid != 0)
            KillProcessTreeById(pid);
        else
            TerminateProcess(process, 1);
    }
}

static bool RunHiddenCommandCapture(const std::wstring& command, std::wstring& output, DWORD timeoutMs)
{
    output.clear();
    g_lastHiddenProcessTimedOut = false;
    g_lastHiddenProcessExitCode = STILL_ACTIVE;
    g_lastHiddenProcessCreateError = 0;
    DebugLogLine(L"process", L"cmd start timeout=" + std::to_wstring(timeoutMs) + L" command=" + command);

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0))
    {
        DebugLogLine(L"process", L"cmd CreatePipe failed error=" + FormatWin32ErrorForLog(GetLastError()));
        return false;
    }

    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::wstring cmdLine = L"cmd.exe /d /c " + command;

    BOOL ok = CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

    if (ok)
        RegisterChildProcess(pi.hProcess);
    CloseHandle(writePipe);

    if (!ok)
    {
        g_lastHiddenProcessCreateError = GetLastError();
        DebugLogLine(L"process", L"cmd CreateProcess failed error=" + FormatWin32ErrorForLog(g_lastHiddenProcessCreateError));
        CloseHandle(readPipe);
        return false;
    }

    std::vector<BYTE> bytes;
    const DWORD chunkSize = 4096;
    BYTE buffer[chunkSize];
    DWORD startTick = GetTickCount();
    bool timedOut = false;

    for (;;)
    {
        DWORD available = 0;
        if (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) && available > 0)
        {
            DWORD read = 0;
            if (ReadFile(readPipe, buffer, std::min<DWORD>(chunkSize, available), &read, nullptr) && read > 0)
                bytes.insert(bytes.end(), buffer, buffer + read);
        }

        // Отмена: убиваем всё дерево процесса и выходим, не дожидаясь таймаута.
        // Во время удаления (g_deleteInProgress) свои служебные команды не трогаем.
        if ((g_cancelRequested.load() || g_scanCancelRequested.load()) && !g_deleteInProgress.load())
        {
            KillProcessTreeById(pi.dwProcessId);
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 800);
            break;
        }

        DWORD wait = WaitForSingleObject(pi.hProcess, 100);
        if (wait == WAIT_OBJECT_0)
        {
            for (;;)
            {
                DWORD availableTail = 0;
                if (!PeekNamedPipe(readPipe, nullptr, 0, nullptr, &availableTail, nullptr) || availableTail == 0)
                    break;

                DWORD read = 0;
                if (!ReadFile(readPipe, buffer, std::min<DWORD>(chunkSize, availableTail), &read, nullptr) || read == 0)
                    break;

                bytes.insert(bytes.end(), buffer, buffer + read);
            }
            break;
        }

        if (GetTickCount() - startTick > timeoutMs)
        {
            timedOut = true;
            KillProcessTreeById(pi.dwProcessId);
            TerminateProcess(pi.hProcess, 1);
            break;
        }
    }

    DWORD exitCode = STILL_ACTIVE;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    g_lastHiddenProcessTimedOut = timedOut;
    g_lastHiddenProcessExitCode = exitCode;
    DebugLogLine(L"process", L"cmd finish timedOut=" + std::to_wstring(timedOut ? 1 : 0) +
        L" exit=" + std::to_wstring(exitCode) + L" bytes=" + std::to_wstring(bytes.size()));

    CloseHandle(pi.hThread);
    UnregisterChildProcess(pi.hProcess);
    CloseHandle(pi.hProcess);
    CloseHandle(readPipe);

    output = DecodeAutomationTextBytes(bytes);

    if (timedOut)
    {
        if (!output.empty())
            output += L"\n";
        output += L"fsutil: команда остановлена по таймауту.";
    }

    return true;
}



static bool RunHiddenProcessCapture(const std::wstring& exePath, const std::wstring& arguments, std::wstring& output, DWORD timeoutMs)
{
    output.clear();
    g_lastHiddenProcessTimedOut = false;
    g_lastHiddenProcessExitCode = STILL_ACTIVE;
    g_lastHiddenProcessCreateError = 0;
    DebugLogLine(L"process", L"process start exe=" + exePath + L" timeout=" + std::to_wstring(timeoutMs) + L" args=" + arguments);

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0))
    {
        DebugLogLine(L"process", L"process CreatePipe failed exe=" + exePath + L" error=" + FormatWin32ErrorForLog(GetLastError()));
        return false;
    }

    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::wstring cmdLine = L"\"" + exePath + L"\"";
    if (!arguments.empty())
        cmdLine += L" " + arguments;

    LPCWSTR appName = (exePath.find(L"\\") != std::wstring::npos || exePath.find(L":") != std::wstring::npos) ? exePath.c_str() : nullptr;
    BOOL ok = CreateProcessW(appName, &cmdLine[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

    if (ok)
        RegisterChildProcess(pi.hProcess);
    CloseHandle(writePipe);

    if (!ok)
    {
        g_lastHiddenProcessCreateError = GetLastError();
        DebugLogLine(L"process", L"process CreateProcess failed exe=" + exePath + L" error=" + FormatWin32ErrorForLog(g_lastHiddenProcessCreateError));
        CloseHandle(readPipe);
        return false;
    }

    std::vector<BYTE> bytes;
    const DWORD chunkSize = 4096;
    BYTE buffer[chunkSize];
    DWORD startTick = GetTickCount();
    bool timedOut = false;

    for (;;)
    {
        DWORD available = 0;
        if (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) && available > 0)
        {
            DWORD read = 0;
            if (ReadFile(readPipe, buffer, std::min<DWORD>(chunkSize, available), &read, nullptr) && read > 0)
                bytes.insert(bytes.end(), buffer, buffer + read);
        }

        // Отмена: убиваем всё дерево процесса и выходим, не дожидаясь таймаута.
        // Во время удаления (g_deleteInProgress) свои служебные команды не трогаем.
        if ((g_cancelRequested.load() || g_scanCancelRequested.load()) && !g_deleteInProgress.load())
        {
            KillProcessTreeById(pi.dwProcessId);
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 800);
            break;
        }

        DWORD wait = WaitForSingleObject(pi.hProcess, 100);
        if (wait == WAIT_OBJECT_0)
        {
            for (;;)
            {
                DWORD availableTail = 0;
                if (!PeekNamedPipe(readPipe, nullptr, 0, nullptr, &availableTail, nullptr) || availableTail == 0)
                    break;

                DWORD read = 0;
                if (!ReadFile(readPipe, buffer, std::min<DWORD>(chunkSize, availableTail), &read, nullptr) || read == 0)
                    break;

                bytes.insert(bytes.end(), buffer, buffer + read);
            }
            break;
        }

        if (GetTickCount() - startTick > timeoutMs)
        {
            timedOut = true;
            KillProcessTreeById(pi.dwProcessId);
            TerminateProcess(pi.hProcess, 1);
            break;
        }
    }

    DWORD exitCode = STILL_ACTIVE;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    g_lastHiddenProcessTimedOut = timedOut;
    g_lastHiddenProcessExitCode = exitCode;
    DebugLogLine(L"process", L"process finish exe=" + exePath + L" timedOut=" + std::to_wstring(timedOut ? 1 : 0) +
        L" exit=" + std::to_wstring(exitCode) + L" bytes=" + std::to_wstring(bytes.size()));

    CloseHandle(pi.hThread);
    UnregisterChildProcess(pi.hProcess);
    CloseHandle(pi.hProcess);
    CloseHandle(readPipe);

    output = DecodeAutomationTextBytes(bytes);

    if (timedOut)
    {
        if (!output.empty())
            output += L"\n";
        output += L"команда остановлена по таймауту.";
    }

    return true;
}

static bool WriteUtf16LeTextFileLocal(const std::wstring& path, const std::wstring& text)
{
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;

    const BYTE bom[2] = { 0xFF, 0xFE };
    DWORD written = 0;
    BOOL ok = WriteFile(file, bom, 2, &written, nullptr);

    if (ok && !text.empty())
    {
        DWORD bytes = static_cast<DWORD>(text.size() * sizeof(wchar_t));
        ok = WriteFile(file, text.data(), bytes, &written, nullptr);
    }

    CloseHandle(file);
    return ok != FALSE;
}

static bool EnsureDirectoryLocalEarly(const std::wstring& path)
{
    if (path.empty())
        return false;

    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
        return true;

    int r = SHCreateDirectoryExW(nullptr, path.c_str(), nullptr);
    attr = GetFileAttributesW(path.c_str());
    return r == ERROR_SUCCESS || r == ERROR_ALREADY_EXISTS ||
        (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
}

static std::wstring CombinePathLocalEarly(const std::wstring& a, const std::wstring& b)
{
    if (a.empty())
        return b;
    if (b.empty())
        return a;
    if (b.size() >= 2 && b[1] == L':')
        return b;
    if (b[0] == L'\\' || b[0] == L'/')
        return b;

    std::wstring out = a;
    if (!out.empty() && out.back() != L'\\' && out.back() != L'/')
        out.push_back(L'\\');
    out += b;
    return out;
}

static std::wstring GetHolyCheckTempRoot()
{
    wchar_t tempDir[MAX_PATH]{};
    DWORD len = GetTempPathW(ARRAYSIZE(tempDir), tempDir);
    std::wstring root = (len > 0 && len < ARRAYSIZE(tempDir)) ? std::wstring(tempDir, len) : L"C:\\Windows\\Temp\\";
    if (!root.empty() && root.back() != L'\\')
        root.push_back(L'\\');
    root += L"HolyCheck";
    EnsureDirectoryLocalEarly(root);
    return root;
}

static std::wstring MakeAutomationTempPs1Path(const wchar_t* prefix)
{
    std::wstring dir = CombinePathLocalEarly(GetHolyCheckTempRoot(), L"Automation");
    EnsureDirectoryLocalEarly(dir);

    // Important: keep the generated file name simple and without spaces.
    // PowerShell is launched with -File and Windows PowerShell 5.1 is less forgiving
    // when another scan deletes/replaces the temporary .ps1 between creation and launch.
    return CombinePathLocalEarly(dir, std::wstring(prefix ? prefix : L"script") + L"_" +
        std::to_wstring(GetCurrentProcessId()) + L"_" +
        std::to_wstring(GetCurrentThreadId()) + L"_" +
        std::to_wstring(GetTickCount64()) + L".ps1");
}

static void DeleteFileOrScheduleLocalEarly(const std::wstring& path)
{
    if (path.empty())
        return;
    if (!DeleteFileW(path.c_str()) && GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
        MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
}

static bool IsTempScriptOldEnoughToCleanupLocalEarly(const std::wstring& path, ULONGLONG minAgeMs)
{
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data))
        return false;

    FILETIME nowFt{};
    GetSystemTimeAsFileTime(&nowFt);

    ULONGLONG now = FileTimeToUInt64(nowFt);
    ULONGLONG written = FileTimeToUInt64(data.ftLastWriteTime);
    if (now <= written)
        return false;

    ULONGLONG ageMs = (now - written) / 10000ULL;
    return ageMs >= minAgeMs;
}

static void CleanupHolyCheckTempScriptsLocalEarly(ULONGLONG minAgeMs = 10ULL * 60ULL * 1000ULL)
{
    std::wstring root = GetHolyCheckTempRoot();
    const wchar_t* subdirs[] = { L"Automation", L"PowerShell" };
    for (const wchar_t* sub : subdirs)
    {
        std::wstring dir = CombinePathLocalEarly(root, sub);
        std::wstring mask = CombinePathLocalEarly(dir, L"*.ps1");
        WIN32_FIND_DATAW data{};
        HANDLE hFind = FindFirstFileW(mask.c_str(), &data);
        if (hFind == INVALID_HANDLE_VALUE)
            continue;
        do
        {
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                continue;

            std::wstring candidate = CombinePathLocalEarly(dir, data.cFileName);
            if (IsTempScriptOldEnoughToCleanupLocalEarly(candidate, minAgeMs))
                DeleteFileOrScheduleLocalEarly(candidate);
        }
        while (FindNextFileW(hFind, &data));
        FindClose(hFind);
    }
}

static std::wstring NormalizeExistingPathForPowerShellLocalEarly(const std::wstring& path)
{
    if (path.empty())
        return path;

    std::vector<wchar_t> buffer(32768);
    DWORD len = GetLongPathNameW(path.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
    if (len > 0 && len < buffer.size())
        return std::wstring(buffer.data(), len);

    return path;
}

static bool LooksLikeMissingPowerShellFileErrorLocalEarly(const std::wstring& output)
{
    std::wstring lower = ToLowerCopy(output);
    return lower.find(L"-file") != std::wstring::npos &&
        (lower.find(L"не существует") != std::wstring::npos ||
            lower.find(L"does not exist") != std::wstring::npos ||
            lower.find(L"cannot find") != std::wstring::npos ||
            lower.find(L"could not find") != std::wstring::npos);
}

static bool RunHiddenPowerShellScriptCapture(const std::wstring& script, std::wstring& output, DWORD timeoutMs)
{
    static std::mutex s_powerShellScriptMutex;
    std::lock_guard<std::mutex> psLock(s_powerShellScriptMutex);

    CleanupHolyCheckTempScriptsLocalEarly();

    bool lastOk = false;
    std::wstring lastOutput;

    for (int attempt = 0; attempt < 2; ++attempt)
    {
        std::wstring ps1 = MakeAutomationTempPs1Path(L"holycheck_scan");
        DebugLogLine(L"powershell", L"write ps1=" + ps1 + L" chars=" + std::to_wstring(script.size()) +
            L" timeout=" + std::to_wstring(timeoutMs) + L" attempt=" + std::to_wstring(attempt + 1));

        if (!WriteUtf16LeTextFileLocal(ps1, script))
        {
            DebugLogLine(L"powershell", L"write ps1 failed path=" + ps1 + L" error=" + FormatWin32ErrorForLog(GetLastError()));
            output = lastOutput;
            return false;
        }

        if (GetFileAttributesW(ps1.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            DebugLogLine(L"powershell", L"write ps1 verification failed path=" + ps1 + L" error=" + FormatWin32ErrorForLog(GetLastError()));
            output = lastOutput;
            return false;
        }

        std::wstring launchPs1 = NormalizeExistingPathForPowerShellLocalEarly(ps1);
        if (GetFileAttributesW(launchPs1.c_str()) == INVALID_FILE_ATTRIBUTES)
            launchPs1 = ps1;

        std::wstring psExe = L"powershell.exe";
        wchar_t winDir[MAX_PATH]{};
        UINT winLen = GetWindowsDirectoryW(winDir, ARRAYSIZE(winDir));
        if (winLen > 0 && winLen < ARRAYSIZE(winDir))
        {
            std::wstring sysnative = std::wstring(winDir) + L"\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe";
            std::wstring system32 = std::wstring(winDir) + L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
            if (PathFileExistsW(sysnative.c_str()))
                psExe = sysnative;
            else if (PathFileExistsW(system32.c_str()))
                psExe = system32;
        }

        std::wstring args;
        args.reserve(96 + launchPs1.size());
        args.assign(L"-NoLogo -NoProfile -ExecutionPolicy Bypass -File ");
        args.append(QuoteShellArgument(launchPs1));
        DebugLogLine(L"powershell", L"launch exe=" + psExe + L" args=" + args + L" ps1=" + launchPs1 + L" attempt=" + std::to_wstring(attempt + 1));

        std::wstring attemptOutput;
        bool ok = RunHiddenProcessCapture(psExe, args, attemptOutput, timeoutMs);
        lastOk = ok;
        lastOutput = attemptOutput;

        DebugLogLine(L"powershell", L"finish ok=" + std::to_wstring(ok ? 1 : 0) +
            L" timedOut=" + std::to_wstring(g_lastHiddenProcessTimedOut ? 1 : 0) +
            L" exit=" + std::to_wstring(g_lastHiddenProcessExitCode) +
            L" outputChars=" + std::to_wstring(attemptOutput.size()) +
            L" attempt=" + std::to_wstring(attempt + 1));

        DeleteFileOrScheduleLocalEarly(ps1);

        // Отмена между попытками: второй заход не запускаем.
        if ((g_cancelRequested.load() || g_scanCancelRequested.load()) && !g_deleteInProgress.load())
        {
            output = attemptOutput;
            CleanupHolyCheckTempScriptsLocalEarly();
            return ok;
        }

        // If an external cleanup/AV race removed the .ps1 right before PowerShell opened it,
        // PowerShell returns exactly the visible error from checkmods. Retry once with a fresh name.
        if (LooksLikeMissingPowerShellFileErrorLocalEarly(attemptOutput) && attempt == 0)
        {
            DebugLogLine(L"powershell", L"missing -File ps1 detected, retrying once");
            Sleep(80);
            continue;
        }

        output = attemptOutput;
        CleanupHolyCheckTempScriptsLocalEarly();
        return ok;
    }

    output = lastOutput;
    CleanupHolyCheckTempScriptsLocalEarly();
    return lastOk;
}


static std::wstring TrimAutomationField(std::wstring value)
{
    while (!value.empty() && iswspace(value.front()))
        value.erase(value.begin());

    while (!value.empty() && iswspace(value.back()))
        value.pop_back();

    return value;
}

static std::vector<std::wstring> ParseAutomationCsvLine(const std::wstring& line)
{
    std::vector<std::wstring> fields;
    std::wstring cur;
    bool quoted = false;

    for (size_t i = 0; i < line.size(); ++i)
    {
        wchar_t ch = line[i];

        if (ch == L'"')
        {
            if (quoted && i + 1 < line.size() && line[i + 1] == L'"')
            {
                cur.push_back(L'"');
                ++i;
            }
            else
            {
                quoted = !quoted;
            }
            continue;
        }

        if (ch == L',' && !quoted)
        {
            fields.push_back(TrimAutomationField(cur));
            cur.clear();
            continue;
        }

        cur.push_back(ch);
    }

    fields.push_back(TrimAutomationField(cur));
    return fields;
}

static bool TryExtractFirstHexMask(const std::wstring& text, ULONGLONG& mask)
{
    std::wstring lower = ToLowerCopy(text);
    size_t pos = lower.find(L"0x");

    while (pos != std::wstring::npos)
    {
        size_t end = pos + 2;
        while (end < lower.size() && iswxdigit(lower[end]))
            ++end;

        if (end > pos + 2)
        {
            std::wstring token = lower.substr(pos + 2, end - pos - 2);
            wchar_t* tail = nullptr;
            unsigned long long value = wcstoull(token.c_str(), &tail, 16);
            if (tail && *tail == 0)
            {
                mask = static_cast<ULONGLONG>(value);
                return true;
            }
        }

        pos = lower.find(L"0x", pos + 2);
    }

    return false;
}

static bool LooksLikeAutomationDate(const std::wstring& value)
{
    if (value.size() < 8 || value.size() > 42)
        return false;

    int digits = 0;
    bool hasTime = false;
    bool hasDateSep = false;

    for (wchar_t ch : value)
    {
        if (iswdigit(ch))
            ++digits;
        else if (ch == L':')
            hasTime = true;
        else if (ch == L'.' || ch == L'/' || ch == L'-')
            hasDateSep = true;
    }

    return digits >= 6 && hasTime && hasDateSep;
}


static bool TryParseAutomationDateKeyAnywhere(const std::wstring& text, long long& key)
{
    key = 0;

    for (size_t i = 0; i < text.size(); ++i)
    {
        if (!iswdigit(text[i]))
            continue;

        int nums[6] = { 0, 0, 0, 0, 0, 0 };
        int count = 0;
        size_t j = i;
        bool sawDateSep = false;
        bool sawTimeSep = false;

        while (j < text.size() && count < 6)
        {
            while (j < text.size() && !iswdigit(text[j]))
            {
                if (text[j] == L'.' || text[j] == L'/' || text[j] == L'-')
                    sawDateSep = true;
                else if (text[j] == L':')
                    sawTimeSep = true;
                else if (text[j] == L'|' || text[j] == L'[' || text[j] == L']')
                {
                    if (count >= 5)
                        break;
                }
                ++j;
            }

            if (j >= text.size() || !iswdigit(text[j]))
                break;

            int v = 0;
            int digits = 0;
            while (j < text.size() && iswdigit(text[j]) && digits < 6)
            {
                v = v * 10 + (text[j] - L'0');
                ++j;
                ++digits;
            }
            nums[count++] = v;
        }

        if (count >= 5 && sawDateSep && sawTimeSep)
        {
            int day = nums[0];
            int month = nums[1];
            int year = nums[2];

            if (nums[0] > 1900)
            {
                year = nums[0];
                month = nums[1];
                day = nums[2];
            }

            int hour = nums[3];
            int minute = nums[4];
            int second = (count >= 6) ? nums[5] : 0;

            if (year < 100)
                year += 2000;

            if (year >= 2000 && year <= 2099 && month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
                hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59 && second >= 0 && second <= 59)
            {
                key = static_cast<long long>(year) * 10000000000LL +
                      static_cast<long long>(month) * 100000000LL +
                      static_cast<long long>(day) * 1000000LL +
                      static_cast<long long>(hour) * 10000LL +
                      static_cast<long long>(minute) * 100LL +
                      static_cast<long long>(second);
                return true;
            }
        }
    }

    return false;
}

static void SortAutomationOutputLinesByDateDesc(std::vector<std::wstring>& lines, size_t headerLines = 1)
{
    if (lines.size() <= headerLines + 1)
        return;

    struct SortRow
    {
        std::wstring line;
        long long key;
        size_t order;
        bool hasDate;
    };

    std::vector<SortRow> rows;
    rows.reserve(lines.size() - headerLines);

    for (size_t i = headerLines; i < lines.size(); ++i)
    {
        long long key = 0;
        bool hasDate = TryParseAutomationDateKeyAnywhere(lines[i], key);
        rows.push_back({ lines[i], key, i, hasDate });
    }

    std::stable_sort(rows.begin(), rows.end(), [](const SortRow& a, const SortRow& b)
    {
        if (a.hasDate != b.hasDate)
            return a.hasDate;
        if (a.hasDate && b.hasDate && a.key != b.key)
            return a.key > b.key;
        return a.order < b.order;
    });

    for (size_t i = 0; i < rows.size(); ++i)
        lines[headerLines + i] = rows[i].line;
}


static bool TryParseAutomationDateKeyInPipeColumn(const std::wstring& line, size_t column, long long& key)
{
    std::wstring clean = line;
    if (!clean.empty() && clean[0] == L'\xE000')
        clean.erase(clean.begin());
    size_t start = 0;
    for (size_t c = 0; ; ++c)
    {
        size_t pos = clean.find(L" | ", start);
        std::wstring part = (pos == std::wstring::npos) ? clean.substr(start) : clean.substr(start, pos - start);
        if (c == column)
            return TryParseAutomationDateKeyAnywhere(part, key);
        if (pos == std::wstring::npos)
            break;
        start = pos + 3;
    }
    return false;
}

static void SortAutomationOutputLinesByPipeColumnDateDesc(std::vector<std::wstring>& lines, size_t column, size_t headerLines = 1)
{
    if (lines.size() <= headerLines + 1)
        return;

    struct SortRow
    {
        std::wstring line;
        long long key;
        size_t order;
        bool hasDate;
    };

    std::vector<SortRow> rows;
    rows.reserve(lines.size() - headerLines);
    for (size_t i = headerLines; i < lines.size(); ++i)
    {
        long long key = 0;
        bool hasDate = TryParseAutomationDateKeyInPipeColumn(lines[i], column, key);
        rows.push_back({ lines[i], key, i, hasDate });
    }

    std::stable_sort(rows.begin(), rows.end(), [](const SortRow& a, const SortRow& b)
    {
        if (a.hasDate != b.hasDate)
            return a.hasDate;
        if (a.hasDate && b.hasDate && a.key != b.key)
            return a.key > b.key;
        return a.order < b.order;
    });

    for (size_t i = 0; i < rows.size(); ++i)
        lines[headerLines + i] = rows[i].line;
}

static bool SortAutomationTargetLinesByPipeColumnDateDesc(int target, size_t column)
{
    std::lock_guard<std::mutex> lock(g_automationMutex);
    std::vector<std::wstring>& lines = AutomationLinesRef(target);
    if (lines.size() <= 2)
        return false;

    std::vector<std::wstring> before = lines;
    SortAutomationOutputLinesByPipeColumnDateDesc(lines, column, 1);
    AutomationScrollRef(target) = 0;
    return before != lines;
}

static std::wstring PickUsnFileNameFromCsvFields(const std::vector<std::wstring>& fields, const std::wstring& rawLine)
{
    if (fields.size() > 1)
    {
        std::wstring candidate = TrimAutomationField(fields[1]);
        std::wstring lowerCandidate = ToLowerCopy(candidate);
        if (!candidate.empty() && lowerCandidate != L"name" && lowerCandidate != L"file name" && lowerCandidate != L"filename")
            return ExtractFileNameOnly(candidate);
    }

    for (const std::wstring& field : fields)
    {
        std::wstring lower = ToLowerCopy(field);
        if (lower.find(L".jar") != std::wstring::npos || lower.find(L"jar") != std::wstring::npos)
            return ExtractFileNameOnly(field);
    }

    std::wstring lower = ToLowerCopy(rawLine);
    size_t jarPos = lower.find(L"jar");
    if (jarPos == std::wstring::npos)
        return L"";

    size_t start = jarPos;
    while (start > 0)
    {
        wchar_t ch = rawLine[start - 1];
        if (ch == L',' || ch == L'"' || ch == L'|' || ch == L' ' || ch == L'\t')
            break;
        --start;
    }

    size_t end = jarPos + 3;
    while (end < rawLine.size())
    {
        wchar_t ch = rawLine[end];
        if (ch == L',' || ch == L'"' || ch == L'|' || ch == L' ' || ch == L'\t')
            break;
        ++end;
    }

    return ExtractFileNameOnly(rawLine.substr(start, end - start));
}

static bool ContainsExtensionToken(const std::wstring& text, const std::wstring& ext);
static std::wstring CleanPipeCell(std::wstring value);


static std::wstring PickUsnFileNameFromCsvFieldsGeneric(const std::vector<std::wstring>& fields, const std::wstring& rawLine, const std::wstring& ext)
{
    if (fields.size() > 1)
    {
        std::wstring candidate = TrimAutomationField(fields[1]);
        std::wstring lowerCandidate = ToLowerCopy(candidate);
        if (!candidate.empty() && lowerCandidate != L"name" && lowerCandidate != L"file name" && lowerCandidate != L"filename")
            return ExtractFileNameOnly(candidate);
    }

    for (const std::wstring& field : fields)
    {
        if (ContainsExtensionToken(field, ext))
            return ExtractFileNameOnly(field);
    }

    std::wstring lower = ToLowerCopy(rawLine);
    std::wstring lowerExt = ToLowerCopy(ext);
    size_t extPos = lower.find(lowerExt);
    if (extPos == std::wstring::npos)
        return L"";

    size_t start = extPos;
    while (start > 0)
    {
        wchar_t ch = rawLine[start - 1];
        if (ch == L',' || ch == L'"' || ch == L'|' || ch == L' ' || ch == L'\t')
            break;
        --start;
    }

    size_t endPos = extPos + lowerExt.size();
    while (endPos < rawLine.size())
    {
        wchar_t ch = rawLine[endPos];
        if (ch == L',' || ch == L'"' || ch == L'|' || ch == L' ' || ch == L'\t')
            break;
        ++endPos;
    }

    return ExtractFileNameOnly(rawLine.substr(start, endPos - start));
}

static bool ContainsExtensionToken(const std::wstring& text, const std::wstring& ext)
{
    if (text.empty() || ext.empty())
        return false;

    std::wstring name = ToLowerCopy(ExtractFileNameOnly(text));
    std::wstring lowerExt = ToLowerCopy(ext);

    if (name.empty())
        return false;

    if (lowerExt == L".jar")
    {
        if (name.size() < 4)
            return false;
        return name.compare(name.size() - 4, 4, L".jar") == 0;
    }

    if (name.size() < lowerExt.size())
        return false;

    return name.compare(name.size() - lowerExt.size(), lowerExt.size(), lowerExt) == 0;
}

static std::wstring ExtractUsnPathLikeForExtension(const std::wstring& text, const std::wstring& ext)
{
    std::wstring clean = TrimAutomationField(text);
    if (clean.empty())
        return L"";

    std::wstring lower = ToLowerCopy(clean);
    std::wstring lowerExt = ToLowerCopy(ext);
    size_t extPos = lower.find(lowerExt);
    if (extPos == std::wstring::npos)
        return L"";

    size_t endPos = extPos + lowerExt.size();
    while (endPos < clean.size())
    {
        wchar_t ch = clean[endPos];
        if (ch == L'"' || ch == L'|' || ch == L',' || ch == L'\r' || ch == L'\n' || ch == L'\t')
            break;
        ++endPos;
    }

    size_t start = std::wstring::npos;
    size_t drivePos = lower.rfind(L":\\", extPos);
    if (drivePos != std::wstring::npos && drivePos > 0)
        start = drivePos - 1;
    else
    {
        size_t devPos = lower.rfind(L"\\device\\", extPos);
        if (devPos != std::wstring::npos)
            start = devPos;
    }

    if (start == std::wstring::npos)
        return L"";

    return CleanPipeCell(DevicePathToDosPath(clean.substr(start, endPos - start)));
}

static std::wstring PickUsnPathFromCsvFieldsGeneric(const std::vector<std::wstring>& fields, const std::wstring& rawLine, const std::wstring& ext)
{
    // USN usually contains only the file name. If a full path is present in CSV,
    // show it; otherwise keep the filename in the path column instead of leaving it empty.
    for (const std::wstring& field : fields)
    {
        std::wstring path = ExtractUsnPathLikeForExtension(field, ext);
        if (!path.empty())
            return path;
    }

    std::wstring path = ExtractUsnPathLikeForExtension(rawLine, ext);
    if (!path.empty())
        return path;

    return CleanPipeCell(PickUsnFileNameFromCsvFieldsGeneric(fields, rawLine, ext));
}


static std::wstring NormalizeUsnFileReferenceField(std::wstring value)
{
    value = TrimAutomationField(value);
    if (value.empty())
        return L"";

    while (!value.empty() && (value.front() == L'"' || value.front() == L'['))
        value.erase(value.begin());
    while (!value.empty() && (value.back() == L'"' || value.back() == L']' || value.back() == L','))
        value.pop_back();

    if (value.empty())
        return L"";

    std::wstring lower = ToLowerCopy(value);
    bool hasHexPrefix = lower.rfind(L"0x", 0) == 0;
    std::wstring digits = hasHexPrefix ? lower.substr(2) : lower;
    if (digits.empty())
        return L"";

    bool allDecimal = true;
    bool allHex = true;
    bool hasHexLetter = false;
    for (wchar_t ch : digits)
    {
        if (!iswdigit(ch))
            allDecimal = false;
        if (!iswxdigit(ch))
            allHex = false;
        if ((ch >= L'a' && ch <= L'f') || (ch >= L'A' && ch <= L'F'))
            hasHexLetter = true;
    }

    if (hasHexPrefix)
    {
        if (!allHex || digits.size() > 16)
            return L"";
        return L"0x" + digits;
    }

    // fsutil csv can print file reference numbers as decimal.  Do not convert
    // decimal-looking values to hex: queryfilenamebyid accepts the decimal form,
    // while adding 0x changes the value and breaks parent path recovery.
    if (allDecimal)
        return digits;

    if (allHex && hasHexLetter && digits.size() <= 16)
        return L"0x" + digits;

    return L"";
}

static void PickUsnReferenceFields(const std::vector<std::wstring>& fields, std::wstring& fileRef, std::wstring& parentRef)
{
    fileRef.clear();
    parentRef.clear();

    // fsutil usn readjournal C: csv normally starts with:
    // USN | File name | File reference number | Parent file reference number | Reason | Time stamp | ...
    if (fields.size() > 2)
        fileRef = NormalizeUsnFileReferenceField(fields[2]);
    if (fields.size() > 3)
        parentRef = NormalizeUsnFileReferenceField(fields[3]);
}

static std::wstring ExtractDosPathFromFsutilFileIdOutput(const std::wstring& output)
{
    std::wstring text = output;
    size_t start = text.find(L":\\");
    if (start == std::wstring::npos || start == 0)
        return L"";

    --start; // include the drive letter
    size_t end = text.find_first_of(L"\r\n", start);
    std::wstring path = (end == std::wstring::npos) ? text.substr(start) : text.substr(start, end - start);

    while (!path.empty() && (path.front() == L'"' || path.front() == L'[' || path.front() == L' ' || path.front() == L'\t'))
        path.erase(path.begin());
    while (!path.empty() && (path.back() == L'"' || path.back() == L']' || path.back() == L' ' || path.back() == L'\t' || path.back() == L'.'))
        path.pop_back();

    return CleanPipeCell(DevicePathToDosPath(path));
}

static std::wstring QueryNtfsPathByFileReferenceCached(const std::wstring& fileRef)
{
    static std::mutex cacheMutex;
    static std::map<std::wstring, std::wstring> cache;

    std::wstring ref = NormalizeUsnFileReferenceField(fileRef);
    if (ref.empty())
        return L"";

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto it = cache.find(ref);
        if (it != cache.end())
            return it->second;
    }

    std::wstring output;
    std::wstring command = L"fsutil file queryfilenamebyid C: " + ref;
    std::wstring result;
    if (RunHiddenCommandCapture(command, output, 12000))
        result = ExtractDosPathFromFsutilFileIdOutput(output);

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        cache[ref] = result;
    }

    return result;
}


static bool ContainsJarExtensionToken(const std::wstring& text)
{
    return ContainsExtensionToken(text, L".jar");
}

static std::wstring PickJarDateFromCsvFields(const std::vector<std::wstring>& fields)
{
    if (fields.size() > 5 && LooksLikeAutomationDate(fields[5]))
        return fields[5];

    for (const std::wstring& field : fields)
    {
        if (LooksLikeAutomationDate(field))
            return field;
    }

    return L"-";
}

static ULONGLONG PickJarReasonMaskFromCsvFields(const std::vector<std::wstring>& fields, const std::wstring& rawLine)
{
    ULONGLONG mask = 0;

    for (const std::wstring& field : fields)
    {
        if (TryExtractFirstHexMask(field, mask))
            return mask;
    }

    if (TryExtractFirstHexMask(rawLine, mask))
        return mask;

    return 0;
}

static std::wstring NormalizeUsnReasonText(std::wstring text)
{
    text = TrimAutomationField(text);
    if (text.empty())
        return L"activity";

    size_t pos = 0;
    while ((pos = text.find(L"  ", pos)) != std::wstring::npos)
    {
        text.replace(pos, 2, L" ");
        if (pos > 0)
            --pos;
    }

    return text;
}

static void AddReasonPart(std::vector<std::wstring>& parts, ULONGLONG mask, ULONGLONG bit, const wchar_t* text)
{
    if ((mask & bit) != 0)
        parts.push_back(text);
}

static std::wstring JoinReasonParts(const std::vector<std::wstring>& parts)
{
    if (parts.empty())
        return L"activity";

    std::wstring out;
    for (size_t i = 0; i < parts.size(); ++i)
    {
        if (i)
            out += L" | ";
        out += parts[i];
    }
    return out;
}

static std::wstring ReasonTextFromMask(ULONGLONG mask)
{
    std::vector<std::wstring> parts;
    AddReasonPart(parts, mask, 0x00000001ULL, L"Data overwrite");
    AddReasonPart(parts, mask, 0x00000002ULL, L"Data extend");
    AddReasonPart(parts, mask, 0x00000004ULL, L"Data truncation");
    AddReasonPart(parts, mask, 0x00000100ULL, L"File create");
    AddReasonPart(parts, mask, 0x00000200ULL, L"File delete");
    AddReasonPart(parts, mask, 0x00001000ULL, L"Rename old name");
    AddReasonPart(parts, mask, 0x00002000ULL, L"Rename new name");
    AddReasonPart(parts, mask, 0x00008000ULL, L"Basic info change");
    AddReasonPart(parts, mask, 0x00200000ULL, L"Stream change");
    AddReasonPart(parts, mask, 0x80000000ULL, L"Close");
    return JoinReasonParts(parts);
}

static bool FieldLooksLikeReasonText(const std::wstring& field)
{
    std::wstring lower = ToLowerCopy(field);
    return lower.find(L"data ") != std::wstring::npos ||
        lower.find(L"file ") != std::wstring::npos ||
        lower.find(L"rename") != std::wstring::npos ||
        lower.find(L"basic info") != std::wstring::npos ||
        lower.find(L"stream") != std::wstring::npos ||
        lower.find(L"close") != std::wstring::npos;
}

static std::wstring PickUsnReasonTextFromCsvFields(const std::vector<std::wstring>& fields, const std::wstring& rawLine, ULONGLONG mask)
{
    if (fields.size() > 6 && FieldLooksLikeReasonText(fields[6]))
        return NormalizeUsnReasonText(fields[6]);

    for (const std::wstring& field : fields)
    {
        if (FieldLooksLikeReasonText(field))
            return NormalizeUsnReasonText(field);
    }

    if (mask != 0)
        return ReasonTextFromMask(mask);

    if (FieldLooksLikeReasonText(rawLine))
        return NormalizeUsnReasonText(rawLine);

    return L"activity";
}

struct JarUsnEntry
{
    std::wstring date;
    std::wstring name;
    std::wstring path;
    std::wstring fileRef;
    std::wstring parentRef;
    std::wstring lowerRaw;
    ULONGLONG reason = 0;
    std::wstring reasonText;
    bool hasJarExtension = false;
    bool created = false;
    bool deleted = false;
    bool renameOld = false;
    bool renameNew = false;
    bool dataExtend = false;
    bool basicInfo = false;
    bool streamChange = false;
    bool close = false;
};

static std::wstring ResolveUsnFullPathForEntry(const JarUsnEntry& e, const std::wstring& ext)
{
    std::wstring path = CleanPipeCell(DevicePathToDosPath(e.path));
    if (path.find(L":\\") != std::wstring::npos || ToLowerCopy(path).find(L"\\device\\") != std::wstring::npos)
        return path;

    std::wstring name = CleanPipeCell(e.name.empty() ? ExtractFileNameOnly(path) : e.name);
    if (name.empty())
        name = ExtractFileNameOnly(path);
    if (name.empty())
        return path;

    if (!e.deleted && !e.fileRef.empty())
    {
        std::wstring exact = QueryNtfsPathByFileReferenceCached(e.fileRef);
        if (!exact.empty() && ContainsExtensionToken(exact, ext))
            return exact;
    }

    if (!e.parentRef.empty())
    {
        std::wstring parent = QueryNtfsPathByFileReferenceCached(e.parentRef);
        if (!parent.empty())
        {
            while (!parent.empty() && (parent.back() == L'\\' || parent.back() == L'/'))
                parent.pop_back();
            if (!parent.empty())
                return CleanPipeCell(parent + L"\\" + ExtractFileNameOnly(name));
        }
    }

    return CleanPipeCell(path.empty() ? name : path);
}


static bool TextHasAny(const std::wstring& lower, const wchar_t* a, const wchar_t* b = L"", const wchar_t* c = L"")
{
    if (a && *a && lower.find(a) != std::wstring::npos)
        return true;
    if (b && *b && lower.find(b) != std::wstring::npos)
        return true;
    if (c && *c && lower.find(c) != std::wstring::npos)
        return true;
    return false;
}

static JarUsnEntry MakeJarUsnEntry(const std::wstring& rawLine)
{
    std::vector<std::wstring> fields = ParseAutomationCsvLine(rawLine);

    JarUsnEntry e;
    e.date = PickJarDateFromCsvFields(fields);
    e.name = PickUsnFileNameFromCsvFields(fields, rawLine);
    e.path = CleanPipeCell(e.name);
    PickUsnReferenceFields(fields, e.fileRef, e.parentRef);
    e.lowerRaw = ToLowerCopy(rawLine);
    e.reason = PickJarReasonMaskFromCsvFields(fields, rawLine);
    e.reasonText = PickUsnReasonTextFromCsvFields(fields, rawLine, e.reason);
    e.hasJarExtension = ContainsJarExtensionToken(e.name) || ContainsJarExtensionToken(rawLine);

    e.created = ((e.reason & 0x00000100ULL) != 0) || TextHasAny(e.lowerRaw, L"file_create", L"file create", L"filecreate");
    e.deleted = ((e.reason & 0x00000200ULL) != 0) || TextHasAny(e.lowerRaw, L"file_delete", L"file delete", L"filedelete");
    e.renameOld = ((e.reason & 0x00001000ULL) != 0) || TextHasAny(e.lowerRaw, L"rename: old name", L"rename old", L"old name");
    e.renameNew = ((e.reason & 0x00002000ULL) != 0) || TextHasAny(e.lowerRaw, L"rename: new name", L"rename new", L"new name");
    e.dataExtend = ((e.reason & 0x00000002ULL) != 0) || TextHasAny(e.lowerRaw, L"data_extend", L"data extend");
    e.basicInfo = ((e.reason & 0x00008000ULL) != 0) || TextHasAny(e.lowerRaw, L"basic_info_change", L"basic info change");
    e.streamChange = ((e.reason & 0x00200000ULL) != 0) || TextHasAny(e.lowerRaw, L"stream_change", L"stream change");
    e.close = ((e.reason & 0x80000000ULL) != 0) || TextHasAny(e.lowerRaw, L"close", L"reason_close", L"usn_reason_close");

    return e;
}

static JarUsnEntry MakeUsnEntryForExtension(const std::wstring& rawLine, const std::wstring& ext)
{
    std::vector<std::wstring> fields = ParseAutomationCsvLine(rawLine);

    JarUsnEntry e;
    e.date = PickJarDateFromCsvFields(fields);
    e.name = PickUsnFileNameFromCsvFieldsGeneric(fields, rawLine, ext);
    e.path = PickUsnPathFromCsvFieldsGeneric(fields, rawLine, ext);
    PickUsnReferenceFields(fields, e.fileRef, e.parentRef);
    e.lowerRaw = ToLowerCopy(rawLine);
    e.reason = PickJarReasonMaskFromCsvFields(fields, rawLine);
    e.reasonText = PickUsnReasonTextFromCsvFields(fields, rawLine, e.reason);
    e.hasJarExtension = ContainsExtensionToken(e.name, ext) || ContainsExtensionToken(rawLine, ext);

    e.created = ((e.reason & 0x00000100ULL) != 0) || TextHasAny(e.lowerRaw, L"file_create", L"file create", L"filecreate");
    e.deleted = ((e.reason & 0x00000200ULL) != 0) || TextHasAny(e.lowerRaw, L"file_delete", L"file delete", L"filedelete");
    e.renameOld = ((e.reason & 0x00001000ULL) != 0) || TextHasAny(e.lowerRaw, L"rename: old name", L"rename old", L"old name");
    e.renameNew = ((e.reason & 0x00002000ULL) != 0) || TextHasAny(e.lowerRaw, L"rename: new name", L"rename new", L"new name");
    e.dataExtend = ((e.reason & 0x00000002ULL) != 0) || TextHasAny(e.lowerRaw, L"data_extend", L"data extend");
    e.basicInfo = ((e.reason & 0x00008000ULL) != 0) || TextHasAny(e.lowerRaw, L"basic_info_change", L"basic info change");
    e.streamChange = ((e.reason & 0x00200000ULL) != 0) || TextHasAny(e.lowerRaw, L"stream_change", L"stream change");
    e.close = ((e.reason & 0x80000000ULL) != 0) || TextHasAny(e.lowerRaw, L"close", L"reason_close", L"usn_reason_close");

    return e;
}

static bool ShouldShowUsnEntryForExtension(const JarUsnEntry& e, const std::wstring& ext)
{
    return e.hasJarExtension && ContainsExtensionToken(e.name, ext);
}

static bool ShouldShowJarUsnEntry(const JarUsnEntry& e)
{
    if (!e.hasJarExtension)
        return false;

    return ContainsJarExtensionToken(e.name);
}

static std::wstring CleanPipeCell(std::wstring value)
{
    for (wchar_t& ch : value)
    {
        if (ch == L'\r' || ch == L'\n' || ch == L'\t')
            ch = L' ';
    }

    size_t pos = 0;
    while ((pos = value.find(L" | ", pos)) != std::wstring::npos)
    {
        value.replace(pos, 3, L", ");
        pos += 2;
    }

    while ((pos = value.find(L"  ")) != std::wstring::npos)
        value.replace(pos, 2, L" ");

    return TrimAutomationField(value);
}

static const wchar_t* AUTOMATION_DELETED_MARKER = L"\xE000";
static const wchar_t* AUTOMATION_ARCHIVE_MARKER = L"\xE001";
static const wchar_t* AUTOMATION_FORBIDDEN_MARKER = L"\xE002";
static const wchar_t* AUTOMATION_RENAMED_MARKER = L"\xE003";

static bool AutomationLineHasDeletedMarker(const std::wstring& line)
{
    return line.find(L'\xE000') != std::wstring::npos && line.find_first_not_of(L"\xE000\xE001\xE002\xE003") != 0;
}

static bool AutomationLineHasArchiveMarker(const std::wstring& line)
{
    return line.find(L'\xE001') != std::wstring::npos && line.find_first_not_of(L"\xE000\xE001\xE002\xE003") != 0;
}

static bool AutomationLineHasForbiddenMarker(const std::wstring& line)
{
    return line.find(L'\xE002') != std::wstring::npos && line.find_first_not_of(L"\xE000\xE001\xE002\xE003") != 0;
}

static bool AutomationLineHasRenamedMarker(const std::wstring& line)
{
    return line.find(L'\xE003') != std::wstring::npos && line.find_first_not_of(L"\xE000\xE001\xE002\xE003") != 0;
}

static std::wstring StripAutomationDeletedMarker(std::wstring line)
{
    while (!line.empty() && (line[0] == L'\xE000' || line[0] == L'\xE001' || line[0] == L'\xE002' || line[0] == L'\xE003'))
        line.erase(line.begin());
    return line;
}

static std::wstring BuildProgramNameAndPathCell(const std::wstring& pathOrName)
{
    std::wstring clean = CleanPipeCell(DevicePathToDosPath(pathOrName));
    if (clean.empty())
        return L"";

    std::wstring name = ExtractFileNameOnly(clean);
    if (name.empty() || _wcsicmp(name.c_str(), clean.c_str()) == 0)
        return clean;

    return CleanPipeCell(name) + L"    " + clean;
}

static void AppendJarActivityRow(std::vector<std::wstring>& lines, const std::wstring& date, const wchar_t* action, const std::wstring& name, const std::wstring& path = L"")
{
    if (name.empty() && path.empty())
        return;

    std::wstring cleanDate = CleanPipeCell(date);
    std::wstring cleanAction = ToLowerCopy(CleanPipeCell(action ? std::wstring(action) : std::wstring()));
    std::wstring cleanPath = CleanPipeCell(DevicePathToDosPath(path.empty() ? name : path));
    std::wstring program = CleanPipeCell(name.empty() ? ExtractFileNameOnly(cleanPath) : ExtractFileNameOnly(name));
    if (program.empty())
        program = ExtractFileNameOnly(cleanPath);
    if (program.empty())
        program = cleanPath;
    if (program.empty() || cleanPath.empty())
        return;

    std::wstring row = cleanDate + L" | " + program + L" | " + cleanPath;
    if (cleanAction.find(L"deleted") != std::wstring::npos ||
        cleanAction.find(L"file delete") != std::wstring::npos ||
        cleanAction.find(L"file_delete") != std::wstring::npos)
    {
        row.insert(0, AUTOMATION_DELETED_MARKER);
    }

    lines.push_back(std::move(row));
}


static std::wstring SimpleJarJournalReason(const JarUsnEntry& e)
{
    if (e.created) return L"created";
    if (e.deleted) return L"deleted";
    if (e.renameOld) return L"rename old name";
    if (e.renameNew) return L"rename new name";
    return L"";
}


static std::wstring BuildJarActivityReasonWithUsnDate(const std::wstring& reason, const std::wstring& usnDate)
{
    std::wstring cleanReason = CleanPipeCell(reason);
    std::wstring cleanUsnDate = CleanPipeCell(usnDate);
    if (cleanReason.empty())
        return L"";
    if (cleanUsnDate.empty() || cleanUsnDate == L"дата неизвестна")
        return cleanReason;
    return cleanReason + L" (" + cleanUsnDate + L")";
}


static bool IsUnknownAutomationDate(const std::wstring& text);

static std::wstring FileLastWriteTimeText(const std::wstring& path, ULONGLONG* outSortTime = nullptr)
{
    if (outSortTime)
        *outSortTime = 0;

    std::wstring dosPath = DevicePathToDosPath(path);
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (dosPath.empty() || GetFileAttributesExW(dosPath.c_str(), GetFileExInfoStandard, &data) == FALSE || !IsPlausibleFileTime(data.ftLastWriteTime))
        return L"дата неизвестна";

    if (outSortTime)
        *outSortTime = FileTimeToUInt64(data.ftLastWriteTime);
    return FileTimeToLocalText(data.ftLastWriteTime);
}

static void AddJarSearchRootIfExists(std::vector<std::wstring>& roots, const std::wstring& path)
{
    if (path.empty())
        return;

    std::wstring clean = DevicePathToDosPath(path);
    while (!clean.empty() && (clean.back() == L'\\' || clean.back() == L'/'))
        clean.pop_back();
    if (clean.empty())
        return;

    DWORD attrs = GetFileAttributesW(clean.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
        return;

    std::wstring lower = ToLowerCopy(clean);
    for (const std::wstring& existing : roots)
    {
        if (ToLowerCopy(existing) == lower)
            return;
    }
    roots.push_back(clean);
}

static bool IsLunarDependenciesPathForCheckmods(const std::wstring& path)
{
    if (path.empty())
        return false;

    std::wstring lower = ToLowerCopy(path);
    for (wchar_t& ch : lower)
    {
        if (ch == L'/')
            ch = L'\\';
    }

    bool underLunarProfiles = lower.find(L"\\.lunarclient\\profiles\\") != std::wstring::npos;
    bool insideDependencies = lower.find(L"\\dependencies\\") != std::wstring::npos ||
        (lower.size() >= 13 && lower.compare(lower.size() - 13, 13, L"\\dependencies") == 0);
    return underLunarProfiles && insideDependencies;
}


static void SearchJarModificationRecursive(const std::wstring& root, const std::wstring& lowerName, int depth, int& visited, ULONGLONG& bestTime, std::wstring& bestText, std::wstring& bestPath)
{
    if (root.empty() || depth < 0 || visited > 14000)
        return;

    std::wstring mask = root + L"\\*";
    WIN32_FIND_DATAW data{};
    HANDLE h = FindFirstFileW(mask.c_str(), &data);
    if (h == INVALID_HANDLE_VALUE)
        return;

    do
    {
        const wchar_t* name = data.cFileName;
        if (wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0)
            continue;

        std::wstring full = root + L"\\" + name;
        if (IsLunarDependenciesPathForCheckmods(full))
            continue;

        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            std::wstring lowerDir = ToLowerCopy(name);
            if (lowerDir == L"windows" || lowerDir == L"program files" || lowerDir == L"program files (x86)" ||
                lowerDir == L"programdata" || lowerDir == L"$recycle.bin" || lowerDir == L"system volume information")
                continue;
            SearchJarModificationRecursive(full, lowerName, depth - 1, visited, bestTime, bestText, bestPath);
            continue;
        }

        ++visited;
        if (ToLowerCopy(name) != lowerName)
            continue;

        if (!IsPlausibleFileTime(data.ftLastWriteTime))
            continue;

        ULONGLONG t = FileTimeToUInt64(data.ftLastWriteTime);
        if (t >= bestTime)
        {
            bestTime = t;
            bestText = FileTimeToLocalText(data.ftLastWriteTime);
            bestPath = CleanPipeCell(full);
        }
    } while (FindNextFileW(h, &data));

    FindClose(h);
}

static bool FindJarModificationByName(const std::wstring& fileName, std::wstring& outDate, ULONGLONG* outSortTime = nullptr, std::wstring* outPath = nullptr)
{
    if (outSortTime)
        *outSortTime = 0;
    if (outPath)
        outPath->clear();

    std::wstring name = ExtractFileNameOnly(fileName);
    if (name.empty() || !ContainsJarExtensionToken(name))
        return false;

    static std::mutex cacheMutex;
    static std::map<std::wstring, std::pair<ULONGLONG, std::pair<std::wstring, std::wstring>>> cache;

    std::wstring lowerName = ToLowerCopy(name);
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto it = cache.find(lowerName);
        if (it != cache.end())
        {
            if (it->second.first == 0)
                return false;
            if (outSortTime)
                *outSortTime = it->second.first;
            outDate = it->second.second.first;
            if (outPath)
                *outPath = it->second.second.second;
            return true;
        }
    }

    std::vector<std::wstring> roots;
    wchar_t userProfile[MAX_PATH]{};
    wchar_t appData[MAX_PATH]{};
    wchar_t localAppData[MAX_PATH]{};
    wchar_t publicProfile[MAX_PATH]{};

    GetEnvironmentVariableW(L"USERPROFILE", userProfile, ARRAYSIZE(userProfile));
    GetEnvironmentVariableW(L"APPDATA", appData, ARRAYSIZE(appData));
    GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, ARRAYSIZE(localAppData));
    GetEnvironmentVariableW(L"PUBLIC", publicProfile, ARRAYSIZE(publicProfile));

    if (userProfile[0])
    {
        AddJarSearchRootIfExists(roots, std::wstring(userProfile) + L"\\Desktop");
        AddJarSearchRootIfExists(roots, std::wstring(userProfile) + L"\\Downloads");
        AddJarSearchRootIfExists(roots, std::wstring(userProfile) + L"\\Documents");
        AddJarSearchRootIfExists(roots, std::wstring(userProfile) + L"\\AppData\\Roaming\\.minecraft");
        AddJarSearchRootIfExists(roots, std::wstring(userProfile));
    }
    if (appData[0])
    {
        AddJarSearchRootIfExists(roots, std::wstring(appData) + L"\\.minecraft");
        AddJarSearchRootIfExists(roots, appData);
    }
    if (localAppData[0])
        AddJarSearchRootIfExists(roots, localAppData);
    if (publicProfile[0])
    {
        AddJarSearchRootIfExists(roots, std::wstring(publicProfile) + L"\\Desktop");
        AddJarSearchRootIfExists(roots, std::wstring(publicProfile) + L"\\Downloads");
    }

    ULONGLONG bestTime = 0;
    std::wstring bestText;
    std::wstring bestPath;
    int visited = 0;
    for (const std::wstring& root : roots)
    {
        SearchJarModificationRecursive(root, lowerName, 6, visited, bestTime, bestText, bestPath);
        if (visited > 14000)
            break;
    }

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        cache[lowerName] = { bestTime, { bestText, bestPath } };
    }

    if (bestTime == 0 || bestText.empty())
        return false;

    if (outSortTime)
        *outSortTime = bestTime;
    outDate = bestText;
    if (outPath)
        *outPath = bestPath;
    return true;
}

static std::wstring JarFileModificationTimeText(const JarUsnEntry& e, const std::wstring& fullPath, ULONGLONG* outSortTime = nullptr)
{
    if (outSortTime)
        *outSortTime = 0;

    ULONGLONG directTime = 0;
    std::wstring direct = FileLastWriteTimeText(fullPath, &directTime);
    if (!IsUnknownAutomationDate(direct))
    {
        if (outSortTime)
            *outSortTime = directTime;
        return direct;
    }

    std::wstring foundDate;
    ULONGLONG foundTime = 0;
    std::wstring foundPath;
    std::wstring name = ExtractFileNameOnly(fullPath);
    if (name.empty())
        name = ExtractFileNameOnly(e.name);
    if (FindJarModificationByName(name, foundDate, &foundTime, &foundPath))
    {
        if (outSortTime)
            *outSortTime = foundTime;
        return foundDate;
    }

    return L"дата неизвестна";
}

static bool IsUnknownAutomationDate(const std::wstring& text)
{
    std::wstring lower = ToLowerCopy(TrimAutomationField(text));
    return lower.empty() || lower == L"дата неизвестна" || lower == L"n/a" || lower == L"na";
}

static void AppendJarUnifiedActivityRow(std::vector<std::wstring>& lines, const JarUsnEntry& e)
{
    std::wstring reason = SimpleJarJournalReason(e);
    if (reason.empty())
        return;

    std::wstring fullPath = ResolveUsnFullPathForEntry(e, L".jar");
    ULONGLONG modSortTime = 0;
    std::wstring modDate = JarFileModificationTimeText(e, fullPath, &modSortTime);
    std::wstring program = CleanPipeCell(ExtractFileNameOnly(fullPath));
    if (program.empty())
        program = CleanPipeCell(ExtractFileNameOnly(e.name));
    if (program.empty())
        program = CleanPipeCell(e.name);
    if (program.empty())
        return;

    std::wstring reasonCell = BuildJarActivityReasonWithUsnDate(reason, e.date);
    if (reasonCell.empty())
        return;

    std::wstring row = CleanPipeCell(modDate) + L" | " + reasonCell + L" | " + program;
    if (reason == L"deleted")
        row.insert(0, AUTOMATION_DELETED_MARKER);
    lines.push_back(std::move(row));
}

static std::wstring JarUnifiedDedupKey(const JarUsnEntry& e)
{
    std::wstring reason = SimpleJarJournalReason(e);
    std::wstring fullPath = ResolveUsnFullPathForEntry(e, L".jar");
    std::wstring name = ExtractFileNameOnly(fullPath);
    if (name.empty())
        name = ExtractFileNameOnly(e.name);
    if (name.empty())
        name = e.name;

    // Deduplicate by visible file name + visible action. USN can emit many rows
    // for the same command with different references/close events; the user wants
    // one row per same file/action in .jar activity.
    std::wstring key = ToLowerCopy(CleanPipeCell(name)) + L"|" + ToLowerCopy(CleanPipeCell(reason));
    return key;
}

struct UsnFilteredRawCacheEntry
{
    ULONGLONG tick = 0;
    std::wstring output;
    bool ok = false;
    bool loading = false;
};

static bool ReadUsnFilteredOutputCached(const std::wstring& ext, std::wstring& output, DWORD timeoutMs = 120000)
{
    static std::mutex cacheMutex;
    static std::condition_variable cacheCv;
    static std::map<std::wstring, UsnFilteredRawCacheEntry> cache;
    static const DWORD USN_RAW_CACHE_TTL_MS = 15000;

    std::wstring key = ToLowerCopy(ext);
    if (key.empty())
        return false;

    for (;;)
    {
        std::unique_lock<std::mutex> lock(cacheMutex);
        UsnFilteredRawCacheEntry& entry = cache[key];
        ULONGLONG now = GetTickCount64();

        if (!entry.loading && entry.tick != 0 && now >= entry.tick && now - entry.tick <= USN_RAW_CACHE_TTL_MS)
        {
            output = entry.output;
            return entry.ok;
        }

        if (!entry.loading)
        {
            entry.loading = true;
            break;
        }

        cacheCv.wait(lock, [&entry]() { return !entry.loading; });
    }

    std::wstring freshOutput;
    std::wstring command = L"fsutil usn readjournal C: csv | findstr /l /i /c:\"" + ext + L"\"";
    bool ok = RunHiddenCommandCapture(command, freshOutput, timeoutMs);

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        UsnFilteredRawCacheEntry& entry = cache[key];
        entry.output = freshOutput;
        entry.ok = ok;
        entry.tick = GetTickCount64();
        entry.loading = false;

        if (cache.size() > 8)
        {
            ULONGLONG oldestTick = ULLONG_MAX;
            std::wstring oldestKey;
            for (const auto& item : cache)
            {
                if (!item.second.loading && item.second.tick < oldestTick)
                {
                    oldestTick = item.second.tick;
                    oldestKey = item.first;
                }
            }
            if (!oldestKey.empty())
                cache.erase(oldestKey);
        }
    }
    cacheCv.notify_all();

    output = std::move(freshOutput);
    return ok;
}

static std::vector<std::wstring> ReadUsnEntriesForActivityExt(const std::wstring& ext)
{
    std::vector<std::wstring> rawLines;
    std::wstring output;
    if (!ReadUsnFilteredOutputCached(ext, output, 120000))
    {
        rawLines.push_back(L"__ERROR__");
        return rawLines;
    }
    return SplitAutomationTextLines(output);
}

static std::vector<std::wstring> ReadJarUsnEntriesForActivity()
{
    return ReadUsnEntriesForActivityExt(L".jar");
}

static std::vector<JarUsnEntry> CollectReasonEntriesForExtension(const std::wstring& ext)
{
    std::vector<JarUsnEntry> entries;
    std::vector<std::wstring> raw = ReadUsnEntriesForActivityExt(ext);
    if (raw.size() == 1 && raw[0] == L"__ERROR__")
        return entries;

    entries.reserve(raw.size());
    for (const std::wstring& rawLine : raw)
    {
        if (rawLine.empty())
            continue;
        std::wstring lower = ToLowerCopy(rawLine);
        if (lower.find(L"usn") != std::wstring::npos && lower.find(L"reason") != std::wstring::npos && lower.find(L"name") != std::wstring::npos)
            continue;

        JarUsnEntry e = MakeUsnEntryForExtension(rawLine, ext);
        if (!ShouldShowUsnEntryForExtension(e, ext))
            continue;
        if (SimpleJarJournalReason(e).empty())
            continue;
        entries.push_back(std::move(e));
    }
    return entries;
}

static std::vector<JarUsnEntry> CollectJarReasonEntries()
{
    return CollectReasonEntriesForExtension(L".jar");
}

static std::wstring FileActivityModificationTimeText(const JarUsnEntry& e, const std::wstring& fullPath, const std::wstring& ext, ULONGLONG* outSortTime = nullptr)
{
    if (_wcsicmp(ext.c_str(), L".jar") == 0)
        return JarFileModificationTimeText(e, fullPath, outSortTime);

    std::wstring direct = FileLastWriteTimeText(fullPath, outSortTime);
    if (!IsUnknownAutomationDate(direct))
        return direct;
    return L"дата неизвестна";
}

static void AppendUnifiedFileActivityRow(std::vector<std::wstring>& lines, const std::wstring& ext, const JarUsnEntry& e, const std::wstring& reasonOverride = L"", const std::wstring& programOverride = L"")
{
    std::wstring reason = reasonOverride.empty() ? SimpleJarJournalReason(e) : reasonOverride;
    if (reason.empty())
        return;

    std::wstring fullPath = ResolveUsnFullPathForEntry(e, ext);
    ULONGLONG modSortTime = 0;
    std::wstring modDate = FileActivityModificationTimeText(e, fullPath, ext, &modSortTime);
    std::wstring program = CleanPipeCell(programOverride);
    if (program.empty())
        program = CleanPipeCell(ExtractFileNameOnly(fullPath));
    if (program.empty())
        program = CleanPipeCell(ExtractFileNameOnly(e.name));
    if (program.empty())
        program = CleanPipeCell(e.name);
    if (program.empty())
        return;

    std::wstring reasonCell = BuildJarActivityReasonWithUsnDate(reason, e.date);
    if (reasonCell.empty())
        return;

    std::wstring row = CleanPipeCell(modDate) + L" | " + reasonCell + L" | " + program;
    if (SimpleJarJournalReason(e) == L"deleted")
        row.insert(0, AUTOMATION_DELETED_MARKER);
    lines.push_back(std::move(row));
}

static std::wstring UnifiedActivityDedupKey(const JarUsnEntry& e, const std::wstring& ext, const std::wstring& reasonOverride = L"", const std::wstring& programOverride = L"")
{
    std::wstring reason = reasonOverride.empty() ? SimpleJarJournalReason(e) : reasonOverride;
    std::wstring fullPath = ResolveUsnFullPathForEntry(e, ext);
    std::wstring name = programOverride.empty() ? ExtractFileNameOnly(fullPath) : programOverride;
    if (name.empty())
        name = ExtractFileNameOnly(e.name);
    if (name.empty())
        name = e.name;
    return ToLowerCopy(CleanPipeCell(name)) + L"|" + ToLowerCopy(CleanPipeCell(reason));
}

static std::vector<std::wstring> ScanFileActivityJournalReasonsOnly(const std::wstring& ext)
{
    std::vector<std::wstring> lines;
    lines.push_back(L"дата модификации | действие | программа");

    std::vector<JarUsnEntry> entries = CollectReasonEntriesForExtension(ext);
    if (entries.empty())
    {
        std::vector<std::wstring> probe = ReadUsnEntriesForActivityExt(ext);
        if (probe.size() == 1 && probe[0] == L"__ERROR__")
            lines.push_back(L"не удалось запустить fsutil");
        else
            lines.push_back(L"не найдено");
        return lines;
    }

    std::set<std::wstring> seen;
    std::vector<bool> used(entries.size(), false);
    for (size_t i = 0; i < entries.size(); ++i)
    {
        if (used[i])
            continue;
        const JarUsnEntry& e = entries[i];
        std::wstring reason = SimpleJarJournalReason(e);

        if (e.renameOld)
        {
            size_t pairIndex = static_cast<size_t>(-1);
            for (size_t j = i + 1; j < entries.size(); ++j)
            {
                if (!used[j] && entries[j].renameNew)
                {
                    pairIndex = j;
                    break;
                }
            }
            if (pairIndex != static_cast<size_t>(-1))
            {
                std::wstring oldName = CleanPipeCell(ExtractFileNameOnly(entries[i].name));
                std::wstring newName = CleanPipeCell(ExtractFileNameOnly(entries[pairIndex].name));
                if (oldName.empty()) oldName = CleanPipeCell(entries[i].name);
                if (newName.empty()) newName = CleanPipeCell(entries[pairIndex].name);
                // Не показываем технический rename, если имя фактически не изменилось
                // (например: rename d1.jar -> d1.jar).
                if (ToLowerCopy(oldName) != ToLowerCopy(newName))
                {
                    std::wstring action = L"rename " + oldName + L" -> " + newName;
                    std::wstring key = UnifiedActivityDedupKey(entries[pairIndex], ext, action, newName);
                    if (!key.empty() && seen.insert(key).second)
                        AppendUnifiedFileActivityRow(lines, ext, entries[pairIndex], action, newName);
                }
                used[i] = true;
                used[pairIndex] = true;
                continue;
            }
        }
        if (e.renameNew)
        {
            // Одиночный rename-new часто является технической ��аписью USN без реального
            // изменения имени (визуально получается rename -> same_name). Такие строки
            // не показываем, пока рядом не найден rename-old и можно собрать пару old -> new.
            used[i] = true;
            continue;
        }

        std::wstring key = UnifiedActivityDedupKey(e, ext);
        if (!key.empty() && !seen.insert(key).second)
            continue;
        AppendUnifiedFileActivityRow(lines, ext, e);
    }

    if (lines.size() == 1)
        lines.push_back(L"не найдено");
    return lines;
}

static std::vector<std::wstring> ScanJarActivityJournalReasonsOnly()
{
    return ScanFileActivityJournalReasonsOnly(L".jar");
}

static std::vector<std::wstring> ScanDllActivityJournalReasonsOnly()
{
    return ScanFileActivityJournalReasonsOnly(L".dll");
}

static std::vector<std::wstring> ScanUsnActivityForExtension(const std::wstring& ext, bool deletedOnly, bool keepDeletedInActivity = false)
{
    std::vector<std::wstring> lines;
    lines.push_back(L"дата | программа | путь");

    std::wstring output;
    if (!ReadUsnFilteredOutputCached(ext, output, 120000))
    {
        lines.push_back(L"не удалось запустить fsutil");
        return lines;
    }

    std::vector<std::wstring> raw = SplitAutomationTextLines(output);
    std::vector<JarUsnEntry> entries;
    entries.reserve(raw.size());

    for (const std::wstring& rawLine : raw)
    {
        if (rawLine.empty())
            continue;

        std::wstring lower = ToLowerCopy(rawLine);
        if (lower.find(L"usn") != std::wstring::npos && lower.find(L"reason") != std::wstring::npos && lower.find(L"name") != std::wstring::npos)
            continue;

        JarUsnEntry entry = MakeUsnEntryForExtension(rawLine, ext);
        if (!entry.name.empty())
            entries.push_back(entry);
    }

    for (const JarUsnEntry& e : entries)
    {
        if (!ShouldShowUsnEntryForExtension(e, ext))
            continue;

        if (deletedOnly)
        {
            // В окнах deleted показываем только те записи USN,
            // где реально есть FILE_DELETE. Один только CLOSE не означает удаление.
            if (e.deleted)
                AppendJarActivityRow(lines, e.date, L"deleted", e.name, ResolveUsnFullPathForEntry(e, ext));
            continue;
        }

        if (e.deleted)
        {
            if (keepDeletedInActivity)
                AppendJarActivityRow(lines, e.date, L"deleted", e.name, ResolveUsnFullPathForEntry(e, ext));
            continue;
        }

        AppendJarActivityRow(lines, e.date, e.reasonText.empty() ? L"activity" : e.reasonText.c_str(), e.name, ResolveUsnFullPathForEntry(e, ext));
    }

    if (lines.size() == 1)
        lines.push_back(L"не найдено");

    return lines;
}


static std::vector<std::wstring> SplitTextByPipe(const std::wstring& line)
{
    std::vector<std::wstring> cols;
    size_t start = 0;
    while (start <= line.size())
    {
        size_t pos = line.find(L"|", start);
        std::wstring part = (pos == std::wstring::npos) ? line.substr(start) : line.substr(start, pos - start);
        cols.push_back(TrimAutomationField(part));
        if (pos == std::wstring::npos)
            break;
        start = pos + 1;
    }
    return cols;
}

struct ExeLaunchRegistryRow
{
    std::wstring date;
    std::wstring source;
    std::wstring name;
    std::wstring path;
    ULONGLONG sortTime = 0;
};

static std::wstring RegistryValueTimeText(const FILETIME& ft, ULONGLONG& sortTime)
{
    sortTime = 0;
    if (!IsPlausibleFileTime(ft))
        return L"дата неизвестна";
    sortTime = FileTimeToUInt64(ft);
    return FileTimeToLocalText(ft);
}

static bool ExtractExePathFromRegistryText(const std::wstring& text, std::wstring& outPath)
{
    std::wstring cleaned = TrimAutomationField(text);
    if (cleaned.empty())
        return false;

    size_t exePos = ToLowerCopy(cleaned).find(L".exe");
    if (exePos == std::wstring::npos)
        return false;

    size_t end = exePos + 4;
    size_t start = cleaned.rfind(L'\"', exePos);
    if (start != std::wstring::npos)
    {
        start += 1;
        outPath = cleaned.substr(start, end - start);
        return !outPath.empty();
    }

    start = cleaned.rfind(L"C:\\", exePos);
    if (start == std::wstring::npos)
        start = cleaned.rfind(L"D:\\", exePos);
    if (start == std::wstring::npos)
        start = cleaned.rfind(L"E:\\", exePos);
    if (start == std::wstring::npos)
        start = cleaned.rfind(L"\\Device\\", exePos);
    if (start == std::wstring::npos)
        start = 0;

    outPath = cleaned.substr(start, end - start);
    while (!outPath.empty() && (outPath.front() == L' ' || outPath.front() == L'\t' || outPath.front() == L'\"'))
        outPath.erase(outPath.begin());
    while (!outPath.empty() && (outPath.back() == L' ' || outPath.back() == L'\t' || outPath.back() == L'\"'))
        outPath.pop_back();
    return !outPath.empty();
}

static std::wstring Rot13Wide(const std::wstring& text)
{
    std::wstring out = text;
    for (wchar_t& ch : out)
    {
        if (ch >= L'a' && ch <= L'z')
            ch = static_cast<wchar_t>(L'a' + ((ch - L'a' + 13) % 26));
        else if (ch >= L'A' && ch <= L'Z')
            ch = static_cast<wchar_t>(L'A' + ((ch - L'A' + 13) % 26));
    }
    return out;
}

static void AddExeLaunchRow(std::vector<ExeLaunchRegistryRow>& rows, const std::wstring& source, const std::wstring& rawPath, const std::wstring& fallbackDate, ULONGLONG sortTime)
{
    std::wstring path = DevicePathToDosPath(rawPath);
    path = TrimAutomationField(path);

    std::wstring lower = ToLowerCopy(path);
    if (lower.find(L".exe") == std::wstring::npos)
        return;

    // Системные exe не добавляем в .exe activity ни из реестра, ни и�� Prefetch.
    if (IsLikelySystemExecutable(path))
        return;

    ExeLaunchRegistryRow row;
    row.date = fallbackDate.empty() ? L"дата ��еизвестна" : fallbackDate;
    row.source = source;
    row.path = path;
    row.name = ExtractFileNameOnly(path);
    if (row.name.empty())
        row.name = path;
    row.sortTime = sortTime;
    rows.push_back(std::move(row));
}

static bool IsPrefetchLaunchRow(const ExeLaunchRegistryRow& row)
{
    return ToLowerCopy(row.source).find(L"prefetch") != std::wstring::npos;
}


struct PrefetchLaunchInfo
{
    std::wstring exeName;
    std::wstring path;
    std::wstring date;
    ULONGLONG sortTime = 0;
};

static std::wstring NormalizeExeLaunchKey(const std::wstring& text)
{
    std::wstring value = ToLowerCopy(DevicePathToDosPath(TrimAutomationField(text)));
    std::replace(value.begin(), value.end(), L'/', L'\\');
    return value;
}

static bool SameExeLaunchPathOrName(const ExeLaunchRegistryRow& row, const PrefetchLaunchInfo& pf)
{
    std::wstring rowPath = NormalizeExeLaunchKey(row.path);
    std::wstring pfPath = NormalizeExeLaunchKey(pf.path);
    if (!rowPath.empty() && !pfPath.empty() && rowPath == pfPath)
        return true;

    std::wstring rowName = ToLowerCopy(row.name.empty() ? ExtractFileNameOnly(row.path) : row.name);
    std::wstring pfName = ToLowerCopy(pf.exeName.empty() ? ExtractFileNameOnly(pf.path) : pf.exeName);
    return !rowName.empty() && !pfName.empty() && rowName == pfName;
}

static bool ApplyPrefetchTimeToRegistryRow(ExeLaunchRegistryRow& row, const std::vector<PrefetchLaunchInfo>& prefetch)
{
    const PrefetchLaunchInfo* best = nullptr;
    for (const PrefetchLaunchInfo& pf : prefetch)
    {
        if (!SameExeLaunchPathOrName(row, pf))
            continue;
        if (!best || pf.sortTime > best->sortTime)
            best = &pf;
    }

    if (!best || best->sortTime == 0)
        return false;

    row.date = best->date;
    row.sortTime = best->sortTime;
    if (ToLowerCopy(row.source).find(L"prefetch") == std::wstring::npos)
        row.source += L" / Prefetch time";
    return true;
}

static std::wstring PrefetchExeNameFromFileName(const std::wstring& fileName)
{
    std::wstring name = ExtractFileNameOnly(fileName);
    std::wstring lower = ToLowerCopy(name);

    if (lower.size() < 3 || lower.substr(lower.size() - 3) != L".pf")
        return L"";

    name = name.substr(0, name.size() - 3);

    size_t dash = name.find_last_of(L'-');
    if (dash != std::wstring::npos && dash > 0)
        name = name.substr(0, dash);

    name = TrimAutomationField(name);
    if (name.empty())
        return L"";

    if (ToLowerCopy(name).find(L".exe") == std::wstring::npos)
        name += L".exe";

    return name;
}

static bool IsReadablePrefetchChar(wchar_t ch)
{
    return ch >= 32 && ch < 127 || ch >= 0x0400 && ch <= 0x052F;
}

static bool ReadWholeFileBytes(const std::wstring& path, std::vector<BYTE>& bytes)
{
    bytes.clear();

    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 || size.QuadPart > 32LL * 1024LL * 1024LL)
    {
        CloseHandle(h);
        return false;
    }

    bytes.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    CloseHandle(h);

    if (!ok || read == 0)
    {
        bytes.clear();
        return false;
    }

    bytes.resize(read);
    return true;
}

static bool IsBetterPrefetchExePathCandidate(const std::wstring& candidate, const std::wstring& currentBest)
{
    if (currentBest.empty())
        return true;

    std::wstring c = ToLowerCopy(candidate);
    std::wstring b = ToLowerCopy(currentBest);

    bool cDos = c.size() > 2 && c[1] == L':' && (c[2] == L'\\' || c[2] == L'/');
    bool bDos = b.size() > 2 && b[1] == L':' && (b[2] == L'\\' || b[2] == L'/');
    if (cDos != bDos)
        return cDos;

    bool cDevice = c.rfind(L"\\device\\", 0) == 0;
    bool bDevice = b.rfind(L"\\device\\", 0) == 0;
    if (cDevice != bDevice)
        return cDevice;

    return candidate.size() > currentBest.size();
}

static bool TryExtractExePathFromPrefetchFile(const std::wstring& pfPath, const std::wstring& exeName, std::wstring& outPath)
{
    outPath.clear();

    std::vector<BYTE> bytes;
    if (!ReadWholeFileBytes(pfPath, bytes) || bytes.size() < sizeof(wchar_t))
        return false;

    std::wstring target = ToLowerCopy(ExtractFileNameOnly(exeName));
    std::wstring current;
    std::wstring best;

    auto flush = [&]()
    {
        if (current.size() >= 5)
        {
            std::wstring lower = ToLowerCopy(current);
            if (lower.find(L".exe") != std::wstring::npos &&
                (target.empty() || ToLowerCopy(ExtractFileNameOnly(current)) == target || lower.find(target) != std::wstring::npos))
            {
                std::wstring candidate;
                if (ExtractExePathFromRegistryText(current, candidate))
                {
                    candidate = DevicePathToDosPath(candidate);
                    if (!IsLikelySystemExecutable(candidate) && IsBetterPrefetchExePathCandidate(candidate, best))
                        best = candidate;
                }
            }
        }
        current.clear();
    };

    for (size_t i = 0; i + 1 < bytes.size(); i += 2)
    {
        wchar_t ch = static_cast<wchar_t>(bytes[i] | (static_cast<WORD>(bytes[i + 1]) << 8));
        if (IsReadablePrefetchChar(ch))
        {
            current.push_back(ch);
            if (current.size() > 1024)
                flush();
        }
        else
        {
            flush();
        }
    }
    flush();

    if (best.empty())
        return false;

    outPath = best;
    return true;
}


static std::vector<PrefetchLaunchInfo> BuildPrefetchLaunchInfos()
{
    std::vector<PrefetchLaunchInfo> infos;

    wchar_t windowsDir[MAX_PATH * 4]{};
    UINT len = GetWindowsDirectoryW(windowsDir, ARRAYSIZE(windowsDir));
    if (len == 0 || len >= ARRAYSIZE(windowsDir))
        return infos;

    std::wstring folder(windowsDir);
    while (!folder.empty() && (folder.back() == L'\\' || folder.back() == L'/'))
        folder.pop_back();
    folder += L"\\Prefetch";

    std::wstring mask = folder + L"\\*.pf";
    WIN32_FIND_DATAW data{};
    HANDLE h = FindFirstFileW(mask.c_str(), &data);
    if (h == INVALID_HANDLE_VALUE)
        return infos;

    do
    {
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        std::wstring exeName = PrefetchExeNameFromFileName(data.cFileName);
        if (exeName.empty())
            continue;

        // Системные exe не добавляем даже как источник времени для .exe activity.
        if (IsLikelySystemExecutable(exeName))
            continue;

        ULONGLONG sortTime = 0;
        std::wstring when = L"дата неизвестна";
        if (IsPlausibleFileTime(data.ftLastWriteTime))
        {
            sortTime = FileTimeToUInt64(data.ftLastWriteTime);
            when = FileTimeToLocalText(data.ftLastWriteTime);
        }

        std::wstring pfPath = folder + L"\\" + data.cFileName;
        std::wstring exePath;
        TryExtractExePathFromPrefetchFile(pfPath, exeName, exePath);

        if (!exePath.empty() && IsLikelySystemExecutable(exePath))
            continue;

        PrefetchLaunchInfo info;
        info.exeName = exeName;
        info.path = exePath;
        info.date = when;
        info.sortTime = sortTime;
        infos.push_back(std::move(info));
    }
    while (FindNextFileW(h, &data));

    FindClose(h);
    return infos;
}

static void AppendPrefetchExeLaunchRows(std::vector<ExeLaunchRegistryRow>& rows)
{
    wchar_t windowsDir[MAX_PATH * 4]{};
    UINT len = GetWindowsDirectoryW(windowsDir, ARRAYSIZE(windowsDir));
    if (len == 0 || len >= ARRAYSIZE(windowsDir))
        return;

    std::wstring folder(windowsDir);
    while (!folder.empty() && (folder.back() == L'\\' || folder.back() == L'/'))
        folder.pop_back();
    folder += L"\\Prefetch";

    std::wstring mask = folder + L"\\*.pf";
    WIN32_FIND_DATAW data{};
    HANDLE h = FindFirstFileW(mask.c_str(), &data);
    if (h == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        std::wstring exeName = PrefetchExeNameFromFileName(data.cFileName);
        if (exeName.empty())
            continue;

        std::wstring pfPath = folder + L"\\" + data.cFileName;
        std::wstring exePath;

        // Из Prefetch берём не только имя .pf, а пытаемся достать реальный путь запущенного exe из содержимого .pf.
        // Если путь восстановить нельзя, строку не добавляем, чтобы в .exe activity не было записей без пути.
        if (!TryExtractExePathFromPrefetchFile(pfPath, exeName, exePath))
            continue;

        ULONGLONG sortTime = 0;
        std::wstring when = L"дата неизвестна";
        if (IsPlausibleFileTime(data.ftLastWriteTime))
        {
            sortTime = FileTimeToUInt64(data.ftLastWriteTime);
            when = FileTimeToLocalText(data.ftLastWriteTime);
        }

        AddExeLaunchRow(rows, L"Prefetch / modified", exePath, when, sortTime);
    }
    while (FindNextFileW(h, &data));

    FindClose(h);
}

static void AppendMuiCacheValues(HKEY root, const std::wstring& subKey, const std::wstring& label, std::vector<ExeLaunchRegistryRow>& rows)
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS &&
        RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_32KEY, &key) != ERROR_SUCCESS)
        return;

    DWORD valueCount = 0, maxValueNameLen = 0, maxValueDataLen = 0;
    RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valueCount, &maxValueNameLen, &maxValueDataLen, nullptr, nullptr);
    ULONGLONG sortTime = 0;
    std::wstring when;

    for (DWORD i = 0; i < valueCount; ++i)
    {
        std::vector<wchar_t> valueName(maxValueNameLen + 2, L'\0');
        std::vector<BYTE> valueData(std::max<DWORD>(maxValueDataLen + 4, 8));
        DWORD nameLen = static_cast<DWORD>(valueName.size());
        DWORD dataLen = static_cast<DWORD>(valueData.size());
        DWORD type = 0;
        if (RegEnumValueW(key, i, valueName.data(), &nameLen, nullptr, &type, valueData.data(), &dataLen) != ERROR_SUCCESS)
            continue;

        std::wstring raw(valueName.data(), nameLen);
        std::wstring path;
        if (ExtractExePathFromRegistryText(raw, path))
            AddExeLaunchRow(rows, label + L" / MuiCache", path, when, sortTime);
    }

    RegCloseKey(key);
}

static void AppendRegistryExeValueNames(HKEY root, const std::wstring& subKey, const std::wstring& label, bool userAssistRot13, std::vector<ExeLaunchRegistryRow>& rows)
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS &&
        RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_32KEY, &key) != ERROR_SUCCESS)
        return;

    DWORD subKeyCount = 0, maxSubKeyLen = 0, valueCount = 0, maxValueNameLen = 0, maxValueDataLen = 0;
    RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKeyLen, nullptr, &valueCount, &maxValueNameLen, &maxValueDataLen, nullptr, nullptr);
    ULONGLONG sortTime = 0;
    std::wstring when;

    for (DWORD i = 0; i < valueCount; ++i)
    {
        std::vector<wchar_t> valueName(maxValueNameLen + 2, L'\0');
        std::vector<BYTE> valueData(std::max<DWORD>(maxValueDataLen + 4, 8));
        DWORD nameLen = static_cast<DWORD>(valueName.size());
        DWORD dataLen = static_cast<DWORD>(valueData.size());
        DWORD type = 0;
        if (RegEnumValueW(key, i, valueName.data(), &nameLen, nullptr, &type, valueData.data(), &dataLen) != ERROR_SUCCESS)
            continue;

        std::wstring text(valueName.data(), nameLen);
        if (userAssistRot13)
            text = Rot13Wide(text);

        std::wstring path;
        if (ExtractExePathFromRegistryText(text, path))
            AddExeLaunchRow(rows, label, path, when, sortTime);
    }

    for (DWORD i = 0; i < subKeyCount; ++i)
    {
        std::vector<wchar_t> child(maxSubKeyLen + 2, L'\0');
        DWORD childLen = static_cast<DWORD>(child.size());
        if (RegEnumKeyExW(key, i, child.data(), &childLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS && childLen > 0)
            AppendRegistryExeValueNames(root, subKey + L"\\" + std::wstring(child.data(), childLen), label, userAssistRot13, rows);
    }

    RegCloseKey(key);
}

static void AppendRegistryExeValueData(HKEY root, const std::wstring& subKey, const std::wstring& label, std::vector<ExeLaunchRegistryRow>& rows)
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS &&
        RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | KEY_WOW64_32KEY, &key) != ERROR_SUCCESS)
        return;

    DWORD subKeyCount = 0, maxSubKeyLen = 0, valueCount = 0, maxValueNameLen = 0, maxValueDataLen = 0;
    RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKeyLen, nullptr, &valueCount, &maxValueNameLen, &maxValueDataLen, nullptr, nullptr);
    ULONGLONG sortTime = 0;
    std::wstring when;

    for (DWORD i = 0; i < valueCount; ++i)
    {
        std::vector<wchar_t> valueName(maxValueNameLen + 2, L'\0');
        std::vector<BYTE> valueData(std::max<DWORD>(maxValueDataLen + 4, 8));
        DWORD nameLen = static_cast<DWORD>(valueName.size());
        DWORD dataLen = static_cast<DWORD>(valueData.size());
        DWORD type = 0;
        if (RegEnumValueW(key, i, valueName.data(), &nameLen, nullptr, &type, valueData.data(), &dataLen) != ERROR_SUCCESS)
            continue;

        std::wstring text;
        if ((type == REG_SZ || type == REG_EXPAND_SZ) && dataLen >= sizeof(wchar_t))
            text.assign(reinterpret_cast<wchar_t*>(valueData.data()), dataLen / sizeof(wchar_t));
        else
            text.assign(valueName.data(), nameLen);

        std::wstring path;
        if (ExtractExePathFromRegistryText(text, path))
            AddExeLaunchRow(rows, label, path, when, sortTime);
    }

    for (DWORD i = 0; i < subKeyCount; ++i)
    {
        std::vector<wchar_t> child(maxSubKeyLen + 2, L'\0');
        DWORD childLen = static_cast<DWORD>(child.size());
        if (RegEnumKeyExW(key, i, child.data(), &childLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS && childLen > 0)
            AppendRegistryExeValueData(root, subKey + L"\\" + std::wstring(child.data(), childLen), label, rows);
    }

    RegCloseKey(key);
}

static void AppendMuiCacheForAllUsers(std::vector<ExeLaunchRegistryRow>& rows)
{
    const std::wstring muiSub = L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache";
    AppendMuiCacheValues(HKEY_CLASSES_ROOT, L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", L"HKCR", rows);
    AppendMuiCacheValues(HKEY_CURRENT_USER, muiSub, L"HKCU", rows);

    HKEY users = nullptr;
    if (RegOpenKeyExW(HKEY_USERS, nullptr, 0, KEY_READ, &users) != ERROR_SUCCESS)
        return;

    DWORD subKeyCount = 0, maxSubKeyLen = 0;
    if (RegQueryInfoKeyW(users, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKeyLen, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
    {
        for (DWORD i = 0; i < subKeyCount; ++i)
        {
            std::vector<wchar_t> sid(maxSubKeyLen + 2, L'\0');
            DWORD sidLen = static_cast<DWORD>(sid.size());
            if (RegEnumKeyExW(users, i, sid.data(), &sidLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS || sidLen == 0)
                continue;

            std::wstring sidText(sid.data(), sidLen);
            AppendMuiCacheValues(HKEY_USERS, sidText + L"\\" + muiSub, L"HKU\\" + ShortSidTail(sidText), rows);
            AppendMuiCacheValues(HKEY_USERS, sidText + L"_Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", L"HKU\\" + ShortSidTail(sidText) + L"_Classes", rows);
        }
    }

    RegCloseKey(users);
}

static void AppendExeLaunchArtifactsForUserRoot(HKEY root, const std::wstring& prefix, const std::wstring& labelPrefix, std::vector<ExeLaunchRegistryRow>& rows)
{
    std::wstring base = prefix.empty() ? L"" : prefix + L"\\";
    AppendRegistryExeValueNames(root, base + L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist", labelPrefix + L"UserAssist", true, rows);
    AppendRegistryExeValueData(root, base + L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store", labelPrefix + L"Compatibility Assistant Store", rows);
    AppendRegistryExeValueData(root, base + L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted", labelPrefix + L"Compatibility Assistant Persisted", rows);
    AppendRegistryExeValueData(root, base + L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers", labelPrefix + L"AppCompat Layers", rows);
    AppendRegistryExeValueData(root, base + L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", labelPrefix + L"RunMRU", rows);
    AppendRegistryExeValueData(root, base + L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU", labelPrefix + L"OpenSavePidlMRU", rows);
    AppendRegistryExeValueData(root, base + L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", labelPrefix + L"RecentDocs", rows);
}

static void AppendExeLaunchArtifactsForAllUsers(std::vector<ExeLaunchRegistryRow>& rows)
{
    AppendExeLaunchArtifactsForUserRoot(HKEY_CURRENT_USER, L"", L"HKCU / ", rows);
    AppendExeLaunchArtifactsForUserRoot(HKEY_LOCAL_MACHINE, L"", L"HKLM / ", rows);

    HKEY users = nullptr;
    if (RegOpenKeyExW(HKEY_USERS, nullptr, 0, KEY_READ, &users) != ERROR_SUCCESS)
        return;

    DWORD subKeyCount = 0, maxSubKeyLen = 0;
    if (RegQueryInfoKeyW(users, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKeyLen, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
    {
        for (DWORD i = 0; i < subKeyCount; ++i)
        {
            std::vector<wchar_t> sid(maxSubKeyLen + 2, L'\0');
            DWORD sidLen = static_cast<DWORD>(sid.size());
            if (RegEnumKeyExW(users, i, sid.data(), &sidLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS || sidLen == 0)
                continue;

            std::wstring sidText(sid.data(), sidLen);
            if (sidText.find(L"_Classes") != std::wstring::npos)
                continue;
            AppendExeLaunchArtifactsForUserRoot(HKEY_USERS, sidText, L"HKU\\" + ShortSidTail(sidText) + L" / ", rows);
        }
    }

    RegCloseKey(users);
}

static void AppendBamExeLaunchRows(std::vector<ExeLaunchRegistryRow>& rows)
{
    std::vector<BamEntry> bamRows;
    std::vector<std::wstring> notes;
    const wchar_t* subPaths[] =
    {
        L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
        L"SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings",
        L"SYSTEM\\ControlSet001\\Services\\bam\\UserSettings",
        L"SYSTEM\\ControlSet002\\Services\\bam\\State\\UserSettings",
        L"SYSTEM\\ControlSet002\\Services\\bam\\UserSettings"
    };

    for (const wchar_t* subPath : subPaths)
        AppendBamRegistryKey(subPath, true, bamRows, notes);

    for (const BamEntry& entry : bamRows)
    {
        if (entry.signature != BamSignatureState::NotSigned)
            continue;

        std::wstring raw = entry.path.empty() ? entry.exeName : entry.path;
        AddExeLaunchRow(rows, L"BAM / unsigned", raw, entry.when, entry.fileTimeValue);
    }
}

static std::vector<std::wstring> ScanExeLaunchesFromRegistry()
{
    std::vector<std::wstring> lines;
    lines.push_back(L"дата запуска | программа | путь");

    std::vector<ExeLaunchRegistryRow> rows;

    // .exe activity снова сканирует реестр, но НЕ берёт дату через RegQueryInfoKeyW(..., &keyWrite).
    // Реестр здесь используется как источник путей/факта активности, а время запуска берётся из Prefetch modified time.
    std::vector<PrefetchLaunchInfo> prefetch = BuildPrefetchLaunchInfos();

    AppendPrefetchExeLaunchRows(rows);

    std::vector<ExeLaunchRegistryRow> registryRows;
    AppendExeLaunchArtifactsForAllUsers(registryRows);
    AppendMuiCacheForAllUsers(registryRows);
    for (ExeLaunchRegistryRow& regRow : registryRows)
    {
        // Без совпадения с Prefetch не показываем строку: иначе дата была бы не временем запуска конкретного exe.
        if (ApplyPrefetchTimeToRegistryRow(regRow, prefetch))
            rows.push_back(std::move(regRow));
    }

    // BAM имеет отдельный FILETIME у значения, поэтому его можно использовать как источник времени.
    // В .exe activity из BAM выводим только unsigned/not signed.
    AppendBamExeLaunchRows(rows);

    // Сначала убираем дубли одной программы, потом сортируем строго по времени.
    // Старый вариант сортировал Prefetch внутри компаратора и из-за этого порядок мог быть "разнобой".
    std::vector<ExeLaunchRegistryRow> uniqueRows;
    for (const ExeLaunchRegistryRow& row : rows)
    {
        std::wstring key = ToLowerCopy(row.name);
        if (key.empty())
            key = ToLowerCopy(row.path);
        if (key.empty())
            continue;

        auto it = std::find_if(uniqueRows.begin(), uniqueRows.end(), [&](const ExeLaunchRegistryRow& existing)
        {
            std::wstring existingKey = ToLowerCopy(existing.name);
            if (existingKey.empty())
                existingKey = ToLowerCopy(existing.path);
            return existingKey == key;
        });

        if (it == uniqueRows.end())
        {
            uniqueRows.push_back(row);
            continue;
        }

        bool rowPrefetch = IsPrefetchLaunchRow(row);
        bool oldPrefetch = IsPrefetchLaunchRow(*it);

        if ((rowPrefetch && row.sortTime > 0 && !oldPrefetch) ||
            (row.sortTime > it->sortTime) ||
            (row.sortTime == it->sortTime && rowPrefetch && !oldPrefetch))
        {
            *it = row;
        }
    }

    rows.swap(uniqueRows);

    std::sort(rows.begin(), rows.end(), [](const ExeLaunchRegistryRow& a, const ExeLaunchRegistryRow& b)
    {
        if (a.sortTime != b.sortTime)
            return a.sortTime > b.sortTime;

        bool au = (a.sortTime == 0);
        bool bu = (b.sortTime == 0);
        if (au != bu)
            return !au;

        int p = _wcsicmp(a.date.c_str(), b.date.c_str());
        if (p != 0)
            return p > 0;

        p = _wcsicmp(a.path.c_str(), b.path.c_str());
        if (p != 0)
            return p < 0;

        return _wcsicmp(a.source.c_str(), b.source.c_str()) < 0;
    });

    for (const ExeLaunchRegistryRow& row : rows)
    {
        std::wstring cleanPath = CleanPipeCell(DevicePathToDosPath(row.path.empty() ? row.name : row.path));
        std::wstring rawProgram = row.name.empty() ? ExtractFileNameOnly(cleanPath) : row.name;
        std::wstring program = CleanPipeCell(ExtractFileNameOnly(rawProgram));
        if (program.empty())
            program = ExtractFileNameOnly(cleanPath);
        if (program.empty() || cleanPath.empty())
            continue;
        lines.push_back(CleanPipeCell(row.date) + L" | " + program + L" | " + cleanPath);
    }

    if (lines.size() == 1)
        lines.push_back(L"не найдено");

    return lines;
}

static std::vector<std::wstring> ScanExeDeletedFromUsnDeleteClose()
{
    std::vector<std::wstring> lines;
    lines.push_back(L"дата | программа | путь");

    std::wstring output;
    if (!ReadUsnFilteredOutputCached(L".exe", output, 120000))
    {
        lines.push_back(L"не удалось запустить fsutil");
        return lines;
    }

    std::vector<std::wstring> raw = SplitAutomationTextLines(output);
    for (const std::wstring& rawLine : raw)
    {
        if (rawLine.empty())
            continue;

        std::wstring lower = ToLowerCopy(rawLine);
        if (lower.find(L"usn") != std::wstring::npos && lower.find(L"reason") != std::wstring::npos && lower.find(L"name") != std::wstring::npos)
            continue;

        JarUsnEntry e = MakeUsnEntryForExtension(rawLine, L".exe");
        if (!ShouldShowUsnEntryForExtension(e, L".exe"))
            continue;

        // Только FILE_DELETE считается подтверждённым удалением.
        // CLOSE без FILE_DELETE больше не выводится в deleted.
        if (e.deleted)
            AppendJarActivityRow(lines, e.date, L"deleted", e.name, ResolveUsnFullPathForEntry(e, L".exe"));
    }

    if (lines.size() == 1)
        lines.push_back(L"не найдено");

    return lines;
}


static std::vector<std::wstring> ScanExeActivityWithDeleted()
{
    std::vector<std::wstring> lines = ScanExeLaunchesFromRegistry();

    // .exe deleted больше не отдельное окно: добавляем подтверждённые удаления в .exe activity.
    std::vector<std::wstring> deleted = ScanExeDeletedFromUsnDeleteClose();

    if (lines.size() == 2 && TrimAutomationField(lines[1]) == L"не найдено")
        lines.pop_back();

    for (size_t i = 1; i < deleted.size(); ++i)
    {
        std::wstring row = TrimAutomationField(deleted[i]);
        if (row.empty() || row == L"не найдено")
            continue;
        lines.push_back(row);
    }

    if (lines.size() == 1)
        lines.push_back(L"не найдено");

    return lines;
}

static bool LooksLikeMinecraftLogFileNameStrict(const std::wstring& name)
{
    std::wstring n = ToLowerCopy(ExtractFileNameOnly(name));
    if (n == L"latest.log" || n == L"debug.log" || n.find(L"hs_err_pid") != std::wstring::npos)
        return true;
    if (n.size() >= 14 && n[4] == L'-' && n[7] == L'-' && n.find(L".log") != std::wstring::npos)
        return true;
    return n.find(L".log.gz") != std::wstring::npos;
}

static bool RawUsnLineLooksLikeMinecraftLogsActivity(const std::wstring& rawLine)
{
    std::wstring lower = ToLowerCopy(rawLine);
    bool hasPath = (lower.find(L".minecraft") != std::wstring::npos && lower.find(L"logs") != std::wstring::npos) ||
        (lower.find(L"minecraft\\game") != std::wstring::npos && lower.find(L"logs") != std::wstring::npos) ||
        (lower.find(L"minecraft/game") != std::wstring::npos && lower.find(L"logs") != std::wstring::npos);

    if (hasPath)
        return lower.find(L".log") != std::wstring::npos || lower.find(L"log.gz") != std::wstring::npos ||
            lower.find(L"latest") != std::wstring::npos || lower.find(L"debug") != std::wstring::npos ||
            lower.find(L"hs_err_pid") != std::wstring::npos;

    return lower.find(L"latest.log") != std::wstring::npos ||
        lower.find(L"debug.log") != std::wstring::npos ||
        lower.find(L"hs_err_pid") != std::wstring::npos ||
        (lower.find(L".log") != std::wstring::npos && lower.find(L"-") != std::wstring::npos);
}

static std::wstring PickMinecraftLogActivityName(const std::wstring& rawLine)
{
    std::vector<std::wstring> fields = ParseAutomationCsvLine(rawLine);

    for (const std::wstring& field : fields)
    {
        std::wstring candidate = ExtractFileNameOnly(TrimAutomationField(field));
        if (LooksLikeMinecraftLogFileNameStrict(candidate))
            return candidate;
    }

    std::wstring lower = ToLowerCopy(rawLine);
    const wchar_t* tokens[] = { L"latest.log", L"debug.log", L".log.gz", L".log", L"hs_err_pid" };
    size_t pos = std::wstring::npos;
    size_t tokenLen = 0;
    for (const wchar_t* token : tokens)
    {
        size_t p = lower.find(token);
        if (p != std::wstring::npos && (pos == std::wstring::npos || p < pos))
        {
            pos = p;
            tokenLen = wcslen(token);
        }
    }
    if (pos == std::wstring::npos)
        return L"";

    size_t start = pos;
    while (start > 0)
    {
        wchar_t ch = rawLine[start - 1];
        if (ch == L',' || ch == L'"' || ch == L'|' || ch == L' ' || ch == L'\t' || ch == L'\\' || ch == L'/')
            break;
        --start;
    }

    size_t end = pos + tokenLen;
    while (end < rawLine.size())
    {
        wchar_t ch = rawLine[end];
        if (ch == L',' || ch == L'"' || ch == L'|' || ch == L' ' || ch == L'\t')
            break;
        ++end;
    }

    std::wstring name = ExtractFileNameOnly(rawLine.substr(start, end - start));
    return LooksLikeMinecraftLogFileNameStrict(name) ? name : L"";
}

static std::vector<std::wstring> ScanMinecraftLogsFolders()
{
    std::vector<std::wstring> lines;
    lines.push_back(L"дата | действие | файл");

    std::wstring script = LR"HCPS(
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
function SplitCsvLine([string]$line){
  $list = New-Object System.Collections.Generic.List[string]
  $sb = New-Object System.Text.StringBuilder
  $q = $false
  for($i=0; $i -lt $line.Length; $i++){
    $ch = $line[$i]
    if($ch -eq '"'){
      if($q -and ($i + 1) -lt $line.Length -and $line[$i+1] -eq '"'){[void]$sb.Append('"'); $i++} else {$q = -not $q}
    } elseif($ch -eq ',' -and -not $q){$list.Add($sb.ToString()); [void]$sb.Clear()}
    else {[void]$sb.Append($ch)}
  }
  $list.Add($sb.ToString())
  return @($list)
}
function IsMcLogName([string]$n){
  if([string]::IsNullOrWhiteSpace($n)){return $false}
  $x=[IO.Path]::GetFileName($n.Trim(' "')).ToLowerInvariant()
  return ($x -eq 'latest.log' -or $x -eq 'debug.log' -or $x -like '*.log.gz' -or $x -like '*.log' -or $x -like 'hs_err_pid*')
}
function ActionFromReason([string]$reason){
  $r=$reason.ToLowerInvariant()
  if($r -match 'rename.*old|old name|0x00001000'){return 'rename old'}
  if($r -match 'rename.*new|new name|0x00002000'){return 'rename new'}
  if($r -match 'file delete|file_delete|0x00000200'){return 'deleted'}
  if($r -match 'file create|file_create|0x00000100'){return 'created'}
  if($r -match 'data extend|data_extend|0x00000002'){return 'data extend'}
  if($r -match 'basic info|basic_info|0x00008000'){return 'basic info'}
  if($r -match 'stream change|stream_change|0x00200000'){return 'stream change'}
  return 'activity'
}
$raw = cmd /d /c 'fsutil usn readjournal C: csv 2^>nul ^| findstr /i /c:"latest.log" /c:"debug.log" /c:".log.gz" /c:"hs_err_pid"'
if($LASTEXITCODE -ne 0 -or $null -eq $raw){exit}
$seen=@{}
foreach($line in @($raw)){
  if([string]::IsNullOrWhiteSpace($line)){continue}
  if($line -match 'Reason' -and $line -match 'Name'){continue}
  $fields=SplitCsvLine $line
  $name=''
  foreach($f in $fields){ if(IsMcLogName $f){$name=[IO.Path]::GetFileName($f.Trim(' "')); break} }
  if(-not (IsMcLogName $name)){continue}
  $lower=$line.ToLowerInvariant()
  if(($lower -match '\\' -or $lower -match '/') -and -not (($lower -match '\\.minecraft\\.*\\logs\\') -or ($lower -match '\\minecraft\\game\\.*\\logs\\') -or ($lower -match '\\minecraft\\game\\logs\\'))){
    if($lower -match 'c:\\|d:\\|e:\\'){continue}
  }
  $date='-'
  foreach($f in $fields){ if($f -match '\d{1,2}[\.\-/]\d{1,2}[\.\-/]\d{2,4}.*\d{1,2}:\d{2}'){$date=$f.Trim(' "'); break} }
  $row='{0} | {1} | {2}' -f $date,(ActionFromReason ($fields -join ' ')),$name
  if(-not $seen.ContainsKey($row)){$seen[$row]=1; $row}
}
)HCPS";

    std::wstring output;
    if (!RunHiddenPowerShellScriptCapture(script, output, 120000))
    {
        lines.push_back(L"не удалось запустить fsutil");
        return lines;
    }

    std::vector<std::wstring> raw = SplitAutomationTextLines(output);
    for (const std::wstring& line : raw)
    {
        if (!line.empty() && ToLowerCopy(line).find(L"filename, directory name, or volume label") == std::wstring::npos)
            AppendWrappedAutomationLine(lines, line, 170);
    }

    if (lines.size() == 1)
        lines.push_back(L"не найдено");
    return lines;
}

static std::vector<std::wstring> ScanActivityByMode(int mode)
{
    if (mode == 1)
        return ScanUsnActivityForExtension(L".exe", false);
    if (mode == 2)
        return ScanUsnActivityForExtension(L".pf", true);
    if (mode == 3)
        return ScanMinecraftLogsFolders();
    return ScanUsnActivityForExtension(L".jar", false);
}

static std::vector<std::wstring> ScanModrinthHashes(int scanMode)
{
    std::vector<std::wstring> lines;
    lines.push_back(L"название | путь");

    // Обычного режима больше нет: checkmods всегда работает как fullscan.
    DebugLogSeparator(L"checkmods fullscan start");
    DebugLogLine(L"checkmods", L"mode=" + std::to_wstring(scanMode));

    wchar_t selfExePathBuf[32768]{};
    std::wstring selfExePath;
    DWORD selfExeLen = GetModuleFileNameW(nullptr, selfExePathBuf, ARRAYSIZE(selfExePathBuf));
    if (selfExeLen > 0 && selfExeLen < ARRAYSIZE(selfExePathBuf))
        selfExePath.assign(selfExePathBuf, selfExeLen);

    std::wstring script;
    script.reserve(110592);
    script += L"$script:HolyCheckFullScan=$true\n";
    script += L"$script:HolyCheckDebugLog=''\n";
    script += L"$script:HolyCheckSelfExe='" + EscapePowerShellSingleQuotedForDebug(selfExePath) + L"'\n";
    script += LR"HCPS(
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
try{[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12}catch{}
try{Add-Type -AssemblyName System.IO.Compression.FileSystem}catch{}
try{Add-Type -AssemblyName System.IO.Compression}catch{}
function HCLog([string]$m){ }
HCLog ('start fullscan=' + $script:HolyCheckFullScan)

$script:roots=@()
$script:rootKeys=@{}
$script:downloadRoots=@()
$script:downloadRootKeys=@{}
$script:sevenZipSkipReported=$false

function PathKey([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){return ''}
  return (($p -replace '/','\').TrimEnd('\')).ToLowerInvariant()
}
function AddRoot([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){return}
  try{
    if(-not (Test-Path -LiteralPath $p)){return}
    foreach($rp in @(Resolve-Path -LiteralPath $p -ErrorAction SilentlyContinue)){
      $v=$rp.Path
      if([string]::IsNullOrWhiteSpace($v)){continue}
      $k=PathKey $v
      if(-not $script:rootKeys.ContainsKey($k)){
        $script:rootKeys[$k]=1
        $script:roots += $v
        HCLog ('root add: ' + $v)
      }
    }
  }catch{}
}
function AddDownloadRoot([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){return}
  try{
    if(-not (Test-Path -LiteralPath $p)){return}
    foreach($rp in @(Resolve-Path -LiteralPath $p -ErrorAction SilentlyContinue)){
      $v=$rp.Path
      if([string]::IsNullOrWhiteSpace($v)){continue}
      $k=PathKey $v
      if(-not $script:downloadRootKeys.ContainsKey($k)){
        $script:downloadRootKeys[$k]=1
        $script:downloadRoots += $v
        HCLog ('download/archive root add: ' + $v)
      }
      AddRoot $v
    }
  }catch{}
}
function GetReadyDriveRoots(){
  $list=New-Object System.Collections.Generic.List[string]
  try{
    [IO.DriveInfo]::GetDrives() | Where-Object {
      $_.IsReady -and ($_.DriveType -eq [IO.DriveType]::Fixed -or $_.DriveType -eq [IO.DriveType]::Removable)
    } | ForEach-Object {
      $root=$_.RootDirectory.FullName
      if(-not [string]::IsNullOrWhiteSpace($root) -and -not $list.Contains($root)){[void]$list.Add($root)}
    }
  }catch{}
  if($list.Count -eq 0){
    try{
      Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | ForEach-Object {
        $root=$_.Root
        if(-not [string]::IsNullOrWhiteSpace($root) -and (Test-Path -LiteralPath $root) -and -not $list.Contains($root)){[void]$list.Add($root)}
      }
    }catch{}
  }
  HCLog ('ready drives: ' + (($list | ForEach-Object {[string]$_}) -join ', '))
  return @($list)
}
function IsExcludedSystemPath([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){return $true}
  $x=($p -replace '/','\')
  if($x -match '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\)|ProgramData|Recovery|System Volume Information|\$Recycle\.Bin)(\\|$)'){return $true}
  if($x -match '\\Windows\\(System32|SysWOW64|WinSxS|Installer|servicing|INF|SystemApps|Temp)(\\|$)'){return $true}
  if($x -match '\\(System Volume Information|\$Recycle\.Bin|Recovery)(\\|$)'){return $true}
  if($x -match '\\ProgramData\\(Microsoft|Package Cache)(\\|$)'){return $true}
  return $false
}
function IsLunarDependenciesPath([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){return $false}
  $x=($p -replace '/','\')
  return ($x -match '\\\.lunarclient\\profiles\\' -and $x -match '\\dependencies(\\|$)')
}
function IsAllowedPath([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){return $false}
  if(IsExcludedSystemPath $p){return $false}
  if(IsLunarDependenciesPath $p){return $false}
  if($p -match '\\(jdk|jre|java|javapath|libraries|assets|runtime|versions)\\'){return $false}
  if($p -match '\\.minecraft\\(libraries|assets|runtime|versions)\\'){return $false}
  if($p -match '\\.tlauncher\\legacy\\Minecraft\\game\\(libraries|assets|runtime|versions)\\'){return $false}
  return $true
}
function ShouldSkipDirectory([string]$p){
  if(IsExcludedSystemPath $p){return $true}
  if(IsLunarDependenciesPath $p){return $true}
  try{
    $leaf=[IO.Path]::GetFileName(($p -replace '/','\').TrimEnd('\'))
    # Ускорение без потери находок: не заходим в каталоги, чьи файлы и так
    # отбрасывались фильтром IsAllowedPath (libraries/assets/runtime/versions/
    # jdk/jre/java/javapath). Обход этих гигантских деревьев (.minecraft\libraries,
    # versions, ...) был самым долгим, а результат оттуда — всегда пустым.
    if($leaf -in @('Windows','Program Files','Program Files (x86)','ProgramData','$Recycle.Bin','System Volume Information','Recovery','WinSxS','Installer','libraries','assets','runtime','versions','jdk','jre','java','javapath')){return $true}
    $attrs=[IO.File]::GetAttributes($p)
    if(($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0){return $true}
  }catch{return $true}
  return $false
}
function IsCandidateExtension([string]$ext){
  if([string]::IsNullOrWhiteSpace($ext)){return $false}
  $e=$ext.ToLowerInvariant()
  return ($e -eq '.jar' -or $e -eq '.zip' -or $e -eq '.rar' -or $e -eq '.7z')
}
function EnumerateCandidateFiles([string]$root){
  if([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root)){return}
  HCLog ('enumerate start: ' + $root + ' fullscan=' + $script:HolyCheckFullScan)

  # Режим только один — fullscan: в список корней всегда входят и папки
  # лаунчеров, и корни дисков. Обход не ходит через junction/symlink.
  $stack=New-Object System.Collections.Generic.Stack[string]
  # dirSeen общий на все корни: папки, уже пройденные через другой корень,
  # повторно не обходим (раньше каждый корень обходил их заново).
  if($null -eq $script:dirSeen){ $script:dirSeen=@{} }
  $dirSeen=$script:dirSeen
  try{[void]$stack.Push((Resolve-Path -LiteralPath $root -ErrorAction Stop).Path)}catch{ HCLog ('enumerate resolve failed: ' + $root + ' error=' + $_.Exception.Message); return}

  while($stack.Count -gt 0){
    $dir=$stack.Pop()
    if([string]::IsNullOrWhiteSpace($dir)){continue}
    $dk=PathKey $dir
    if($dirSeen.ContainsKey($dk)){continue}
    $dirSeen[$dk]=1
    if(ShouldSkipDirectory $dir){continue}

    try{
      foreach($sub in [IO.Directory]::EnumerateDirectories($dir)){
        if(-not (ShouldSkipDirectory $sub)){[void]$stack.Push($sub)}
      }
    }catch{}

    try{
      foreach($file in [IO.Directory]::EnumerateFiles($dir)){
        try{
          $ext=[IO.Path]::GetExtension($file)
          if((IsCandidateExtension $ext) -and (IsAllowedPath $file)){
            New-Object System.IO.FileInfo -ArgumentList $file
          }
        }catch{}
      }
    }catch{}
  }
}
function Find7Zip(){
  $c=@('C:\Program Files\7-Zip\7z.exe','C:\Program Files (x86)\7-Zip\7z.exe',
       'C:\Program Files\NanaZip\7z.exe','C:\Program Files\7-Zip-Zstandard\7z.exe')
  foreach($x in $c){if(Test-Path -LiteralPath $x){return $x}}
  foreach($n in @('7z.exe','7za.exe','7zr.exe')){
    try{$cmd=Get-Command $n -ErrorAction SilentlyContinue; if($cmd){return $cmd.Source}}catch{}
  }
  return $null
}
function FindWinRar(){
  # UnRAR/Rar/WinRAR используются как замена 7-Zip для .rar и .7z.
  $c=@('C:\Program Files\WinRAR\UnRAR.exe','C:\Program Files (x86)\WinRAR\UnRAR.exe',
       'C:\Program Files\WinRAR\Rar.exe','C:\Program Files (x86)\WinRAR\Rar.exe',
       'C:\Program Files\WinRAR\WinRAR.exe','C:\Program Files (x86)\WinRAR\WinRAR.exe')
  foreach($x in $c){if(Test-Path -LiteralPath $x){return $x}}
  foreach($n in @('unrar.exe','rar.exe','winrar.exe')){
    try{$cmd=Get-Command $n -ErrorAction SilentlyContinue; if($cmd){return $cmd.Source}}catch{}
  }
)HCPS"
LR"HCPS(
  foreach($key in @('HKLM:\SOFTWARE\WinRAR','HKLM:\SOFTWARE\WOW6432Node\WinRAR')){
    try{
      $reg=Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
      if($reg){
        foreach($v in @($reg.exe64,$reg.exe32)){
          if(-not [string]::IsNullOrWhiteSpace($v) -and (Test-Path -LiteralPath $v)){ return $v }
        }
      }
    }catch{}
  }
  return $null
}
function FindBsdTar(){
  # tar.exe (bsdtar/libarchive) встроен в Windows 10 1803+ и читает 7z/rar
  # без установки чего-либо вообще.
  foreach($x in @((Join-Path $env:SystemRoot 'System32\tar.exe'),(Join-Path $env:SystemRoot 'Sysnative\tar.exe'))){
    try{ if(Test-Path -LiteralPath $x){ return $x } }catch{}
  }
  try{$cmd=Get-Command tar.exe -ErrorAction SilentlyContinue; if($cmd){return $cmd.Source}}catch{}
  return $null
}
$cheatJarNames=@()
function NormName([string]$s){ return (([IO.Path]::GetFileNameWithoutExtension($s)).ToLowerInvariant() -replace '[^a-z0-9]+','') }
function VersionAtLeast2530([int]$maj,[int]$min,[int]$patch){
  if($maj -gt 25){return $true}
  if($maj -lt 25){return $false}
  if($min -gt 3){return $true}
  if($min -lt 3){return $false}
  return ($patch -ge 0)
}
function IsBadXaeroMinimap([string]$name){
  if([string]::IsNullOrWhiteSpace($name)){return $false}
  if([IO.Path]::GetExtension($name).ToLowerInvariant() -ne '.jar'){return $false}
  $base=([IO.Path]::GetFileNameWithoutExtension($name)).ToLowerInvariant()
  if($base -notmatch '(xaeros?[\s_\.-]*minimap|xaerominimap)'){return $false}

  #   xaerominimap-fabric-26.1.2-25.3.14.jar
  $matches=[regex]::Matches($base, '(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)')
  if($matches.Count -le 0){return $false}
  $m=$matches[$matches.Count-1]
  return (VersionAtLeast2530 ([int]$m.Groups[1].Value) ([int]$m.Groups[2].Value) ([int]$m.Groups[3].Value))
}
$cheatKeys=New-Object System.Collections.Generic.List[string]
function AddRedName([string]$value){
  if([string]::IsNullOrWhiteSpace($value)){return}
  $k=NormName ($value + '.jar')
  if(-not [string]::IsNullOrWhiteSpace($k) -and $k.Length -ge 3 -and -not $script:cheatKeys.Contains($k)){ $script:cheatKeys.Add($k) }
}
function AddRedNamesFromText([string]$text){
  if([string]::IsNullOrWhiteSpace($text)){return}
  $t=$text -replace '<script[\s\S]*?</script>',' ' -replace '<style[\s\S]*?</style>',' ' -replace '<[^>]+>',' '
  foreach($m in [regex]::Matches($t,'[A-Za-z0-9][A-Za-z0-9_\.\- ]{1,63}[A-Za-z0-9]')){
    $v=([string]$m.Value).Trim()
    if($v.Length -ge 3 -and $v.Length -le 64){ AddRedName $v }
  }
}
function AddRedNamesFromSource([string]$source){
  if([string]::IsNullOrWhiteSpace($source)){return}
  try{
    if($source -match '^https?://'){
      $headers=@{'User-Agent'='HolyCheck/1.0';'Cache-Control'='no-cache';'Pragma'='no-cache'}
      if($source -match 'gist\.githubusercontent\.com/[^/]+/([0-9a-fA-F]+)/raw'){
        try{
          $api='https://api.github.com/gists/' + $matches[1] + '?t=' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
          $g=Invoke-RestMethod -Uri $api -UseBasicParsing -TimeoutSec 10 -Headers $headers
          foreach($file in $g.files.PSObject.Properties){
            if($file.Value -and $file.Value.content){ AddRedNamesFromText ([string]$file.Value.content) }
          }
          return
        }catch{}
      }
      $sep=if($source.Contains('?')){'&'}else{'?'}
      $url=$source + $sep + 't=' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
      $r=Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10 -Headers $headers
      AddRedNamesFromText ([string]$r.Content)
    }elseif(Test-Path -LiteralPath $source){
      AddRedNamesFromText (Get-Content -LiteralPath $source -Raw -ErrorAction SilentlyContinue)
    }
  }catch{}
}
function LoadRemoteRedNames(){
  $sources=New-Object System.Collections.Generic.List[string]
  [void]$sources.Add('https://gist.githubusercontent.com/IOPODL/8487494183e47a7e9d66c93a9a54efb0/raw/rednames.txt')
  foreach($v in @($env:HOLYCHECK_CHECKMODS_RED_URL,$env:HOLYCHECK_CHECKMODS_RED_URLS)){
    if(-not [string]::IsNullOrWhiteSpace($v)){
      foreach($x in ($v -split '[;,]')){ if(-not [string]::IsNullOrWhiteSpace($x)){ [void]$sources.Add($x.Trim()) } }
    }
  }
  $cfg=@()
  try{ if(-not [string]::IsNullOrWhiteSpace($script:HolyCheckSelfExe)){ $cfg += (Join-Path ([IO.Path]::GetDirectoryName($script:HolyCheckSelfExe)) 'checkmods_red_sources.txt') } }catch{}
  try{ $cfg += (Join-Path $env:APPDATA 'HolyCheck\checkmods_red_sources.txt') }catch{}
)HCPS"
LR"HCPS(
  try{ $cfg += (Join-Path $env:ProgramData 'HolyCheck\checkmods_red_sources.txt') }catch{}
  foreach($file in $cfg){
    try{
      if(Test-Path -LiteralPath $file){
        foreach($line in @(Get-Content -LiteralPath $file -ErrorAction SilentlyContinue)){
          $x=([string]$line).Trim()
          if($x.Length -gt 0 -and -not $x.StartsWith('#')){ [void]$sources.Add($x) }
        }
      }
    }catch{}
  }
  foreach($src in @($sources)){ AddRedNamesFromSource $src }
}
LoadRemoteRedNames
function IsCheatJarName([string]$name){
  if([string]::IsNullOrWhiteSpace($name)){return $false}
  if([IO.Path]::GetExtension($name).ToLowerInvariant() -ne '.jar'){return $false}
  $n=NormName $name
  foreach($k in $script:cheatKeys){ if($n.Contains($k)){ return $true } }
  return $false
}
function NormText([string]$s){ if($null -eq $s){return ''}; return ($s.ToLowerInvariant() -replace '[^a-z0-9]+','') }
function ReadZipEntryText($zip,[string]$entryName){
  try{
    $entry=$zip.GetEntry($entryName)
    if($null -eq $entry){return $null}
    $sr=New-Object IO.StreamReader($entry.Open())
    try{ return $sr.ReadToEnd() }finally{ $sr.Dispose() }
  }catch{ return $null }
}
function CollectJarModNames($zip){
  $names=New-Object System.Collections.Generic.List[string]
  if($null -eq $zip){ return $names }
  try{
    $fabric=ReadZipEntryText $zip 'fabric.mod.json'
    if($fabric){ foreach($m in [regex]::Matches($fabric,'"(?:id|name)"\s*:\s*"([^"]+)"')){ [void]$names.Add($m.Groups[1].Value) } }
    $quilt=ReadZipEntryText $zip 'quilt.mod.json'
    if($quilt){ foreach($m in [regex]::Matches($quilt,'"(?:id|name)"\s*:\s*"([^"]+)"')){ [void]$names.Add($m.Groups[1].Value) } }
    foreach($tn in @('META-INF/mods.toml','META-INF/neoforge.mods.toml')){
      $toml=ReadZipEntryText $zip $tn
      if($toml){ foreach($m in [regex]::Matches($toml,'(?im)^\s*(?:modId|displayName)\s*=\s*"([^"]+)"')){ [void]$names.Add($m.Groups[1].Value) } }
    }
    $mc=ReadZipEntryText $zip 'mcmod.info'
    if($mc){ foreach($m in [regex]::Matches($mc,'"(?:modid|name)"\s*:\s*"([^"]+)"')){ [void]$names.Add($m.Groups[1].Value) } }
    $man=ReadZipEntryText $zip 'META-INF/MANIFEST.MF'
    if($man){ foreach($m in [regex]::Matches($man,'(?im)^(?:Implementation-Title|Specification-Title|Automatic-Module-Name)\s*:\s*(.+)$')){ [void]$names.Add(($m.Groups[1].Value).Trim()) } }
  }catch{}
  return $names
}
function MatchCheatName($names){
  foreach($nm in @($names)){
    if([string]::IsNullOrWhiteSpace($nm)){continue}
    $n=NormText $nm
    if($n.Length -lt 3){continue}
    foreach($k in $script:cheatKeys){ if($n.Contains($k)){ return $nm } }
  }
  return $null
}
function GetCheatNameFromJarPath([string]$path){
  $zip=$null
  try{
    $zip=[IO.Compression.ZipFile]::OpenRead($path)
    return (MatchCheatName (CollectJarModNames $zip))
  }catch{ return $null }
  finally{ if($zip){ try{$zip.Dispose()}catch{} } }
}
function GetCheatNameFromJarStream($stream){
  $ms=$null; $zip=$null
  try{
    $ms=New-Object IO.MemoryStream
    $stream.CopyTo($ms)
    $ms.Position=0
    $zip=New-Object IO.Compression.ZipArchive($ms,[IO.Compression.ZipArchiveMode]::Read)
    return (MatchCheatName (CollectJarModNames $zip))
  }catch{ return $null }
  finally{ if($zip){ try{$zip.Dispose()}catch{} }; if($ms){ try{$ms.Dispose()}catch{} } }
}
function JarModNamesFromPath([string]$path){
  $zip=$null
  try{ $zip=[IO.Compression.ZipFile]::OpenRead($path); return (CollectJarModNames $zip) }
  catch{ return (New-Object System.Collections.Generic.List[string]) }
  finally{ if($zip){ try{$zip.Dispose()}catch{} } }
}
function FirstModName($names){
  foreach($nm in @($names)){ if(-not [string]::IsNullOrWhiteSpace($nm)){ return $nm } }
  return ''
}
function CoreTokens([string]$s){
  if($null -eq $s){ return ,@() }
  $t=[regex]::Replace($s,'([a-z0-9])([A-Z])','$1 $2')
  $t=$t.ToLowerInvariant()
  $parts=[regex]::Split($t,'[^a-z]+') | Where-Object { $_.Length -ge 2 }
  $noise=@{'fabric'=1;'forge'=1;'quilt'=1;'neoforge'=1;'neo'=1;'mc'=1;'minecraft'=1;'mod'=1;'mods'=1;'loader'=1;'api'=1;'lib'=1;'library'=1;'version'=1;'client'=1;'server'=1;'common'=1;'snapshot'=1;'release'=1;'build'=1;'jar'=1;'refabricated'=1;'port'=1;'backport'=1}
  $sig=@($parts | Where-Object { -not $noise.ContainsKey($_) })
  if($sig.Count -eq 0){ $sig=@($parts) }
  return ,$sig
}
function IsSubsequenceStr([string]$short,[string]$long){
  if([string]::IsNullOrEmpty($short)){ return $true }
  if([string]::IsNullOrEmpty($long)){ return $false }
  $j=0
  for($i=0;$i -lt $long.Length -and $j -lt $short.Length;$i++){ if($long[$i] -eq $short[$j]){ $j++ } }
  return ($j -eq $short.Length)
}
function LcsLen([string]$a,[string]$b){
  if([string]::IsNullOrEmpty($a) -or [string]::IsNullOrEmpty($b)){ return 0 }
  $la=$a.Length; $lb=$b.Length
  $prev=New-Object 'int[]' ($lb+1)
  $best=0
  for($i=1;$i -le $la;$i++){
    $curr=New-Object 'int[]' ($lb+1)
    for($j=1;$j -le $lb;$j++){
      if($a[$i-1] -eq $b[$j-1]){ $curr[$j]=$prev[$j-1]+1; if($curr[$j] -gt $best){ $best=$curr[$j] } }
    }
    $prev=$curr
  }
  return $best
}
function IsRenamedJar([string]$fileName,$names){
  $rawBase=[IO.Path]::GetFileNameWithoutExtension($fileName)
  $baseFull=NormText $rawBase
  if($baseFull.Length -lt 3){ return $false }
  $baseTokens=CoreTokens $rawBase
  $baseCore=([string]::Join('',$baseTokens))
  if($baseCore.Length -lt 3){ $baseCore=$baseFull }
  $has=$false
  foreach($nm in @($names)){
    if([string]::IsNullOrWhiteSpace($nm)){continue}
    $nFull=NormText $nm
    if($nFull.Length -lt 3){continue}
    $has=$true
    $nTokens=CoreTokens $nm
    $nCore=([string]::Join('',$nTokens))
    if($nCore.Length -lt 3){ $nCore=$nFull }
    if($baseFull.Contains($nFull) -or $nFull.Contains($baseFull)){ return $false }
    if($baseCore.Contains($nCore) -or $nCore.Contains($baseCore)){ return $false }
    $short=$baseCore; $long=$nCore
    if($short.Length -gt $long.Length){ $short=$nCore; $long=$baseCore }
    if($short.Length -le 6 -and (IsSubsequenceStr $short $long)){ return $false }
    foreach($bt in $baseTokens){ if($bt.Length -ge 4 -and ($nTokens -contains $bt)){ return $false } }
    $lcs=LcsLen $baseCore $nCore
    $minLen=[Math]::Min($baseCore.Length,$nCore.Length)
    if($minLen -gt 0 -and $lcs -ge 4 -and (($lcs/$minLen) -ge 0.5)){ return $false }
  }
  return $has
}
$sha=[Security.Cryptography.SHA1]::Create()  # sha1 ~в 2 раза быстрее sha512 и принимается Modrinth
function HashStreamHex([IO.Stream]$stream){
  $h=$script:sha.ComputeHash($stream)
  return ([BitConverter]::ToString($h)).Replace('-','').ToLowerInvariant()
}
function HashFileHex([string]$path){
  $fs=$null
  try{
    # jar больше 300 МБ — не мод: пропускаем хэширование ради скорости
    if(([IO.FileInfo]$path).Length -gt 314572800){ HCLog ('hash skipped, file too large: ' + $path); return $null }
    $fs=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    return HashStreamHex $fs
  }catch{return $null}
  finally{ if($fs){$fs.Dispose()} }
}
$items=New-Object System.Collections.Generic.List[object]
$nameHits=New-Object System.Collections.Generic.List[object]
$cleanupHits=New-Object System.Collections.Generic.List[object]
$renamedHits=New-Object System.Collections.Generic.List[object]
$reported=@{}
function AddNameHit([string]$name,[string]$path){
  if([string]::IsNullOrWhiteSpace($path)){return}
  $k=PathKey $path
  if($script:reported.ContainsKey($k)){return}
  $script:reported[$k]=1
)HCPS"
LR"HCPS(
  $script:nameHits.Add([PSCustomObject]@{Name=$name;Path=$path}) | Out-Null
}
function AddCleanupHit([string]$name,[string]$path){
  if([string]::IsNullOrWhiteSpace($path)){return}
  $script:cleanupHits.Add([PSCustomObject]@{Name=$name;Path=$path}) | Out-Null
}
function AddRenamedHit([string]$name,[string]$path){
  if([string]::IsNullOrWhiteSpace($path)){return}
  $k=PathKey $path
  if($script:reported.ContainsKey($k)){return}
  $script:reported[$k]=1
  $script:renamedHits.Add([PSCustomObject]@{Name=$name;Path=$path}) | Out-Null
}
# --- smart library / jar-in-jar filtering ---------------------------------
# Modrinth only indexes published mods, so helper libraries (lwjgl, guava,
# joda-time, ...) and jar-in-jar submodules unpacked by launchers always come
# back as "unknown" and used to flood the report. These checks drop that noise
# BEFORE hashing, which also cuts the number of Modrinth requests.
# Red (forbidden name) and yellow (renamed jar) detection already ran at every
# call site, so nothing dangerous can be hidden by this filter.
$script:libraryNames=@(
  'lwjgl','joda-time','opentest4j','j2objc-annotations','guava','gson','asm',
  'slf4j','log4j','netty','kotlin','kotlinx','commons','jackson','junit',
  'hamcrest','jsr305','checker-qual','error_prone','byte-buddy','javax',
  'jakarta','annotations','annotation','brigadier','datafixerupper','authlib',
  'oshi','icu4j','jopt-simple','jopt','text2speech','caffeineconfig','mixin',
  'mixinextras','mixinsquared','fastutil','rhino','jna','jsch','httpclient',
  'httpcore','bcprov','snakeyaml','jarjar','failureaccess','objenesis',
  'mockito','commonmark','blossom','architectury','forgeconfigapiport',
  'placeholder-api','night-config','authlib-injector','logback','jline',
  'ap-loader','jsr','guice','protobuf','grpc','okhttp','okio','trove','vecmath'
)
$script:librarySkipped=0
function IsLibraryJarName([string]$name){
  if([string]::IsNullOrWhiteSpace($name)){return $false}
  $base=''
  try{ $base=([IO.Path]::GetFileNameWithoutExtension($name)).ToLowerInvariant() }catch{ return $false }
  if([string]::IsNullOrWhiteSpace($base)){return $false}
  # Standard fabric/quilt API submodules shipped as jar-in-jar, for example
  #   fabric-biome-api-v1-13.0.13+... / fabric-tag-extensions-v0-1.1.2+...
  if($base -match '^(fabric|quilt)-[a-z0-9-]+-v\d+'){return $true}
  if($base -match '^(fabric|quilt)-(api|api-base|loader|language|renderer|rendering)'){return $true}
  foreach($lib in $script:libraryNames){
    if($base -eq $lib){return $true}
    if($base.StartsWith($lib + '-')){return $true}
    if($base.StartsWith($lib + '_')){return $true}
  }
  return $false
}
function IsNonModLocation([string]$path){
  if([string]::IsNullOrWhiteSpace($path)){return $false}
  $p=$path.ToLowerInvariant()
  # The [\\/]+ separator class matches / and \ and repeated separators, so this
  # works for plain paths, archive inner paths and normalised paths alike.
  # Anything that really sits in a mods folder always stays a mod.
  if($p -match '[\\/]+mods[\\/]+'){return $false}
  # Launcher scratch copies of mods that are already installed elsewhere.
  if($p -match '[\\/]+processedmods[\\/]+'){return $true}
  # Java / Gradle / launcher library and build locations.
  if($p -match '[\\/]+(libraries|client-libs|clientlibs|natives|versions|runtime|jre|jdk|dependencies|caches|maven|\.m2|\.gradle|gradle|wrapper|build|target|classes|plugins)[\\/]+'){return $true}
  return $false
}
function ShouldSkipAsLibrary([string]$name,[string]$path){
  if(IsNonModLocation $path){return $true}
  if(IsLibraryJarName $name){return $true}
  return $false
}
function AddJarItem([string]$name,[string]$path,[string]$hash){
  if(IsCheatJarName $name){ AddNameHit $name $path; return }
  if(ShouldSkipAsLibrary $name $path){ $script:librarySkipped++; HCLog ('skip library/non-mod: ' + $path); return }
  if([string]::IsNullOrWhiteSpace($hash)){return}
  $script:items.Add([PSCustomObject]@{Hash=$hash.ToLowerInvariant();Name=$name;Path=$path}) | Out-Null
}

$driveRoots=@(GetReadyDriveRoots)
HCLog ('drive root count=' + $driveRoots.Count)
foreach($drive in $driveRoots){
  try{
    $users=Join-Path $drive 'Users'
    if(Test-Path -LiteralPath $users){
      Get-ChildItem -LiteralPath $users -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
        AddDownloadRoot (Join-Path $_.FullName 'Downloads')
        AddDownloadRoot (Join-Path $_.FullName 'Desktop')
        AddDownloadRoot (Join-Path $_.FullName 'OneDrive\Desktop')
)HCPS"
LR"HCPS(
        AddRoot (Join-Path $_.FullName 'Documents')
        AddRoot (Join-Path $_.FullName '.lunarclient\profiles')
        AddRoot (Join-Path $_.FullName 'AppData\Roaming\.minecraft\mods')
        AddRoot (Join-Path $_.FullName 'AppData\Roaming\.tlauncher\legacy\Minecraft\game\mods')
        AddRoot (Join-Path $_.FullName 'AppData\Roaming\PrismLauncher\instances')
        AddRoot (Join-Path $_.FullName 'curseforge\minecraft\Instances')
      }
    }
  }catch{}
}
if($env:USERPROFILE){
  AddDownloadRoot (Join-Path $env:USERPROFILE 'Downloads')
  AddDownloadRoot (Join-Path $env:USERPROFILE 'Desktop')
  AddRoot (Join-Path $env:USERPROFILE 'Documents')
  AddRoot (Join-Path $env:USERPROFILE '.lunarclient\profiles')
}
try{ AddDownloadRoot ([Environment]::GetFolderPath('Desktop')) }catch{}
foreach($od in @($env:OneDrive,$env:OneDriveConsumer,$env:OneDriveCommercial)){
  if(-not [string]::IsNullOrWhiteSpace($od)){ AddDownloadRoot (Join-Path $od 'Desktop') }
}
if($env:APPDATA){
  AddRoot (Join-Path $env:APPDATA '.minecraft\mods')
  AddRoot (Join-Path $env:APPDATA '.tlauncher\legacy\Minecraft\game\mods')
  AddRoot (Join-Path $env:APPDATA 'PrismLauncher\instances')
}
# Режим только один (fullscan): корни дисков добавляются всегда.
foreach($drive in $driveRoots){ AddRoot $drive }

HCLog ('final roots=' + $roots.Count + '; download/archive roots=' + $downloadRoots.Count)
if($roots.Count -eq 0){HCLog 'no roots, exit'; 'mods folder not found'; exit}
$seen=@{}
$archives=@{}
$downloadArchives=@{}
foreach($r in $roots){
  $rootCandidateCount=0
  HCLog ('scan root begin: ' + $r)
  foreach($f in @(EnumerateCandidateFiles $r)){
    try{
      if($null -eq $f){continue}
      $rootCandidateCount++
      $ext=$f.Extension.ToLowerInvariant()
      $k=PathKey $f.FullName
      if(-not $seen.ContainsKey($k)){
        $seen[$k]=1
        if($ext -eq '.jar'){
          if(IsCheatJarName $f.Name){ AddNameHit $f.Name $f.FullName; HCLog ('name hit: ' + $f.FullName) }
          else{
            $names=JarModNamesFromPath $f.FullName
            $inner=MatchCheatName $names
            if($inner){ AddNameHit ($f.Name + ' (mod: ' + $inner + ')') $f.FullName; HCLog ('content hit: ' + $f.FullName + ' inner=' + $inner) }
            elseif(IsRenamedJar $f.Name $names){ AddRenamedHit ($f.Name + ' (mod: ' + (FirstModName $names) + ')') $f.FullName; HCLog ('renamed hit: ' + $f.FullName + ' inner=' + (FirstModName $names)) }
            else{
              # Сначала дешёвый фильтр библиотек — и только потом дорогой хэш.
              if(ShouldSkipAsLibrary $f.Name $f.FullName){ $script:librarySkipped++; HCLog ('skip library/non-mod: ' + $f.FullName) }
              else{ AddJarItem $f.Name $f.FullName (HashFileHex $f.FullName) }
            }
          }
        }elseif($ext -eq '.zip' -or $ext -eq '.rar' -or $ext -eq '.7z'){
          $archives[$k]=$f
        }
      }
    }catch{HCLog ('scan root item error: ' + $_.Exception.Message)}
  }
  HCLog ('scan root done: ' + $r + ' candidates=' + $rootCandidateCount + ' unique=' + $seen.Count + ' archives=' + $archives.Count + ' jars=' + $items.Count + ' nameHits=' + $nameHits.Count)
}
# Второй проход по downloadRoots убран: эти папки и так покрываются основными
# корнями (AddDownloadRoot дополнительно вызывает AddRoot), а собранная
# $downloadArchives нигде дальше не использовалась. Раньше Downloads/Desktop
# обходились дважды — чистая потеря времени.
HCLog ('collection done: jars=' + $items.Count + '; nameHits=' + $nameHits.Count + '; archives=' + $archives.Count + '; holy archives candidates=' + $downloadArchives.Count)
)HCPS";

    script += LR"HCPS(
$tempRoot=Join-Path $env:TEMP ('HolyCheck_checkmods_' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
$seven=Find7Zip
$script:winrar=FindWinRar
$script:bsdtar=FindBsdTar
$script:archToolMissing=$false
$sevenText = if($seven){$seven}else{'not found'}
$winrarText = if($script:winrar){$script:winrar}else{'not found'}
$tarText = if($script:bsdtar){$script:bsdtar}else{'not found'}
HCLog ('tempRoot=' + $tempRoot + '; sevenZip=' + $sevenText + '; winrar=' + $winrarText + '; bsdtar=' + $tarText)
function HasArchiveTool(){
  return (($null -ne $seven) -or ($null -ne $script:winrar) -or ($null -ne $script:bsdtar))
}
function QuoteProcArg([string]$s){
  if($null -eq $s){return '""'}
  return '"' + ($s -replace '"','\"') + '"'
}
function Invoke7ZipListSafe([string]$path){
  if(-not $seven){return $null}
  $p=$null
  try{
    $psi=New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName=$seven
    $psi.Arguments=('l -slt -p"" ' + (QuoteProcArg $path))
    $psi.UseShellExecute=$false
    $psi.RedirectStandardInput=$true
    $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true
    $psi.CreateNoWindow=$true
    $p=New-Object System.Diagnostics.Process
    $p.StartInfo=$psi
    [void]$p.Start()
    $stdout=$p.StandardOutput.ReadToEndAsync()
    $stderr=$p.StandardError.ReadToEndAsync()
    try{$p.StandardInput.Close()}catch{}
    if(-not $p.WaitForExit(15000)){
      try{$p.Kill()}catch{}
      HCLog ('7z list timeout, archive skipped: ' + $path)
      return $null
    }
    $out=($stdout.Result + "`n" + $stderr.Result)
    HCLog ('7z list exit=' + $p.ExitCode + ' path=' + $path)
    return @($out -split "`r?`n")
  }catch{
    HCLog ('7z list error: ' + $path + ' error=' + $_.Exception.Message)
    return $null
  }finally{
    if($p){try{$p.Dispose()}catch{}}
  }
}
function Invoke7ZipExtractJarsSafe([string]$archive,[string]$outDir){
  if(-not $seven){return $false}
  $p=$null
  try{
    $psi=New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName=$seven
    $psi.Arguments=('x -y -p"" ' + (QuoteProcArg ('-o' + $outDir)) + ' ' + (QuoteProcArg $archive) + ' "*.jar" -r')
    $psi.UseShellExecute=$false
    $psi.RedirectStandardInput=$true
    $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true
    $psi.CreateNoWindow=$true
    $p=New-Object System.Diagnostics.Process
    $p.StartInfo=$psi
    [void]$p.Start()
    $stdout=$p.StandardOutput.ReadToEndAsync()
    $stderr=$p.StandardError.ReadToEndAsync()
    try{$p.StandardInput.Close()}catch{}
    if(-not $p.WaitForExit(30000)){
      try{$p.Kill()}catch{}
      HCLog ('7z extract timeout, archive skipped: ' + $archive)
      return $false
    }
    $null=$stdout.Result
    $err=$stderr.Result
    HCLog ('7z extract exit=' + $p.ExitCode + ' archive=' + $archive)
    if($p.ExitCode -ne 0 -and -not [string]::IsNullOrWhiteSpace($err)){ HCLog ('7z extract stderr: ' + ($err.Substring(0,[Math]::Min(200,$err.Length)))) }
    return ($p.ExitCode -eq 0)
  }catch{
    HCLog ('7z extract error: ' + $archive + ' error=' + $_.Exception.Message)
    return $false
  }finally{
    if($p){try{$p.Dispose()}catch{}}
  }
}
function RunArchiveToolSafe([string]$exe,[string]$toolArgs,[int]$timeoutMs){
  if([string]::IsNullOrWhiteSpace($exe)){return $false}
  $p=$null
  try{
    $psi=New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName=$exe
    $psi.Arguments=$toolArgs
    $psi.UseShellExecute=$false
    $psi.RedirectStandardInput=$true
    $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true
    $psi.CreateNoWindow=$true
    $p=New-Object System.Diagnostics.Process
    $p.StartInfo=$psi
    [void]$p.Start()
    $stdout=$p.StandardOutput.ReadToEndAsync()
    $stderr=$p.StandardError.ReadToEndAsync()
    try{$p.StandardInput.Close()}catch{}
    if(-not $p.WaitForExit($timeoutMs)){
      try{$p.Kill()}catch{}
      HCLog ('archive tool timeout: ' + $exe + ' ' + $toolArgs)
      return $false
    }
    $null=$stdout.Result
    $err=$stderr.Result
    HCLog ('archive tool exit=' + $p.ExitCode + ' exe=' + $exe)
    if($p.ExitCode -ne 0 -and -not [string]::IsNullOrWhiteSpace($err)){ HCLog ('archive tool stderr: ' + ($err.Substring(0,[Math]::Min(200,$err.Length)))) }
    return ($p.ExitCode -eq 0)
  }catch{
    HCLog ('archive tool error: ' + $exe + ' error=' + $_.Exception.Message)
    return $false
  }finally{
    if($p){try{$p.Dispose()}catch{}}
  }
}
function DirHasJars([string]$dir){
  try{ return ((@(Get-ChildItem -LiteralPath $dir -Filter '*.jar' -File -Recurse -Force -ErrorAction SilentlyContinue)).Count -gt 0) }catch{ return $false }
}
function ExtractJarsFromArchiveSafe([string]$archive,[string]$outDir){
  # .rar и .7z больше не требуют именно 7-Zip: по очереди пробуем
  # 7z-совместимые утилиты (7z/7za/7zr/NanaZip), затем UnRAR/Rar/WinRAR,
  # затем встроенный в Windows tar.exe (bsdtar). Если нет ничего — ставим
  # флаг и в конце требуем от пользователя установить 7-Zip или WinRAR.
  if($seven){
    if(Invoke7ZipExtractJarsSafe $archive $outDir){ return $true }
    if(DirHasJars $outDir){ return $true }
  }
  if($script:winrar){
    $exeName=''
    try{ $exeName=([IO.Path]::GetFileName($script:winrar)).ToLowerInvariant() }catch{}
    $target=$outDir
    if(-not $target.EndsWith('\')){ $target=$target + '\' }
    $toolArgs=''
    if($exeName -eq 'winrar.exe'){
      $toolArgs='x -y -ibck -p- ' + (QuoteProcArg $archive) + ' *.jar ' + (QuoteProcArg $target)
    }else{
      $toolArgs='x -y -p- -idq ' + (QuoteProcArg $archive) + ' *.jar ' + (QuoteProcArg $target)
    }
    if(RunArchiveToolSafe $script:winrar $toolArgs 60000){ return $true }
    if(DirHasJars $outDir){ return $true }
  }
  if($script:bsdtar){
    try{
      $fi=New-Object System.IO.FileInfo($archive)
      # tar распаковывает архив целиком, поэтому применяем его только к
      # умеренным по размеру архивам (до 256 МБ).
      if($fi.Length -le 268435456){
        $toolArgs='-xf ' + (QuoteProcArg $archive) + ' -C ' + (QuoteProcArg $outDir)
        if(RunArchiveToolSafe $script:bsdtar $toolArgs 90000){ return $true }
        if(DirHasJars $outDir){ return $true }
      }else{
        HCLog ('bsdtar skipped, archive too large: ' + $archive)
      }
    }catch{}
  }
  if(-not (HasArchiveTool)){ $script:archToolMissing=$true }
  return $false
}
function ZipHasEncryptedEntries([string]$path){
  $fs=$null; $br=$null
  try{
    $fs=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    if($fs.Length -lt 22){return $false}
    $max=[int][Math]::Min([int64]66000,$fs.Length)
    [void]$fs.Seek(-$max,[IO.SeekOrigin]::End)
    $buf=New-Object byte[] $max
    $read=$fs.Read($buf,0,$max)
    $eocd=-1
    for($i=$read-22; $i -ge 0; $i--){
      if($buf[$i] -eq 0x50 -and $buf[$i+1] -eq 0x4b -and $buf[$i+2] -eq 0x05 -and $buf[$i+3] -eq 0x06){$eocd=$i; break}
    }
    if($eocd -lt 0){return $false}
    $cdSize=[BitConverter]::ToUInt32($buf,$eocd+12)
    $cdOffset=[BitConverter]::ToUInt32($buf,$eocd+16)
    $entries=[BitConverter]::ToUInt16($buf,$eocd+10)
    if($cdSize -eq 0 -or $cdOffset -ge $fs.Length){return $false}
    [void]$fs.Seek([int64]$cdOffset,[IO.SeekOrigin]::Begin)
    $br=New-Object IO.BinaryReader($fs)
    $limit=[Math]::Min(([int64]$cdOffset + [int64]$cdSize), $fs.Length)
    $count=0
    while($fs.Position + 46 -le $limit -and ($entries -eq 0 -or $count -lt $entries) -and $count -lt 100000){
)HCPS"
LR"HCPS(
      $entryStart=$fs.Position
      $sig=$br.ReadUInt32()
      if($sig -ne 0x02014b50){break}
      [void]$fs.Seek($entryStart + 8,[IO.SeekOrigin]::Begin)
      $flags=$br.ReadUInt16()
      if(($flags -band 1) -ne 0){return $true}
      [void]$fs.Seek($entryStart + 28,[IO.SeekOrigin]::Begin)
      $nameLen=$br.ReadUInt16(); $extraLen=$br.ReadUInt16(); $commentLen=$br.ReadUInt16()
      $next=$entryStart + 46 + $nameLen + $extraLen + $commentLen
      if($next -le $entryStart -or $next -gt $fs.Length){break}
      [void]$fs.Seek($next,[IO.SeekOrigin]::Begin)
      $count++
    }
  }catch{
    HCLog ('zip encryption check error: ' + $path + ' error=' + $_.Exception.Message)
    return $false
  }finally{
    if($br){try{$br.Dispose()}catch{}}
    elseif($fs){try{$fs.Dispose()}catch{}}
  }
  return $false
}
function SevenZipListIndicatesEncrypted($lines){
  foreach($line in @($lines)){
    if($line -match '^(Encrypted|Headers Encrypted)\s*=\s*\+'){return $true}
    if($line -match 'Wrong password|Can not open encrypted archive|password is incorrect|Headers Error'){return $true}
  }
  return $false
}
$script:sha256=[Security.Cryptography.SHA256]::Create()
$script:HolyCheckSelfSha256=$null
function HashStreamSha256Hex([IO.Stream]$stream){
  $h=$script:sha256.ComputeHash($stream)
  return ([BitConverter]::ToString($h)).Replace('-','').ToLowerInvariant()
}
function HashFileSha256Hex([string]$path){
  $fs=$null
  try{
    $fs=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    return HashStreamSha256Hex $fs
  }catch{
    HCLog ('sha256 file error: ' + $path + ' error=' + $_.Exception.Message)
    return $null
  }finally{ if($fs){$fs.Dispose()} }
}
function InitHolyCheckSelfHash(){
  if(-not [string]::IsNullOrWhiteSpace($script:HolyCheckSelfSha256)){return $true}
  if([string]::IsNullOrWhiteSpace($script:HolyCheckSelfExe)){ HCLog 'self exe path empty; self-exe archive check disabled'; return $false }
  if(-not (Test-Path -LiteralPath $script:HolyCheckSelfExe)){ HCLog ('self exe missing; self-exe archive check disabled: ' + $script:HolyCheckSelfExe); return $false }
  $script:HolyCheckSelfSha256=HashFileSha256Hex $script:HolyCheckSelfExe
  if([string]::IsNullOrWhiteSpace($script:HolyCheckSelfSha256)){ HCLog ('self sha256 unavailable; self-exe archive check disabled: ' + $script:HolyCheckSelfExe); return $false }
  HCLog ('self sha256=' + $script:HolyCheckSelfSha256 + ' exe=' + $script:HolyCheckSelfExe)
  return $true
}
function IsArchiveEntryExecutable([string]$entryPath){
  if([string]::IsNullOrWhiteSpace($entryPath)){return $false}
  try{ return (([IO.Path]::GetExtension($entryPath)) -ieq '.exe') }catch{return $false}
}
function ArchiveIsEncryptedOrUnreadable([string]$path,[string]$ext){
  if($ext -eq '.zip'){
    if(ZipHasEncryptedEntries $path){ HCLog ('encrypted zip archive skipped: ' + $path); return $true }
    return $false
  }
  if($ext -eq '.rar' -or $ext -eq '.7z'){
    if(-not (HasArchiveTool)){ $script:archToolMissing=$true; HCLog ('no archive tool available, archive skipped: ' + $path); return $true }
    if($seven){
      $lines=Invoke7ZipListSafe $path
      if($null -eq $lines){ HCLog ('7z archive list unavailable, archive skipped: ' + $path); return $true }
      if(SevenZipListIndicatesEncrypted $lines){ HCLog ('encrypted archive skipped: ' + $path); return $true }
    }
  }
  return $false
}
function ShouldSkipHugeArchive([System.IO.FileInfo]$a){
  try{
    if($null -eq $a){return $true}
    if($a.Length -gt 1610612736){ HCLog ('huge archive skipped (>1.5GB): ' + $a.FullName); return $true }
  }catch{}
  return $false
}
function ZipContainsCurrentHolyCheckExe([string]$path){
  HCLog ('zip self-exe archive scan disabled: ' + $path)
  return $false
}
function Invoke7ZipExtractExesSafe([string]$archive,[string]$outDir){
  if(-not $seven){return $false}
  $p=$null
  try{
    $psi=New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName=$seven
    $psi.Arguments=('x -y -p"" ' + (QuoteProcArg ('-o' + $outDir)) + ' ' + (QuoteProcArg $archive) + ' "*.exe" -r')
    $psi.UseShellExecute=$false
    $psi.RedirectStandardInput=$true
    $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true
    $psi.CreateNoWindow=$true
    $p=New-Object System.Diagnostics.Process
    $p.StartInfo=$psi
    [void]$p.Start()
    $stdout=$p.StandardOutput.ReadToEndAsync()
    $stderr=$p.StandardError.ReadToEndAsync()
    try{$p.StandardInput.Close()}catch{}
    if(-not $p.WaitForExit(30000)){
)HCPS"
LR"HCPS(
      try{$p.Kill()}catch{}
      HCLog ('7z exe extract timeout, archive skipped: ' + $archive)
      return $false
    }
    $null=$stdout.Result
    $err=$stderr.Result
    HCLog ('7z exe extract exit=' + $p.ExitCode + ' archive=' + $archive)
    if($p.ExitCode -ne 0 -and -not [string]::IsNullOrWhiteSpace($err)){ HCLog ('7z exe extract stderr: ' + ($err.Substring(0,[Math]::Min(200,$err.Length)))) }
    return ($p.ExitCode -eq 0)
  }catch{
    HCLog ('7z exe extract error: ' + $archive + ' error=' + $_.Exception.Message)
    return $false
  }finally{
    if($p){try{$p.Dispose()}catch{}}
  }
}
function SevenZipContainsCurrentHolyCheckExe([string]$path){
  HCLog ('7z/rar self-exe archive scan disabled: ' + $path)
  return $false
}
try{
    HCLog ('embedded jar archive scan begin count=' + $archives.Values.Count)
  foreach($a in @($archives.Values)){
    if($null -eq $a){continue}
    if(ShouldSkipHugeArchive $a){continue}
    if(-not (Test-Path -LiteralPath $a.FullName)){ HCLog ('embedded jar archive missing after self cleanup skip: ' + $a.FullName); continue }
    $ext=[IO.Path]::GetExtension($a.FullName).ToLowerInvariant()
    HCLog ('embedded jar archive scan: ' + $a.FullName)
    if(ArchiveIsEncryptedOrUnreadable $a.FullName $ext){ HCLog ('embedded jar archive encrypted/unreadable skip: ' + $a.FullName); continue }
    if($ext -eq '.zip'){
      $zip=$null
      try{
        $zip=[IO.Compression.ZipFile]::OpenRead($a.FullName)
        foreach($e in $zip.Entries){
          if($e.FullName -match '\.jar$' -and -not ($e.FullName -match '(^|/)(libraries|assets|runtime|versions)/')){
            $n=[IO.Path]::GetFileName($e.FullName)
            $p=$a.FullName + '!' + $e.FullName
            if(IsCheatJarName $n){ AddNameHit $n $p; continue }
            $st=$null; $ms=$null
            try{
              $st=$e.Open()
              $ms=New-Object IO.MemoryStream
              $st.CopyTo($ms)
              $names=New-Object System.Collections.Generic.List[string]
              try{ $ms.Position=0; $za=New-Object IO.Compression.ZipArchive($ms,[IO.Compression.ZipArchiveMode]::Read,$true); try{ $names=CollectJarModNames $za }finally{ $za.Dispose() } }catch{}
              $inner=MatchCheatName $names
              if($inner){ AddNameHit ($n + ' (mod: ' + $inner + ')') $p; HCLog ('content hit (zip): ' + $p + ' inner=' + $inner) }
              elseif(IsRenamedJar $n $names){ AddRenamedHit ($n + ' (mod: ' + (FirstModName $names) + ')') $p; HCLog ('renamed hit (zip): ' + $p + ' inner=' + (FirstModName $names)) }
              else{
                if(ShouldSkipAsLibrary $n $p){ $script:librarySkipped++; HCLog ('skip library/non-mod (zip): ' + $p) }
                else{ $ms.Position=0; AddJarItem $n $p (HashStreamHex $ms) }
              }
            }catch{} finally{ if($ms){$ms.Dispose()}; if($st){$st.Dispose()} }
          }
        }
      }catch{} finally{ if($zip){$zip.Dispose()} }
    }elseif($ext -eq '.rar' -or $ext -eq '.7z'){
      if(-not (HasArchiveTool)){ $script:archToolMissing=$true; HCLog ('no archive tool for: ' + $a.FullName); continue }
      try{
        $out=Join-Path $tempRoot ([Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $out | Out-Null
        if(-not (ExtractJarsFromArchiveSafe $a.FullName $out)){ Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue; continue }
        Get-ChildItem -LiteralPath $out -Filter '*.jar' -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
          if($_.FullName -notmatch '\\(libraries|assets|runtime|versions)\\'){
            try{
              $rel=$_.FullName.Substring($out.Length).TrimStart('\\')
              $p=$a.FullName + '!' + $rel
              if(IsCheatJarName $_.Name){ AddNameHit $_.Name $p }
              else{
                $names=JarModNamesFromPath $_.FullName
                $inner=MatchCheatName $names
                if($inner){ AddNameHit ($_.Name + ' (mod: ' + $inner + ')') $p; HCLog ('content hit (7z): ' + $p + ' inner=' + $inner) }
                elseif(IsRenamedJar $_.Name $names){ AddRenamedHit ($_.Name + ' (mod: ' + (FirstModName $names) + ')') $p; HCLog ('renamed hit (7z): ' + $p + ' inner=' + (FirstModName $names)) }
                else{
                  if(ShouldSkipAsLibrary $_.Name $p){ $script:librarySkipped++; HCLog ('skip library/non-mod (7z): ' + $p) }
                  else{ AddJarItem $_.Name $p (HashFileHex $_.FullName) }
                }
              }
            }catch{}
          }
        }
        Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue
      }catch{}
    }
  }
}finally{
  Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
  try{$sha.Dispose()}catch{}
  try{$sha256.Dispose()}catch{}
  HCLog ('archive phase done: jars=' + $items.Count + '; nameHits=' + $nameHits.Count + '; cleanupHits=' + $cleanupHits.Count)
}
if($items.Count -eq 0 -and $nameHits.Count -eq 0 -and $renamedHits.Count -eq 0){HCLog 'no items/hits after archive phase, exit'; 'mods not found'; exit}
$known=@{}
HCLog ('modrinth lookup begin count=' + $items.Count)
for($i=0;$i -lt $items.Count;$i+=100){
  $to=[Math]::Min($i+99,$items.Count-1)
  if($to -lt $i){break}
  $batch=@($items[$i..$to])
  $body=@{hashes=@($batch|ForEach-Object{$_.Hash});algorithm='sha1'}|ConvertTo-Json -Compress
  try{
    HCLog ('modrinth batch begin from=' + $i + ' to=' + $to)
    $res=Invoke-RestMethod -Uri 'https://api.modrinth.com/v2/version_files' -Method Post -ContentType 'application/json' -Body $body -Headers @{'User-Agent'='HolyCheck/1.0'} -TimeoutSec 10
    if($res){$res.PSObject.Properties.Name|ForEach-Object{$known[$_]=1}}
    HCLog ('modrinth batch done from=' + $i + ' known=' + $known.Count)
  }catch{HCLog ('modrinth batch failed from=' + $i + ' error=' + $_.Exception.Message)}
}
HCLog ('modrinth lookup done known=' + $known.Count)
function FormatFoundModLine([string]$name,[string]$path,[bool]$forbiddenName,[bool]$renamedName=$false){
  $prefix=''
  if($renamedName){ $prefix=([string][char]0xE003) }
  elseif($forbiddenName){ $prefix=([string][char]0xE002) }
  if($path -match '\.(?:zip|rar|7z)!'){ return ($prefix + ([char]0xE001) + $name + ' (архив) | ' + $path) }
  return ($prefix + ('{0} | {1}' -f $name,$path))
}
$bad=0
foreach($it in $nameHits){ $bad++; FormatFoundModLine $it.Name $it.Path $true }
foreach($it in $renamedHits){ $bad++; FormatFoundModLine $it.Name $it.Path $false $true }
foreach($it in $items){
  if(-not $known.ContainsKey($it.Hash)){
    $k=PathKey $it.Path
    if(-not $reported.ContainsKey($k)){
      $bad++
      $reported[$k]=1
      FormatFoundModLine $it.Name $it.Path $false
    }
  }
}
HCLog ('finish bad=' + $bad + '; skippedLibs=' + $script:librarySkipped + '; known=' + $known.Count + '; nameHits=' + $nameHits.Count + '; items=' + $items.Count)
if($bad -eq 0){'не найдено'}
if($script:archToolMissing){ 'установите 7-Zip или WinRAR | архивы .rar/.7z не проверены' }
)HCPS";

    std::wstring output;
    DWORD timeoutMs = 900000;
    DebugLogLine(L"checkmods", L"powershell capture start timeout=" + std::to_wstring(timeoutMs));
    if (!RunHiddenPowerShellScriptCapture(script, output, timeoutMs))
    {
        DebugLogLine(L"checkmods", L"powershell capture launch failed mode=" + std::to_wstring(scanMode));
        lines.push_back(L"не удалось запустить checkmods");
        return lines;
    }
    DebugLogLine(L"checkmods", L"powershell capture done timedOut=" + std::to_wstring(g_lastHiddenProcessTimedOut ? 1 : 0) +
        L" exit=" + std::to_wstring(g_lastHiddenProcessExitCode) + L" outputChars=" + std::to_wstring(output.size()));

    std::vector<std::wstring> raw = SplitAutomationTextLines(output);
    for (const std::wstring& line : raw)
    {
        if (!line.empty())
            AppendWrappedAutomationLine(lines, line, 180);
    }

    if (lines.size() == 1)
        lines.push_back(L"не найдено");

    DebugLogLine(L"checkmods", L"result lines=" + std::to_wstring(lines.size()));
    return lines;
}

static std::vector<std::wstring> ScanUnsignedDlls()
{
    std::vector<std::wstring> lines;
    lines.push_back(L"название | путь");

    std::wstring script = LR"HCPS(
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
function AddRoot([string]$p){ if(-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path -LiteralPath $p)){ $script:roots += (Resolve-Path -LiteralPath $p).Path } }
function IsUserDll([System.IO.FileInfo]$f){
  $p=$f.FullName
  if($p -match '^C:\\(Windows|Program Files|Program Files \(x86\)|ProgramData|Recovery|System Volume Information|\\$Recycle\.Bin)(\\|$)'){return $false}
  if($p -match '\\(WindowsApps|Microsoft|Package Cache|AppData\\Local\\Packages|AppData\\Local\\Microsoft|AppData\\Local\\Programs|Python|Python\d+|pip|nodejs|gradle|maven|\.gradle|\.m2|jdk|jre|java|libraries|assets|runtime|versions|site-packages|venv|node_modules)\\'){return $false}
  if($p -match '\\(Downloads|Desktop)\\'){return $true}
  if($p -match '\\.minecraft\\'){return $true}
  if($p -match '\\.tlauncher\\legacy\\Minecraft\\game\\'){return $true}
  return $false
}
$roots=@()
if(Test-Path -LiteralPath 'C:\Users'){
  Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
    AddRoot (Join-Path $_.FullName 'Downloads')
    AddRoot (Join-Path $_.FullName 'Desktop')
    AddRoot (Join-Path $_.FullName 'AppData\Roaming\.minecraft')
    AddRoot (Join-Path $_.FullName 'AppData\Roaming\.tlauncher\legacy\Minecraft\game')
  }
}
if($env:USERPROFILE){ AddRoot (Join-Path $env:USERPROFILE 'Downloads'); AddRoot (Join-Path $env:USERPROFILE 'Desktop') }
if($env:APPDATA){ AddRoot (Join-Path $env:APPDATA '.minecraft'); AddRoot (Join-Path $env:APPDATA '.tlauncher\legacy\Minecraft\game') }
$roots=@($roots | Where-Object {$_} | Select-Object -Unique)
if($roots.Count -eq 0){'minecraft folder not found'; exit}
$seen=@{}
$count=0
foreach($r in $roots){
  try{
    Get-ChildItem -LiteralPath $r -Filter '*.dll' -File -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { IsUserDll $_ } | ForEach-Object {
      $key=$_.FullName.ToLowerInvariant()
      if(-not $seen.ContainsKey($key)){
        $seen[$key]=1
        try{
          $v=$_.VersionInfo
          $emptyAll=([string]::IsNullOrWhiteSpace($v.FileDescription) -and [string]::IsNullOrWhiteSpace($v.ProductName) -and [string]::IsNullOrWhiteSpace($v.LegalCopyright) -and [string]::IsNullOrWhiteSpace($v.ProductVersion))
          if($emptyAll){$count++; '{0} | {1}' -f $_.Name,$_.FullName}
        }catch{}
      }
    }
  }catch{}
}
if($count -eq 0){'не найдено'}
)HCPS";

    std::wstring output;
    if (!RunHiddenPowerShellScriptCapture(script, output, 180000))
    {
        lines.push_back(L"не удалось запустить dll scan");
        return lines;
    }

    std::vector<std::wstring> raw = SplitAutomationTextLines(output);
    for (const std::wstring& line : raw)
    {
        if (!line.empty())
            AppendWrappedAutomationLine(lines, line, 180);
    }

    if (lines.size() == 1)
        lines.push_back(L"не найдено");

    return lines;
}

static std::vector<std::wstring> ScanPage4ByMode(int mode)
{
    // Любая кнопка checkmods запускает полное сканирование.
    (void)mode;
    return ScanModrinthHashes(1);
}

static std::vector<std::wstring> ScanInjGenStyle()
{
    std::vector<std::wstring> lines;

    std::wstring script;
    script.reserve(32768);
    script += LR"HCPS(
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8

$src=@"
using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class HCInjGenNativeExact {
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_VM_READ = 0x0010;
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_NOACCESS = 0x01;
    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_GUARD = 0x100;
    const int MIN_STRING_LENGTH = 12;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern UIntPtr VirtualQueryEx(IntPtr hProcess, IntPtr address, out MEMORY_BASIC_INFORMATION mbi, UIntPtr length);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr baseAddress, byte[] buffer, IntPtr size, out IntPtr bytesRead);

    static ulong U(IntPtr p) { return unchecked((ulong)p.ToInt64()); }
    static bool EndsWithJavaw(Process p) {
        try {
            string path = (p.MainModule != null ? p.MainModule.FileName : "") ?? "";
            if (path.EndsWith("\\javaw.exe", StringComparison.OrdinalIgnoreCase) ||
                path.EndsWith("/javaw.exe", StringComparison.OrdinalIgnoreCase)) return true;
        } catch { }
        try { return String.Equals(p.ProcessName, "javaw", StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }
    static ProcessModule FindJvm(Process p) {
        try {
            foreach (ProcessModule m in p.Modules) {
                string f = (m.FileName ?? "");
                if (f.IndexOf("jvm.dll", StringComparison.OrdinalIgnoreCase) >= 0) return m;
            }
        } catch { }
        return null;
    }
    static uint ReadUInt32(byte[] b, int off) { return BitConverter.ToUInt32(b, off); }
    static int ReadInt32(byte[] b, int off) { return BitConverter.ToInt32(b, off); }
    static ulong GetJvmEnd(IntPtr hp, ProcessModule jvm) {
        ulong baseAddr = U(jvm.BaseAddress);
        try {
            byte[] dos = new byte[64];
            IntPtr got;
            if (!ReadProcessMemory(hp, jvm.BaseAddress, dos, new IntPtr(dos.Length), out got) || got.ToInt64() != dos.Length) return 0;
            if (dos[0] != (byte)'M' || dos[1] != (byte)'Z') return 0;
            int pe = ReadInt32(dos, 0x3c);
            byte[] nt = new byte[264];
            if (!ReadProcessMemory(hp, new IntPtr(unchecked((long)(baseAddr + (ulong)pe))), nt, new IntPtr(nt.Length), out got) || got.ToInt64() != nt.Length) return 0;
            if (nt[0] != (byte)'P' || nt[1] != (byte)'E' || nt[2] != 0 || nt[3] != 0) return 0;
            uint sizeOfImage = ReadUInt32(nt, 24 + 56);
            if (sizeOfImage == 0 || sizeOfImage > 0x40000000U) return 0;
            return baseAddr + (ulong)sizeOfImage;
        } catch { return 0; }
    }
    static bool IsOriginalWritable(uint protect) {
        return (protect & PAGE_READWRITE) != 0;
    }
)HCPS";

    script += LR"HCPS(
    static bool Trace(IntPtr hp, ulong baseAddress, ulong endAddress, uint expected) {
        int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
        ulong current = baseAddress;
        while (current < endAddress) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hp, new IntPtr(unchecked((long)current)), out mbi, (UIntPtr)mbiSize) == UIntPtr.Zero) break;
            ulong rb = U(mbi.BaseAddress);
            ulong rs = mbi.RegionSize.ToUInt64();
            if (rs == 0) break;
            if (mbi.State == MEM_COMMIT && IsOriginalWritable(mbi.Protect)) {
                ulong a = rb;
                ulong b = rb + rs;
                if (a < baseAddress) a = baseAddress;
                if (b > endAddress) b = endAddress;
                ulong len64 = b > a ? b - a : 0;
                if (len64 > 0 && len64 <= 128UL * 1024UL * 1024UL) {
                    byte[] buf = new byte[(int)len64];
                    IntPtr got;
                    if (ReadProcessMemory(hp, new IntPtr(unchecked((long)a)), buf, new IntPtr(buf.Length), out got) && got.ToInt64() == buf.Length) {
                        for (int i = 0; i + 4 <= buf.Length; i += 4) {
                            if (BitConverter.ToUInt32(buf, i) == expected) return true;
                        }
                    }
                }
            }
            ulong next = rb + rs;
            current = next > current ? next : current + 0x1000;
        }
        return false;
    }
    static bool ContainsAsciiInPrintableRuns(byte[] data, int len, string needle) {
        string cur = "";
        for (int i = 0; i < len; ++i) {
            byte c = data[i];
            if (c >= 32 && c <= 126) cur += (char)c;
            else {
                if (cur.Length >= MIN_STRING_LENGTH && cur.IndexOf(needle, StringComparison.Ordinal) >= 0) return true;
                cur = "";
            }
        }
        return cur.Length >= MIN_STRING_LENGTH && cur.IndexOf(needle, StringComparison.Ordinal) >= 0;
    }
)HCPS";

    script += LR"HCPS(
    static bool ValidatePattern(IntPtr hp) {
        int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
        ulong cur = 0;
        ulong max = IntPtr.Size == 8 ? 0x00007fffffffffffUL : 0x7fffffffUL;
        while (cur < max) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hp, new IntPtr(unchecked((long)cur)), out mbi, (UIntPtr)mbiSize) != UIntPtr.Zero) {
                ulong rb = U(mbi.BaseAddress);
                ulong rs = mbi.RegionSize.ToUInt64();
                if (rs == 0) break;
                if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) != 0 && (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0) {
                    ulong half = rs / 2;
                    if (half > 0 && half <= 128UL * 1024UL * 1024UL) {
                        byte[] buf = new byte[(int)half];
                        IntPtr got;
                        if (ReadProcessMemory(hp, new IntPtr(unchecked((long)rb)), buf, new IntPtr(buf.Length), out got) && got.ToInt64() > 0) {
                            if (ContainsAsciiInPrintableRuns(buf, (int)got.ToInt64(), "com/lunarclient")) return true;
                        }
                    }
                }
                ulong next = rb + rs;
                cur = next > cur ? next : cur + 0x1000;
            } else cur += 0x1000;
        }
        return false;
    }
)HCPS";

    script += LR"HCPS(
    public static string Run() {
        StringBuilder sb = new StringBuilder();
        int scanned = 0;
        foreach (Process p in Process.GetProcesses()) {
            if (!EndsWithJavaw(p)) continue;
            ProcessModule jvm = FindJvm(p);
            if (jvm == null) continue;
            IntPtr hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, p.Id);
            if (hp == IntPtr.Zero) { sb.AppendLine(p.Id + " | javaw.exe | error"); continue; }
            try {
                ulong baseAddress = U(jvm.BaseAddress);
                ulong endAddress = GetJvmEnd(hp, jvm);
                if (baseAddress == 0 || endAddress == 0 || endAddress <= baseAddress) { sb.AppendLine(p.Id + " | javaw.exe | error"); continue; }
                scanned++;
                bool flag = true;
                flag = flag && Trace(hp, baseAddress, endAddress, 524294U);
                flag = flag && Trace(hp, baseAddress, endAddress, 4242546329U);
                if (flag) {
                    if (ValidatePattern(hp)) sb.AppendLine(p.Id + " | javaw.exe | injection detected");
                    else sb.AppendLine(p.Id + " | javaw.exe | injection detected");
                } else {
                    sb.AppendLine(p.Id + " | javaw.exe | clean");
                }
            } catch { sb.AppendLine(p.Id + " | javaw.exe | error"); }
            finally { CloseHandle(hp); }
        }
        if (scanned == 0) return "minecraft/java process not found";
        return sb.ToString();
    }
}
"@

try {
  Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop
  [HCInjGenNativeExact]::Run()
} catch {
  'injgen native scanner error: ' + (($_.Exception.Message) -replace '\r|\n',' ')
}
)HCPS";

    std::wstring output;
    if (!RunHiddenPowerShellScriptCapture(script, output, 180000))
    {
        lines.push_back(L"не удалось запустить injgen");
        return lines;
    }

    std::vector<std::wstring> raw = SplitAutomationTextLines(output);
    bool hasRows = false;
    for (const std::wstring& line : raw)
    {
        if (line.empty() || ToLowerCopy(line).find(L"filename, directory name, or volume label") != std::wstring::npos)
            continue;

        std::wstring lower = ToLowerCopy(line);
        if (lower.find(L"minecraft/java process not found") != std::wstring::npos)
        {
            lines.push_back(L"minecraft/java process not found");
            continue;
        }

        std::vector<std::wstring> cols = SplitTextByPipe(line);
        if (cols.size() >= 3)
        {
            if (!hasRows)
            {
                lines.push_back(L"pid | процесс | статус");
                hasRows = true;
            }
            lines.push_back(TrimAutomationField(cols[0]) + L" | " + TrimAutomationField(cols[1]) + L" | " + TrimAutomationField(cols[2]));
        }
        else
        {
            AppendWrappedAutomationLine(lines, line, 180);
        }
    }

    if (lines.empty())
        lines.push_back(L"не найдено");

    return lines;
}

static int BuildAutomationScanCacheKey(int target, bool unsignedOnly, int activityMode, int page4Mode)
{
    int key = target * 1000;

    if (target == AUTOMATION_OUTPUT_BAM)
        key += unsignedOnly ? 1 : 0;
    else if (target == AUTOMATION_OUTPUT_JAR_ACTIVITY || target == AUTOMATION_OUTPUT_EXE_DELETED || target == AUTOMATION_OUTPUT_PF_DELETED || target == AUTOMATION_OUTPUT_MC_LOGS)
        key += (activityMode & 0xFF) * 10;
    else if (target == AUTOMATION_OUTPUT_PAGE4)
        key += (page4Mode & 0xFF) * 10;

    return key;
}

static int CurrentAutomationScanCacheKey(int target, bool unsignedOnly)
{
    return BuildAutomationScanCacheKey(target, unsignedOnly, g_activityScanMode.load(), g_page4ScanMode.load());
}

static bool TryGetAutomationCachedLines(int cacheKey, std::vector<std::wstring>& lines)
{
    ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(g_automationCacheMutex);
    auto it = g_automationCache.find(cacheKey);

    if (it == g_automationCache.end())
        return false;

    if (now < it->second.tick || now - it->second.tick > AUTOMATION_CACHE_TTL_MS)
    {
        g_automationCache.erase(it);
        return false;
    }

    lines = it->second.lines;
    return true;
}

static void StoreAutomationCachedLines(int cacheKey, const std::vector<std::wstring>& lines)
{
    if (lines.empty())
        return;

    AutomationCacheEntry entry;
    entry.tick = GetTickCount64();
    entry.lines = lines;

    std::lock_guard<std::mutex> lock(g_automationCacheMutex);
    g_automationCache[cacheKey] = std::move(entry);

    if (g_automationCache.size() > 32)
    {
        ULONGLONG oldestTick = ULLONG_MAX;
        int oldestKey = 0;
        for (const auto& item : g_automationCache)
        {
            if (item.second.tick < oldestTick)
            {
                oldestTick = item.second.tick;
                oldestKey = item.first;
            }
        }
        g_automationCache.erase(oldestKey);
    }
}

static std::vector<std::wstring> ExecuteAutomationScanTarget(int target, bool unsignedOnly, int activityMode, int page4Mode)
{
    DebugLogLine(L"automation", L"execute start target=" + std::to_wstring(target) +
        L" unsignedOnly=" + std::to_wstring(unsignedOnly ? 1 : 0) +
        L" activityMode=" + std::to_wstring(activityMode) +
        L" page4Mode=" + std::to_wstring(page4Mode));

    std::vector<std::wstring> lines;
    UNREFERENCED_PARAMETER(activityMode);

    if (target == AUTOMATION_OUTPUT_BAM)
        lines = ScanBamRegistry(unsignedOnly);
    else if (target == AUTOMATION_OUTPUT_EVENTVWR)
        lines = ScanEventViewerLogs();
    else if (target == AUTOMATION_OUTPUT_JAR_ACTIVITY)
        lines = ScanJarActivityJournalReasonsOnly();
    else if (target == AUTOMATION_OUTPUT_EXE_DELETED)
        // .exe deleted больше не отдельное окно: deleted-строки показываются внутри .exe activity.
        lines = ScanExeActivityWithDeleted();
    else if (target == AUTOMATION_OUTPUT_PF_DELETED)
        lines = ScanUsnActivityForExtension(L".jar", true);
    else if (target == AUTOMATION_OUTPUT_MC_LOGS)
        lines = ScanExeDeletedFromUsnDeleteClose();
    else if (target == AUTOMATION_OUTPUT_PAGE4)
        lines = ScanPage4ByMode(page4Mode);
    else if (target == AUTOMATION_OUTPUT_DLL_UNSIGNED)
        lines = ScanUnsignedDlls();
    else if (target == AUTOMATION_OUTPUT_DLL_ACTIVITY)
        lines = ScanDllActivityJournalReasonsOnly();
    else if (target == AUTOMATION_OUTPUT_INJGEN)
        lines = ScanInjGenStyle();

    if (target == AUTOMATION_OUTPUT_JAR_ACTIVITY || target == AUTOMATION_OUTPUT_DLL_ACTIVITY)
        SortAutomationOutputLinesByPipeColumnDateDesc(lines, 0, 1);
    else
        SortAutomationOutputLinesByDateDesc(lines, target == AUTOMATION_OUTPUT_EVENTVWR ? 0 : 1);

    DebugLogLine(L"automation", L"execute finish target=" + std::to_wstring(target) +
        L" lines=" + std::to_wstring(lines.size()));
    return lines;
}

static void PostAutomationBatchDone(std::vector<AutomationBatchItem>&& items)
{
    HWND hwnd = g_hMain;

    if (!hwnd || g_destroying.load())
        return;

    AutomationBatchResult* result = new (std::nothrow) AutomationBatchResult();
    if (!result)
        return;

    result->items = std::move(items);
    if (!PostMessageW(hwnd, WM_APP_AUTOMATION_BATCH_DONE, 0, reinterpret_cast<LPARAM>(result)))
        delete result;
}

static void StartAutomationScan(int target)
{
    // Новый запуск снимает оба флага отмены. Иначе после нажатия «Отмена»
    // g_cancelRequested оставался поднятым навсегда и мгновенно убивал любой
    // следующий PowerShell-скан (checkmods находил «ничего»).
    g_scanCancelRequested = false;
    g_cancelRequested = false;

    bool unsignedOnly = g_bamUnsignedOnly.load();
    int activityMode = g_activityScanMode.load();
    int page4Mode = g_page4ScanMode.load();
    int cacheKey = BuildAutomationScanCacheKey(target, unsignedOnly, activityMode, page4Mode);
    DebugLogLine(L"automation", L"start request target=" + std::to_wstring(target) +
        L" cacheKey=" + std::to_wstring(cacheKey) +
        L" unsignedOnly=" + std::to_wstring(unsignedOnly ? 1 : 0) +
        L" activityMode=" + std::to_wstring(activityMode) +
        L" page4Mode=" + std::to_wstring(page4Mode));

    std::vector<std::wstring> cached;
    if (TryGetAutomationCachedLines(cacheKey, cached))
    {
        DebugLogLine(L"automation", L"cache hit target=" + std::to_wstring(target) + L" cacheKey=" + std::to_wstring(cacheKey) + L" lines=" + std::to_wstring(cached.size()));
        SetAutomationLines(target, std::move(cached));
        if (AutomationEditForTarget(target))
            UpdateAutomationEditWindow(target);
        InvalidateAutomationPanel(target);
        return;
    }

    bool expected = false;
    std::atomic_bool& working = AutomationWorkingRef(target);

    if (!working.compare_exchange_strong(expected, true))
    {
        DebugLogLine(L"automation", L"start skipped already working target=" + std::to_wstring(target));
        SetAutomationStatusLine(target, L"сканирование...");
        InvalidateAutomationPanel(target);
        return;
    }

    SetAutomationStatusLine(target, L"сканирование...");
    if (AutomationEditForTarget(target))
        UpdateAutomationEditWindow(target);
    InvalidateAutomationPanel(target);

    std::thread([target, unsignedOnly, activityMode, page4Mode, cacheKey]()
    {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        std::vector<std::wstring> lines = ExecuteAutomationScanTarget(target, unsignedOnly, activityMode, page4Mode);

        if (g_scanCancelRequested.load())
        {
            // Скан убили по «Отмене»: результат не кэшируем (иначе пустой
            // «не найдено» залипал в кэше и выдавался при всех повторных
            // запусках), а вместо него показываем понятный статус.
            lines.clear();
            lines.push_back(L"сканирование отменено пользователем");
        }
        else
        {
            StoreAutomationCachedLines(cacheKey, lines);
        }
        DebugLogLine(L"automation", L"post done target=" + std::to_wstring(target) + L" lines=" + std::to_wstring(lines.size()));
        PostAutomationDone(target, std::move(lines));
    }).detach();
}

static void StartAutomationBatchScan(const std::vector<int>& targets)
{
    // См. StartAutomationScan: снимаем оба флага отмены при новом запуске.
    g_scanCancelRequested = false;
    g_cancelRequested = false;

    bool unsignedOnly = g_bamUnsignedOnly.load();
    int activityMode = g_activityScanMode.load();
    int page4Mode = g_page4ScanMode.load();
    DebugLogLine(L"automation", L"batch start targets=" + std::to_wstring(targets.size()) +
        L" unsignedOnly=" + std::to_wstring(unsignedOnly ? 1 : 0) +
        L" activityMode=" + std::to_wstring(activityMode) +
        L" page4Mode=" + std::to_wstring(page4Mode));
    std::vector<std::pair<int, int>> started;
    started.reserve(targets.size());

    for (int target : targets)
    {
        int cacheKey = BuildAutomationScanCacheKey(target, unsignedOnly, activityMode, page4Mode);
        std::vector<std::wstring> cached;
        if (TryGetAutomationCachedLines(cacheKey, cached))
        {
            SetAutomationLines(target, std::move(cached));
            if (AutomationEditForTarget(target))
                UpdateAutomationEditWindow(target);
            InvalidateAutomationPanel(target);
            continue;
        }

        bool expected = false;
        std::atomic_bool& working = AutomationWorkingRef(target);
        if (working.compare_exchange_strong(expected, true))
        {
            started.emplace_back(target, cacheKey);
            SetAutomationStatusLine(target, L"сканирование...");
            if (AutomationEditForTarget(target))
                UpdateAutomationEditWindow(target);
            InvalidateAutomationPanel(target);
        }
        else
        {
            SetAutomationStatusLine(target, L"сканирование...");
            InvalidateAutomationPanel(target);
        }
    }

    if (started.empty())
        return;

    std::thread([started, unsignedOnly, activityMode, page4Mode]()
    {
        std::vector<AutomationBatchItem> items;
        std::mutex itemsMutex;
        std::vector<std::thread> workers;
        const size_t workerCount = std::min<size_t>(2, started.size());
        workers.reserve(workerCount);
        std::atomic_size_t nextItem{0};

        for (size_t workerIndex = 0; workerIndex < workerCount; ++workerIndex)
        {
            workers.emplace_back([&started, unsignedOnly, activityMode, page4Mode, &items, &itemsMutex, &nextItem]()
            {
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
                for (;;)
                {
                    size_t index = nextItem.fetch_add(1);
                    if (index >= started.size()) break;
                    int target = started[index].first;
                    int cacheKey = started[index].second;
                    AutomationBatchItem item;
                    item.target = target;
                    item.lines = ExecuteAutomationScanTarget(target, unsignedOnly, activityMode, page4Mode);

                    if (g_scanCancelRequested.load())
                    {
                        item.lines.clear();
                        item.lines.push_back(L"сканирование отменено пользователем");
                    }
                    else
                    {
                        StoreAutomationCachedLines(cacheKey, item.lines);
                    }
                    std::lock_guard<std::mutex> lock(itemsMutex);
                    items.push_back(std::move(item));
                }
            });
        }

        for (std::thread& worker : workers)
        {
            if (worker.joinable())
                worker.join();
        }

        PostAutomationBatchDone(std::move(items));
    }).detach();
}


static bool IsAllowedDownloadLogLine(const std::wstring& line)
{
    return line.rfind(L"скачивается:", 0) == 0 ||
        line.rfind(L"не скачалось:", 0) == 0 ||
        line.rfind(L"лог:", 0) == 0 ||
        line.rfind(L"Сохранено", 0) == 0 ||
        line.rfind(L"Не удалось", 0) == 0 ||
        line.rfind(L"Не создана папка", 0) == 0 ||
        line.rfind(L"Отменено:", 0) == 0 ||
        line == L"Сейчас идут одиночные загрузки" ||
        line == L"Отмена загрузок..." ||
        line == L"текст скопирован" ||
        line == L"текст не скопирован";
}

static void PostLog(const std::wstring& line)
{
    DebugLogLine(L"ui-log", line);

    if (!IsAllowedDownloadLogLine(line))
        return;

    HWND hwnd = g_hMain;

    if (!hwnd || g_destroying.load())
        return;

    std::wstring* heapLine = new (std::nothrow) std::wstring(line);

    if (!heapLine)
        return;

    if (!PostMessageW(hwnd, WM_APP_LOG, 0, reinterpret_cast<LPARAM>(heapLine)))
        delete heapLine;
}

static std::shared_ptr<HttpHandleSlot> TrackHttpHandle(HINTERNET handle)
{
    if (!handle)
        return nullptr;

    auto slot = std::make_shared<HttpHandleSlot>();
    slot->handle = handle;

    std::lock_guard<std::mutex> lock(g_httpHandlesMutex);
    g_httpHandles.push_back(slot);
    return slot;
}

static void CloseTrackedHttpHandle(std::shared_ptr<HttpHandleSlot>& slot)
{
    HINTERNET handle = nullptr;

    {
        std::lock_guard<std::mutex> lock(g_httpHandlesMutex);

        if (!slot || slot->closed)
            return;

        handle = slot->handle;
        slot->handle = nullptr;
        slot->closed = true;

        g_httpHandles.erase(
            std::remove(g_httpHandles.begin(), g_httpHandles.end(), slot),
            g_httpHandles.end()
        );
    }

    if (handle)
        WinHttpCloseHandle(handle);
}

static void AbortActiveHttpHandles()
{
    std::vector<std::shared_ptr<HttpHandleSlot>> handles;

    {
        std::lock_guard<std::mutex> lock(g_httpHandlesMutex);
        handles = g_httpHandles;
    }

    for (auto& slot : handles)
        CloseTrackedHttpHandle(slot);
}

static bool IsCancelRequested()
{
    return g_cancelRequested.load();
}

static void RequestCancelDownloads()
{
    // Cancel is unconditional on purpose. The old hasWork guard returned
    // early whenever the counters were already clear, which left orphaned
    // child processes and sockets running and looked like a freeze.
    g_cancelRequested = true;
    g_scanCancelRequested = true;

    AbortActiveHttpHandles();
    TerminateTrackedChildProcesses();
    PostLog(L"Отмена загрузок...");
}


static bool IsItemBusyIndex(int index)
{
    std::lock_guard<std::mutex> lock(g_itemBusyMutex);

    if (index < 0 || index >= static_cast<int>(g_itemBusy.size()))
        return false;

    return g_itemBusy[index] != 0;
}

static void SetItemBusyIndex(int index, bool busy)
{
    std::lock_guard<std::mutex> lock(g_itemBusyMutex);

    if (index < 0 || index >= static_cast<int>(g_itemBusy.size()))
        return;

    g_itemBusy[index] = busy ? 1 : 0;
}

static void SetTileEnabledByIndex(int index, bool enabled)
{
    if (index < 0 || index >= static_cast<int>(g_tileButtons.size()))
        return;

    EnableWindow(g_tileButtons[index], enabled ? TRUE : FALSE);
    InvalidateRect(g_tileButtons[index], nullptr, FALSE);
}

static bool IsUiThread()
{
    return g_uiThreadId != 0 && GetCurrentThreadId() == g_uiThreadId;
}

static void PostUiRefresh()
{
    HWND hwnd = g_hMain;

    if (!hwnd || g_destroying.load())
        return;

    PostMessageW(hwnd, WM_APP_REFRESH, 0, 0);
}

static void InvalidateBottomPanel()
{
    HWND hwnd = g_hMain;

    if (!hwnd || g_destroying.load())
        return;

    if (!IsUiThread())
    {
        PostUiRefresh();
        return;
    }

    if (g_currentPage != 0)
        return;

    RECT rc{};
    GetClientRect(hwnd, &rc);
    RECT panelRect{ 0, HOME_TILE_TOP, rc.right, rc.bottom };
    InvalidateRect(hwnd, &panelRect, FALSE);

    for (size_t index : g_operationItems)
    {
        if (g_downloadCardPhases[index] == DownloadCardPhase::Downloading && IsWindowVisible(g_tileButtons[index]))
            InvalidateRect(g_tileButtons[index], nullptr, FALSE);
    }
}

static void BeginDownloadPresentation(const std::vector<DownloadItem>& items, bool batch, bool newOperation)
{
    if (newOperation)
    {
        g_operationItems.clear();
        g_operationBatch = batch;
        g_operationFinished = false;
        g_operationCancelled = false;
        g_operationHadError = false;
    }

    for (const DownloadItem& item : items)
    {
        auto found = std::find_if(g_items.begin(), g_items.end(),
            [&](const DownloadItem& candidate) { return candidate.name == item.name; });
        if (found == g_items.end())
            continue;

        size_t index = static_cast<size_t>(found - g_items.begin());
        if (std::find(g_operationItems.begin(), g_operationItems.end(), index) == g_operationItems.end())
            g_operationItems.push_back(index);
        g_downloadCardPhases[index] = DownloadCardPhase::Queued;
        InvalidateRect(g_tileButtons[index], nullptr, FALSE);
    }
}

static void ReportDownloadCard(const DownloadItem& item, DownloadCardPhase phase)
{
    if (!g_hMain || g_destroying.load())
        return;

    auto found = std::find_if(g_items.begin(), g_items.end(),
        [&](const DownloadItem& candidate) { return candidate.name == item.name; });
    if (found != g_items.end())
        PostMessageW(g_hMain, WM_APP_DOWNLOAD_CARD, static_cast<WPARAM>(found - g_items.begin()), static_cast<LPARAM>(phase));
}

static std::wstring FormatOneDecimal(unsigned long long value, unsigned long long divisor)
{
    if (divisor == 0)
        return std::to_wstring(value);

    unsigned long long whole = value / divisor;
    unsigned long long tenth = ((value % divisor) * 10ull) / divisor;
    return std::to_wstring(whole) + L"." + std::to_wstring(tenth);
}

static std::wstring FormatBytes(unsigned long long bytes)
{
    if (bytes >= 1024ull * 1024ull * 1024ull)
        return FormatOneDecimal(bytes, 1024ull * 1024ull * 1024ull) + L" ГБ";

    if (bytes >= 1024ull * 1024ull)
        return FormatOneDecimal(bytes, 1024ull * 1024ull) + L" МБ";

    if (bytes >= 1024ull)
        return FormatOneDecimal(bytes, 1024ull) + L" КБ";

    return std::to_wstring(bytes) + L" Б";
}

static std::wstring FormatSpeedBps(unsigned long long bps)
{
    if (bps == 0)
        return L"0 КБ/с";

    if (bps >= 1024ull * 1024ull)
        return FormatOneDecimal(bps, 1024ull * 1024ull) + L" МБ/с";

    if (bps >= 1024ull)
        return FormatOneDecimal(bps, 1024ull) + L" КБ/с";

    return std::to_wstring(bps) + L" Б/с";
}

static std::wstring FormatSpeedForLog(unsigned long long bps)
{
    if (bps == 0)
        return L"0 КБ/сек";

    if (bps >= 1024ull * 1024ull)
        return FormatOneDecimal(bps, 1024ull * 1024ull) + L" МБ/сек";

    if (bps >= 1024ull)
        return FormatOneDecimal(bps, 1024ull) + L" КБ/сек";

    return std::to_wstring(bps) + L" Б/сек";
}

static bool StartsWithDownloadLineForName(const std::wstring& line, const std::wstring& name)
{
    const std::wstring prefix = L"скачивается: " + name;
    return line == prefix || line.rfind(prefix + L" | ", 0) == 0;
}

static void UpsertLiveDownloadLogLine(const std::wstring& name, unsigned long long speedBps)
{
    if (name.empty())
        return;

    std::wstring line = L"скачивается: " + name;

    if (speedBps > 0)
        line += L" | " + FormatSpeedForLog(speedBps);

    {
        std::lock_guard<std::mutex> lock(g_logMutex);

        for (auto it = g_logLines.rbegin(); it != g_logLines.rend(); ++it)
        {
            if (StartsWithDownloadLineForName(it->message, name))
            {
                it->message = ShortLogLine(line);
                ClampLogScrollOffsetLocked();
                InvalidateBottomPanel();
                return;
            }
        }
    }

    PushLogLine(line);
    InvalidateBottomPanel();
}

static void RemoveLiveDownloadLogLine(const std::wstring& name)
{
    if (name.empty())
        return;

    {
        std::lock_guard<std::mutex> lock(g_logMutex);

        g_logLines.erase(
            std::remove_if(g_logLines.begin(), g_logLines.end(), [&](const DownloadLogEntry& line)
            {
                return StartsWithDownloadLineForName(line.message, name);
            }),
            g_logLines.end()
        );

        ClampLogScrollOffsetLocked();
    }

    InvalidateBottomPanel();
}

static std::wstring FormatElapsedMs(ULONGLONG elapsedMs)
{
    unsigned long long sec = static_cast<unsigned long long>(elapsedMs / 1000ull);

    if (sec < 60)
        return std::to_wstring(sec) + L"с";

    unsigned long long min = sec / 60ull;
    sec %= 60ull;
    return std::to_wstring(min) + L"м " + std::to_wstring(sec) + L"с";
}

static void ClearActiveDownloads()
{
    std::lock_guard<std::mutex> lock(g_activeDownloadsMutex);
    g_activeDownloads.clear();
}

static void AddActiveDownload(const std::wstring& name)
{
    {
        std::lock_guard<std::mutex> lock(g_activeDownloadsMutex);

        auto it = std::find_if(g_activeDownloads.begin(), g_activeDownloads.end(), [&](const ActiveDownloadInfo& info)
        {
            return info.name == name;
        });

        if (it == g_activeDownloads.end())
        {
            ActiveDownloadInfo info;
            info.name = name;
            info.method = L"ожидание";
            info.startedTick = GetTickCount64();
            info.updatedTick = info.startedTick;
            g_activeDownloads.push_back(info);
        }
    }

    InvalidateBottomPanel();
}

static void UpdateActiveDownloadStatus(
    const std::wstring& name,
    const std::wstring& method,
    size_t linkIndex,
    size_t linkTotal,
    unsigned long long bytes,
    unsigned long long speedBps,
    unsigned long long totalBytes = 0)
{
    {
        std::lock_guard<std::mutex> lock(g_activeDownloadsMutex);

        auto it = std::find_if(g_activeDownloads.begin(), g_activeDownloads.end(), [&](const ActiveDownloadInfo& info)
        {
            return info.name == name;
        });

        if (it == g_activeDownloads.end())
        {
            ActiveDownloadInfo info;
            info.name = name;
            info.startedTick = GetTickCount64();
            info.updatedTick = info.startedTick;
            g_activeDownloads.push_back(info);
            it = g_activeDownloads.end() - 1;
        }

        it->method = method.empty() ? L"загрузка" : method;
        it->linkIndex = linkIndex;
        it->linkTotal = linkTotal;
        it->bytes = bytes;
        it->speedBps = speedBps;
        it->totalBytes = totalBytes;
        it->updatedTick = GetTickCount64();
    }

    UpsertLiveDownloadLogLine(name, speedBps);
    InvalidateBottomPanel();
}

static void RemoveActiveDownload(const std::wstring& name)
{
    {
        std::lock_guard<std::mutex> lock(g_activeDownloadsMutex);
        g_activeDownloads.erase(
            std::remove_if(g_activeDownloads.begin(), g_activeDownloads.end(), [&](const ActiveDownloadInfo& info)
            {
                return info.name == name;
            }),
            g_activeDownloads.end()
        );
    }

    RemoveLiveDownloadLogLine(name);
    InvalidateBottomPanel();
}

static std::wstring GetActiveDownloadsText()
{
    std::lock_guard<std::mutex> lock(g_activeDownloadsMutex);

    if (g_activeDownloads.empty())
        return L"";

    unsigned long long totalSpeed = 0;

    for (const auto& info : g_activeDownloads)
        totalSpeed += info.speedBps;

    std::wstring result = L"Сейчас: ";

    if (totalSpeed > 0)
    {
        result += L"итого ";
        result += FormatSpeedBps(totalSpeed);
        result += L" | ";
    }

    const size_t maxShown = 3;

    for (size_t i = 0; i < g_activeDownloads.size() && i < maxShown; ++i)
    {
        if (i > 0)
            result += L"; ";

        const ActiveDownloadInfo& info = g_activeDownloads[i];
        result += L"скачивается: ";
        result += info.name;
        result += L" | ";
        result += FormatSpeedBps(info.speedBps);

        if (!info.method.empty() && info.method != L"ожидание")
        {
            result += L" | ";
            result += info.method;
        }

        if (info.linkTotal > 0 && info.linkIndex > 0)
        {
            result += L" | ссылка ";
            result += std::to_wstring(info.linkIndex);
            result += L"/";
            result += std::to_wstring(info.linkTotal);
        }
    }

    if (g_activeDownloads.size() > maxShown)
        result += L" +" + std::to_wstring(g_activeDownloads.size() - maxShown);

    return result;
}

static std::wstring ToLower(std::wstring s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c)
    {
        return static_cast<wchar_t>(towlower(c));
    });
    return s;
}

static bool EndsWithI(const std::wstring& s, const std::wstring& suffix)
{
    std::wstring a = ToLower(s);
    std::wstring b = ToLower(suffix);

    return a.size() >= b.size() &&
        a.compare(a.size() - b.size(), b.size(), b) == 0;
}


static bool IsFastFailName(const std::wstring& name)
{
    UNREFERENCED_PARAMETER(name);
    return false;
}

static bool IsFastFailItem(const DownloadItem& item)
{
    return IsFastFailName(item.name);
}

static bool IsEricZimmermanUrl(const std::wstring& url)
{
    return ToLower(url).find(L"download.ericzimmermanstools.com") != std::wstring::npos;
}

static bool IsFastFailUrl(const std::wstring& url)
{
    std::wstring lower = ToLower(url);

    return lower.find(L"simpleunlocker.ds1nc.ru") != std::wstring::npos;
}

static bool IsFastFailDownload(const std::wstring& displayName, const std::wstring& url)
{
    return IsFastFailName(displayName) || IsFastFailUrl(url);
}

static bool IsRegistryExplorerItem(const DownloadItem& item)
{
    std::wstring name = ToLower(item.name);
    return name.find(L"registryexplorer") != std::wstring::npos ||
        (name.find(L"registry") != std::wstring::npos && name.find(L"explorer") != std::wstring::npos);
}

static bool IsJumpListExplorerItem(const DownloadItem& item)
{
    std::wstring name = ToLower(item.name);
    return name.find(L"jumplistexplorer") != std::wstring::npos ||
        (name.find(L"jumplist") != std::wstring::npos && name.find(L"explorer") != std::wstring::npos);
}

static bool IsSimpleUnlockerItem(const DownloadItem& item)
{
    std::wstring name = ToLower(item.name);
    return name.find(L"simpleunlocker") != std::wstring::npos ||
        (name.find(L"simple") != std::wstring::npos && name.find(L"unlocker") != std::wstring::npos);
}


static bool IsProcessHackerItem(const DownloadItem& item)
{
    std::wstring name = ToLower(item.name);
    return name.find(L"processhacker") != std::wstring::npos ||
        (name.find(L"process") != std::wstring::npos && name.find(L"hacker") != std::wstring::npos);
}

static bool IsBamParserItem(const DownloadItem& item)
{
    std::wstring name = ToLower(item.name);
    std::wstring file = ToLower(item.file);
    return name.find(L"bamparser") != std::wstring::npos ||
        name.find(L"bam parser") != std::wstring::npos ||
        file.find(L"bamparser") != std::wstring::npos;
}

static bool IsDetectItEasyItem(const DownloadItem& item)
{
    std::wstring name = ToLower(item.name);
    std::wstring file = ToLower(item.file);

    return name.find(L"detect it easy") != std::wstring::npos ||
        file.find(L"die_win64") != std::wstring::npos ||
        file.find(L"detect-it-easy") != std::wstring::npos;
}

static bool IsWinRarItem(const DownloadItem& item)
{
    return ToLower(item.name).find(L"winrar") != std::wstring::npos;
}

static bool IsSystemInformerItem(const DownloadItem& item)
{
    std::wstring name = ToLower(item.name);
    return name.find(L"systeminformer") != std::wstring::npos ||
        (name.find(L"system") != std::wstring::npos && name.find(L"informer") != std::wstring::npos);
}


static bool IsGitHubUrl(const std::wstring& url)
{
    std::wstring lower = ToLower(url);
    return lower.find(L"github.com") != std::wstring::npos ||
        lower.find(L"githubusercontent.com") != std::wstring::npos ||
        lower.find(L"release-assets.githubusercontent.com") != std::wstring::npos ||
        lower.find(L"objects.githubusercontent.com") != std::wstring::npos;
}

static bool IsSourceForgeUrl(const std::wstring& url)
{
    std::wstring lower = ToLower(url);
    return lower.find(L"sourceforge.net") != std::wstring::npos ||
        lower.find(L"downloads.sourceforge.net") != std::wstring::npos ||
        lower.find(L"sourceforge.io") != std::wstring::npos;
}

static bool IsSourceForgeDownloadWaitUrl(const std::wstring& url)
{
    std::wstring lower = ToLower(url);

    if (lower.find(L"downloads.sourceforge.net") != std::wstring::npos)
        return true;

    if (lower.find(L"sourceforge.net") != std::wstring::npos &&
        (lower.find(L"/download") != std::wstring::npos || lower.find(L"/projects/") != std::wstring::npos))
    {
        return true;
    }

    if (lower.find(L"sourceforge.io") != std::wstring::npos &&
        (lower.find(L".exe") != std::wstring::npos || lower.find(L"/download") != std::wstring::npos))
    {
        return true;
    }

    return false;
}

static bool IsEricZimmermanLargeItem(const DownloadItem& item)
{
    UNREFERENCED_PARAMETER(item);
    return false;
}

static DWORD GetDirectDownloadTimeoutMs(const DownloadItem& item)
{
    if (IsSystemInformerItem(item))
        return 600000;

    if (IsWinRarItem(item))
        return 180000;

    return IsFastFailItem(item) ? 30000 : 300000;
}

static void GetHttpTimeouts(const std::wstring& displayName, const std::wstring& url, int& resolveMs, int& connectMs, int& sendMs, int& receiveMs)
{
    std::wstring lowerUrl = ToLower(url);

    if (IsEricZimmermanUrl(url))
    {
        resolveMs = 10000;
        connectMs = 15000;
        sendMs = 15000;
        receiveMs = 15000;
    }
    else if (IsFastFailDownload(displayName, url))
    {
        resolveMs = 3500;
        connectMs = 3500;
        sendMs = 5000;
        receiveMs = 8000;
    }
    else
    {
        resolveMs = 4500;
        connectMs = 4500;
        sendMs = 8000;
        receiveMs = 10000;
    }
}

static bool FileExists(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}


static bool GetFileSizeBytes(const std::wstring& path, unsigned long long& outSize)
{
    outSize = 0;

    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER size{};
    bool ok = GetFileSizeEx(file, &size) != FALSE && size.QuadPart >= 0;
    CloseHandle(file);

    if (!ok)
        return false;

    outSize = static_cast<unsigned long long>(size.QuadPart);
    return true;
}

static unsigned long long GetFileSizeBytesOrZero(const std::wstring& path)
{
    unsigned long long size = 0;
    GetFileSizeBytes(path, size);
    return size;
}

static bool ParseUnsignedLongLong(const std::wstring& value, unsigned long long& out)
{
    out = 0;
    if (value.empty())
        return false;

    size_t i = 0;
    while (i < value.size() && iswspace(value[i]))
        ++i;

    bool hasDigit = false;
    for (; i < value.size(); ++i)
    {
        wchar_t ch = value[i];
        if (iswspace(ch))
            break;

        if (ch < L'0' || ch > L'9')
            return false;

        hasDigit = true;
        unsigned long long digit = static_cast<unsigned long long>(ch - L'0');
        if (out > (ULLONG_MAX - digit) / 10)
            return false;

        out = out * 10 + digit;
    }

    return hasDigit;
}

static std::wstring DownloadErrorToString(DownloadError error)
{
    switch (error)
    {
    case DownloadError::None: return L"None";
    case DownloadError::Cancelled: return L"Cancelled";
    case DownloadError::InvalidUrl: return L"InvalidUrl";
    case DownloadError::OpenSessionFailed: return L"OpenSessionFailed";
    case DownloadError::ConnectFailed: return L"ConnectFailed";
    case DownloadError::OpenRequestFailed: return L"OpenRequestFailed";
    case DownloadError::SendFailed: return L"SendFailed";
    case DownloadError::ReceiveFailed: return L"ReceiveFailed";
    case DownloadError::HttpStatus: return L"HttpStatus";
    case DownloadError::HtmlInsteadOfFile: return L"HtmlInsteadOfFile";
    case DownloadError::HtmlLinkNotFound: return L"HtmlLinkNotFound";
    case DownloadError::ReadFailed: return L"ReadFailed";
    case DownloadError::FileOpenFailed: return L"FileOpenFailed";
    case DownloadError::FileWriteFailed: return L"FileWriteFailed";
    case DownloadError::MoveFailed: return L"MoveFailed";
    case DownloadError::SizeMismatch: return L"SizeMismatch";
    case DownloadError::TooManyRedirects: return L"TooManyRedirects";
    case DownloadError::Stalled: return L"Stalled";
    }
    return L"Unknown";
}

static void LogDownloadAttemptFailure(const std::wstring& displayName, int attempt, int totalAttempts, const DownloadResult& result)
{
    DebugLogLine(L"download", L"WinHTTP attempt failed item=" + displayName +
        L" attempt=" + std::to_wstring(attempt) + L"/" + std::to_wstring(totalAttempts) +
        L" error=" + DownloadErrorToString(result.error) +
        L" http=" + std::to_wstring(result.httpStatus) +
        L" win32=" + FormatWin32ErrorForLog(result.win32Error) +
        L" retryable=" + std::to_wstring(result.retryable ? 1 : 0) +
        L" contentLength=" + std::to_wstring(result.contentLength) +
        L" bytesWritten=" + std::to_wstring(result.bytesWritten) +
        L" resumeFrom=" + std::to_wstring(result.resumeFrom) +
        L" finalUrl=" + result.finalUrl);
}

static DWORD GetRetryDelayMs(int attempt)
{
    UNREFERENCED_PARAMETER(attempt);
    return 0;
}

static bool SleepRetryDelay(DWORD delayMs)
{
    DWORD slept = 0;
    while (slept < delayMs)
    {
        if (IsCancelRequested())
            return false;

        DWORD chunk = std::min<DWORD>(150, delayMs - slept);
        Sleep(chunk);
        slept += chunk;
    }

    return true;
}

static bool DirectoryExists(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

static bool EnsureDirectory(const std::wstring& path)
{
    if (DirectoryExists(path))
        return true;

    int r = SHCreateDirectoryExW(nullptr, path.c_str(), nullptr);
    return r == ERROR_SUCCESS || r == ERROR_ALREADY_EXISTS || DirectoryExists(path);
}

static std::wstring CombinePath(const std::wstring& a, const std::wstring& b)
{
    if (a.empty())
        return b;

    if (b.empty())
        return a;

    if (b.size() >= 2 && b[1] == L':')
        return b;

    if (b[0] == L'\\' || b[0] == L'/')
        return b;

    std::wstring out = a;

    if (!out.empty() && out.back() != L'\\' && out.back() != L'/')
        out.push_back(L'\\');

    out += b;
    return out;
}

static std::wstring RemoveExtension(std::wstring s)
{
    size_t p = s.find_last_of(L'.');
    if (p != std::wstring::npos)
        s = s.substr(0, p);
    return s;
}

static std::wstring GetTabFolderName(int tab)
{
    switch (tab)
    {
    case 0: return L"Мл.сотрудник";
    case 1: return L"Сотрудник";
    case 2: return L"Вед.сотрудник";
    case 3: return L"Доп.программы";
    default: return L"Прочее";
    }
}

static std::wstring BuildHolyCheckFolderPath(bool ensureDirectory)
{
    PWSTR downloads = nullptr;
    std::wstring result;

    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &downloads)) && downloads)
    {
        result = CombinePath(downloads, L"holycheck");
        CoTaskMemFree(downloads);
    }
    else
    {
        wchar_t profile[MAX_PATH]{};
        GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH);
        result = CombinePath(CombinePath(profile, L"Downloads"), L"holycheck");
    }

    if (ensureDirectory)
        EnsureDirectory(result);

    return result;
}

static std::wstring GetHolyCheckFolder()
{
    return BuildHolyCheckFolderPath(true);
}

static std::wstring GetHolyCheckFolderPathOnly()
{
    return BuildHolyCheckFolderPath(false);
}
static std::wstring GetFullPathSafe(const std::wstring& path)
{
    if (path.empty())
        return L"";

    DWORD required = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);

    if (required == 0)
        return path;

    std::wstring out(required, L'\0');
    DWORD written = GetFullPathNameW(path.c_str(), required, &out[0], nullptr);

    if (written == 0 || written >= required)
        return path;

    out.resize(written);

    while (!out.empty() && (out.back() == L'\\' || out.back() == L'/'))
        out.pop_back();

    return out;
}

static bool IsSafeHolyCheckDeletionTarget(const std::wstring& folder)
{
    std::wstring full = ToLower(GetFullPathSafe(folder));
    std::wstring expected = ToLower(GetFullPathSafe(GetHolyCheckFolderPathOnly()));

    if (full.empty() || expected.empty())
        return false;

    if (full != expected)
        return false;

    if (full.size() < 12)
        return false;

    return EndsWithI(full, L"\\holycheck") || EndsWithI(full, L"/holycheck");
}

struct MinecraftFolderCandidate
{
    std::wstring path;
    bool exists = false;
    bool isRoot = false;
};

static void AddUniquePath(std::vector<std::wstring>& paths, const std::wstring& path)
{
    if (path.empty())
        return;

    std::wstring normalized = GetFullPathSafe(path);

    if (normalized.empty())
        normalized = path;

    std::wstring lower = ToLower(normalized);

    for (const std::wstring& existing : paths)
    {
        if (ToLower(GetFullPathSafe(existing)) == lower)
            return;
    }

    paths.push_back(normalized);
}

static std::wstring GetLastPathPart(std::wstring path)
{
    while (!path.empty() && (path.back() == L'\\' || path.back() == L'/'))
        path.pop_back();

    size_t pos = path.find_last_of(L"\\/");

    if (pos == std::wstring::npos)
        return path;

    return path.substr(pos + 1);
}

static bool IsExcludedMinecraftFolderName(const std::wstring& name)
{
    std::wstring lower = ToLower(name);

    return lower == L"labymod" || lower == L"labymod-neo";
}

static bool IsExcludedMinecraftFolderPath(const std::wstring& path)
{
    return IsExcludedMinecraftFolderName(GetLastPathPart(path));
}

static std::wstring GetCurrentUserProfilePath()
{
    wchar_t profile[MAX_PATH * 4]{};
    DWORD profileLen = GetEnvironmentVariableW(L"USERPROFILE", profile, ARRAYSIZE(profile));

    if (profileLen == 0 || profileLen >= ARRAYSIZE(profile))
        return L"";

    return GetFullPathSafe(profile);
}

static bool IsPathUnderFolder(const std::wstring& path, const std::wstring& root)
{
    std::wstring fullPath = ToLower(GetFullPathSafe(path));
    std::wstring fullRoot = ToLower(GetFullPathSafe(root));

    if (fullPath.empty() || fullRoot.empty())
        return false;

    while (!fullRoot.empty() && (fullRoot.back() == L'\\' || fullRoot.back() == L'/'))
        fullRoot.pop_back();

    if (fullPath == fullRoot)
        return true;

    std::wstring rootWithSlash = fullRoot + L"\\";
    return fullPath.rfind(rootWithSlash, 0) == 0;
}

static bool IsPathUnderCurrentUserProfile(const std::wstring& path)
{
    std::wstring profile = GetCurrentUserProfilePath();

    if (profile.empty())
        return false;

    return IsPathUnderFolder(path, profile);
}

static bool HasJarFileRecursiveLimited(const std::wstring& folder, int depth)
{
    if (depth < 0 || !DirectoryExists(folder))
        return false;

    WIN32_FIND_DATAW data{};
    std::wstring mask = CombinePath(folder, L"*");
    HANDLE h = FindFirstFileW(mask.c_str(), &data);

    if (h == INVALID_HANDLE_VALUE)
        return false;

    bool found = false;

    do
    {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
            continue;

        std::wstring child = CombinePath(folder, data.cFileName);

        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                continue;

            if (IsExcludedMinecraftFolderName(data.cFileName))
                continue;

            if (HasJarFileRecursiveLimited(child, depth - 1))
            {
                found = true;
                break;
            }
        }
        else
        {
            std::wstring name = ToLower(data.cFileName);

            if (name.size() >= 4 && name.substr(name.size() - 4) == L".jar")
            {
                found = true;
                break;
            }
        }
    }
    while (FindNextFileW(h, &data));

    FindClose(h);
    return found;
}

static bool IsStrictMinecraftRootFolder(const std::wstring& path)
{
    if (!DirectoryExists(path))
        return false;

    if (IsExcludedMinecraftFolderPath(path))
        return false;

    if (!IsPathUnderCurrentUserProfile(path))
        return false;

    std::wstring assets = CombinePath(path, L"assets");
    std::wstring versions = CombinePath(path, L"versions");
    std::wstring logs = CombinePath(path, L"logs");

    if (!DirectoryExists(assets))
        return false;

    if (!DirectoryExists(versions))
        return false;

    if (!DirectoryExists(logs))
        return false;

    if (!HasJarFileRecursiveLimited(versions, 3))
        return false;

    return true;
}

static bool HasAnyStrictMinecraftMarker(const std::wstring& path)
{
    if (!DirectoryExists(path) || IsExcludedMinecraftFolderPath(path) || !IsPathUnderCurrentUserProfile(path))
        return false;

    return DirectoryExists(CombinePath(path, L"assets")) ||
        DirectoryExists(CombinePath(path, L"versions")) ||
        DirectoryExists(CombinePath(path, L"logs"));
}

static bool IsMinecraftSearchContainerName(const std::wstring& name)
{
    std::wstring lower = ToLower(name);

    if (IsExcludedMinecraftFolderName(lower))
        return false;

    return lower == L".minecraft" ||
        lower == L"minecraft" ||
        lower == L"game" ||
        lower == L"games" ||
        lower == L"instances" ||
        lower == L"launchers" ||
        lower == L"appdata" ||
        lower == L"roaming" ||
        lower == L"local" ||
        lower == L"documents" ||
        lower == L"downloads" ||
        lower.find(L"minecraft") != std::wstring::npos ||
        lower.find(L"launcher") != std::wstring::npos ||
        lower.find(L"tlauncher") != std::wstring::npos ||
        lower.find(L"lunar") != std::wstring::npos ||
        lower.find(L"badlion") != std::wstring::npos ||
        lower.find(L"feather") != std::wstring::npos ||
        lower.find(L"curseforge") != std::wstring::npos ||
        lower.find(L"modrinth") != std::wstring::npos ||
        lower.find(L"technic") != std::wstring::npos ||
        lower.find(L"atlauncher") != std::wstring::npos ||
        lower.find(L"polymc") != std::wstring::npos ||
        lower.find(L"prism") != std::wstring::npos ||
        lower.find(L"gdlauncher") != std::wstring::npos ||
        lower.find(L"multimc") != std::wstring::npos ||
        lower.find(L"pulsevisuals") != std::wstring::npos;
}

static void ScanMinecraftFoldersRecursive(const std::wstring& root, int depth, int& visited, std::vector<std::wstring>& paths)
{
    if (depth < 0 || visited > 6000 || !DirectoryExists(root) || IsExcludedMinecraftFolderPath(root) || !IsPathUnderCurrentUserProfile(root))
        return;

    ++visited;

    if (IsStrictMinecraftRootFolder(root))
        AddUniquePath(paths, root);

    if (depth == 0)
        return;

    WIN32_FIND_DATAW data{};
    std::wstring mask = CombinePath(root, L"*");
    HANDLE h = FindFirstFileW(mask.c_str(), &data);

    if (h == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;

        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;

        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
            continue;

        if (IsExcludedMinecraftFolderName(data.cFileName))
            continue;

        std::wstring child = CombinePath(root, data.cFileName);

        if (IsMinecraftSearchContainerName(data.cFileName) || HasAnyStrictMinecraftMarker(child))
            ScanMinecraftFoldersRecursive(child, depth - 1, visited, paths);
    }
    while (FindNextFileW(h, &data));

    FindClose(h);
}

static std::vector<std::wstring> BuildMinecraftCandidatePaths()
{
    std::vector<std::wstring> paths;
    std::wstring profile = GetCurrentUserProfilePath();

    if (profile.empty())
        return paths;

    wchar_t appData[MAX_PATH * 4]{};
    DWORD appLen = GetEnvironmentVariableW(L"APPDATA", appData, ARRAYSIZE(appData));

    if (appLen > 0 && appLen < ARRAYSIZE(appData) && IsPathUnderFolder(appData, profile))
        AddUniquePath(paths, CombinePath(appData, L".minecraft"));

    wchar_t localAppData[MAX_PATH * 4]{};
    DWORD localLen = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, ARRAYSIZE(localAppData));

    AddUniquePath(paths, CombinePath(CombinePath(profile, L"AppData\\Roaming"), L".minecraft"));
    AddUniquePath(paths, CombinePath(CombinePath(profile, L"curseforge"), L"minecraft\\Instances"));
    AddUniquePath(paths, CombinePath(CombinePath(profile, L"Documents"), L"Curse\\Minecraft\\Instances"));
    AddUniquePath(paths, CombinePath(profile, L"Games\\Minecraft"));
    AddUniquePath(paths, CombinePath(profile, L"Minecraft"));
    AddUniquePath(paths, CombinePath(profile, L"game"));

    int visited = 0;

    ScanMinecraftFoldersRecursive(profile, 7, visited, paths);

    if (localLen > 0 && localLen < ARRAYSIZE(localAppData) && IsPathUnderFolder(localAppData, profile))
        ScanMinecraftFoldersRecursive(localAppData, 6, visited, paths);

    return paths;
}

static std::vector<MinecraftFolderCandidate> GetMinecraftFolderCandidates()
{
    std::vector<MinecraftFolderCandidate> result;
    std::vector<std::wstring> paths = BuildMinecraftCandidatePaths();

    for (const std::wstring& path : paths)
    {
        if (IsExcludedMinecraftFolderPath(path) || !IsPathUnderCurrentUserProfile(path))
            continue;

        MinecraftFolderCandidate item;
        item.path = path;
        item.exists = DirectoryExists(path);
        item.isRoot = IsStrictMinecraftRootFolder(path);
        result.push_back(item);
    }

    std::stable_sort(result.begin(), result.end(), [](const MinecraftFolderCandidate& a, const MinecraftFolderCandidate& b)
    {
        if (a.isRoot != b.isRoot)
            return a.isRoot;

        if (a.exists != b.exists)
            return a.exists;

        return ToLower(a.path) < ToLower(b.path);
    });

    return result;
}

static std::wstring GetMinecraftFolder()
{
    std::vector<MinecraftFolderCandidate> candidates = GetMinecraftFolderCandidates();

    for (const MinecraftFolderCandidate& candidate : candidates)
    {
        if (candidate.exists && candidate.isRoot)
            return candidate.path;
    }

    std::wstring profile = GetCurrentUserProfilePath();

    if (!profile.empty() && DirectoryExists(profile))
        return profile;

    return candidates.empty() ? std::wstring() : candidates.front().path;
}

static std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty())
        return L"";

    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(n, L'\0');

    if (n > 0)
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &out[0], n);

    return out;
}

static std::string WideToUtf8(const std::wstring& s)
{
    if (s.empty())
        return "";

    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');

    if (n > 0)
        WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &out[0], n, nullptr, nullptr);

    return out;
}

static std::wstring UrlEncodeUtf8(const std::wstring& s)
{
    static const wchar_t* hex = L"0123456789ABCDEF";
    std::string utf8 = WideToUtf8(s);
    std::wstring out;

    for (unsigned char c : utf8)
    {
        if ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~')
        {
            out.push_back(static_cast<wchar_t>(c));
        }
        else if (c == ' ')
        {
            out += L"%20";
        }
        else
        {
            out.push_back(L'%');
            out.push_back(hex[(c >> 4) & 0x0F]);
            out.push_back(hex[c & 0x0F]);
        }
    }

    return out;
}

static bool ParseUrl(const std::wstring& url, ParsedUrl& out)
{
    WinHttpUrlComponents uc{};
    uc.dwStructSize = sizeof(uc);

    wchar_t host[512]{};
    wchar_t path[4096]{};
    wchar_t extra[4096]{};

    uc.lpszHostName = host;
    uc.dwHostNameLength = ARRAYSIZE(host);
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = ARRAYSIZE(path);
    uc.lpszExtraInfo = extra;
    uc.dwExtraInfoLength = ARRAYSIZE(extra);

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc))
        return false;

    out.host.assign(host, uc.dwHostNameLength);
    out.port = uc.nPort;
    out.https = uc.nScheme == INTERNET_SCHEME_HTTPS;
    out.pathAndQuery.assign(path, uc.dwUrlPathLength);
    out.pathAndQuery.append(extra, uc.dwExtraInfoLength);

    if (out.pathAndQuery.empty())
        out.pathAndQuery = L"/";

    return !out.host.empty();
}

static std::wstring MakeAbsoluteUrl(const std::wstring& base, const std::wstring& href)
{
    if (href.rfind(L"http://", 0) == 0 || href.rfind(L"https://", 0) == 0)
        return href;

    ParsedUrl p;
    if (!ParseUrl(base, p))
        return href;

    std::wstring origin = (p.https ? L"https://" : L"http://") + p.host;

    if (href.rfind(L"//", 0) == 0)
        return p.https ? L"https:" + href : L"http:" + href;

    if (!href.empty() && href[0] == L'/')
        return origin + href;

    std::wstring dir = p.pathAndQuery;
    size_t q = dir.find(L'?');
    if (q != std::wstring::npos)
        dir = dir.substr(0, q);

    size_t slash = dir.find_last_of(L'/');
    dir = slash != std::wstring::npos ? dir.substr(0, slash + 1) : L"/";

    return origin + dir + href;
}
