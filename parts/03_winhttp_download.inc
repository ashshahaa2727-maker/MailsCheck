static void ReplaceAllAscii(std::string& s, const std::string& from, const std::string& to)
{
    if (from.empty())
        return;

    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos)
    {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
}

static std::wstring CleanHtmlUrl(std::string raw)
{
    ReplaceAllAscii(raw, "&amp;", "&");
    ReplaceAllAscii(raw, "&quot;", "\"");
    ReplaceAllAscii(raw, "&#34;", "\"");
    ReplaceAllAscii(raw, "&#x22;", "\"");
    ReplaceAllAscii(raw, "&#39;", "'");
    ReplaceAllAscii(raw, "&#x27;", "'");
    ReplaceAllAscii(raw, "&#x2F;", "/");
    ReplaceAllAscii(raw, "\\/", "/");
    ReplaceAllAscii(raw, "\\u002F", "/");
    ReplaceAllAscii(raw, "\\u002f", "/");
    ReplaceAllAscii(raw, "\\u003A", ":");
    ReplaceAllAscii(raw, "\\u003a", ":");
    ReplaceAllAscii(raw, "\\u0026", "&");
    ReplaceAllAscii(raw, "\\u003D", "=");
    ReplaceAllAscii(raw, "\\u003d", "=");
    ReplaceAllAscii(raw, "\\u003F", "?");
    ReplaceAllAscii(raw, "\\u003f", "?");

    while (!raw.empty() && (raw.back() == ',' || raw.back() == ';' || raw.back() == ')' || raw.back() == ']'))
        raw.pop_back();

    return Utf8ToWide(raw);
}

static std::wstring FindBinaryLink(const std::wstring& baseUrl, const std::vector<unsigned char>& bytes)
{
    std::string html(bytes.begin(), bytes.end());

    std::regex hrefRe(
        R"((?:href|src|data-url|data-download-url)\s*=\s*["']([^"']+\.(?:zip|exe|jar|7z|rar|msi)(?:/download)?(?:\?[^"']*)?)["'])",
        std::regex_constants::icase
    );

    std::smatch m;
    auto b = html.cbegin();
    auto e = html.cend();

    while (std::regex_search(b, e, m, hrefRe))
        return MakeAbsoluteUrl(baseUrl, CleanHtmlUrl(m[1].str()));

    std::regex plainRe(
        R"((https?://[^\s"'<>]+?\.(?:zip|exe|jar|7z|rar|msi)(?:/download)?(?:\?[^\s"'<>]+)?))",
        std::regex_constants::icase
    );

    if (std::regex_search(html.cbegin(), html.cend(), m, plainRe))
        return MakeAbsoluteUrl(baseUrl, CleanHtmlUrl(m[1].str()));

    std::regex refreshRe(
        R"((?:url|URL)\s*=\s*([^"'>\s]+?\.(?:zip|exe|jar|7z|rar|msi)(?:/download)?(?:\?[^"'>\s]+)?))",
        std::regex_constants::icase
    );

    if (std::regex_search(html.cbegin(), html.cend(), m, refreshRe))
        return MakeAbsoluteUrl(baseUrl, CleanHtmlUrl(m[1].str()));

    std::regex softPortalRe(
        R"((?:href|src)\s*=\s*["']([^"']*(?:getsoft-\d+[^"']*\.html|get-\d+[^"']*\.html|software-\d+[^"']*\.html|/en/[^"']+/download|/en/[^"']+/getsoft)[^"']*)["'])",
        std::regex_constants::icase
    );

    if (std::regex_search(html.cbegin(), html.cend(), m, softPortalRe))
        return MakeAbsoluteUrl(baseUrl, CleanHtmlUrl(m[1].str()));

    std::regex jsLocationRe(
        R"((?:location\.href|window\.location|document\.location)\s*=\s*["']([^"']+)["'])",
        std::regex_constants::icase
    );

    if (std::regex_search(html.cbegin(), html.cend(), m, jsLocationRe))
        return MakeAbsoluteUrl(baseUrl, CleanHtmlUrl(m[1].str()));

    return L"";
}

static DWORD QueryStatus(HINTERNET request)
{
    DWORD status = 0;
    DWORD size = sizeof(status);

    WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status,
        &size,
        WINHTTP_NO_HEADER_INDEX
    );

    return status;
}

static std::wstring QueryHeader(HINTERNET request, DWORD query)
{
    DWORD size = 0;

    WinHttpQueryHeaders(
        request,
        query,
        WINHTTP_HEADER_NAME_BY_INDEX,
        nullptr,
        &size,
        WINHTTP_NO_HEADER_INDEX
    );

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0)
        return L"";

    std::wstring value(size / sizeof(wchar_t), L'\0');

    if (!WinHttpQueryHeaders(
        request,
        query,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &value[0],
        &size,
        WINHTTP_NO_HEADER_INDEX))
    {
        return L"";
    }

    while (!value.empty() && value.back() == L'\0')
        value.pop_back();

    return value;
}

static unsigned long long QueryContentLength(HINTERNET request)
{
    std::wstring header = QueryHeader(request, WINHTTP_QUERY_CONTENT_LENGTH);
    unsigned long long value = 0;
    return ParseUnsignedLongLong(header, value) ? value : 0;
}

static bool ReadAll(HINTERNET request, std::vector<unsigned char>& out, size_t maxBytes = HTML_READ_LIMIT)
{
    out.clear();

    for (;;)
    {
        if (IsCancelRequested())
            return false;

        DWORD available = 0;

        if (!WinHttpQueryDataAvailable(request, &available))
            return false;

        if (available == 0)
            break;

        if (out.size() + static_cast<size_t>(available) > maxBytes)
            return false;

        size_t oldSize = out.size();
        out.resize(oldSize + available);

        DWORD read = 0;

        if (IsCancelRequested())
            return false;

        if (!WinHttpReadData(request, out.data() + oldSize, available, &read))
            return false;

        out.resize(oldSize + read);

        if (read == 0)
            break;
    }

    return true;
}

static bool LooksLikeHtml(const std::wstring& contentType)
{
    std::wstring ct = ToLower(contentType);
    return ct.find(L"text/html") != std::wstring::npos ||
        ct.find(L"application/xhtml") != std::wstring::npos;
}

static bool PreallocateDownloadFile(HANDLE file, unsigned long long finalSize, unsigned long long writeOffset)
{
    if (file == INVALID_HANDLE_VALUE || finalSize == 0 || finalSize > static_cast<unsigned long long>(LLONG_MAX))
        return false;

    LARGE_INTEGER endPos{};
    endPos.QuadPart = static_cast<LONGLONG>(finalSize);

    if (!SetFilePointerEx(file, endPos, nullptr, FILE_BEGIN))
        return false;

    if (!SetEndOfFile(file))
        return false;

    LARGE_INTEGER writePos{};
    writePos.QuadPart = static_cast<LONGLONG>(writeOffset);
    return SetFilePointerEx(file, writePos, nullptr, FILE_BEGIN) != FALSE;
}

static bool IsRetryableHttpStatus(DWORD status)
{
    return status == 408 || status == 416 || status == 429 || status >= 500;
}


static bool IsAggressiveWinHttpSwitchName(const std::wstring& displayName)
{
    std::wstring lower = ToLower(displayName);

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

static DownloadResult DownloadRecursiveOnce(
    const std::wstring& url,
    const std::wstring& targetPath,
    const std::wstring& displayName,
    int depth)
{
    ClearTransferStalledFlag();
    DebugLogLine(L"download", L"WinHTTP once start item=" + displayName + L" depth=" + std::to_wstring(depth) +
        L" target=" + targetPath + L" url=" + url);

    if (IsCancelRequested())
        return MakeDownloadError(DownloadError::Cancelled, 0, false);

    if (depth > 4)
        return MakeDownloadError(DownloadError::TooManyRedirects, 0, false);

    ParsedUrl p;

    if (!ParseUrl(url, p))
        return MakeDownloadError(DownloadError::InvalidUrl, GetLastError(), false);

    HINTERNET session = nullptr;
    HINTERNET connect = nullptr;
    HINTERNET request = nullptr;
    std::shared_ptr<HttpHandleSlot> sessionSlot;
    std::shared_ptr<HttpHandleSlot> connectSlot;
    std::shared_ptr<HttpHandleSlot> requestSlot;

    auto finish = [&](DownloadResult result) -> DownloadResult
    {
        DebugLogLine(L"download", L"WinHTTP once finish item=" + displayName +
            L" ok=" + std::to_wstring(result.ok ? 1 : 0) +
            L" error=" + DownloadErrorToString(result.error) +
            L" http=" + std::to_wstring(result.httpStatus) +
            L" win32=" + FormatWin32ErrorForLog(result.win32Error) +
            L" bytes=" + std::to_wstring(result.bytesWritten) +
            L" contentLength=" + std::to_wstring(result.contentLength) +
            L" finalUrl=" + result.finalUrl);
        CloseTrackedHttpHandle(requestSlot);
        CloseTrackedHttpHandle(connectSlot);
        CloseTrackedHttpHandle(sessionSlot);
        return result;
    };

    session = WinHttpOpen(
        L"Mozilla/5.0 HolyCheckDownloader/9.3",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!session)
        return MakeDownloadError(DownloadError::OpenSessionFailed, GetLastError(), true);

    sessionSlot = TrackHttpHandle(session);

    DWORD secureProtocols =
        WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 |
        WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &secureProtocols, sizeof(secureProtocols));

    int resolveMs = 4000;
    int connectMs = 4000;
    int sendMs = 7000;
    int receiveMs = 20000;
    GetHttpTimeouts(displayName, url, resolveMs, connectMs, sendMs, receiveMs);
    WinHttpSetTimeouts(session, resolveMs, connectMs, sendMs, receiveMs);

    DWORD redirects = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(session, WINHTTP_OPTION_REDIRECT_POLICY, &redirects, sizeof(redirects));

    connect = WinHttpConnect(session, p.host.c_str(), p.port, 0);

    if (!connect)
        return finish(MakeDownloadError(DownloadError::ConnectFailed, GetLastError(), true));

    connectSlot = TrackHttpHandle(connect);

    request = WinHttpOpenRequest(
        connect,
        L"GET",
        p.pathAndQuery.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        p.https ? WINHTTP_FLAG_SECURE : 0
    );

    if (!request)
        return finish(MakeDownloadError(DownloadError::OpenRequestFailed, GetLastError(), true));

    requestSlot = TrackHttpHandle(request);

    std::wstring requestHeaders =
        L"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36\r\n"
        L"Accept: application/octet-stream,application/zip,application/x-zip-compressed,application/x-msdownload,application/java-archive,*/*;q=0.8\r\n"
        L"Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.7,en;q=0.6\r\n"
        L"Accept-Encoding: identity\r\n"
        L"Cache-Control: no-cache\r\n"
        L"Pragma: no-cache\r\n";


    std::wstring partPath = targetPath + L".part";
    unsigned long long resumeFrom = GetFileSizeBytesOrZero(partPath);

    if (resumeFrom > 0)
        requestHeaders += L"Range: bytes=" + std::to_wstring(resumeFrom) + L"-\r\n";

    WinHttpAddRequestHeaders(
        request,
        requestHeaders.c_str(),
        static_cast<DWORD>(-1),
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE
    );

    if (IsCancelRequested())
        return finish(MakeDownloadError(DownloadError::Cancelled, 0, false));

    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        return finish(MakeDownloadError(DownloadError::SendFailed, GetLastError(), true));

    if (IsCancelRequested())
        return finish(MakeDownloadError(DownloadError::Cancelled, 0, false));

    if (!WinHttpReceiveResponse(request, nullptr))
    {
        DWORD err = GetLastError();
        if (err == ERROR_WINHTTP_TIMEOUT)
        {
            MarkTransferStalled();
            return finish(MakeDownloadError(DownloadError::Stalled, err, true));
        }

        return finish(MakeDownloadError(DownloadError::ReceiveFailed, err, true));
    }

    if (IsCancelRequested())
        return finish(MakeDownloadError(DownloadError::Cancelled, 0, false));

    DWORD status = QueryStatus(request);

    if (resumeFrom > 0 && status == 416)
    {
        DeleteFileW(partPath.c_str());
        DownloadResult result = MakeDownloadError(DownloadError::HttpStatus, 0, true);
        result.httpStatus = status;
        result.resumeFrom = resumeFrom;
        return finish(result);
    }

    if (status < 200 || status >= 300)
    {
        DownloadResult result = MakeDownloadError(DownloadError::HttpStatus, 0, IsRetryableHttpStatus(status));
        result.httpStatus = status;
        result.resumeFrom = resumeFrom;
        return finish(result);
    }

    bool appendToPart = resumeFrom > 0 && status == 206;

    if (resumeFrom > 0 && status == 200)
    {
        DeleteFileW(partPath.c_str());
        resumeFrom = 0;
        appendToPart = false;
    }

    std::wstring contentType = QueryHeader(request, WINHTTP_QUERY_CONTENT_TYPE);

    if (LooksLikeHtml(contentType))
    {
        std::vector<unsigned char> html;

        if (!ReadAll(request, html, HTML_READ_LIMIT))
        {
            DownloadResult result = MakeDownloadError(DownloadError::ReadFailed, GetLastError(), true);
            result.httpStatus = status;
            result.resumeFrom = resumeFrom;
            return finish(result);
        }

        std::wstring direct = FindBinaryLink(url, html);

        if (direct.empty())
        {
            if (IsSourceForgeDownloadWaitUrl(url) && depth < 4)
            {
                CloseTrackedHttpHandle(requestSlot);
                CloseTrackedHttpHandle(connectSlot);
                CloseTrackedHttpHandle(sessionSlot);

                PostLog(L"SourceForge: повторяем без ожидания: " + displayName);

                DownloadResult retry = DownloadRecursiveOnce(url, targetPath, displayName, depth + 1);
                if (retry.finalUrl.empty())
                    retry.finalUrl = url;
                return retry;
            }

            DownloadResult result = MakeDownloadError(DownloadError::HtmlLinkNotFound, 0, false);
            result.httpStatus = status;
            result.resumeFrom = resumeFrom;
            return finish(result);
        }

        CloseTrackedHttpHandle(requestSlot);
        CloseTrackedHttpHandle(connectSlot);
        CloseTrackedHttpHandle(sessionSlot);

        DownloadResult redirected = DownloadRecursiveOnce(direct, targetPath, displayName, depth + 1);
        if (redirected.finalUrl.empty())
            redirected.finalUrl = direct;
        return redirected;
    }

    unsigned long long expectedBytesThisResponse = QueryContentLength(request);

    HANDLE file = CreateFileW(
        partPath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        appendToPart ? OPEN_ALWAYS : CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );

    if (file == INVALID_HANDLE_VALUE)
    {
        DownloadResult result = MakeDownloadError(DownloadError::FileOpenFailed, GetLastError(), true);
        result.httpStatus = status;
        result.resumeFrom = resumeFrom;
        return finish(result);
    }

    if (appendToPart)
    {
        LARGE_INTEGER pos{};
        pos.QuadPart = static_cast<LONGLONG>(resumeFrom);
        if (!SetFilePointerEx(file, pos, nullptr, FILE_BEGIN))
        {
            DWORD err = GetLastError();
            CloseHandle(file);
            DownloadResult result = MakeDownloadError(DownloadError::FileOpenFailed, err, true);
            result.httpStatus = status;
            result.resumeFrom = resumeFrom;
            return finish(result);
        }
    }


    const DWORD BUFFER_SIZE = 2 * 1024 * 1024;
    std::vector<unsigned char> buffer(BUFFER_SIZE);
    unsigned long long bytesWrittenThisResponse = 0;

    const ULONGLONG transferStarted = GetTickCount64();
    ULONGLONG lowSpeedWindowStarted = transferStarted;
    unsigned long long lowSpeedWindowBytes = 0;
    ULONGLONG speedWindowStarted = transferStarted;
    unsigned long long speedWindowBytes = 0;
    ULONGLONG lastUiUpdate = transferStarted;

    const bool aggressiveSwitch = IsAggressiveWinHttpSwitchName(displayName) ||
        IsEricZimmermanUrl(url) ||
        IsFastFailDownload(displayName, url);

    // Не обрываем WinHTTP по "низкой скорости". Реального лимита скорости в коде нет;
    // этот блок раньше только считал загрузку зависшей при медленном соединении.
    const DWORD lowSpeedWindowMs = 0;
    const unsigned long long minBytesPerSecond = 0ull;

    auto makeStalled = [&](DWORD err) -> DownloadResult
    {
        MarkTransferStalled();
        CloseHandle(file);
        DownloadResult result = MakeDownloadError(DownloadError::Stalled, err, true);
        result.httpStatus = status;
        result.resumeFrom = resumeFrom;
        result.bytesWritten = bytesWrittenThisResponse;
        result.contentLength = expectedBytesThisResponse;
        return result;
    };

    for (;;)
    {
        if (IsCancelRequested())
        {
            CloseHandle(file);
            DownloadResult result = MakeDownloadError(DownloadError::Cancelled, 0, false);
            result.httpStatus = status;
            result.resumeFrom = resumeFrom;
            result.bytesWritten = bytesWrittenThisResponse;
            return finish(result);
        }

        DWORD read = 0;

        if (!WinHttpReadData(request, buffer.data(), BUFFER_SIZE, &read))
        {
            DWORD err = GetLastError();

            if (err == ERROR_WINHTTP_TIMEOUT)
                return finish(makeStalled(err));

            CloseHandle(file);
            DownloadResult result = MakeDownloadError(DownloadError::ReadFailed, err, true);
            result.httpStatus = status;
            result.resumeFrom = resumeFrom;
            result.bytesWritten = bytesWrittenThisResponse;
            return finish(result);
        }

        if (read == 0)
            break;

        DWORD written = 0;

        if (!WriteFile(file, buffer.data(), read, &written, nullptr) || written != read)
        {
            DWORD err = GetLastError();
            CloseHandle(file);
            DownloadResult result = MakeDownloadError(DownloadError::FileWriteFailed, err, true);
            result.httpStatus = status;
            result.resumeFrom = resumeFrom;
            result.bytesWritten = bytesWrittenThisResponse;
            return finish(result);
        }

        bytesWrittenThisResponse += written;

        ULONGLONG now = GetTickCount64();

        if (now - speedWindowStarted >= 1000)
        {
            unsigned long long delta = bytesWrittenThisResponse >= speedWindowBytes ?
                bytesWrittenThisResponse - speedWindowBytes : 0;
            g_lastDownloadSpeedBps = (delta * 1000ull) / std::max<ULONGLONG>(1, now - speedWindowStarted);
            speedWindowStarted = now;
            speedWindowBytes = bytesWrittenThisResponse;
        }

        if (!displayName.empty() && now - lastUiUpdate >= 500)
        {
            UpdateActiveDownloadStatus(displayName, L"WinHTTP", 0, 0, resumeFrom + bytesWrittenThisResponse, g_lastDownloadSpeedBps,
                expectedBytesThisResponse ? resumeFrom + expectedBytesThisResponse : 0);
            lastUiUpdate = now;
        }

        ULONGLONG windowMs = now - lowSpeedWindowStarted;

        if (lowSpeedWindowMs > 0 && minBytesPerSecond > 0 && windowMs >= lowSpeedWindowMs)
        {
            unsigned long long delta = bytesWrittenThisResponse - lowSpeedWindowBytes;
            unsigned long long bytesPerSecond = (delta * 1000ull) / std::max<ULONGLONG>(1, windowMs);

            if (bytesPerSecond < minBytesPerSecond)
                return finish(makeStalled(0));

            lowSpeedWindowStarted = now;
            lowSpeedWindowBytes = bytesWrittenThisResponse;
        }
    }

    CloseHandle(file);

    if (expectedBytesThisResponse > 0 && bytesWrittenThisResponse < expectedBytesThisResponse)
    {
        DownloadResult result = MakeDownloadError(DownloadError::SizeMismatch, 0, true);
        result.httpStatus = status;
        result.contentLength = expectedBytesThisResponse;
        result.bytesWritten = bytesWrittenThisResponse;
        result.resumeFrom = resumeFrom;
        return finish(result);
    }

    if (IsCancelRequested())
    {
        DownloadResult result = MakeDownloadError(DownloadError::Cancelled, 0, false);
        result.httpStatus = status;
        result.resumeFrom = resumeFrom;
        result.bytesWritten = bytesWrittenThisResponse;
        return finish(result);
    }

    DeleteFileW(targetPath.c_str());

    if (!MoveFileW(partPath.c_str(), targetPath.c_str()))
    {
        DownloadResult result = MakeDownloadError(DownloadError::MoveFailed, GetLastError(), true);
        result.httpStatus = status;
        result.resumeFrom = resumeFrom;
        result.bytesWritten = bytesWrittenThisResponse;
        return finish(result);
    }

    DownloadResult ok = MakeDownloadOk();
    ok.httpStatus = status;
    ok.contentLength = expectedBytesThisResponse;
    ok.bytesWritten = bytesWrittenThisResponse;
    ok.resumeFrom = resumeFrom;
    ok.resumed = appendToPart;
    ok.finalUrl = url;
    return finish(ok);
}

static bool DownloadRecursive(
    const std::wstring& url,
    const std::wstring& targetPath,
    const std::wstring& displayName,
    int depth)
{
    const bool fastSwitchName = IsAggressiveWinHttpSwitchName(displayName);
    const int maxAttempts = fastSwitchName ? 1 : (depth == 0 ? 4 : 3);
    DownloadResult lastResult;

    for (int attempt = 1; attempt <= maxAttempts; ++attempt)
    {
        if (attempt > 1 && !SleepRetryDelay(GetRetryDelayMs(attempt - 1)))
            return false;

        DebugLogLine(L"download", L"WinHTTP attempt start item=" + displayName + L" attempt=" + std::to_wstring(attempt) + L"/" + std::to_wstring(maxAttempts));
        lastResult = DownloadRecursiveOnce(url, targetPath, displayName, depth);

        if (lastResult.ok)
        {
            if (lastResult.resumed)
                PostLog(L"Докачано: " + displayName);
            DebugLogLine(L"download", L"WinHTTP recursive success item=" + displayName + L" attempt=" + std::to_wstring(attempt) +
                L" bytes=" + std::to_wstring(GetFileSizeBytesOrZero(targetPath)));
            return true;
        }

        LogDownloadAttemptFailure(displayName, attempt, maxAttempts, lastResult);

        if (lastResult.error == DownloadError::Stalled)
            break;

        if (!lastResult.retryable || IsCancelRequested())
            break;
    }

    DebugLogLine(L"download", L"WinHTTP recursive failed item=" + displayName + L" error=" + DownloadErrorToString(lastResult.error));
    return false;
}

static bool FindFirstExeRecursive(const std::wstring& folder, std::wstring& outPath);

