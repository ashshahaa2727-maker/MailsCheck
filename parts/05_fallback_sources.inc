static void AddUniqueString(std::vector<std::wstring>& values, const std::wstring& value)
{
    if (value.empty())
        return;

    if (std::find(values.begin(), values.end(), value) == values.end())
        values.push_back(value);
}

static std::vector<std::wstring> GetFastFallbackUrls(const DownloadItem& item)
{
    (void)item;
    return {};
}

static bool TryFastFallbackUrls(const DownloadItem& item, const std::wstring& targetPath)
{
    (void)item;
    (void)targetPath;
    return false;
}

static bool TrySoftPortalFallback(const DownloadItem& item, const std::wstring& targetPath)
{
    (void)item;
    (void)targetPath;
    return false;
}
