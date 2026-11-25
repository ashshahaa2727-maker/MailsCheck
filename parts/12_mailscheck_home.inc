static void MoveChildWindow(HWND child, int x, int y, int w, int h, BOOL repaint);
static void SetChildVisible(HWND child, bool visible);
static void PaintParentSceneForButton(HWND button, HDC hdc);

namespace MailsUi
{
    using namespace MailsTheme;

    enum class Glyph { Prompt, Search, Sliders, Folder, Download, Check, Alert, File, Activity, Disk, Archive, Code, Clock, Arrow };

    static HWND hovered = nullptr;
    static HWND previousHover = nullptr;
    static ULONGLONG hoverSince = 0;
    static HWND catalog = nullptr;
    static int catalogOffset = 0;
    static int catalogWheelRemainder = 0;
    static int catalogThumbGrab = 0;
    static bool catalogDragging = false;
    static ULONGLONG welcomeSince = 0;

    static Color ToColor(COLORREF color)
    {
        return Color(255, GetRValue(color), GetGValue(color), GetBValue(color));
    }

    static COLORREF Mix(COLORREF from, COLORREF to, float amount)
    {
        const auto channel = [amount](int a, int b) { return static_cast<int>(std::lround(a + (b - a) * amount)); };
        return RGB(channel(GetRValue(from), GetRValue(to)), channel(GetGValue(from), GetGValue(to)), channel(GetBValue(from), GetBValue(to)));
    }

    static float Ease(ULONGLONG since)
    {
        if (!since || g_reduceMotion)
            return 1.0f;
        float progress = std::min(1.0f, static_cast<float>(GetTickCount64() - since) / MotionMs);
        const float remaining = 1.0f - progress;
        return 1.0f - remaining * remaining * remaining;
    }

    static RectF Bounds(const RECT& r)
    {
        return RectF(static_cast<REAL>(r.left), static_cast<REAL>(r.top),
            static_cast<REAL>(r.right - r.left), static_cast<REAL>(r.bottom - r.top));
    }

    static void RoundPath(GraphicsPath& path, const RectF& r, float radius)
    {
        const float d = std::min({ radius * 2, r.Width, r.Height });
        path.AddArc(r.X, r.Y, d, d, 180, 90);
        path.AddArc(r.GetRight() - d, r.Y, d, d, 270, 90);
        path.AddArc(r.GetRight() - d, r.GetBottom() - d, d, d, 0, 90);
        path.AddArc(r.X, r.GetBottom() - d, d, d, 90, 90);
        path.CloseFigure();
    }

    static void SurfaceBox(Graphics& g, const RectF& r, float radius, COLORREF fill,
        COLORREF outline = CLR_INVALID, float stroke = 1.0f)
    {
        GraphicsPath path;
        RoundPath(path, r, radius);
        if (fill != CLR_INVALID)
        {
            SolidBrush brush(ToColor(fill));
            g.FillPath(&brush, &path);
        }
        if (outline != CLR_INVALID)
        {
            Pen pen(ToColor(outline), stroke);
            g.DrawPath(&pen, &path);
        }
    }

    static void Fill(Graphics& g, const RectF& r, COLORREF color)
    {
        SolidBrush brush(ToColor(color));
        g.FillRectangle(&brush, r);
    }

    static void Label(Graphics& g, const std::wstring& value, const RectF& r, int size = BodySize,
        COLORREF color = Text, bool bold = false, StringAlignment align = StringAlignmentNear,
        const wchar_t* face = nullptr, bool wrap = false)
    {
        Font font(face ? face : g_homeFontFace, static_cast<REAL>(size), bold ? FontStyleBold : FontStyleRegular, UnitPixel);
        SolidBrush brush(ToColor(color));
        StringFormat format(StringFormat::GenericTypographic());
        format.SetAlignment(align);
        format.SetLineAlignment(StringAlignmentCenter);
        format.SetTrimming(wrap ? StringTrimmingWord : StringTrimmingEllipsisCharacter);
        if (!wrap)
            format.SetFormatFlags(StringFormatFlagsNoWrap);
        g.DrawString(value.c_str(), static_cast<INT>(value.size()), &font, r, &format, &brush);
    }

    static void Icon(Graphics& g, Glyph glyph, float x, float y, COLORREF color, float size = 16)
    {
        GraphicsState state = g.Save();
        g.TranslateTransform(x, y);
        g.ScaleTransform(size / 16.0f, size / 16.0f);
        Pen stroke(ToColor(color), 1.4f);
        stroke.SetStartCap(LineCapRound);
        stroke.SetEndCap(LineCapRound);
        stroke.SetLineJoin(LineJoinRound);

        const auto line = [&](float x1, float y1, float x2, float y2) { g.DrawLine(&stroke, x1, y1, x2, y2); };
        const auto poly = [&](std::initializer_list<PointF> points) {
            g.DrawLines(&stroke, points.begin(), static_cast<INT>(points.size()));
        };
        switch (glyph)
        {
        case Glyph::Prompt:
            poly({{2,4}, {6,8}, {2,12}});
            line(8,12,14,12);
            break;
        case Glyph::Search:
            g.DrawEllipse(&stroke, 2, 2, 9, 9);
            line(10,10,14,14);
            break;
        case Glyph::Sliders:
            line(2,4,14,4); line(2,8,14,8); line(2,12,14,12);
            line(6,2,6,6); line(10,6,10,10); line(6,10,6,14);
            break;
        case Glyph::Folder:
            poly({{2,13}, {2,4}, {6,4}, {8,6}, {14,6}, {14,13}, {2,13}});
            break;
        case Glyph::Download:
            poly({{4,7}, {8,11}, {12,7}});
            line(8,2,8,11); line(3,14,13,14);
            break;
        case Glyph::Check:
            poly({{3,8}, {6.5f,11.5f}, {13,4.5f}});
            break;
        case Glyph::Alert:
            g.DrawEllipse(&stroke, 2, 2, 12, 12);
            line(8,5,8,8); line(8,10.5f,8,11);
            break;
        case Glyph::File:
            poly({{4,14}, {4,2}, {9,2}, {13,6}, {13,14}, {4,14}});
            poly({{9,2}, {9,6}, {13,6}});
            line(6,9,10.5f,9); line(6,11.5f,10.5f,11.5f);
            break;
        case Glyph::Activity:
            poly({{1.5f,8}, {4,8}, {6,4}, {9,12}, {11,8}, {14.5f,8}});
            break;
        case Glyph::Disk:
            g.DrawRectangle(&stroke, 2, 5, 12, 7);
            line(5,9,5.5f,9); line(8,9,11,9);
            break;
        case Glyph::Archive:
            g.DrawRectangle(&stroke, 3, 6, 10, 8);
            g.DrawRectangle(&stroke, 2, 2, 12, 4);
            line(6,9,10,9);
            break;
        case Glyph::Code:
            poly({{5,4}, {2,8}, {5,12}});
            poly({{11,4}, {14,8}, {11,12}});
            line(9,3,7,13);
            break;
        case Glyph::Clock:
            g.DrawEllipse(&stroke, 2, 2, 12, 12);
            poly({{8,4.5f}, {8,8}, {11,9.5f}});
            break;
        case Glyph::Arrow:
            poly({{5,3}, {10,8}, {5,13}});
            break;
        }
        g.Restore(state);
    }

    static Glyph UtilityIcon(const DownloadItem& item)
    {
        const auto& name = item.name;
        if (name == L"Everything" || name == L"RegScanner" || name == L"Recuva") return Glyph::Search;
        if (name == L"ShellBag Analyzer" || name == L"SimpleUnlocker" || name == L"PathsParser") return Glyph::Folder;
        if (name == L"SystemInformer" || name == L"ProcessHacker" || name == L"LastActivityView" ||
            name == L"BAMParser" || name == L"WinDefLogView") return Glyph::Activity;
        if (name == L"USBDriveLog" || name == L"USBDeview" || name == L"FTK Imager" ||
            name == L"AlternateStreamView" || name == L"KernelLiveDumpTool") return Glyph::Disk;
        if (name == L"WinRAR") return Glyph::Archive;
        if (name == L"Recaf CLI" || name == L"Detect It Easy" || name == L"RegistryExplorer" ||
            name == L"MinecraftVersionChecker" || name == L"VolatilityWorkbench") return Glyph::Code;
        if (name == L"BrowsingHistoryView" || name == L"RecentFilesView" || name == L"ExecutedProgramsList" ||
            name == L"WinPrefetchView" || name == L"JournalTrace") return Glyph::Clock;
        if (name == L"BrowserDownloadsView") return Glyph::Download;
        return Glyph::File;
    }

    static void Configure(Graphics& g)
    {
        g.SetSmoothingMode(SmoothingModeAntiAlias);
        g.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);
    }

    static HICON CreateAppIcon()
    {
        Bitmap bitmap(32, 32, PixelFormat32bppARGB);
        Graphics g(&bitmap);
        Configure(g);
        g.Clear(Color(0, 0, 0, 0));
        SurfaceBox(g, RectF(1, 1, 30, 30), ControlRadius, Accent);
        Icon(g, Glyph::Prompt, 6, 6, Ink, 20);
        HICON icon = nullptr;
        bitmap.GetHICON(&icon);
        return icon;
    }

    static void DrawHeader(Graphics& g, const RECT& rc)
    {
        const float y = 20;
        SurfaceBox(g, RectF(HOME_MARGIN, y, 24, 24), SmallRadius, Accent);
        Icon(g, Glyph::Prompt, HOME_MARGIN + 4.0f, y + 4.0f, Ink);
        Label(g, L"mailscheck", RectF(56, 12, 152, Target), TitleSize, Text, true);
        Fill(g, RectF(208, 24, 1, 16), Line);
        const float subtitleWidth = g_currentPage == 0 ? 280.0f : static_cast<float>(std::min(280L, rc.right - 744));
        if (subtitleWidth > 0)
            Label(g, L"Лаунчер утилит для проверки ПК", RectF(224, 12, subtitleWidth, Target), BodySize, Muted);
        Fill(g, RectF(0, HOME_HEADER - 1, static_cast<float>(rc.right), 1), Line);
    }

    struct CatalogLayout
    {
        int width;
        int height;
        int columns;
        int maxOffset;

        RECT Card(int position) const
        {
            const int row = position / columns;
            const int col = position % columns;
            const int columnSpan = width - (columns - 1) * HOME_TILE_GAP;
            const int left = col * HOME_TILE_GAP + columnSpan * col / columns;
            const int right = col * HOME_TILE_GAP + columnSpan * (col + 1) / columns;
            const int top = row * (HOME_TILE_HEIGHT + HOME_TILE_GAP);
            return { left, top, right, top + HOME_TILE_HEIGHT };
        }

        int ThumbHeight() const
        {
            return std::clamp(MulDiv(height, height, height + maxOffset), 24, height);
        }

        int ThumbTop() const
        {
            return MulDiv(catalogOffset, height - ThumbHeight(), maxOffset);
        }
    };

    static CatalogLayout MeasureCatalog()
    {
        RECT rc{};
        GetClientRect(catalog, &rc);

        const int total = static_cast<int>(g_items.size());
        const int height = std::max(24L, rc.bottom);
        const auto columnsFor = [](int width) { return std::clamp((width + HOME_TILE_GAP) / 216, 3, 5); };
        const auto extentFor = [total](int columns) {
            const int rows = (total + columns - 1) / columns;
            return rows ? rows * (HOME_TILE_HEIGHT + HOME_TILE_GAP) - HOME_TILE_GAP : 0;
        };

        const int fullWidth = std::max(1L, rc.right);
        const bool overflow = extentFor(columnsFor(fullWidth)) > height;
        const int width = overflow ? std::max(1, fullWidth - 3 * Grid) : fullWidth;
        const int columns = columnsFor(width);
        return { width, height, columns, std::max(0, extentFor(columns) - height) };
    }

    static void PositionCatalogCards(const CatalogLayout& layout)
    {
        for (size_t i = 0; i < g_tileButtons.size(); ++i)
        {
            const RECT bounds = layout.Card(static_cast<int>(i));
            MoveChildWindow(g_tileButtons[i], bounds.left, bounds.top - catalogOffset,
                bounds.right - bounds.left, bounds.bottom - bounds.top, FALSE);
        }
        RedrawWindow(catalog, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN);
    }

    static void ScrollCatalogTo(const CatalogLayout& layout, int offset)
    {
        const int next = std::clamp(offset, 0, layout.maxOffset);
        if (next == catalogOffset)
            return;
        catalogOffset = next;
        PositionCatalogCards(layout);
    }

    static void ScrollCatalogWheel(int delta)
    {
        UINT lines = 3;
        SystemParametersInfoW(SPI_GETWHEELSCROLLLINES, 0, &lines, 0);
        const CatalogLayout layout = MeasureCatalog();
        const int distance = lines == WHEEL_PAGESCROLL ? layout.height : static_cast<int>(lines) * 24;
        const int movement = catalogWheelRemainder - delta * distance;
        catalogWheelRemainder = movement % WHEEL_DELTA;
        ScrollCatalogTo(layout, catalogOffset + movement / WHEEL_DELTA);
    }

    static bool HandleCatalogKey(HWND control, WPARAM key)
    {
        if (control != catalog && !IsChild(catalog, control))
            return false;

        const CatalogLayout layout = MeasureCatalog();
        switch (key)
        {
        case VK_HOME: ScrollCatalogTo(layout, 0); break;
        case VK_END: ScrollCatalogTo(layout, layout.maxOffset); break;
        case VK_UP: ScrollCatalogTo(layout, catalogOffset - HOME_TILE_HEIGHT - HOME_TILE_GAP); break;
        case VK_DOWN: ScrollCatalogTo(layout, catalogOffset + HOME_TILE_HEIGHT + HOME_TILE_GAP); break;
        case VK_PRIOR: ScrollCatalogTo(layout, catalogOffset - layout.height + HOME_TILE_HEIGHT); break;
        case VK_NEXT: ScrollCatalogTo(layout, catalogOffset + layout.height - HOME_TILE_HEIGHT); break;
        default: return false;
        }
        return true;
    }

    static void RevealCatalogCard(int index)
    {
        const CatalogLayout layout = MeasureCatalog();
        const RECT card = layout.Card(index);
        if (card.top < catalogOffset)
            ScrollCatalogTo(layout, card.top);
        else if (card.bottom > catalogOffset + layout.height)
            ScrollCatalogTo(layout, card.bottom - layout.height);
    }

    static void DragCatalogThumb(const CatalogLayout& layout, int y)
    {
        const int track = layout.height - layout.ThumbHeight();
        if (track > 0)
            ScrollCatalogTo(layout, MulDiv(std::clamp(y - catalogThumbGrab, 0, track), layout.maxOffset, track));
    }

    static LRESULT CALLBACK CatalogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        switch (message)
        {
        case WM_DRAWITEM:
        case WM_COMMAND:
            return SendMessageW(GetParent(hwnd), message, wParam, lParam);
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT:
        {
            PAINTSTRUCT paint{};
            HDC dc = BeginPaint(hwnd, &paint);
            {
                Graphics g(dc);
                Configure(g);
                Fill(g, Bounds(paint.rcPaint), Canvas);
                const CatalogLayout layout = MeasureCatalog();
                if (layout.maxOffset > 0)
                {
                    const float x = static_cast<float>(layout.width + 16);
                    SurfaceBox(g, RectF(x, 0, 4, static_cast<float>(layout.height)), SmallRadius, Line);
                    SurfaceBox(g, RectF(x - 1, static_cast<float>(layout.ThumbTop()), 6,
                        static_cast<float>(layout.ThumbHeight())), SmallRadius,
                        catalogDragging ? Accent : Mix(Line, Muted, .65f));
                }
            }
            EndPaint(hwnd, &paint);
            return 0;
        }
        case WM_LBUTTONDOWN:
        {
            const CatalogLayout layout = MeasureCatalog();
            if (GET_X_LPARAM(lParam) >= layout.width && layout.maxOffset > 0)
            {
                const int y = GET_Y_LPARAM(lParam);
                const int top = layout.ThumbTop();
                const int height = layout.ThumbHeight();
                catalogThumbGrab = y >= top && y < top + height ? y - top : height / 2;
                catalogDragging = true;
                SetFocus(hwnd);
                SetCapture(hwnd);
                DragCatalogThumb(layout, y);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }
        case WM_MOUSEMOVE:
            if (catalogDragging && GetCapture() == hwnd)
                DragCatalogThumb(MeasureCatalog(), GET_Y_LPARAM(lParam));
            return 0;
        case WM_LBUTTONUP:
            if (GetCapture() == hwnd)
                ReleaseCapture();
            return 0;
        case WM_CAPTURECHANGED:
            catalogDragging = false;
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        // Windows forwards unhandled wheel events to the parent. It routes them
        // by pointer location so the catalog and journal scroll independently.
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }

    static HWND CreateCatalog(HWND parent)
    {
        constexpr wchar_t className[] = L"MailscheckCatalog";
        WNDCLASSW wc{};
        wc.lpfnWndProc = CatalogProc;
        wc.hInstance = g_hInst;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.lpszClassName = className;
        if (!RegisterClassW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
            return nullptr;

        catalog = CreateWindowExW(WS_EX_CONTROLPARENT, className, L"Каталог утилит",
            WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
            0, 0, 0, 0, parent, nullptr, g_hInst, nullptr);
        return catalog;
    }

    struct HomeLayout
    {
        int contentWidth;
        int railWidth;
        int footer;
        RECT catalog;
        RECT log;
    };

    static HomeLayout MeasureHome(const RECT& rc)
    {
        const int right = rc.right - HOME_MARGIN;
        const int footer = rc.bottom - HOME_FOOTER_HEIGHT;
        const int logBottom = footer - HOME_MARGIN;
        const int logHeight = std::clamp(static_cast<int>(rc.bottom) / 5, 136, 208);
        const int logTop = logBottom - logHeight;
        return { right - HOME_MAIN_X, HOME_RAIL_RIGHT - 2 * HOME_MARGIN, footer,
            { HOME_MAIN_X, HOME_TILE_TOP, right, logTop - 3 * Grid },
            { HOME_MAIN_X, logTop, right, logBottom } };
    }

    static constexpr UINT WelcomeHoldMs = 820;
    static constexpr UINT WelcomeTotalMs = 2 * MotionMs + WelcomeHoldMs;

    static RECT WelcomeBounds()
    {
        return { HOME_MARGIN - Grid, 344, HOME_RAIL_RIGHT - HOME_MARGIN + Grid, 440 };
    }

    static void BeginWelcome()
    {
        welcomeSince = GetTickCount64();
        RECT area = WelcomeBounds();
        InvalidateRect(g_hMain, &area, FALSE);
        SetTimer(g_hMain, TIMER_UI_TRANSITION, g_reduceMotion ? WelcomeTotalMs : FrameMs, nullptr);
    }

    static void DrawWelcome(Graphics& g)
    {
        if (!welcomeSince)
            return;

        const ULONGLONG elapsed = GetTickCount64() - welcomeSince;
        if (elapsed >= WelcomeTotalMs)
            return;

        const float fadeIn = std::min(1.0f, static_cast<float>(elapsed) / MotionMs);
        const float fadeOut = std::min(1.0f, static_cast<float>(WelcomeTotalMs - elapsed) / MotionMs);
        const float opacity = g_reduceMotion ? 1.0f : std::min(fadeIn, fadeOut);
        const float y = 360.0f + (g_reduceMotion ? 0.0f : 8.0f * (1.0f - fadeIn));
        const float x = HOME_MARGIN;
        const float width = HOME_RAIL_RIGHT - 2 * HOME_MARGIN;

        SurfaceBox(g, RectF(x, y, width, 64), ControlRadius, Mix(Rail, Surface, opacity), Mix(Rail, Line, opacity));
        SurfaceBox(g, RectF(x + 12, y + 20, 24, 24), SmallRadius, Mix(Rail, Accent, opacity));
        Icon(g, Glyph::Prompt, x + 16, y + 24, Mix(Rail, Ink, opacity));
        Label(g, L"Добро пожаловать", RectF(x + 48, y + 12, width - 56, 40),
            BodySize, Mix(Rail, Text, opacity), true);
    }

    static void SetHover(HWND button)
    {
        if (hovered == button)
            return;
        if (previousHover && IsWindow(previousHover))
            InvalidateRect(previousHover, nullptr, FALSE);
        previousHover = hovered;
        hovered = button;
        hoverSince = g_reduceMotion ? 0 : GetTickCount64();
        if (previousHover)
            InvalidateRect(previousHover, nullptr, FALSE);
        if (hovered)
            InvalidateRect(hovered, nullptr, FALSE);
        if (hoverSince)
            SetTimer(g_hMain, TIMER_UI_TRANSITION, FrameMs, nullptr);
    }

    static void Tick(HWND hwnd)
    {
        if (welcomeSince)
        {
            if (GetTickCount64() - welcomeSince >= WelcomeTotalMs)
                welcomeSince = 0;
            RECT area = WelcomeBounds();
            InvalidateRect(hwnd, &area, FALSE);
        }

        if (hoverSince)
        {
            if (hovered && IsWindowVisible(hovered))
                InvalidateRect(hovered, nullptr, FALSE);
            if (previousHover && IsWindowVisible(previousHover))
                InvalidateRect(previousHover, nullptr, FALSE);
            if (Ease(hoverSince) >= 1.0f)
            {
                hoverSince = 0;
                previousHover = nullptr;
            }
        }

        if (!welcomeSince && !hoverSince)
            KillTimer(hwnd, TIMER_UI_TRANSITION);
    }

    static ActiveDownloadInfo ActiveInfo(const std::wstring& name)
    {
        std::lock_guard<std::mutex> lock(g_activeDownloadsMutex);
        auto found = std::find_if(g_activeDownloads.begin(), g_activeDownloads.end(),
            [&](const ActiveDownloadInfo& info) { return info.name == name; });
        return found == g_activeDownloads.end() ? ActiveDownloadInfo{} : *found;
    }

    static float Fraction(const ActiveDownloadInfo& active)
    {
        return active.totalBytes ? std::min(1.0f, static_cast<float>(active.bytes) / active.totalBytes) : 0.0f;
    }

    static const wchar_t* PhaseLabel(DownloadCardPhase phase)
    {
        switch (phase)
        {
        case DownloadCardPhase::Queued: return L"В очереди";
        case DownloadCardPhase::Downloading: return L"Скачивается";
        case DownloadCardPhase::Extracting: return L"Распаковка";
        case DownloadCardPhase::Ready: return L"Готово";
        case DownloadCardPhase::Error: return L"Ошибка";
        case DownloadCardPhase::Cancelled: return L"Отменено";
        default: return L"";
        }
    }

    static void Track(Graphics& g, RectF r, float fraction, COLORREF color, bool unknown = false)
    {
        SurfaceBox(g, r, SmallRadius, Line);
        if (unknown)
        {
            for (float x = r.X; x + 4 <= r.GetRight(); x += 12)
                Fill(g, RectF(x, r.Y, 4, r.Height), color);
            return;
        }
        r.Width *= fraction;
        if (r.Width >= 1)
            SurfaceBox(g, r, SmallRadius, color);
    }

    static void DrawDownloadLog(Graphics& g, const HomeLayout& layout)
    {
        const RectF panel = Bounds(layout.log);
        if (panel.Height < 1)
            return;

        std::vector<DownloadLogEntry> lines;
        bool follow;
        {
            std::lock_guard<std::mutex> lock(g_logMutex);
            ClampLogScrollOffsetLocked();
            follow = g_logScrollOffset == 0;
            const size_t last = g_logLines.size() - static_cast<size_t>(g_logScrollOffset);
            const size_t first = last - std::min(last, g_logVisibleLines);
            lines.assign(g_logLines.begin() + first, g_logLines.begin() + last);
        }

        SurfaceBox(g, panel, PanelRadius, Inset, Line);
        const float x = panel.X + 16;
        const float y = panel.Y;
        const float w = panel.Width - 32;
        Label(g, L"Журнал загрузок", RectF(x, y, w, LOG_HEADER_HEIGHT), BodySize, Text, true);
        Fill(g, RectF(panel.X + 1, y + LOG_HEADER_HEIGHT, panel.Width - 2, 1), Line);

        if (lines.empty())
        {
            const float emptyY = y + LOG_HEADER_HEIGHT + std::min(32.0f, (panel.Height - LOG_HEADER_HEIGHT - 48) * .5f);
            SurfaceBox(g, RectF(x, emptyY + 4, 32, 32), ControlRadius, Surface);
            Icon(g, Glyph::Download, x + 8, emptyY + 12, Muted);
            Label(g, L"Загрузок пока нет", RectF(x + 48, emptyY, w - 48, 20), BodySize, Text, true);
            Label(g, L"Выберите утилиту для загрузки.", RectF(x + 48, emptyY + 20, w - 48, 20), CaptionSize, Muted);
            return;
        }

        const float headerY = y + LOG_HEADER_HEIGHT;
        const auto lineText = [&](const std::wstring& text, float offset, float top, float width, COLORREF color) {
            Label(g, text, RectF(x + offset, top, width, LOG_ROW_HEIGHT), CaptionSize, color,
                false, StringAlignmentNear, g_homeMonoFace);
        };
        Label(g, follow ? L"Автопрокрутка" : L"Прокрутите вниз к новым событиям",
            RectF(x, y, w, LOG_HEADER_HEIGHT), CaptionSize, Muted, false, StringAlignmentFar);
        lineText(L"ВРЕМЯ", 0, headerY, 80, Muted);
        lineText(L"СТАТУС", 88, headerY, 96, Muted);
        lineText(L"СОБЫТИЕ", 192, headerY, w - 192, Muted);

        float rowY = headerY + LOG_COLUMN_HEIGHT;
        for (const DownloadLogEntry& entry : lines)
        {
            Fill(g, RectF(x, rowY, w, 1), Line);
            const auto& message = entry.message;
            const wchar_t* status = L"Инфо";
            COLORREF tint = Muted;
            size_t prefix = 0;
            if (message.rfind(L"скачивается: ", 0) == 0)
            {
                status = L"Загрузка"; tint = Accent; prefix = std::wcslen(L"скачивается: ");
            }
            else if (message.rfind(L"Сохранено", 0) == 0)
            {
                status = L"Готово"; tint = Success;
                if (message.rfind(L"Сохранено: ", 0) == 0)
                    prefix = std::wcslen(L"Сохранено: ");
            }
            else if (message.rfind(L"Не удалось", 0) == 0 || message.rfind(L"Не создана", 0) == 0 ||
                message.rfind(L"не скачалось:", 0) == 0 || message == L"текст не скопирован")
            {
                status = L"Ошибка"; tint = Error;
            }
            else if (message.rfind(L"Отмен", 0) == 0 || message.rfind(L"Сейчас идут", 0) == 0)
            {
                status = L"Внимание"; tint = Warning;
            }
            lineText(entry.time, 0, rowY, 80, Muted);
            lineText(status, 88, rowY, 96, tint);
            lineText(message.substr(prefix), 192, rowY, w - 192, Text);
            rowY += LOG_ROW_HEIGHT;
        }
    }

    static void DrawFooter(Graphics& g, const RECT& rc, const HomeLayout& layout)
    {
        const float y = static_cast<float>(layout.footer);
        const float width = static_cast<float>(rc.right - 2 * HOME_MARGIN - CANCEL_BUTTON_W - 24);
        Fill(g, RectF(0, y, static_cast<float>(rc.right), HOME_FOOTER_HEIGHT), Rail);
        Fill(g, RectF(0, y, static_cast<float>(rc.right), 1), Line);

        std::wstring operation = L"Загрузки · ожидание команды";
        COLORREF color = Muted;
        int percent = g_progressPercent;
        if (g_operationFinished)
        {
            operation = g_operationCancelled ? L"Загрузка отменена" :
                (g_operationHadError ? L"Загрузка завершена с ошибками" : L"Загрузка завершена");
            color = g_operationCancelled ? Warning : (g_operationHadError ? Error : Success);
        }
        else if (!g_operationItems.empty() && IsCancelRequested())
        {
            operation = L"Отмена загрузки…";
            color = Warning;
        }
        else if (g_operationBatch)
        {
            operation = L"Скачивание каталога";
            color = Accent;
        }
        else if (g_operationItems.size() == 1)
        {
            const size_t index = g_operationItems.front();
            const DownloadCardPhase phase = g_downloadCardPhases[index];
            operation = std::wstring(PhaseLabel(phase)) + L" · " + g_items[index].name;
            color = Accent;
            if (phase == DownloadCardPhase::Downloading)
            {
                const ActiveDownloadInfo active = ActiveInfo(g_items[index].name);
                if (active.totalBytes)
                    percent = static_cast<int>(Fraction(active) * 100);
                else if (active.bytes)
                    operation += L" · " + FormatBytes(active.bytes);
            }
        }
        else if (!g_operationItems.empty())
        {
            operation = L"Загрузка программ · " + std::to_wstring(g_operationItems.size());
            color = Accent;
        }

        Label(g, operation, RectF(HOME_MARGIN, y + 12, width - 56, 26), BodySize, Text);
        Label(g, std::to_wstring(percent) + L"%", RectF(HOME_MARGIN + width - 56, y + 12, 56, 26),
            CaptionSize, color, true, StringAlignmentFar);
        Track(g, RectF(HOME_MARGIN, y + 48, width, 4), std::clamp(percent, 0, 100) / 100.0f, color);
    }

    static void DrawHome(Graphics& g, const RECT& rc)
    {
        const HomeLayout layout = MeasureHome(rc);
        const float railWidth = static_cast<float>(layout.railWidth);
        const float mainWidth = static_cast<float>(layout.contentWidth);
        const float railX = HOME_MARGIN;
        const float mainX = HOME_MAIN_X;
        Fill(g, RectF(0, HOME_HEADER, HOME_RAIL_RIGHT, static_cast<float>(layout.footer - HOME_HEADER)), Rail);
        Fill(g, RectF(HOME_RAIL_RIGHT - 1, HOME_HEADER, 1, static_cast<float>(layout.footer - HOME_HEADER)), Line);

        Label(g, L"Проверка ПК", RectF(railX, 88, railWidth, 24), BodySize, Muted, true);
        Label(g, L"Everything", RectF(railX, 120, railWidth, 40), TitleSize, Text, true);
        Label(g, L"Поиск по именам файлов и папок", RectF(railX, 160, railWidth, 40),
            BodySize, Muted, false, StringAlignmentNear, nullptr, true);
        Label(g, L"Конфиги за последние 14 дней", RectF(railX, 312, railWidth, 24), CaptionSize, Muted);

        const float locationY = static_cast<float>(layout.footer - 128);
        Fill(g, RectF(railX, locationY, railWidth, 1), Line);
        Label(g, L"Папка загрузок", RectF(railX, locationY + 12, railWidth, 24), CaptionSize, Muted);
        Label(g, L"Загрузки / holycheck", RectF(railX, locationY + 34, railWidth, 24));

        Label(g, L"Утилиты", RectF(mainX, 80, mainWidth - 176, Target), TitleSize, Text, true);
        Label(g, std::to_wstring(g_items.size()), RectF(mainX + 120, 80, 40, Target),
            CaptionSize, Muted);
        DrawWelcome(g);

        DrawDownloadLog(g, layout);
        DrawFooter(g, rc, layout);
    }

    static void LayoutHome(HWND hwnd, const RECT& rc)
    {
        const HomeLayout layout = MeasureHome(rc);
        const auto place = [](HWND button, int x, int y, int w, int h) {
            MoveChildWindow(button, x, y, w, h, FALSE);
            SetChildVisible(button, true);
        };

        place(g_hAutomationNav, rc.right - HOME_MARGIN - 160, 12, 160, Target);
        SetWindowTextW(g_hAutomationNav, L"Другие проверки");
        place(g_hSearchCheats, HOME_MARGIN, 208, layout.railWidth, Target);
        place(g_hSearchConfigs, HOME_MARGIN, 256, layout.railWidth, Target);
        place(g_hOpenDownloads, HOME_MARGIN, layout.footer - 64, layout.railWidth, Target);
        place(g_hDownloadAll, rc.right - HOME_MARGIN - 160, 80, 160, Target);
        place(g_hCancelDownload, rc.right - HOME_MARGIN - CANCEL_BUTTON_W, layout.footer + 16, CANCEL_BUTTON_W, Target);
        place(catalog, layout.catalog.left, layout.catalog.top,
            layout.catalog.right - layout.catalog.left, layout.catalog.bottom - layout.catalog.top);
        const CatalogLayout items = MeasureCatalog();
        catalogOffset = std::min(catalogOffset, items.maxOffset);
        PositionCatalogCards(items);

        {
            std::lock_guard<std::mutex> lock(g_logMutex);
            const int available = layout.log.bottom - layout.log.top - LOG_HEADER_HEIGHT - LOG_COLUMN_HEIGHT - Grid;
            g_logVisibleLines = static_cast<size_t>(std::max(1, available / LOG_ROW_HEIGHT));
            ClampLogScrollOffsetLocked();
        }

        RedrawWindow(hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
    }

    static void DrawCard(Graphics& g, RectF r, size_t index, float hover, bool pressed, bool enabled)
    {
        const DownloadItem& item = g_items[index];
        const DownloadCardPhase phase = g_downloadCardPhases[index];
        const bool downloading = phase == DownloadCardPhase::Downloading;
        const bool extracting = phase == DownloadCardPhase::Extracting;
        const bool busy = downloading || extracting;
        const bool hasResult = phase != DownloadCardPhase::Idle;
        COLORREF fill = pressed ? Inset : Mix(Surface, Raised, hover);
        if (!enabled && !hasResult)
            fill = Rail;
        SurfaceBox(g, RectF(r.X + .5f, r.Y + .5f, r.Width - 1, r.Height - 1), ControlRadius, fill,
            pressed || busy ? Line : Mix(Surface, Line, hover));

        const COLORREF foreground = enabled || hasResult ? Text : Muted;
        Icon(g, UtilityIcon(item), r.X + 14, r.Y + 14, foreground);
        Label(g, item.name, RectF(r.X + 40, r.Y + (hasResult ? 5 : 9), r.Width - 72, 22), BodySize, foreground, true);
        Label(g, item.description, RectF(r.X + 40, r.Y + (hasResult ? 25 : 32), r.Width - 52, 16), CaptionSize, Muted);

        std::wstring caption;
        COLORREF captionColor = Muted;
        Glyph trailing = Glyph::Download;
        ActiveDownloadInfo active;
        if (hasResult)
        {
            caption = PhaseLabel(phase);
            if (downloading)
            {
                captionColor = Accent;
                active = ActiveInfo(item.name);
                if (active.totalBytes)
                    caption += L" · " + std::to_wstring(static_cast<int>(Fraction(active) * 100)) + L"%";
                else if (active.bytes)
                    caption += L" · " + FormatBytes(active.bytes);
            }
            else if (phase == DownloadCardPhase::Ready)
            {
                captionColor = Success;
                trailing = Glyph::Check;
            }
            else if (phase == DownloadCardPhase::Error || phase == DownloadCardPhase::Cancelled)
            {
                captionColor = phase == DownloadCardPhase::Error ? Error : Warning;
                trailing = Glyph::Alert;
            }
            else
            {
                trailing = Glyph::Clock;
            }
        }
        if (hasResult)
            Label(g, caption, RectF(r.X + 40, r.Y + 40, r.Width - 52, 16), CaptionSize, captionColor);
        Icon(g, trailing, r.GetRight() - 28, r.Y + 13, captionColor);
        if (busy)
            Track(g, RectF(r.X + 40, r.GetBottom() - 9, r.Width - 52, 3),
                Fraction(active), Accent, extracting || active.totalBytes == 0);
    }

    static void DrawButton(DRAWITEMSTRUCT* d)
    {
        PaintParentSceneForButton(d->hwndItem, d->hDC);
        Graphics g(d->hDC);
        Configure(g);
        const RectF r = Bounds(d->rcItem);
        const int id = static_cast<int>(d->CtlID);
        const bool disabled = (d->itemState & ODS_DISABLED) || !IsWindowEnabled(d->hwndItem);
        const bool pressed = (d->itemState & ODS_SELECTED) != 0;
        const float eased = Ease(hoverSince);
        const float hover = disabled ? 0.0f : d->hwndItem == hovered ? eased :
            (hoverSince && d->hwndItem == previousHover ? 1.0f - eased : 0.0f);
        const bool focused = !disabled && (d->itemState & ODS_FOCUS);
        const bool card = id >= IDC_TILE_BASE && id < IDC_TILE_BASE + static_cast<int>(g_items.size());
        const bool primary = id == IDC_SEARCH_CHEATS;
        const bool ghost = id == IDC_AUTOMATION_NAV || id == IDC_HOME_NAV || id == IDC_CANCEL_DOWNLOAD;
        const bool selected = (id == IDC_AUTOMATION_NAV && g_currentPage == 1) ||
            (id == IDC_AUTOMATION_JAR_PAGE && g_currentPage == 2) ||
            (id == IDC_PAGE4_NAV && g_currentPage == 3) || (id == IDC_PAGE5_NAV && g_currentPage == 5);
        const bool idleCancel = id == IDC_CANCEL_DOWNLOAD && !g_working && g_activeSingleDownloads.load() == 0;
        COLORREF ink = disabled || idleCancel ? Muted : Text;

        if (card)
        {
            DrawCard(g, r, id - IDC_TILE_BASE, hover, pressed, !disabled);
        }
        else
        {
            wchar_t text[256]{};
            GetWindowTextW(d->hwndItem, text, static_cast<int>(std::size(text)));
            if (id == IDC_AUTOMATION_BAM_UNSIGNED_ONLY)
            {
                SurfaceBox(g, RectF(r.X + 4, r.Y + 12, 16, 16), SmallRadius, Surface, Accent);
                if (g_bamUnsignedOnly.load())
                    Icon(g, Glyph::Check, r.X + 4, r.Y + 12, Accent);
                Label(g, text, RectF(r.X + 28, r.Y, r.Width - 32, r.Height), CaptionSize, ink);
            }
            else
            {
                const RectF inner(r.X + 1, r.Y + 1, r.Width - 2, r.Height - 2);
                if (primary && !disabled)
                {
                    COLORREF fill = pressed ? Mix(Accent, Ink, .18f) : Mix(Accent, Text, hover * .14f);
                    SurfaceBox(g, inner, ControlRadius, fill);
                    ink = Ink;
                }
                else if (ghost && !selected)
                {
                    if (!idleCancel && (pressed || hover > 0))
                    {
                        COLORREF base = id == IDC_CANCEL_DOWNLOAD ? Rail : Canvas;
                        SurfaceBox(g, inner, ControlRadius, pressed ? Surface : Mix(base, Surface, hover));
                    }
                    if (id == IDC_CANCEL_DOWNLOAD)
                        SurfaceBox(g, inner, ControlRadius, CLR_INVALID, Line);
                }
                else
                {
                    COLORREF fill = pressed ? Inset : Mix(Surface, Raised, hover);
                    SurfaceBox(g, inner, ControlRadius, fill, Line);
                    if (selected)
                        ink = Accent;
                }

                if (id == IDC_SEARCH_CHEATS || id == IDC_SEARCH_CONFIGS || id == IDC_OPEN_DOWNLOADS)
                {
                    const Glyph glyph = id == IDC_SEARCH_CHEATS ? Glyph::Search :
                        id == IDC_SEARCH_CONFIGS ? Glyph::Sliders : Glyph::Folder;
                    Icon(g, glyph, r.X + 14, r.Y + (r.Height - 16) * .5f, ink);
                    Label(g, text, RectF(r.X + 40, r.Y, r.Width - 52, r.Height), BodySize, ink, primary);
                }
                else if (id == IDC_AUTOMATION_NAV && g_currentPage == 0)
                {
                    Label(g, text, RectF(r.X + 8, r.Y, r.Width - 40, r.Height), BodySize, ink,
                        false, StringAlignmentCenter);
                    Icon(g, Glyph::Arrow, r.GetRight() - 24, r.Y + (r.Height - 16) * .5f, Muted);
                }
                else
                {
                    const bool emphasis = selected;
                    Label(g, text, RectF(r.X + 8, r.Y, r.Width - 16, r.Height), BodySize, ink,
                        emphasis, StringAlignmentCenter);
                }
            }
        }

        if (focused)
        {
            const RectF ring(r.X + 3, r.Y + 3, r.Width - 6, r.Height - 6);
            SurfaceBox(g, ring, ControlRadius, CLR_INVALID, primary ? Ink : Accent, 2);
        }
    }
}
