static bool IsPathLikeAutomationCell(const std::wstring& cell);

#include "12_mailscheck_home.inc"

static std::vector<std::wstring> SplitAutomationPipeColumns(const std::wstring& line)
{
    std::wstring displayLine = StripAutomationDeletedMarker(line);
    std::vector<std::wstring> parts;
    size_t start = 0;

    while (start <= displayLine.size())
    {
        size_t pos = displayLine.find(L" | ", start);

        if (pos == std::wstring::npos)
        {
            parts.push_back(displayLine.substr(start));
            break;
        }

        parts.push_back(displayLine.substr(start, pos - start));
        start = pos + 3;
    }

    return parts;
}

static bool IsBamDataRowForColumns(const std::wstring& line)
{
    if (line.size() < 5 || !iswdigit(line[0]))
        return false;

    std::vector<std::wstring> cols = SplitAutomationPipeColumns(line);
    return cols.size() == 4;
}

static void DrawBamDataRow(Graphics& g, const std::wstring& line, const Font& lineFont, float x, float y, float panelW, float lineH)
{
    std::vector<std::wstring> cols = SplitAutomationPipeColumns(line);

    if (cols.size() != 4)
        return;

    SolidBrush textBrush(MailsUi::ToColor(MailsTheme::Text));
    SolidBrush deletedNameBrush(MailsUi::ToColor(MailsTheme::Error));
    SolidBrush forbiddenNameBrush(MailsUi::ToColor(MailsTheme::Error));
    SolidBrush archiveNameBrush(MailsUi::ToColor(MailsTheme::Warning));
    SolidBrush sepBrush(MailsUi::ToColor(MailsTheme::Muted));
    SolidBrush sigBrush(MailsUi::ToColor(MailsTheme::Error));

    StringFormat fmt;
    fmt.SetTrimming(StringTrimmingEllipsisCharacter);
    fmt.SetFormatFlags(StringFormatFlagsNoWrap);

    const float left = x + 10.0f;
    const float usableW = panelW - 30.0f; // keep clear of the blue scrollbar
    const float sepW = 6.0f;
    float dateW = 126.0f;
    float programW = 158.0f;
    float sigW = 82.0f;

    if (usableW >= 900.0f)
    {
        dateW = 132.0f;
        programW = 176.0f;
        sigW = 88.0f;
    }
    else if (usableW >= 720.0f)
    {
        dateW = 128.0f;
        programW = 162.0f;
        sigW = 84.0f;
    }
    else if (usableW < 520.0f)
    {
        dateW = 112.0f;
        programW = 92.0f;
        sigW = 62.0f;
    }

    float pathW = usableW - dateW - programW - sigW - sepW * 3.0f;

    if (pathW < 72.0f)
    {
        float need = 72.0f - pathW;
        float reduceProgram = std::min(need, std::max(0.0f, programW - 62.0f));
        programW -= reduceProgram;
        need -= reduceProgram;

        float reduceDate = std::min(need, std::max(0.0f, dateW - 96.0f));
        dateW -= reduceDate;
        need -= reduceDate;

        float reduceSig = std::min(need, std::max(0.0f, sigW - 52.0f));
        sigW -= reduceSig;

        pathW = usableW - dateW - programW - sigW - sepW * 3.0f;
    }

    if (pathW < 50.0f)
        pathW = 50.0f;

    float cur = left;
    g.DrawString(cols[0].c_str(), -1, &lineFont, RectF(cur, y, dateW, lineH + 2.0f), &fmt, &textBrush);
    cur += dateW;
    g.DrawString(L"|", -1, &lineFont, RectF(cur, y, sepW, lineH + 2.0f), &fmt, &sepBrush);
    cur += sepW;

    g.DrawString(cols[1].c_str(), -1, &lineFont, RectF(cur, y, programW, lineH + 2.0f), &fmt, &textBrush);
    cur += programW;
    g.DrawString(L"|", -1, &lineFont, RectF(cur, y, sepW, lineH + 2.0f), &fmt, &sepBrush);
    cur += sepW;

    g.DrawString(cols[2].c_str(), -1, &lineFont, RectF(cur, y, pathW, lineH + 2.0f), &fmt, &textBrush);
    cur += pathW;
    g.DrawString(L"|", -1, &lineFont, RectF(cur, y, sepW, lineH + 2.0f), &fmt, &sepBrush);
    cur += sepW;

    g.DrawString(cols[3].c_str(), -1, &lineFont, RectF(cur, y, sigW, lineH + 2.0f), &fmt, &sigBrush);
}


static bool IsPipeSeparatedAutomationRow(const std::wstring& line)
{
    std::vector<std::wstring> cols = SplitAutomationPipeColumns(line);
    if (cols.size() < 2)
        return false;

    if (line == L"не найдено" || line.find(L"не удалось") != std::wstring::npos)
        return false;

    return true;
}

static size_t AutomationPathColumnForDraw(int target, const std::vector<std::wstring>& cols)
{
    // date | program | path.  Do not auto-detect the program column as a path
    // just because the program name ends with .jar/.exe; otherwise the real
    // path column becomes narrow and the full path is hidden.
    if (target == AUTOMATION_OUTPUT_EXE_DELETED && cols.size() >= 3)
        return 2;

    if (target == AUTOMATION_OUTPUT_BAM && cols.size() >= 3)
        return 2;

    // File Check: name | path | declared type | real type | status.
    if (target == AUTOMATION_OUTPUT_FILECHECK && cols.size() >= 2)
        return 1;

    for (size_t i = cols.size(); i-- > 0; )
    {
        if (IsPathLikeAutomationCell(cols[i]))
            return i;
    }
    return static_cast<size_t>(-1);
}

static std::vector<std::wstring> NormalizeAutomationColumnsForDraw(const std::wstring& line, int target)
{
    std::vector<std::wstring> cols = SplitAutomationPipeColumns(line);

    if ((target == AUTOMATION_OUTPUT_EXE_DELETED || target == AUTOMATION_OUTPUT_MC_LOGS || target == AUTOMATION_OUTPUT_PF_DELETED) && cols.size() > 3)
    {
        std::wstring action;
        for (size_t i = 1; i + 1 < cols.size(); ++i)
        {
            if (!action.empty())
                action += L", ";
            action += cols[i];
        }

        std::vector<std::wstring> fixedCols;
        fixedCols.push_back(cols[0]);
        fixedCols.push_back(action);
        fixedCols.push_back(cols.back());
        cols.swap(fixedCols);
    }

    return cols;
}

static std::vector<float> ComputeAutomationColumnWidths(Graphics& g, const std::vector<std::wstring>& lines, size_t startIndex, size_t endIndex, int target, const Font& lineFont, float panelW)
{
    // Оптимизация: для ширин колонок достаточно первых 240 строк —
    // иначе на тысячах строк file check замер каждой ячейки на каждом
    // кадре (60 FPS) заметно тормозил отрисовку.
    if (endIndex > startIndex + 240)
        endIndex = startIndex + 240;

    const float usableW = std::max(60.0f, panelW - 32.0f);
    const float sepW = 6.0f;

    StringFormat measureFmt;
    measureFmt.SetFormatFlags(StringFormatFlagsNoWrap | StringFormatFlagsMeasureTrailingSpaces);
    auto measureCell = [&](const std::wstring& text) -> float {
        RectF bounds;
        g.MeasureString(text.c_str(), -1, &lineFont, PointF(0.0f, 0.0f), &measureFmt, &bounds);
        return std::ceil(bounds.Width) + 16.0f;
    };

    size_t maxCols = 0;
    size_t pathCol = static_cast<size_t>(-1);
    for (size_t i = startIndex; i < endIndex; ++i)
    {
        std::vector<std::wstring> cols = NormalizeAutomationColumnsForDraw(lines[i], target);
        if (cols.size() < 2)
            continue;
        maxCols = std::max(maxCols, cols.size());
        size_t pc = AutomationPathColumnForDraw(target, cols);
        if (pc != static_cast<size_t>(-1))
            pathCol = pc;
    }

    if (maxCols == 0)
        return {};

    std::vector<float> widths(maxCols, 54.0f);
    for (size_t i = startIndex; i < endIndex; ++i)
    {
        std::vector<std::wstring> cols = NormalizeAutomationColumnsForDraw(lines[i], target);
        for (size_t c = 0; c < cols.size(); ++c)
            widths[c] = std::max(widths[c], measureCell(cols[c]));
    }

    if (pathCol == static_cast<size_t>(-1) || pathCol >= widths.size())
    {
        for (size_t c = widths.size(); c-- > 0; )
        {
            for (size_t i = startIndex; i < endIndex; ++i)
            {
                std::vector<std::wstring> cols = NormalizeAutomationColumnsForDraw(lines[i], target);
                if (c < cols.size() && IsPathLikeAutomationCell(cols[c]))
                {
                    pathCol = c;
                    break;
                }
            }
            if (pathCol != static_cast<size_t>(-1))
                break;
        }
    }

    if (widths.size() >= 3)
    {
        for (size_t c = 0; c < widths.size(); ++c)
        {
            if (c == pathCol)
                continue;
            float cap = (c == 0 ? 170.0f : 210.0f);
            if ((target == AUTOMATION_OUTPUT_JAR_ACTIVITY || target == AUTOMATION_OUTPUT_DLL_ACTIVITY) && c == 1)
                cap = 620.0f; // действие: created/deleted/rename + USN date in brackets
            if (target == AUTOMATION_OUTPUT_INJGEN && c == 1)
                cap = 72.0f; // процесс: javaw.exe, держим колонку короткой
            if (target == AUTOMATION_OUTPUT_FILECHECK && (c == 2 || c == 3))
                cap = 86.0f; // «Тип» и «Реальный тип» одинаковой ширины
            widths[c] = std::min(widths[c], cap);
            if ((target == AUTOMATION_OUTPUT_JAR_ACTIVITY || target == AUTOMATION_OUTPUT_DLL_ACTIVITY) && c == 1)
                widths[c] = std::max(widths[c], 430.0f);
            if (target == AUTOMATION_OUTPUT_INJGEN && c == 1)
                widths[c] = std::min(widths[c], 72.0f);
        }
    }

    if (target == AUTOMATION_OUTPUT_FILECHECK && widths.size() >= 4)
    {
        float typeW = std::max(widths[2], widths[3]);
        typeW = std::min(typeW, 86.0f);
        widths[2] = typeW;
        widths[3] = typeW;
    }

    float separators = sepW * static_cast<float>(widths.size() > 0 ? widths.size() - 1 : 0);
    float total = separators;
    for (float w : widths)
        total += w;

    if (pathCol != static_cast<size_t>(-1) && pathCol < widths.size())
    {
        float fixed = separators;
        for (size_t c = 0; c < widths.size(); ++c)
            if (c != pathCol)
                fixed += widths[c];

        const float minPathW = std::min(260.0f, std::max(150.0f, usableW * 0.45f));
        if (fixed + minPathW > usableW)
        {
            float fixedOnly = std::max(1.0f, fixed - separators);
            float fixedBudget = std::max(80.0f, usableW - minPathW - separators);
            float scale = std::max(0.35f, fixedBudget / fixedOnly);
            for (size_t c = 0; c < widths.size(); ++c)
            {
                if (c != pathCol)
                    widths[c] = std::max(38.0f, widths[c] * scale);
            }
            fixed = separators;
            for (size_t c = 0; c < widths.size(); ++c)
                if (c != pathCol)
                    fixed += widths[c];
        }

        // path in the whole result set, then it receives any free space. That keeps
        // all rows under the same vertical columns and prevents per-screen jumps.
        widths[pathCol] = std::max(widths[pathCol], std::max(140.0f, usableW - fixed));

        total = separators;
        for (float w : widths)
            total += w;
    }

    if (total > usableW)
    {
        if (pathCol != static_cast<size_t>(-1) && pathCol < widths.size())
        {
            float fixed = separators;
            for (size_t c = 0; c < widths.size(); ++c)
                if (c != pathCol)
                    fixed += widths[c];
            widths[pathCol] = std::max(90.0f, usableW - fixed);
        }
        else
        {
            float scale = (usableW - separators) / std::max(1.0f, total - separators);
            for (float& w : widths)
                w = std::max(48.0f, w * scale);
        }
    }

    return widths;
}


static bool IsAutomationResizableColumnTarget(int target)
{
    return target == AUTOMATION_OUTPUT_JAR_ACTIVITY ||
        target == AUTOMATION_OUTPUT_DLL_ACTIVITY ||
        target == AUTOMATION_OUTPUT_DLL_UNSIGNED ||
        target == AUTOMATION_OUTPUT_PAGE4 ||
        target == AUTOMATION_OUTPUT_FILECHECK;
}

static void ApplyAutomationColumnWidthOverrides(int target, std::vector<float>& widths)
{
    auto it = g_automationColumnWidthOverrides.find(target);
    if (it == g_automationColumnWidthOverrides.end())
        return;

    if (it->second.size() < widths.size())
        it->second.resize(widths.size(), 0.0f);

    for (size_t i = 0; i < widths.size() && i < it->second.size(); ++i)
    {
        if (it->second[i] > 0.0f)
            widths[i] = std::max(36.0f, it->second[i]);
    }
}

static std::vector<int> GetAutomationResizeTargetsForCurrentPage()
{
    if (g_currentPage == 1)
        return { AUTOMATION_OUTPUT_PAGE4 };
    if (g_currentPage == 2)
        return { AUTOMATION_OUTPUT_JAR_ACTIVITY, AUTOMATION_OUTPUT_DLL_ACTIVITY };
    if (g_currentPage == 5)
        return { AUTOMATION_OUTPUT_FILECHECK, AUTOMATION_OUTPUT_DLL_UNSIGNED };
    return {};
}

static bool AutomationColumnResizeHitTest(HWND hwnd, POINT pt, int& outTarget, size_t& outColumn, float& outColumnWidth)
{
    outTarget = 0;
    outColumn = static_cast<size_t>(-1);
    outColumnWidth = 0.0f;

    std::vector<int> targets = GetAutomationResizeTargetsForCurrentPage();
    if (targets.empty())
        return false;

    RECT rc{};
    GetClientRect(hwnd, &rc);

    HDC hdc = GetDC(hwnd);
    if (!hdc)
        return false;
    Graphics g(hdc);
    FontFamily family(g_homeMonoFace);
    Font lineFont(&family, static_cast<REAL>(MailsTheme::CaptionSize), FontStyleRegular, UnitPixel);

    bool hit = false;
    for (int target : targets)
    {
        if (!IsAutomationResizableColumnTarget(target))
            continue;

        RECT panel = GetAutomationPanelRectForTarget(target, rc);
        if (!PointInRect(panel, pt))
            continue;
        if (pt.y < panel.top + 28 || pt.y > panel.bottom - 8)
            continue;

        std::vector<std::wstring> lines;
        int scrollOffset = 0;
        GetAutomationSnapshot(target, lines, scrollOffset);
        if (lines.empty())
            continue;

        std::vector<float> widths = ComputeAutomationColumnWidths(g, lines, 0, lines.size(), target, lineFont, static_cast<float>(panel.right - panel.left));
        ApplyAutomationColumnWidthOverrides(target, widths);
        if (widths.size() < 2)
            continue;

        const float left = static_cast<float>(panel.left) + 10.0f;
        const float sepW = 6.0f;
        float cur = left;
        for (size_t i = 0; i + 1 < widths.size(); ++i)
        {
            cur += widths[i];
            if (((static_cast<float>(pt.x) - cur) >= -5.0f && (static_cast<float>(pt.x) - cur) <= 5.0f))
            {
                outTarget = target;
                outColumn = i;
                outColumnWidth = widths[i];
                hit = true;
                break;
            }
            cur += sepW;
        }
        if (hit)
            break;
    }

    ReleaseDC(hwnd, hdc);
    return hit;
}

static void DrawAutomationPipeSeparatedRow(Graphics& g, const std::wstring& line, int target, const Font& lineFont, float x, float y, float panelW, float lineH, size_t rowIndex = static_cast<size_t>(-1), const std::vector<float>* sharedWidths = nullptr)
{
    std::vector<std::wstring> cols = NormalizeAutomationColumnsForDraw(line, target);
    if (cols.size() < 2)
        return;

    SolidBrush textBrush(MailsUi::ToColor(MailsTheme::Text));
    SolidBrush deletedNameBrush(MailsUi::ToColor(MailsTheme::Error));
    SolidBrush forbiddenNameBrush(MailsUi::ToColor(MailsTheme::Error));
    SolidBrush renamedNameBrush(MailsUi::ToColor(MailsTheme::Warning));
    SolidBrush archiveNameBrush(MailsUi::ToColor(MailsTheme::Warning));
    SolidBrush sepBrush(MailsUi::ToColor(MailsTheme::Muted));
    StringFormat fmt;
    fmt.SetTrimming(StringTrimmingEllipsisCharacter);
    fmt.SetFormatFlags(StringFormatFlagsNoWrap | StringFormatFlagsLineLimit);

    StringFormat fmtPath;
    fmtPath.SetTrimming(StringTrimmingNone);
    fmtPath.SetFormatFlags(StringFormatFlagsNoWrap | StringFormatFlagsLineLimit);

    StringFormat measurePathFmt;
    measurePathFmt.SetFormatFlags(StringFormatFlagsNoWrap | StringFormatFlagsMeasureTrailingSpaces);

    const float left = x + 10.0f;
    const float sepW = 6.0f;
    float cur = left;

    size_t pathCol = AutomationPathColumnForDraw(target, cols);
    std::vector<float> widths;
    if (sharedWidths && sharedWidths->size() >= cols.size())
        widths = *sharedWidths;
    else
        widths = ComputeAutomationColumnWidths(g, std::vector<std::wstring>{ line }, 0, 1, target, lineFont, panelW);

    // file check: строки со статусом «ВОЗМОЖНО ЧИТ» подсвечиваются красным.
    // «ПОДОЗРИТЕЛЬНО» остаётся без подсветки. Жёлтой подсветки больше нет.
    bool cheatRow = (target == AUTOMATION_OUTPUT_FILECHECK) &&
        (line.find(L"ВОЗМОЖНО ЧИТ") != std::wstring::npos);
    if (cheatRow)
    {
        float execRowW = std::max(20.0f, panelW - 24.0f);
        SolidBrush execBrush(Color(18, 255, 56, 56)); // мягкая прозрачная красная подсветка
        g.FillRectangle(&execBrush, RectF(left - 4.0f, y - 1.0f, execRowW, lineH + 1.0f));
    }

    bool highlightRow = (target == g_automationCopyHighlightTarget && rowIndex == g_automationCopyHighlightIndex);
    SolidBrush highlightBrush(Color(45, 164, 220, 143));
    Pen highlightPen(MailsUi::ToColor(MailsTheme::Accent), 1.0f);

    if (highlightRow)
    {
        float rowW = std::max(20.0f, panelW - 24.0f);
        g.FillRectangle(&highlightBrush, RectF(left - 4.0f, y - 1.0f, rowW, lineH + 1.0f));
        g.DrawRectangle(&highlightPen, RectF(left - 4.0f, y - 1.0f, rowW, lineH + 1.0f));
    }

    for (size_t i = 0; i < cols.size(); ++i)
    {
        float colW = (i < widths.size()) ? widths[i] : 60.0f;

        bool deletedRow = AutomationLineHasDeletedMarker(line);
        bool archiveRow = AutomationLineHasArchiveMarker(line);
        bool forbiddenRow = AutomationLineHasForbiddenMarker(line);
        bool renamedRow = AutomationLineHasRenamedMarker(line);
        Brush* cellBrush = (deletedRow && i > 0) ? static_cast<Brush*>(&deletedNameBrush) : static_cast<Brush*>(&textBrush);
        if (cheatRow)
            cellBrush = static_cast<Brush*>(&deletedNameBrush); // красный текст строки
        if (forbiddenRow && target == AUTOMATION_OUTPUT_PAGE4 && i == 0)
            cellBrush = static_cast<Brush*>(&forbiddenNameBrush);
        else if (renamedRow && target == AUTOMATION_OUTPUT_PAGE4 && i == 0)
            cellBrush = static_cast<Brush*>(&renamedNameBrush);
        else if (archiveRow && i == 0)
            cellBrush = static_cast<Brush*>(&archiveNameBrush);
        bool isLastCol = (i + 1 == cols.size());
        if (i == pathCol && isLastCol)
        {
            // Clip the path to the panel's right edge so text never spills
            // outside the frame; ellipsize when the full path does not fit.
            (void)measurePathFmt;
            (void)fmtPath;
            float availW = (x + panelW - 22.0f) - cur;
            if (availW < 20.0f)
                availW = 20.0f;
            g.DrawString(cols[i].c_str(), -1, &lineFont, RectF(cur, y, availW, lineH + 2.0f), &fmt, cellBrush);
        }
        else
        {
            g.DrawString(cols[i].c_str(), -1, &lineFont, RectF(cur, y, colW, lineH + 2.0f), &fmt, cellBrush);
        }
        cur += colW;

        if (i + 1 < cols.size())
        {
            g.DrawString(L"|", -1, &lineFont, RectF(cur, y, sepW, lineH + 2.0f), &fmt, &sepBrush);
            cur += sepW;
        }
    }
}

static void DrawAutomationOutputPanel(Graphics& g, RECT panelRect, const wchar_t* title, int target)
{
    std::vector<std::wstring> lines;
    int scrollOffset = 0;
    GetAutomationSnapshot(target, lines, scrollOffset);

    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);

    RectF bgRect(
        static_cast<REAL>(panelRect.left),
        static_cast<REAL>(panelRect.top),
        static_cast<REAL>(panelRect.right - panelRect.left),
        static_cast<REAL>(panelRect.bottom - panelRect.top)
    );

    GraphicsPath bgPath;
    bgPath.AddArc(bgRect.X, bgRect.Y, 14.0f, 14.0f, 180.0f, 90.0f);
    bgPath.AddArc(bgRect.GetRight() - 14.0f, bgRect.Y, 14.0f, 14.0f, 270.0f, 90.0f);
    bgPath.AddArc(bgRect.GetRight() - 14.0f, bgRect.GetBottom() - 14.0f, 14.0f, 14.0f, 0.0f, 90.0f);
    bgPath.AddArc(bgRect.X, bgRect.GetBottom() - 14.0f, 14.0f, 14.0f, 90.0f, 90.0f);
    bgPath.CloseFigure();

    bool transparentPanel = (target == AUTOMATION_OUTPUT_PAGE4 || target == AUTOMATION_OUTPUT_EVENTVWR || target == AUTOMATION_OUTPUT_JAR_ACTIVITY || target == AUTOMATION_OUTPUT_JAR_MODIFIED || target == AUTOMATION_OUTPUT_EXE_DELETED || target == AUTOMATION_OUTPUT_MC_LOGS || target == AUTOMATION_OUTPUT_PF_DELETED || target == AUTOMATION_OUTPUT_DLL_UNSIGNED || target == AUTOMATION_OUTPUT_DLL_ACTIVITY);
    SolidBrush bgBrush(MailsUi::ToColor(transparentPanel ? MailsTheme::Canvas : MailsTheme::Inset));
    Pen borderPen(MailsUi::ToColor(MailsTheme::Line), 1.0f);

    if (!transparentPanel)
        g.FillPath(&bgBrush, &bgPath);
    g.DrawPath(&borderPen, &bgPath);

    FontFamily family(g_homeMonoFace);
    Font titleFont(&family, static_cast<REAL>(MailsTheme::CaptionSize), FontStyleRegular, UnitPixel);
    Font lineFont(&family, static_cast<REAL>(MailsTheme::CaptionSize), FontStyleRegular, UnitPixel);
    SolidBrush titleBrush(MailsUi::ToColor(MailsTheme::Text));
    SolidBrush textBrush(MailsUi::ToColor(MailsTheme::Text));
    SolidBrush hintBrush(MailsUi::ToColor(MailsTheme::Muted));

    StringFormat fmt;
    fmt.SetTrimming(StringTrimmingEllipsisCharacter);
    fmt.SetFormatFlags(StringFormatFlagsNoWrap);

    const float x = static_cast<float>(panelRect.left);
    const float y = static_cast<float>(panelRect.top);
    const float panelW = static_cast<float>(panelRect.right - panelRect.left);
    const float panelH = static_cast<float>(panelRect.bottom - panelRect.top);

    g.DrawString(title, -1, &titleFont, RectF(x + 10.0f, y + 6.0f, panelW - 20.0f, 20.0f), &fmt, &titleBrush);

    if (target == AUTOMATION_OUTPUT_EVENTVWR)
        return;

    const float lineH = 15.0f;
    size_t panelLineCapacityHint = static_cast<size_t>(std::max(1.0f, (panelRect.bottom - panelRect.top - 34.0f) / lineH));

    if (lines.size() > panelLineCapacityHint)
    {
        StringFormat rightFmt;
        rightFmt.SetAlignment(StringAlignmentFar);
        rightFmt.SetTrimming(StringTrimmingEllipsisCharacter);
        rightFmt.SetFormatFlags(StringFormatFlagsNoWrap);
        g.DrawString(L"scroll", -1, &lineFont, RectF(x + 10.0f, y + 7.0f, panelW - 20.0f, 16.0f), &rightFmt, &hintBrush);
    }

    if (!lines.empty() && lines.size() > panelLineCapacityHint)
    {
        int maxOffsetBar = std::max<int>(1, static_cast<int>(lines.size()) - static_cast<int>(panelLineCapacityHint));
        float trackX = x + panelW - 10.0f;
        float trackY = y + 30.0f;
        float trackH = panelH - 39.0f;
        SolidBrush trackBrush(MailsUi::ToColor(MailsTheme::Surface));
        SolidBrush thumbBrush(MailsUi::ToColor(MailsTheme::Accent));
        g.FillRectangle(&trackBrush, RectF(trackX, trackY, 6.0f, trackH));
        float thumbH = std::max(22.0f, trackH * (static_cast<float>(panelLineCapacityHint) / static_cast<float>(lines.size())));
        float thumbY = trackY + (trackH - thumbH) * (static_cast<float>(scrollOffset) / static_cast<float>(maxOffsetBar));
        g.FillRectangle(&thumbBrush, RectF(trackX - 2.0f, thumbY, 10.0f, thumbH));
    }

    if (lines.empty())
    {
        g.DrawString(L"Нажмите кнопку слева.", -1, &lineFont, RectF(x + 10.0f, y + 31.0f, panelW - 20.0f, 20.0f), &fmt, &hintBrush);
        return;
    }

    size_t visibleLines = std::min(panelLineCapacityHint, lines.size());
    size_t startIndex = static_cast<size_t>(std::max(0, scrollOffset));
    if (startIndex >= lines.size())
        startIndex = lines.size() > visibleLines ? lines.size() - visibleLines : 0;
    size_t endIndex = std::min(lines.size(), startIndex + visibleLines);

    float lineY = y + 30.0f;
    SolidBrush rowBrush(MailsUi::ToColor(MailsTheme::Surface));
    Pen rowLinePen(MailsUi::ToColor(MailsTheme::Line), 1.0f);
    // rows. The longest path/name becomes the base for every row, so scrolling or
    // new rows do not make columns shift independently.
    std::vector<float> sharedPipeWidths = ComputeAutomationColumnWidths(g, lines, 0, lines.size(), target, lineFont, panelW);
    ApplyAutomationColumnWidthOverrides(target, sharedPipeWidths);

    for (size_t i = startIndex; i < endIndex; ++i)
    {
        RectF textRect(x + 10.0f, lineY, panelW - 30.0f, lineH + 1.0f);
        bool pipeRow = IsPipeSeparatedAutomationRow(lines[i]);
        bool bamRow = target == AUTOMATION_OUTPUT_BAM && IsBamDataRowForColumns(lines[i]);
        bool linedRow = bamRow || (target != AUTOMATION_OUTPUT_EVENTVWR && pipeRow);

        if (linedRow)
        {
            if ((i - startIndex) % 2 == 0)
                g.FillRectangle(&rowBrush, RectF(x + 7.0f, lineY - 1.0f, panelW - 25.0f, lineH + 1.0f));
            g.DrawLine(&rowLinePen, x + 8.0f, lineY + lineH, x + panelW - 17.0f, lineY + lineH);
        }

        if (bamRow)
            DrawBamDataRow(g, lines[i], lineFont, x, lineY, panelW, lineH);
        else if (target != AUTOMATION_OUTPUT_EVENTVWR && pipeRow)
            DrawAutomationPipeSeparatedRow(g, lines[i], target, lineFont, x, lineY, panelW, lineH, i, &sharedPipeWidths);
        else
            { std::wstring displayLine = StripAutomationDeletedMarker(lines[i]); g.DrawString(displayLine.c_str(), -1, &lineFont, textRect, &fmt, &textBrush); }

        lineY += lineH;

        if (lineY > y + panelH - 8.0f)
            break;
    }
}


struct AutomationServiceUiRow
{
    const wchar_t* label;
    const wchar_t* serviceName;
    bool running;
    DWORD processId;
    std::wstring startTime;
};

static std::wstring FormatFileTimeLocalFull(const FILETIME& ft)
{
    FILETIME localFt{};
    SYSTEMTIME st{};
    if (!FileTimeToLocalFileTime(&ft, &localFt) || !FileTimeToSystemTime(&localFt, &st))
        return L"-";
    wchar_t buf[32]{};
    swprintf_s(buf, L"%02u.%02u.%04u %02u:%02u:%02u", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static std::wstring FormatSystemTimeFull(const SYSTEMTIME& st)
{
    wchar_t buf[32]{};
    swprintf_s(buf, L"%02u.%02u.%04u %02u:%02u:%02u", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static std::wstring QueryProcessStartTimeFull(DWORD processId)
{
    if (processId == 0)
        return L"-";

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process)
        process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!process)
        return L"-";

    FILETIME created{}, exited{}, kernel{}, user{};
    bool ok = GetProcessTimes(process, &created, &exited, &kernel, &user) != FALSE;
    CloseHandle(process);
    return ok ? FormatFileTimeLocalFull(created) : L"-";
}

static bool QueryAutomationServiceRunning(const wchar_t* serviceName, bool& running, DWORD& processId)
{
    running = false;
    processId = 0;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);

    if (!scm)
        return false;

    SC_HANDLE service = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);

    if (!service)
    {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    BOOL ok = QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status),
        sizeof(status),
        &bytesNeeded
    );

    if (ok)
    {
        running = status.dwCurrentState == SERVICE_RUNNING;
        processId = status.dwProcessId;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return ok == TRUE;
}

static std::wstring GetLastBootTimeText()
{
    FILETIME nowFt{};
    GetSystemTimeAsFileTime(&nowFt);
    ULARGE_INTEGER now{};
    now.LowPart = nowFt.dwLowDateTime;
    now.HighPart = nowFt.dwHighDateTime;

    ULONGLONG uptime100ns = GetTickCount64() * 10000ULL;
    if (now.QuadPart <= uptime100ns)
        return L"не удалось получить";

    ULARGE_INTEGER boot{};
    boot.QuadPart = now.QuadPart - uptime100ns;
    FILETIME bootFt{ boot.LowPart, boot.HighPart };
    FILETIME localFt{};
    SYSTEMTIME st{};
    if (!FileTimeToLocalFileTime(&bootFt, &localFt) || !FileTimeToSystemTime(&localFt, &st))
        return L"не удалось получить";
    return FormatSystemTimeFull(st);
}

static std::vector<AutomationServiceUiRow> GetAutomationServiceRows()
{
    static ULONGLONG lastTick = 0;
    static std::vector<AutomationServiceUiRow> cached;

    ULONGLONG now = GetTickCount64();

    if (!cached.empty() && now - lastTick < 1200)
        return cached;

    struct ServiceDef
    {
        const wchar_t* label;
        const wchar_t* name;
    };

    static const ServiceDef defs[] =
    {
        { L"bam", L"bam" },
        { L"pcascv", L"PcaSvc" },
        { L"sysmain", L"SysMain" },
        { L"dps", L"DPS" },
        { L"eventlog", L"EventLog" }
    };

    std::vector<AutomationServiceUiRow> rows;
    rows.reserve(sizeof(defs) / sizeof(defs[0]));

    for (const ServiceDef& def : defs)
    {
        bool running = false;
        DWORD processId = 0;
        QueryAutomationServiceRunning(def.name, running, processId);
        rows.push_back({ def.label, def.name, running, processId, running ? QueryProcessStartTimeFull(processId) : L"-" });
    }

    cached = rows;
    lastTick = now;
    return cached;
}

static void DrawAutomationServicesPanel(Graphics& g, RECT panelRect)
{
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);

    RectF bgRect(
        static_cast<REAL>(panelRect.left),
        static_cast<REAL>(panelRect.top),
        static_cast<REAL>(panelRect.right - panelRect.left),
        static_cast<REAL>(panelRect.bottom - panelRect.top)
    );

    GraphicsPath bgPath;
    bgPath.AddArc(bgRect.X, bgRect.Y, 14.0f, 14.0f, 180.0f, 90.0f);
    bgPath.AddArc(bgRect.GetRight() - 14.0f, bgRect.Y, 14.0f, 14.0f, 270.0f, 90.0f);
    bgPath.AddArc(bgRect.GetRight() - 14.0f, bgRect.GetBottom() - 14.0f, 14.0f, 14.0f, 0.0f, 90.0f);
    bgPath.AddArc(bgRect.X, bgRect.GetBottom() - 14.0f, 14.0f, 14.0f, 90.0f, 90.0f);
    bgPath.CloseFigure();

    SolidBrush bgBrush(MailsUi::ToColor(MailsTheme::Inset));
    Pen borderPen(MailsUi::ToColor(MailsTheme::Line), 1.0f);
    g.FillPath(&bgBrush, &bgPath);
    g.DrawPath(&borderPen, &bgPath);

    FontFamily family(g_homeMonoFace);
    Font titleFont(&family, static_cast<REAL>(MailsTheme::CaptionSize), FontStyleRegular, UnitPixel);
    Font lineFont(&family, 12.0f, FontStyleRegular, UnitPixel);

    SolidBrush titleBrush(MailsUi::ToColor(MailsTheme::Text));
    SolidBrush headerBrush(MailsUi::ToColor(MailsTheme::Muted));
    SolidBrush nameBrush(MailsUi::ToColor(MailsTheme::Text));
    SolidBrush onBrush(MailsUi::ToColor(MailsTheme::Success));
    SolidBrush offBrush(MailsUi::ToColor(MailsTheme::Error));
    SolidBrush bootBrush(MailsUi::ToColor(MailsTheme::Text));
    Pen sepPen(MailsUi::ToColor(MailsTheme::Line), 1.0f);

    StringFormat fmt;
    fmt.SetTrimming(StringTrimmingEllipsisCharacter);
    fmt.SetFormatFlags(StringFormatFlagsNoWrap | StringFormatFlagsLineLimit);

    StringFormat centerFmt;
    centerFmt.SetAlignment(StringAlignmentCenter);
    centerFmt.SetTrimming(StringTrimmingEllipsisCharacter);
    centerFmt.SetFormatFlags(StringFormatFlagsNoWrap | StringFormatFlagsLineLimit);

    const float x = static_cast<float>(panelRect.left);
    const float y = static_cast<float>(panelRect.top);
    const float w = static_cast<float>(panelRect.right - panelRect.left);

    g.DrawString(L"Службы", -1, &titleFont, RectF(x + 14.0f, y + 9.0f, w - 28.0f, 18.0f), &fmt, &titleBrush);
    g.DrawLine(&sepPen, x + 12.0f, y + 30.0f, x + w - 12.0f, y + 30.0f);

    const float nameX = x + 14.0f;
    const float statusX = x + 104.0f;
    const float timeX = x + 172.0f;
    g.DrawString(L"имя", -1, &lineFont, RectF(nameX, y + 34.0f, 84.0f, 16.0f), &fmt, &headerBrush);
    g.DrawString(L"статус", -1, &lineFont, RectF(statusX, y + 34.0f, 62.0f, 16.0f), &fmt, &headerBrush);
    g.DrawString(L"старт", -1, &lineFont, RectF(timeX, y + 34.0f, w - 186.0f, 16.0f), &fmt, &headerBrush);

    std::vector<AutomationServiceUiRow> rows = GetAutomationServiceRows();
    float rowY = y + 52.0f;
    const float rowH = 18.0f;

    for (const AutomationServiceUiRow& row : rows)
    {
        const wchar_t* status = row.running ? L"вкл" : L"выкл";
        Brush* statusBrush = row.running ? static_cast<Brush*>(&onBrush) : static_cast<Brush*>(&offBrush);
        g.DrawString(row.label, -1, &lineFont, RectF(nameX, rowY, 84.0f, rowH), &fmt, &nameBrush);
        g.DrawString(status, -1, &lineFont, RectF(statusX, rowY, 62.0f, rowH), &fmt, statusBrush);
        g.DrawString(row.startTime.c_str(), -1, &lineFont, RectF(timeX, rowY, w - 186.0f, rowH), &fmt, &nameBrush);
        rowY += rowH;
    }

    g.DrawLine(&sepPen, x + 12.0f, rowY + 4.0f, x + w - 12.0f, rowY + 4.0f);
    rowY += 12.0f;
    g.DrawString(L"Вкл ПК", -1, &titleFont, RectF(x + 14.0f, rowY, 96.0f, 18.0f), &fmt, &titleBrush);
    std::wstring boot = GetLastBootTimeText();
    g.DrawString(boot.c_str(), -1, &lineFont, RectF(x + 96.0f, rowY + 1.0f, w - 110.0f, 18.0f), &fmt, &bootBrush);
}

static void DrawAutomationScreen(Graphics& g, RECT rc)
{
    g.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);

    // Вкладка check: checkmods сверху во всю ширину, снизу — eventvwr и панель
    // служб (со временем включения ПК), как было раньше. Вся область совпадает
    // по размеру с вкладками dll | jar и file check.
    RECT checkModsPanel = GetAutomationBamPanelRect(rc);
    RECT eventPanel = GetAutomationEventPanelRect(rc);
    RECT servicesPanel = GetAutomationServicesPanelRect(rc);

    DrawAutomationOutputPanel(g, checkModsPanel, L"checkmods", AUTOMATION_OUTPUT_PAGE4);
    DrawAutomationOutputPanel(g, eventPanel, L"eventvwr", AUTOMATION_OUTPUT_EVENTVWR);
    DrawAutomationServicesPanel(g, servicesPanel);
}

static void DrawJarActivityScreen(Graphics& g, RECT rc)
{
    g.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);
    DrawAutomationOutputPanel(g, GetJarActivityPanelRect(rc), L".jar activity", AUTOMATION_OUTPUT_JAR_ACTIVITY);
    DrawAutomationOutputPanel(g, GetDllActivityPanelRect(rc), L".dll activity", AUTOMATION_OUTPUT_DLL_ACTIVITY);
}

static void DrawPage4Screen(Graphics& g, RECT rc)
{
    g.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);
    RECT panel = GetFullAutomationPanelRect(rc);
    RectF textRect(static_cast<REAL>(panel.left + 14), static_cast<REAL>(panel.top + 14),
        static_cast<REAL>(panel.right - panel.left - 28), 80.0f);
    FontFamily family(g_homeFontFace);
    Font font(&family, 14.0f, FontStyleBold, UnitPixel);
    SolidBrush brush(MailsUi::ToColor(MailsTheme::Text));
    StringFormat fmt;
    fmt.SetTrimming(StringTrimmingEllipsisCharacter);
    g.DrawString(L"checkmods перенесён во вкладку check, unsigned dll перенесён во вкладку file check.", -1, &font, textRect, &fmt, &brush);
}

static void DrawPage5Screen(Graphics& g, RECT rc)
{
    // Вкладка "file check": верхняя панель — проверка совпадения
    // фактического типа с расширением, нижняя — unsigned dll.
    DrawAutomationOutputPanel(g, GetFileCheckPanelRect(rc),
        L"file check — тип файла не совпадает с расширением", AUTOMATION_OUTPUT_FILECHECK);
    DrawAutomationOutputPanel(g, GetDllUnsignedPanelRect(rc),
        L"unsigned dll", AUTOMATION_OUTPUT_DLL_UNSIGNED);
}


static bool EnsureSceneBuffer(HDC targetHdc, int width, int height)
{
    if (!g_sceneBufferDc)
        g_sceneBufferDc = CreateCompatibleDC(targetHdc);
    if (!g_sceneBufferDc)
        return false;

    if (g_sceneBufferBitmap &&
        g_sceneBufferWidth == width && g_sceneBufferHeight == height)
        return true;

    if (g_sceneBufferBitmap)
    {
        SelectObject(g_sceneBufferDc, g_sceneBufferOldBitmap);
        DeleteObject(g_sceneBufferBitmap);
        g_sceneBufferBitmap = nullptr;
        g_sceneBufferOldBitmap = nullptr;
    }

    g_sceneBufferBitmap = CreateCompatibleBitmap(targetHdc, width, height);
    if (!g_sceneBufferBitmap)
        return false;
    g_sceneBufferOldBitmap = SelectObject(g_sceneBufferDc, g_sceneBufferBitmap);
    g_sceneBufferWidth = width;
    g_sceneBufferHeight = height;
    return true;
}

static void ReleaseSceneBuffer()
{
    if (g_sceneBufferDc && g_sceneBufferBitmap)
    {
        SelectObject(g_sceneBufferDc, g_sceneBufferOldBitmap);
        DeleteObject(g_sceneBufferBitmap);
    }
    if (g_sceneBufferDc)
        DeleteDC(g_sceneBufferDc);
    g_sceneBufferDc = nullptr;
    g_sceneBufferBitmap = nullptr;
    g_sceneBufferOldBitmap = nullptr;
    g_sceneBufferWidth = 0;
    g_sceneBufferHeight = 0;
}

static void DrawScene(HWND hwnd, HDC targetHdc)
{
    RECT rc{};
    GetClientRect(hwnd, &rc);

    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;

    if (w <= 0 || h <= 0)
        return;

    if (!EnsureSceneBuffer(targetHdc, w, h))
        return;
    HDC memDC = g_sceneBufferDc;

    HBRUSH bgBrush = CreateSolidBrush(BG);
    FillRect(memDC, &rc, bgBrush);
    DeleteObject(bgBrush);

    Graphics g(memDC);
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(PixelOffsetModeHighQuality);
    g.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);

    MailsUi::Configure(g);
    MailsUi::DrawHeader(g, rc);

    if (g_currentPage == 1)
    {
        DrawAutomationScreen(g, rc);
    }
    else if (g_currentPage == 2)
    {
        DrawJarActivityScreen(g, rc);
    }
    else if (g_currentPage == 3)
    {
        DrawPage4Screen(g, rc);
    }
    else if (g_currentPage == 5)
    {
        DrawPage5Screen(g, rc);
    }
    else
    {
        MailsUi::DrawHome(g, rc);
    }

    g.Flush(FlushIntentionSync);
    BitBlt(targetHdc, 0, 0, w, h, memDC, 0, 0, SRCCOPY);

}

static void MoveChildWindow(HWND child, int x, int y, int w, int h, BOOL repaint)
{
    if (!child)
        return;

    RECT current{};
    GetWindowRect(child, &current);

    HWND parent = GetParent(child);
    POINT pts[2] =
    {
        { current.left, current.top },
        { current.right, current.bottom }
    };

    MapWindowPoints(nullptr, parent, pts, 2);

    if (pts[0].x == x && pts[0].y == y &&
        pts[1].x - pts[0].x == w && pts[1].y - pts[0].y == h)
    {
        return;
    }

    MoveWindow(child, x, y, w, h, repaint);
}

static void SetChildVisible(HWND child, bool visible)
{
    if (!child)
        return;

    bool current = IsWindowVisible(child) != FALSE;

    if (current == visible)
        return;

    ShowWindow(child, visible ? SW_SHOWNA : SW_HIDE);
}

static void LayoutControls(HWND hwnd)
{
    RECT rc{};
    GetClientRect(hwnd, &rc);

    int width = rc.right;

    const int topButtonH = MailsTheme::Target;
    const int topGap = MailsTheme::Grid;
    const int topY = 12;
    const int navButtonW = 116;
    const int navX = width - HOME_MARGIN - navButtonW;

    if ((g_currentPage >= 1 && g_currentPage <= 3) || g_currentPage == 5)
    {
        ShowWindow(g_hDeleteHolyCheck, SW_HIDE);
        ShowWindow(g_hEnableServices, SW_HIDE);
        ShowWindow(g_hPowerShell, SW_HIDE);
        ShowWindow(g_hCancelDownload, SW_HIDE);
        ShowWindow(g_hDownloadAll, SW_HIDE);
        ShowWindow(g_hSearchCheats, SW_HIDE);
        ShowWindow(g_hSearchConfigs, SW_HIDE);
        ShowWindow(g_hOpenDownloads, SW_HIDE);
        ShowWindow(g_hCopyPowerShell, SW_HIDE);
        ShowWindow(g_hCopySites, SW_HIDE);

        ShowWindow(MailsUi::catalog, SW_HIDE);

        auto hidePageButtons = []()
        {
            ShowWindow(g_hHomeNav, SW_HIDE);
            ShowWindow(g_hAutomationBam, SW_HIDE);
            ShowWindow(g_hAutomationBamUnsignedOnly, SW_HIDE);
            ShowWindow(g_hAutomationEventVwr, SW_HIDE);
            ShowWindow(g_hAutomationJarPage, SW_HIDE);
            ShowWindow(g_hJarActiv, SW_HIDE);
            ShowWindow(g_hExeDeleted, SW_HIDE);
            ShowWindow(g_hPfDeleted, SW_HIDE);
            ShowWindow(g_hMcLogs, SW_HIDE);
            ShowWindow(g_hPage4Nav, SW_HIDE);
            ShowWindow(g_hModHash, SW_HIDE);
            ShowWindow(g_hModFullScan, SW_HIDE);
            ShowWindow(g_hDllUnsigned, SW_HIDE);
            ShowWindow(g_hDllActivity, SW_HIDE);
            ShowWindow(g_hPage5Nav, SW_HIDE);
            ShowWindow(g_hInjGenCheck, SW_HIDE);
            ShowWindow(g_hEventEdit, SW_HIDE);
            ShowWindow(g_hJarEdit, SW_HIDE);
            ShowWindow(g_hExeEdit, SW_HIDE);
            ShowWindow(g_hPfEdit, SW_HIDE);
            ShowWindow(g_hMcEdit, SW_HIDE);
            ShowWindow(g_hFileCheckScan, SW_HIDE);
            ShowWindow(g_hClipShow, SW_HIDE);
            ShowWindow(g_hClipProc, SW_HIDE);
        };

        hidePageButtons();

        if (g_currentPage == 1)
        {
            RECT scanButton = GetAutomationBamButtonRect(rc);
            RECT fullScanButton = GetModFullScanButtonRect(rc);
            RECT eventButton = GetAutomationEventButtonRect(rc);
            RECT jarPageButton = GetAutomationJarPageButtonRect(rc);

            RECT page4Button = jarPageButton;
            page4Button.right = page4Button.left - topGap;
            page4Button.left = page4Button.right - navButtonW;

            MoveChildWindow(g_hModHash, scanButton.left, scanButton.top, scanButton.right - scanButton.left, scanButton.bottom - scanButton.top, TRUE);
            MoveChildWindow(g_hModFullScan, fullScanButton.left, fullScanButton.top, fullScanButton.right - fullScanButton.left, fullScanButton.bottom - fullScanButton.top, TRUE);
            MoveChildWindow(g_hAutomationJarPage, jarPageButton.left, jarPageButton.top, jarPageButton.right - jarPageButton.left, jarPageButton.bottom - jarPageButton.top, TRUE);
            MoveChildWindow(g_hPage4Nav, page4Button.left, page4Button.top, page4Button.right - page4Button.left, page4Button.bottom - page4Button.top, TRUE);

            RECT eventPanel = GetAutomationEventPanelRect(rc);
            MoveChildWindow(g_hEventEdit, eventPanel.left + 10, eventPanel.top + 30, eventPanel.right - eventPanel.left - 22, eventPanel.bottom - eventPanel.top - 40, TRUE);
            ShowScrollBar(g_hEventEdit, SB_BOTH, FALSE);
            SetWindowTextW(g_hAutomationNav, L"check");
            SetWindowTextW(g_hModHash, L"Проверить");
            SetWindowTextW(g_hModFullScan, L"fullscan");
            SetWindowTextW(g_hAutomationJarPage, L"dll | jar");
            SetWindowTextW(g_hPage4Nav, L"");

            ShowWindow(g_hAutomationBam, SW_HIDE);
            ShowWindow(g_hModHash, SW_SHOWNA);
            ShowWindow(g_hModFullScan, SW_HIDE);
            ShowWindow(g_hAutomationBamUnsignedOnly, SW_HIDE);
            ShowWindow(g_hAutomationEventVwr, SW_HIDE);
            ShowWindow(g_hAutomationJarPage, SW_SHOWNA);
            ShowWindow(g_hPage4Nav, SW_HIDE);
            ShowWindow(g_hEventEdit, SW_SHOWNA);
        }
        else if (g_currentPage == 2)
        {
            RECT jarButton = GetJarActivButtonRect(rc);
            MoveChildWindow(g_hJarActiv, jarButton.left, jarButton.top, jarButton.right - jarButton.left, jarButton.bottom - jarButton.top, TRUE);

            RECT jarPanel = GetJarActivityPanelRect(rc);
            MoveChildWindow(g_hJarEdit, jarPanel.left + 10, jarPanel.top + 30, jarPanel.right - jarPanel.left - 34, jarPanel.bottom - jarPanel.top - 40, TRUE);
            SetWindowTextW(g_hJarActiv, L"Проверить");
            ShowWindow(g_hJarActiv, SW_SHOWNA);
            ShowWindow(g_hDllActivity, SW_HIDE);
            ShowWindow(g_hExeDeleted, SW_HIDE);
            ShowWindow(g_hPfDeleted, SW_HIDE);
            ShowWindow(g_hMcLogs, SW_HIDE);
            ShowWindow(g_hJarEdit, SW_HIDE);
            ShowWindow(g_hExeEdit, SW_HIDE);
            ShowWindow(g_hPfEdit, SW_HIDE);
            ShowWindow(g_hMcEdit, SW_HIDE);
        }
        else if (g_currentPage == 3)
        {
            ShowWindow(g_hModHash, SW_HIDE);
            ShowWindow(g_hModFullScan, SW_HIDE);
            ShowWindow(g_hDllUnsigned, SW_HIDE);
        }
        else if (g_currentPage == 5)
        {
            // Только кнопка scan; кнопки буфера обмена скрыты.
            RECT scanBtn = GetFileCheckButtonRect(rc);
            MoveChildWindow(g_hFileCheckScan, scanBtn.left, scanBtn.top, scanBtn.right - scanBtn.left, scanBtn.bottom - scanBtn.top, TRUE);
            SetWindowTextW(g_hFileCheckScan, L"Проверить");
            ShowWindow(g_hFileCheckScan, SW_SHOWNA);
            ShowWindow(g_hClipShow, SW_HIDE);
            ShowWindow(g_hClipProc, SW_HIDE);
        }
        auto showTopNavAll = [&]()
        {
            int x = navX;
            auto place = [&](HWND h, const wchar_t* text)
            {
                if (!h) return;
                MoveChildWindow(h, x, topY, navButtonW, topButtonH, TRUE);
                SetWindowTextW(h, text);
                ShowWindow(h, SW_SHOWNA);
                x -= navButtonW + topGap;
            };
            place(g_hHomeNav, L"Главная");
            ShowWindow(g_hPage4Nav, SW_HIDE);
            place(g_hAutomationJarPage, L"DLL / JAR");
            place(g_hPage5Nav, L"Файлы");
            place(g_hAutomationNav, L"Проверки");
        };
        showTopNavAll();

        InvalidateRect(g_hHomeNav, nullptr, TRUE);
        InvalidateRect(g_hAutomationNav, nullptr, TRUE);
        InvalidateRect(g_hAutomationBam, nullptr, TRUE);
        InvalidateRect(g_hAutomationBamUnsignedOnly, nullptr, TRUE);
        InvalidateRect(g_hAutomationEventVwr, nullptr, TRUE);
        InvalidateRect(g_hAutomationJarPage, nullptr, TRUE);
        InvalidateRect(g_hJarActiv, nullptr, TRUE);
        InvalidateRect(g_hExeDeleted, nullptr, TRUE);
        InvalidateRect(g_hPfDeleted, nullptr, TRUE);
        InvalidateRect(g_hMcLogs, nullptr, TRUE);
        InvalidateRect(g_hPage4Nav, nullptr, TRUE);
        InvalidateRect(g_hModHash, nullptr, TRUE);
        InvalidateRect(g_hModFullScan, nullptr, TRUE);
        InvalidateRect(g_hDllUnsigned, nullptr, TRUE);
        InvalidateRect(g_hDllActivity, nullptr, TRUE);
        InvalidateRect(g_hPage5Nav, nullptr, TRUE);
        InvalidateRect(g_hInjGenCheck, nullptr, TRUE);
        InvalidateRect(g_hFileCheckScan, nullptr, TRUE);
        InvalidateRect(g_hClipShow, nullptr, TRUE);
        InvalidateRect(g_hClipProc, nullptr, TRUE);

        RedrawWindow(hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_ERASE | RDW_UPDATENOW);
        return;
    }

    ShowWindow(g_hHomeNav, SW_HIDE);
    ShowWindow(g_hAutomationBam, SW_HIDE);
    ShowWindow(g_hAutomationBamUnsignedOnly, SW_HIDE);
    ShowWindow(g_hAutomationEventVwr, SW_HIDE);
    ShowWindow(g_hAutomationJarPage, SW_HIDE);
    ShowWindow(g_hJarActiv, SW_HIDE);
    ShowWindow(g_hExeDeleted, SW_HIDE);
    ShowWindow(g_hPfDeleted, SW_HIDE);
    ShowWindow(g_hMcLogs, SW_HIDE);
    ShowWindow(g_hPage4Nav, SW_HIDE);
    ShowWindow(g_hModHash, SW_HIDE);
    ShowWindow(g_hModFullScan, SW_HIDE);
    ShowWindow(g_hDllUnsigned, SW_HIDE);
    ShowWindow(g_hDllActivity, SW_HIDE);
    ShowWindow(g_hPage5Nav, SW_HIDE);
    ShowWindow(g_hInjGenCheck, SW_HIDE);
    ShowWindow(g_hEventEdit, SW_HIDE);
    ShowWindow(g_hJarEdit, SW_HIDE);
    ShowWindow(g_hExeEdit, SW_HIDE);
    ShowWindow(g_hPfEdit, SW_HIDE);
    ShowWindow(g_hMcEdit, SW_HIDE);
    // Кнопки вкладки file check тоже прячем на главном экране (иначе они «застревают»).
    ShowWindow(g_hFileCheckScan, SW_HIDE);
    ShowWindow(g_hClipShow, SW_HIDE);
    ShowWindow(g_hClipProc, SW_HIDE);

    ShowWindow(g_hDeleteHolyCheck, SW_HIDE);
    ShowWindow(g_hPowerShell, SW_HIDE);
    ShowWindow(g_hEnableServices, SW_HIDE);
    ShowWindow(g_hCopyPowerShell, SW_HIDE);
    ShowWindow(g_hCopySites, SW_HIDE);

    MailsUi::LayoutHome(hwnd, rc);
}

static void PaintParentSceneForButton(HWND button, HDC hdc)
{
    RECT rc{};
    GetClientRect(button, &rc);

    if (g_sceneBufferDc && GetParent(button) != MailsUi::catalog)
    {
        POINT topLeft{};
        MapWindowPoints(button, g_hMain, &topLeft, 1);
        if (topLeft.x >= 0 && topLeft.y >= 0 &&
            topLeft.x + rc.right <= g_sceneBufferWidth && topLeft.y + rc.bottom <= g_sceneBufferHeight &&
            BitBlt(hdc, 0, 0, rc.right, rc.bottom, g_sceneBufferDc, topLeft.x, topLeft.y, SRCCOPY))
            return;
    }

    HBRUSH brush = CreateSolidBrush(BG);
    FillRect(hdc, &rc, brush);
    DeleteObject(brush);
}

// Draws the button off screen first and blits it in one go. Without this the
// translucent cards visibly flashed when the hover state repainted them.
static void DrawRoundButton(DRAWITEMSTRUCT* d)
{
    RECT r = d->rcItem;

    int width = r.right - r.left;
    int height = r.bottom - r.top;

    if (width <= 0 || height <= 0)
        return;

    HDC memDc = CreateCompatibleDC(d->hDC);
    HBITMAP memBitmap = nullptr;
    HGDIOBJ oldBitmap = nullptr;

    if (memDc)
    {
        memBitmap = CreateCompatibleBitmap(d->hDC, width, height);

        if (memBitmap)
        {
            oldBitmap = SelectObject(memDc, memBitmap);

            // Keep drawing in the button's own coordinates.
            OffsetViewportOrgEx(memDc, -r.left, -r.top, nullptr);
        }
        else
        {
            DeleteDC(memDc);
            memDc = nullptr;
        }
    }

    if (!memDc)
    {
        // Out of resources: draw straight to the screen DC.
        MailsUi::DrawButton(d);
        return;
    }

    DRAWITEMSTRUCT buffered = *d;
    buffered.hDC = memDc;

    MailsUi::DrawButton(&buffered);

    OffsetViewportOrgEx(memDc, r.left, r.top, nullptr);
    BitBlt(d->hDC, r.left, r.top, width, height, memDc, 0, 0, SRCCOPY);

    SelectObject(memDc, oldBitmap);
    DeleteObject(memBitmap);
    DeleteDC(memDc);
}

static LRESULT CALLBACK ButtonNoEraseProc(
    HWND hwnd,
    UINT msg,
    WPARAM wParam,
    LPARAM lParam,
    UINT_PTR subclassId,
    DWORD_PTR refData)
{
    UNREFERENCED_PARAMETER(subclassId);
    UNREFERENCED_PARAMETER(refData);

    if (msg == WM_ERASEBKGND)
        return 1;

    if (msg == WM_MOUSEMOVE && MailsUi::hovered != hwnd)
    {
        MailsUi::SetHover(hwnd);
        TRACKMOUSEEVENT track{ sizeof(TRACKMOUSEEVENT), TME_LEAVE, hwnd, 0 };
        TrackMouseEvent(&track);
    }
    if (msg == WM_MOUSELEAVE && MailsUi::hovered == hwnd)
        MailsUi::SetHover(nullptr);
    if (msg == WM_SETFOCUS && GetParent(hwnd) == MailsUi::catalog && GetKeyState(VK_LBUTTON) >= 0)
        MailsUi::RevealCatalogCard(GetDlgCtrlID(hwnd) - IDC_TILE_BASE);
    if (msg == WM_SETFOCUS || msg == WM_KILLFOCUS)
        InvalidateRect(hwnd, nullptr, FALSE);

    if (msg == WM_KEYDOWN && wParam == VK_RETURN)
    {
        SendMessageW(hwnd, BM_CLICK, 0, 0);
        return 0;
    }

    if (msg == WM_NCDESTROY)
    {
        if (MailsUi::hovered == hwnd)
            MailsUi::hovered = nullptr;
        if (MailsUi::previousHover == hwnd)
            MailsUi::previousHover = nullptr;
        RemoveWindowSubclass(hwnd, ButtonNoEraseProc, 1);
    }

    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

static void MakeButtonNoErase(HWND button)
{
    if (button)
    {
        LONG_PTR exStyle = GetWindowLongPtrW(button, GWL_EXSTYLE);
        SetWindowLongPtrW(button, GWL_EXSTYLE, exStyle & ~WS_EX_TRANSPARENT);
        SetWindowSubclass(button, ButtonNoEraseProc, 1, 0);
    }
}

static std::wstring BuildMinecraftPowerShellScript()
{
    std::wstring script;
    script.reserve(36000);

    script += LR"HCPS($ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
try{ if($PSCommandPath){ Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue } }catch{}
function Out($s){[Console]::WriteLine([string]$s)}
try{
    Out 'Команда: Remove-Module PSReadLine -Force'
    Remove-Module PSReadLine -Force -ErrorAction SilentlyContinue
    Out 'Команда активирована'
}catch{
    Out ('Команда не активирована: '+$_.Exception.Message)
}
Out ''

$excluded=@('labymod','labymod-neo')
$skip=@(
    'node_modules','.git','.svn','.hg','__pycache__','.gradle','.m2',
    'temp','tmp','cache','caches','$recycle.bin','system volume information',
    'packages','package cache','npm-cache','pip','pip-cache'
)

function N($p){
    if([string]::IsNullOrWhiteSpace($p)){return ''}
    try{return ([System.IO.Path]::GetFullPath([string]$p) -replace '[\\/]+$','')}catch{return [string]$p}
}
function JoinP([string[]]$parts){
    if($null -eq $parts -or $parts.Count -eq 0){return ''}
    $r=[string]$parts[0]
    for($i=1;$i -lt $parts.Count;$i++){$r=[System.IO.Path]::Combine($r,[string]$parts[$i])}
    return $r
}
function Leaf($p){try{return [System.IO.Path]::GetFileName((N $p))}catch{return ''}}
function Parent($p){try{return [System.IO.Directory]::GetParent((N $p)).FullName}catch{return ''}}

$script:userRoot=N $env:USERPROFILE
$script:userExact=$script:userRoot.ToLowerInvariant()
$script:userKey=$script:userExact
if($script:userKey.Length -gt 0){if($script:userKey[$script:userKey.Length-1] -ne '\'){$script:userKey+='\'}}

function InUser($p){
    $full=(N $p).ToLowerInvariant()
    if($script:userKey.Length -eq 0){return $false}
    return (($full -eq $script:userExact) -or $full.StartsWith($script:userKey))
}
function IsExcluded($p){
    $l=(Leaf $p)
    if([string]::IsNullOrWhiteSpace($l)){return $false}
    return ($excluded -contains $l.ToLowerInvariant())
}
function IsReparsePoint($p){
    try{
        $di=[System.IO.DirectoryInfo]::new($p)
        return (($di.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    }catch{return $true}
}
function SkipDir($p){
    $l=(Leaf $p)
    if([string]::IsNullOrWhiteSpace($l)){return $false}
    $ll=$l.ToLowerInvariant()
    if(($excluded -contains $ll) -or ($skip -contains $ll)){return $true}
    return (IsReparsePoint $p)
}
)HCPS";

    script += L"\n$script:HolyCheckerCheckScript='" + EscapePowerShellSingleQuoted(std::wstring(POWERSHELL_TXT)) + L"'\n";

    script += LR"HCPS(function HasJar($versions){
    if(-not [System.IO.Directory]::Exists($versions)){return $false}
    try{
        foreach($f in [System.IO.Directory]::EnumerateFiles($versions,'*.jar',[System.IO.SearchOption]::AllDirectories)){
            return $true
        }
    }catch{}
    return $false
}
function IsMcRoot($p,$allowOutsideUser){
    $full=N $p
    if([string]::IsNullOrWhiteSpace($full)){return $false}
    if((-not $allowOutsideUser) -and (-not (InUser $full))){return $false}
    if(IsExcluded $full){return $false}
    if(-not [System.IO.Directory]::Exists($full)){return $false}

    $assets=[System.IO.Path]::Combine($full,'assets')
    $versions=[System.IO.Path]::Combine($full,'versions')
    $logs=[System.IO.Path]::Combine($full,'logs')

    if(-not [System.IO.Directory]::Exists($assets)){return $false}
    if(-not [System.IO.Directory]::Exists($versions)){return $false}
    if(-not [System.IO.Directory]::Exists($logs)){return $false}
    return (HasJar $versions)
}

function ResetFound(){
    $script:valid=[System.Collections.Generic.List[string]]::new()
    $script:validSeen=@{}
}
function AddValid($p,$allowOutsideUser){
    $full=N $p
    if([string]::IsNullOrWhiteSpace($full)){return}
    if((-not $allowOutsideUser) -and (-not (InUser $full))){return}
    if(-not (IsMcRoot $full $allowOutsideUser)){return}
    $key=$full.ToLowerInvariant()
    if($script:validSeen.ContainsKey($key)){return}
    $script:validSeen[$key]=$true
    [void]$script:valid.Add($full)
}
function TryCandidateAndParents($p,$allowOutsideUser){
    $full=N $p
    if([string]::IsNullOrWhiteSpace($full)){return}
    AddValid $full $allowOutsideUser
    $leaf=(Leaf $full).ToLowerInvariant()
    if($leaf -eq 'assets' -or $leaf -eq 'logs' -or $leaf -eq 'versions'){
        $par=Parent $full
        if(-not [string]::IsNullOrWhiteSpace($par)){AddValid $par $allowOutsideUser}
    }
}

function AddFastPath([System.Collections.Generic.List[string]]$list,[string]$p){
    $n=N $p
    if([string]::IsNullOrWhiteSpace($n)){return}
    [void]$list.Add($n)
}
function GetFastPaths(){
    $a=N $env:APPDATA
    $u=N $env:USERPROFILE
    $list=[System.Collections.Generic.List[string]]::new()
    if(-not [string]::IsNullOrWhiteSpace($a)){
        AddFastPath $list (JoinP @($a,'.tlauncher','legacy','Minecraft','game'))
        AddFastPath $list (JoinP @($a,'.minecraft'))
    }
    if(-not [string]::IsNullOrWhiteSpace($a)){
        AddFastPath $list (JoinP @($u,'.lunarclient'))
    }
    AddFastPath $list 'C:\PulseVisuals\game'
    return $list.ToArray()
}
function GetPriorityRoots(){
    $list=[System.Collections.Generic.List[string]]::new()
    function A($x){$n=N $x;if($n -and (InUser $n) -and [System.IO.Directory]::Exists($n)){[void]$list.Add($n)}}
    A $env:APPDATA
    A (JoinP @($env:APPDATA,'.minecraft'))
    A (JoinP @($env:APPDATA,'.tlauncher'))
    A (JoinP @($env:USERPROFILE,'Desktop'))
    A (JoinP @($env:USERPROFILE,'Downloads'))
    A (JoinP @($env:USERPROFILE,'Documents'))
    A (JoinP @($env:USERPROFILE,'Games'))
    A (JoinP @($env:USERPROFILE,'OneDrive'))
    A $env:LOCALAPPDATA
    A $env:USERPROFILE
    return $list.ToArray()
}
)HCPS";

    script += LR"HCPS(function AddExistingFastPath($p){
    $full=N $p
    if([string]::IsNullOrWhiteSpace($full)){return}
    if(IsExcluded $full){return}
    if(-not [System.IO.Directory]::Exists($full)){return}
    $key=$full.ToLowerInvariant()
    if($script:validSeen.ContainsKey($key)){return}
    $script:validSeen[$key]=$true
    [void]$script:valid.Add($full)
}
function RunFast(){
    foreach($p in (GetFastPaths)){AddExistingFastPath $p}
}
function RunFull(){
    Out 'Полный режим.'
    if([string]::IsNullOrWhiteSpace($script:userRoot) -or -not [System.IO.Directory]::Exists($script:userRoot)){
        Out 'Не удалось определить папку пользователя.'
        return
    }

    $scanLimit=800000
    $scanned=0
    $seenDirs=@{}
    $queue=[System.Collections.Generic.Queue[string]]::new()

    foreach($root in (GetPriorityRoots)){
        $r=N $root
        if(-not [string]::IsNullOrWhiteSpace($r)){
            $rk=$r.ToLowerInvariant()
            if(-not $seenDirs.ContainsKey($rk)){$queue.Enqueue($r)}
        }
    }

    while($queue.Count -gt 0 -and $scanned -lt $scanLimit){
        $d=N ([string]$queue.Dequeue())
        if([string]::IsNullOrWhiteSpace($d)){continue}
        if(-not (InUser $d)){continue}

        $dk=$d.ToLowerInvariant()
        if($seenDirs.ContainsKey($dk)){continue}
        $seenDirs[$dk]=$true

        if(SkipDir $d){continue}
        $scanned++
        TryCandidateAndParents $d $false

        try{$children=[System.IO.Directory]::EnumerateDirectories($d)}catch{continue}
        foreach($child in $children){
            $c=N $child
            if([string]::IsNullOrWhiteSpace($c)){continue}
            if(-not (InUser $c)){continue}
            if(SkipDir $c){continue}
            TryCandidateAndParents $c $false
            $ck=$c.ToLowerInvariant()
            if(-not $seenDirs.ContainsKey($ck)){$queue.Enqueue($c)}
        }
    }

    if($scanned -ge $scanLimit){Out ('Лимит поиска достигнут: '+$scanLimit+' папок. Показаны найденные пути.')}
}
)HCPS";

    script += LR"HCPS(function ReadLongLine([string]$prompt){
    if($null -ne $prompt){[Console]::Write($prompt)}
    $sb=[System.Text.StringBuilder]::new()
    while($true){
        $k=[Console]::ReadKey($true)
        if($k.Key -eq [System.ConsoleKey]::Enter){
            [Console]::WriteLine()
            return $sb.ToString()
        }
        if($k.Key -eq [System.ConsoleKey]::Backspace){
            if($sb.Length -gt 0){
                [void]$sb.Remove($sb.Length-1,1)
                try{[Console]::Write([char]8);[Console]::Write(' ');[Console]::Write([char]8)}catch{}
            }
            continue
        }
        if(($k.Modifiers -band [System.ConsoleModifiers]::Control) -and $k.Key -eq [System.ConsoleKey]::C){
            [Console]::WriteLine()
            return 'exit'
        }
        if(($k.Modifiers -band [System.ConsoleModifiers]::Control) -and $k.Key -eq [System.ConsoleKey]::V){
            try{
                Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
                $clip=[System.Windows.Forms.Clipboard]::GetText()
                if($null -ne $clip){
                    $clip=$clip -replace "`r",'' -replace "`n",''
                    [void]$sb.Append($clip)
                    [Console]::Write($clip)
                }
            }catch{}
            continue
        }
        $ch=$k.KeyChar
        if([int][char]$ch -eq 0){continue}
        [void]$sb.Append($ch)
        [Console]::Write($ch)
    }
}
function AskMode(){
    ClearScreen
    Out 'Главное меню:'
    Out '----------------------------------------'
    Out ' 1) Быстрый'
    Out ' 2) Полный'
    Out '----------------------------------------'
    while($true){
        $raw=ReadLongLine 'Введите 1, 2 или exit: '
        if($null -eq $raw){return 0}
        $t=$raw.Trim().ToLowerInvariant()
        if($t -eq 'exit'){ClearScreen; Out 'Главное меню:'; Out '----------------------------------------'; Out ' 1) Быстрый'; Out ' 2) Полный'; Out '----------------------------------------'; continue}
        $n=0
        if([int]::TryParse($t,[ref]$n) -and ($n -eq 1 -or $n -eq 2)){return $n}
        Out 'Неверный ввод. Повторите выбор.'
    }
}
function SortedFound(){
    [string[]]$items=$script:valid.ToArray()
    [System.Array]::Sort($items,[System.StringComparer]::OrdinalIgnoreCase)
    foreach($item in $items){$item}
}
function ClearScreen(){
    try{[Console]::Write(([char]27).ToString()+'[2J'+([char]27).ToString()+'[3J'+([char]27).ToString()+'[H')}catch{}
    try{[Console]::Clear()}catch{}
}
function GoHome(){
    ClearScreen
    return 'menu'
}
function ChooseFolder(){
    Out ''
    Out 'Найденные папки Minecraft:'
    if($script:valid.Count -eq 0){
        Out 'Подходящие папки не найдены.'
        Out 'Введите exit для обновления списка.'
        while($true){
            $raw=ReadLongLine '> '
            if($null -eq $raw){return 'menu'}
            if($raw.Trim().ToLowerInvariant() -eq 'exit'){return 'menu'}
        }
    }

    [string[]]$items=@(SortedFound)
    Out ('Найдено: '+$items.Count)
    Out 'Выберите папку:'
    Out '----------------------------------------'
    for($i=0;$i -lt $items.Count;$i++){Out (('{0,2}) {1}' -f ($i+1),$items[$i]))}
    Out '----------------------------------------'
    while($true){
        $raw=ReadLongLine ('Введите номер 1-'+$items.Count+' или exit: ')
        if($null -eq $raw){return 'menu'}
        $t=$raw.Trim().ToLowerInvariant()
        if($t -eq 'exit'){return 'menu'}
        $idx=0
        if([int]::TryParse($t,[ref]$idx) -and $idx -ge 1 -and $idx -le $items.Count){
            $chosen=$items[$idx-1]
            try{$ExecutionContext.SessionState.Path.SetLocation($chosen)}catch{try{[System.IO.Directory]::SetCurrentDirectory($chosen)}catch{}}
            Out ('Выбран путь: '+$chosen)
            Out 'Запуск PowerShell-скрипта check...'
            try{
                $result=[scriptblock]::Create($script:HolyCheckerCheckScript).Invoke()
                if($null -ne $result){foreach($r in $result){if($null -ne $r){Out $r}}}
                Out 'PowerShell-скрипт check завершил работу.'
            }catch{
                Out ('Ошибка запуска PowerShell-скрипта check: '+$_.Exception.Message)
            }
            return 'menu'
        }
        Out 'Неверный ввод. Повторите выбор.'
    }
}
)HCPS";

    script += LR"HCPS(function CommandLoop(){
    while($true){
        try{$loc=[string]$ExecutionContext.SessionState.Path.CurrentLocation}catch{$loc=[System.IO.Directory]::GetCurrentDirectory()}
        $cmd=ReadLongLine ('PS '+$loc+'> ')
        if($null -eq $cmd){return}
        if($cmd.Trim().ToLowerInvariant() -eq 'exit'){ClearScreen;return}
        if([string]::IsNullOrWhiteSpace($cmd)){continue}
        try{
            $result=[scriptblock]::Create($cmd).Invoke()
            if($null -ne $result){foreach($r in $result){if($null -ne $r){Out $r}}}
        }catch{
            Out ('Ошибка: '+$_.Exception.Message)
        }
    }
}

while($true){
    ResetFound
    ClearScreen
    RunFast
    $next=ChooseFolder
    if($next -eq 'shell'){CommandLoop}
    Out ''
}
)HCPS";

    return script;
}

static std::wstring GetHolyCheckerMinecraftScriptPath()
{
    std::wstring dir = CombinePath(GetHolyCheckTempRoot(), L"PowerShell");
    EnsureDirectory(dir);
    return CombinePath(dir, L"HolyChecker_minecraft_check_" + std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(GetTickCount64()) + L".ps1");
}

static void OpenPowerShellMinecraft()
{
    CleanupHolyCheckTempScriptsLocalEarly();
    std::wstring script = BuildMinecraftPowerShellScript();
    std::wstring scriptPath = GetHolyCheckerMinecraftScriptPath();

    if (!WriteUtf8TextFile(scriptPath, script.c_str()))
    {
        PostLog(L"PowerShell не открыт: не удалось создать временный скрипт");
        return;
    }

    std::wstring powerShellExe = GetSystemToolPath(L"WindowsPowerShell\\v1.0\\powershell.exe");
    std::wstring command = L"-NoLogo -NoProfile -NoExit -ExecutionPolicy Bypass -File " + QuoteProcessArgument(scriptPath);
    std::wstring profile = GetCurrentUserProfilePath();
    const wchar_t* workingDir = DirectoryExists(profile) ? profile.c_str() : nullptr;

    HINSTANCE result = ShellExecuteW(
        g_hMain,
        L"runas",
        powerShellExe.c_str(),
        command.c_str(),
        workingDir,
        SW_SHOWNORMAL
    );

    if (reinterpret_cast<INT_PTR>(result) <= 32)
    {
        DeleteFileOrScheduleLocalEarly(scriptPath);
        PostLog(L"PowerShell не открыт: ошибка запуска");
    }
    else
    {
        MoveFileExW(scriptPath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        PostLog(L"PowerShell открыт: выберите путь для запуска check");
    }
}

static void OpenCmdEnableServices()
{
    std::wstring command =
        L"/c sc config PcaSVC start= auto & sc start PcaSVC & "
        L"sc config DPS start= auto & sc start DPS & "
        L"sc config SysMain start= auto & sc start SysMain & "
        L"sc config EventLog start= auto & sc start EventLog & "
        L"sc config bam start= auto & sc start bam";

    ShellExecuteW(
        g_hMain,
        L"runas",
        L"cmd.exe",
        command.c_str(),
        nullptr,
        SW_SHOWNORMAL
    );
}
