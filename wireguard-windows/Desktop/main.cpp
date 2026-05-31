#include <windows.h>
#include <windowsx.h>
#include <commdlg.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <uxtheme.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "quirc.h"
#include "resource.h"

#define WGX_TRAY_MESSAGE (WM_APP + 1)

enum ControlId {
    ID_TUNNEL_LIST = 100,
    ID_IMPORT_BUTTON = 101,
    ID_TOGGLE_TUNNEL = 102,
    ID_IMPORT_QR = 103,
    ID_IMPORT_FILE = 104,
    ID_DELETE = 105,
    ID_FILE_EXIT = 106,
    ID_ABOUT = 107,
    ID_EDIT = 108,
    ID_NAME_EDIT = 109,
    ID_TRAY_SHOW = 200,
    ID_TRAY_EXIT = 201
};

struct TunnelProfile {
    std::wstring name;
    std::wstring path;
    std::wstring address;
    std::wstring dns;
    std::wstring peer;
    std::wstring endpoint;
    std::wstring allowed_ips;
    std::wstring state = L"Stopped";
    std::wstring last_log;
};

struct RunningTunnel {
    PROCESS_INFORMATION pi{};
    HANDLE stdin_write = nullptr;
    HANDLE output_read = nullptr;
    DWORD started_tick = 0;
};

struct OwnerDrawMenuItem {
    const wchar_t *text;
    SHSTOCKICONID icon;
    int resource_icon;
    bool close_icon;
};

static OwnerDrawMenuItem g_import_file_menu{ L"Import Tunnel from file...", SIID_INVALID, IDI_MENU_ADD, false };
static OwnerDrawMenuItem g_import_qr_menu{ L"Import Tunnel from QR Code", SIID_INVALID, IDI_IMPORT_FROM_QR, false };
static OwnerDrawMenuItem g_exit_menu{ L"Exit", SIID_INVALID, IDI_MENU_EXIT, false };

static HWND g_main_window;
static HWND g_list;
static HWND g_path;
static HWND g_address;
static HWND g_dns;
static HWND g_peer;
static HWND g_endpoint;
static HWND g_allowed_ips;
static HWND g_log;
static HWND g_toggle_button;
static HWND g_empty_import_button;
static WNDPROC g_empty_import_button_proc;
static bool g_empty_import_hover = false;
static HFONT g_title_font;
static HFONT g_sidebar_title_font;
static HFONT g_ui_font;
static HICON g_app_icon;
static HICON g_tray_unlock_icon;
static HICON g_tray_lock_icon;
static HICON g_wg_off_icon;
static HICON g_wg_on_icon;
static HICON g_wg_connecting_icon;
static HIMAGELIST g_status_images;
static HBITMAP g_status_dot_stopped;
static HBITMAP g_status_dot_running;
static WNDPROC g_list_proc;
static NOTIFYICONDATAW g_tray{};
static std::vector<TunnelProfile> g_tunnels;
static std::map<std::wstring, RunningTunnel> g_running;
static int g_sidebar_width = 300;
static UINT g_dpi = 96;
static bool g_splitter_hover = false;
static bool g_splitter_dragging = false;
static const int kSplitterWidth = 6;
static const int kSplitterVisualWidth = 1;
static const int kSidebarMin = 220;
static const int kSidebarMax = 520;

static void start_tunnel(HWND hwnd);
static void stop_tunnel();
static void layout_controls(HWND hwnd);
static void append_owner_draw_menu_item(HMENU menu, UINT id, OwnerDrawMenuItem *data);

static int scale_px(int value)
{
    return MulDiv(value, g_dpi, 96);
}

static UINT window_dpi(HWND hwnd)
{
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        typedef UINT(WINAPI *GetDpiForWindowProc)(HWND);
        auto proc = (GetDpiForWindowProc)GetProcAddress(user32, "GetDpiForWindow");
        if (proc)
            return proc(hwnd);
    }
    HDC dc = GetDC(hwnd);
    UINT dpi = dc ? (UINT)GetDeviceCaps(dc, LOGPIXELSX) : 96;
    if (dc)
        ReleaseDC(hwnd, dc);
    return dpi ? dpi : 96;
}

static HFONT create_system_font(int point_size, int weight)
{
    NONCLIENTMETRICSW metrics{};
    metrics.cbSize = sizeof(metrics);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, metrics.cbSize, &metrics, 0)) {
        LOGFONTW lf = metrics.lfMessageFont;
        lf.lfWeight = weight;
        if (point_size > 0)
            lf.lfHeight = -MulDiv(point_size, g_dpi, 72);
        return CreateFontIndirectW(&lf);
    }

    return CreateFontW(-MulDiv(point_size > 0 ? point_size : 9, g_dpi, 72), 0, 0, 0, weight,
                       FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS,
                       L"Segoe UI");
}

static void set_control_font(HWND hwnd)
{
    if (hwnd)
        SendMessageW(hwnd, WM_SETFONT, (WPARAM)g_ui_font, TRUE);
}

static std::wstring trim(const std::wstring &s)
{
    const wchar_t *spaces = L" \t\r\n";
    size_t first = s.find_first_not_of(spaces);
    if (first == std::wstring::npos)
        return L"";
    size_t last = s.find_last_not_of(spaces);
    return s.substr(first, last - first + 1);
}

static std::wstring utf8_to_wide(const std::string &s)
{
    if (s.empty())
        return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out((size_t)len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), len);
    return out;
}

static bool any_tunnel_running()
{
    return !g_running.empty();
}

static void append_log(TunnelProfile &t, const std::wstring &line)
{
    if (line.empty())
        return;
    if (!t.last_log.empty())
        t.last_log += L"\r\n";
    t.last_log += line;
    if (t.last_log.size() > 8192)
        t.last_log.erase(0, t.last_log.size() - 8192);
}

static std::wstring app_data_dir()
{
    wchar_t base[MAX_PATH];
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, base)))
        GetTempPathW(MAX_PATH, base);
    std::wstring dir = std::wstring(base) + L"\\wgx\\tunnels";
    SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
    return dir;
}

static std::wstring exe_dir()
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring full(path);
    size_t slash = full.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"." : full.substr(0, slash);
}

static std::wstring safe_name(std::wstring name)
{
    const std::wstring invalid = L"<>:\"/\\|?*";
    for (wchar_t &ch : name) {
        if (invalid.find(ch) != std::wstring::npos || ch < 32)
            ch = L'-';
    }
    name = trim(name);
    while (!name.empty() && (name.back() == L'.' || name.back() == L' '))
        name.pop_back();
    return name.empty() ? L"tunnel" : name;
}

static std::wstring file_stem(const std::wstring &path)
{
    size_t slash = path.find_last_of(L"\\/");
    size_t start = slash == std::wstring::npos ? 0 : slash + 1;
    size_t dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos || dot < start)
        dot = path.size();
    return path.substr(start, dot - start);
}

static std::wstring unique_target_path(const std::wstring &source)
{
    std::wstring dir = app_data_dir();
    std::wstring base = safe_name(file_stem(source));
    std::wstring target = dir + L"\\" + base + L".conf";
    for (int i = 2; GetFileAttributesW(target.c_str()) != INVALID_FILE_ATTRIBUTES; ++i)
        target = dir + L"\\" + base + L"-" + std::to_wstring(i) + L".conf";
    return target;
}

static std::wstring unique_target_path_for_name(const std::wstring &name)
{
    std::wstring dir = app_data_dir();
    std::wstring base = safe_name(name);
    std::wstring target = dir + L"\\" + base + L".conf";
    for (int i = 2; GetFileAttributesW(target.c_str()) != INVALID_FILE_ATTRIBUTES; ++i)
        target = dir + L"\\" + base + L"-" + std::to_wstring(i) + L".conf";
    return target;
}

static TunnelProfile parse_tunnel(const std::wstring &path)
{
    TunnelProfile t;
    t.path = path;
    t.name = file_stem(path);

    FILE *input = _wfopen(path.c_str(), L"rb");
    if (!input)
        return t;

    char raw[1024];
    std::wstring section;
    while (fgets(raw, sizeof(raw), input)) {
        std::wstring line = trim(utf8_to_wide(raw));
        if (line.empty() || line[0] == L'#')
            continue;
        if (line.front() == L'[' && line.back() == L']') {
            section = trim(line.substr(1, line.size() - 2));
            std::transform(section.begin(), section.end(), section.begin(), towlower);
            continue;
        }

        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos)
            continue;
        std::wstring key = trim(line.substr(0, eq));
        std::wstring value = trim(line.substr(eq + 1));
        std::transform(key.begin(), key.end(), key.begin(), towlower);

        if (section == L"interface" && key == L"address")
            t.address = value;
        else if (section == L"interface" && key == L"dns")
            t.dns = value;
        else if (section == L"peer" && key == L"publickey")
            t.peer = value;
        else if (section == L"peer" && key == L"endpoint")
            t.endpoint = value;
        else if (section == L"peer" && key == L"allowedips")
            t.allowed_ips = value;
    }
    fclose(input);
    return t;
}

static int selected_index()
{
    return ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
}

static TunnelProfile *selected_tunnel()
{
    int idx = selected_index();
    if (idx < 0 || idx >= (int)g_tunnels.size())
        return nullptr;
    return &g_tunnels[(size_t)idx];
}

static bool is_selected_tunnel_running()
{
    TunnelProfile *t = selected_tunnel();
    return t && g_running.find(t->name) != g_running.end();
}

static void set_text(HWND hwnd, const std::wstring &text)
{
    SetWindowTextW(hwnd, text.empty() ? L"-" : text.c_str());
}

static void set_visible(HWND hwnd, bool visible)
{
    if (hwnd)
        ShowWindow(hwnd, visible ? SW_SHOW : SW_HIDE);
}

static HICON status_icon_for_state(const std::wstring &state)
{
    if (state == L"Running")
        return g_wg_on_icon;
    if (state == L"Connecting")
        return g_wg_connecting_icon;
    return g_wg_off_icon;
}

static std::wstring detail_title_text()
{
    TunnelProfile *t = selected_tunnel();
    return t ? t->name : L"No tunnel selected";
}

static std::wstring detail_state()
{
    TunnelProfile *t = selected_tunnel();
    return t ? t->state : L"Stopped";
}

static void invalidate_detail_header()
{
    if (!g_main_window)
        return;
    RECT rc;
    GetClientRect(g_main_window, &rc);
    RECT header{ g_sidebar_width + scale_px(kSplitterWidth), 0, rc.right, scale_px(56) };
    InvalidateRect(g_main_window, &header, FALSE);
}

static void refresh_detail()
{
    bool has_tunnels = !g_tunnels.empty();
    set_visible(g_path, has_tunnels);
    set_visible(g_address, has_tunnels);
    set_visible(g_dns, has_tunnels);
    set_visible(g_peer, has_tunnels);
    set_visible(g_endpoint, has_tunnels);
    set_visible(g_allowed_ips, has_tunnels);
    set_visible(g_log, has_tunnels);
    set_visible(g_toggle_button, has_tunnels);
    set_visible(g_empty_import_button, !has_tunnels);

    TunnelProfile *t = selected_tunnel();
    if (!t) {
        invalidate_detail_header();
        set_text(g_path, L"");
        set_text(g_address, L"");
        set_text(g_dns, L"");
        set_text(g_peer, L"");
        set_text(g_endpoint, L"");
        set_text(g_allowed_ips, L"");
        set_text(g_log, L"");
        if (g_toggle_button)
            SetWindowTextW(g_toggle_button, L"Start");
        return;
    }

    invalidate_detail_header();
    set_text(g_path, t->path);
    set_text(g_address, t->address);
    set_text(g_dns, t->dns);
    set_text(g_peer, t->peer);
    set_text(g_endpoint, t->endpoint);
    set_text(g_allowed_ips, t->allowed_ips);
    set_text(g_log, t->last_log);
    if (g_toggle_button)
        SetWindowTextW(g_toggle_button, is_selected_tunnel_running() ? L"Stop" : L"Start");
}

static void refresh_list()
{
    int old_idx = selected_index();
    std::wstring selected_name;
    if (old_idx >= 0 && old_idx < (int)g_tunnels.size())
        selected_name = g_tunnels[(size_t)old_idx].name;

    ListView_DeleteAllItems(g_list);
    for (size_t i = 0; i < g_tunnels.size(); ++i) {
        const TunnelProfile &t = g_tunnels[i];
        std::wstring row = t.name;
        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
        item.iItem = (int)i;
        item.iImage = t.state == L"Running" ? 1 : 0;
        item.lParam = (LPARAM)i;
        item.pszText = row.data();
        ListView_InsertItem(g_list, &item);
    }
    if (!g_tunnels.empty()) {
        int idx = 0;
        if (!selected_name.empty()) {
            for (size_t i = 0; i < g_tunnels.size(); ++i) {
                if (g_tunnels[i].name == selected_name) {
                    idx = (int)i;
                    break;
                }
            }
        }
        ListView_SetItemState(g_list, idx, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(g_list, idx, FALSE);
    }
    refresh_detail();
    if (g_main_window)
        layout_controls(g_main_window);
}

static void load_tunnels()
{
    g_tunnels.clear();
    std::wstring pattern = app_data_dir() + L"\\*.conf";
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(pattern.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE)
        return;
    do {
        if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            g_tunnels.push_back(parse_tunnel(app_data_dir() + L"\\" + data.cFileName));
    } while (FindNextFileW(find, &data));
    FindClose(find);
    std::sort(g_tunnels.begin(), g_tunnels.end(),
              [](const TunnelProfile &a, const TunnelProfile &b) { return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0; });
}

static HWND label(HWND parent, const wchar_t *text, int id, int x, int y, int w, int h)
{
    HWND hwnd = CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP,
                              x, y, w, h, parent, (HMENU)(INT_PTR)id, nullptr, nullptr);
    set_control_font(hwnd);
    return hwnd;
}

static HWND value(HWND parent, int x, int y, int w, int h)
{
    HWND hwnd = CreateWindowW(L"STATIC", L"-", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                              x, y, w, h, parent, nullptr, nullptr, nullptr);
    set_control_font(hwnd);
    return hwnd;
}

static HWND button(HWND parent, const wchar_t *text, int id)
{
    HWND hwnd = CreateWindowW(L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                              0, 0, scale_px(90), scale_px(30), parent, (HMENU)(INT_PTR)id, nullptr, nullptr);
    set_control_font(hwnd);
    SetWindowTheme(hwnd, L"Explorer", nullptr);
    return hwnd;
}

static LRESULT CALLBACK empty_import_button_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_MOUSEMOVE:
        if (!g_empty_import_hover) {
            g_empty_import_hover = true;
            InvalidateRect(hwnd, nullptr, FALSE);
            TRACKMOUSEEVENT track{};
            track.cbSize = sizeof(track);
            track.dwFlags = TME_LEAVE;
            track.hwndTrack = hwnd;
            TrackMouseEvent(&track);
        }
        break;
    case WM_MOUSELEAVE:
        if (g_empty_import_hover) {
            g_empty_import_hover = false;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        break;
    case WM_NCDESTROY:
        SetWindowLongPtrW(hwnd, GWLP_WNDPROC, (LONG_PTR)g_empty_import_button_proc);
        break;
    }
    return CallWindowProcW(g_empty_import_button_proc, hwnd, msg, wparam, lparam);
}

static HWND rounded_button(HWND parent, const wchar_t *text, int id)
{
    HWND hwnd = CreateWindowW(L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | WS_TABSTOP,
                              0, 0, scale_px(190), scale_px(44), parent, (HMENU)(INT_PTR)id, nullptr, nullptr);
    set_control_font(hwnd);
    g_empty_import_button_proc = (WNDPROC)SetWindowLongPtrW(hwnd, GWLP_WNDPROC, (LONG_PTR)empty_import_button_proc);
    return hwnd;
}

static void move_control(HWND hwnd, int x, int y, int w, int h)
{
    if (!hwnd)
        return;
    SetWindowPos(hwnd, nullptr, x, y, std::max(0, w), std::max(0, h),
                 SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOREDRAW);
}

static void layout_controls(HWND hwnd)
{
    RECT rc;
    GetClientRect(hwnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    int margin = scale_px(18);
    int splitter = scale_px(kSplitterWidth);
    int sidebar_min = scale_px(kSidebarMin);
    int sidebar_max = scale_px(kSidebarMax);
    int sidebar = std::min(std::max(g_sidebar_width, sidebar_min), std::min(sidebar_max, w - scale_px(380)));
    if (sidebar != g_sidebar_width)
        g_sidebar_width = sidebar;

    const int top_h = scale_px(52);
    const int button_h = scale_px(30);
    move_control(g_list, 0, top_h, sidebar, h - top_h);
    ListView_SetColumnWidth(g_list, 0, sidebar - scale_px(8));

    int x = sidebar + splitter + margin;
    int right_w = w - sidebar - splitter - margin * 2;
    int empty_button_w = scale_px(190);
    int empty_button_h = scale_px(44);
    move_control(g_empty_import_button,
                 x + std::max(0, right_w - empty_button_w) / 2,
                 std::max(scale_px(52), (h - empty_button_h) / 2),
                 empty_button_w, empty_button_h);
    move_control(g_path, x, scale_px(56), right_w - scale_px(20), scale_px(22));
    move_control(g_toggle_button, w - scale_px(112), scale_px(18), scale_px(84), button_h);

    int value_x = x + scale_px(130);
    int y = scale_px(104);
    int row = scale_px(34);
    move_control(g_address, value_x, y, right_w - scale_px(140), scale_px(24)); y += row;
    move_control(g_dns, value_x, y, right_w - scale_px(140), scale_px(24)); y += row;
    move_control(g_peer, value_x, y, right_w - scale_px(140), scale_px(24)); y += row;
    move_control(g_endpoint, value_x, y, right_w - scale_px(140), scale_px(24)); y += row;
    move_control(g_allowed_ips, value_x, y, right_w - scale_px(140), scale_px(48));

    int log_y = h - scale_px(150);
    move_control(g_log, x, log_y, right_w, h - log_y - 2);
    InvalidateRect(hwnd, nullptr, FALSE);
}

static HICON load_resource_icon(int id, int size)
{
    return (HICON)LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(id),
                             IMAGE_ICON, size, size, LR_DEFAULTCOLOR | LR_SHARED);
}

static void load_status_icons()
{
    int size = scale_px(24);
    g_wg_off_icon = load_resource_icon(IDI_WG_OFF, size);
    g_wg_on_icon = load_resource_icon(IDI_WG_ON, size);
    g_wg_connecting_icon = load_resource_icon(IDI_WG_CONNECTING, size);
}

static bool hit_splitter(int x)
{
    return x >= g_sidebar_width && x < g_sidebar_width + scale_px(kSplitterWidth);
}

static RECT splitter_rect(HWND hwnd)
{
    RECT rc;
    GetClientRect(hwnd, &rc);
    return RECT{ g_sidebar_width, 0, g_sidebar_width + scale_px(kSplitterWidth), rc.bottom };
}

static void invalidate_splitter(HWND hwnd)
{
    RECT rc = splitter_rect(hwnd);
    InflateRect(&rc, scale_px(2), 0);
    InvalidateRect(hwnd, &rc, FALSE);
}

static HBITMAP create_status_dot(COLORREF color, int width, int height)
{
    HDC screen = GetDC(nullptr);
    BITMAPINFO bmi{};
    bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    void *raw_bits = nullptr;
    HBITMAP bitmap = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &raw_bits, nullptr, 0);
    ReleaseDC(nullptr, screen);

    uint32_t *bits = (uint32_t *)raw_bits;
    if (!bitmap || !bits)
        return bitmap;

    uint8_t r = GetRValue(color);
    uint8_t g = GetGValue(color);
    uint8_t b = GetBValue(color);
    const float cx = (float)width / 2.0f;
    const float cy = (float)height / 2.0f;
    const float radius = (float)std::max(4, scale_px(6));

    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            float dx = (float)x + 0.5f - cx;
            float dy = (float)y + 0.5f - cy;
            float dist2 = dx * dx + dy * dy;
            uint8_t a = dist2 <= radius * radius ? 255 : 0;
            bits[y * width + x] = ((uint32_t)a << 24) |
                                  ((uint32_t)r << 16) |
                                  ((uint32_t)g << 8) |
                                  (uint32_t)b;
        }
    }
    return bitmap;
}

static void recreate_status_images()
{
    if (g_list)
        ListView_SetImageList(g_list, nullptr, LVSIL_SMALL);
    if (g_status_images)
        ImageList_Destroy(g_status_images);
    if (g_status_dot_stopped)
        DeleteObject(g_status_dot_stopped);
    if (g_status_dot_running)
        DeleteObject(g_status_dot_running);

    int image_width = std::max(16, scale_px(32));
    int image_height = std::max(28, scale_px(44));
    g_status_images = ImageList_Create(image_width, image_height, ILC_COLOR32 | ILC_MASK, 2, 0);
    g_status_dot_stopped = create_status_dot(RGB(145, 153, 161), image_width, image_height);
    g_status_dot_running = create_status_dot(RGB(35, 163, 92), image_width, image_height);
    ImageList_Add(g_status_images, g_status_dot_stopped, nullptr);
    ImageList_Add(g_status_images, g_status_dot_running, nullptr);
    if (g_list)
        ListView_SetImageList(g_list, g_status_images, LVSIL_SMALL);
}

static void recreate_fonts()
{
    if (g_ui_font)
        DeleteObject(g_ui_font);
    if (g_title_font)
        DeleteObject(g_title_font);
    if (g_sidebar_title_font)
        DeleteObject(g_sidebar_title_font);
    g_ui_font = create_system_font(9, FW_NORMAL);
    g_title_font = create_system_font(15, FW_SEMIBOLD);
    g_sidebar_title_font = create_system_font(12, FW_SEMIBOLD);
}

static void apply_fonts()
{
    set_control_font(g_list);
    set_control_font(g_path);
    set_control_font(g_address);
    set_control_font(g_dns);
    set_control_font(g_peer);
    set_control_font(g_endpoint);
    set_control_font(g_allowed_ips);
    set_control_font(g_log);
    set_control_font(g_toggle_button);
    set_control_font(g_empty_import_button);
}

static void enable_dpi_awareness()
{
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        typedef BOOL(WINAPI *SetProcessDpiAwarenessContextProc)(HANDLE);
        auto set_context = (SetProcessDpiAwarenessContextProc)GetProcAddress(user32, "SetProcessDpiAwarenessContext");
        if (set_context && set_context((HANDLE)-4))
            return;

        typedef BOOL(WINAPI *SetProcessDPIAwareProc)();
        auto set_aware = (SetProcessDPIAwareProc)GetProcAddress(user32, "SetProcessDPIAware");
        if (set_aware)
            set_aware();
    }
}

static void relayout_and_repaint(HWND hwnd)
{
    layout_controls(hwnd);
    RedrawWindow(hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN);
}

static void add_tray(HWND hwnd)
{
    g_tray.cbSize = sizeof(g_tray);
    g_tray.hWnd = hwnd;
    g_tray.uID = 1;
    g_tray.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_tray.uCallbackMessage = WGX_TRAY_MESSAGE;
    g_tray.hIcon = g_tray_unlock_icon;
    wcscpy_s(g_tray.szTip, L"wgx");
    Shell_NotifyIconW(NIM_ADD, &g_tray);
}

static void update_tray_icon()
{
    if (!g_tray.hWnd)
        return;
    g_tray.uFlags = NIF_ICON | NIF_TIP;
    g_tray.hIcon = any_tunnel_running() ? g_tray_lock_icon : g_tray_unlock_icon;
    wcscpy_s(g_tray.szTip, any_tunnel_running() ? L"wgx connected" : L"wgx");
    Shell_NotifyIconW(NIM_MODIFY, &g_tray);
}

static void remove_tray()
{
    Shell_NotifyIconW(NIM_DELETE, &g_tray);
}

static void show_tray_menu(HWND hwnd)
{
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, ID_TRAY_SHOW, L"Manage tunnels");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, L"Exit");
    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
    DestroyMenu(menu);
}

struct NamePrompt {
    std::wstring title;
    std::wstring initial_name;
    std::wstring result;
    bool accepted = false;
    HWND edit = nullptr;
};

static void center_window_on_owner(HWND hwnd, HWND owner)
{
    RECT rc{};
    RECT owner_rc{};
    GetWindowRect(hwnd, &rc);
    if (owner && IsWindowVisible(owner))
        GetWindowRect(owner, &owner_rc);
    else
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &owner_rc, 0);

    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;
    int x = owner_rc.left + ((owner_rc.right - owner_rc.left) - width) / 2;
    int y = owner_rc.top + ((owner_rc.bottom - owner_rc.top) - height) / 2;
    SetWindowPos(hwnd, nullptr, x, y, 0, 0, SWP_NOZORDER | SWP_NOSIZE | SWP_NOACTIVATE);
}

static LRESULT CALLBACK name_prompt_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    NamePrompt *prompt = (NamePrompt *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE: {
        prompt = (NamePrompt *)((CREATESTRUCTW *)lparam)->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)prompt);
        SetWindowTextW(hwnd, prompt->title.c_str());

        int margin = scale_px(16);
        int label_h = scale_px(22);
        int edit_h = scale_px(24);
        int button_w = scale_px(82);
        int button_h = scale_px(28);
        HWND label_hwnd = CreateWindowW(L"STATIC", L"Tunnel name:", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                        margin, margin, scale_px(330), label_h,
                                        hwnd, nullptr, nullptr, nullptr);
        prompt->edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", prompt->initial_name.c_str(),
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                       margin, margin + label_h + scale_px(6), scale_px(330), edit_h,
                                       hwnd, (HMENU)(INT_PTR)ID_NAME_EDIT, nullptr, nullptr);
        HWND ok = CreateWindowW(L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                margin + scale_px(164), margin + label_h + edit_h + scale_px(18),
                                button_w, button_h, hwnd, (HMENU)(INT_PTR)IDOK, nullptr, nullptr);
        HWND cancel = CreateWindowW(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                    margin + scale_px(254), margin + label_h + edit_h + scale_px(18),
                                    button_w, button_h, hwnd, (HMENU)(INT_PTR)IDCANCEL, nullptr, nullptr);
        set_control_font(label_hwnd);
        set_control_font(prompt->edit);
        set_control_font(ok);
        set_control_font(cancel);
        SendMessageW(prompt->edit, EM_SETLIMITTEXT, MAX_PATH - 16, 0);
        SendMessageW(prompt->edit, EM_SETSEL, 0, -1);
        SetFocus(prompt->edit);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wparam) == IDOK && prompt) {
            int len = GetWindowTextLengthW(prompt->edit);
            std::wstring name((size_t)len + 1, L'\0');
            GetWindowTextW(prompt->edit, name.data(), len + 1);
            name.resize((size_t)len);
            name = trim(name);
            if (name.empty()) {
                MessageBoxW(hwnd, L"Enter a tunnel name.", L"wgx", MB_ICONWARNING);
                SetFocus(prompt->edit);
                return 0;
            }
            prompt->result = name;
            prompt->accepted = true;
            DestroyWindow(hwnd);
            return 0;
        }
        if (LOWORD(wparam) == IDCANCEL) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static bool prompt_tunnel_name(HWND owner, const wchar_t *title, const std::wstring &initial_name, std::wstring &name)
{
    HINSTANCE instance = GetModuleHandleW(nullptr);
    static bool registered = false;
    if (!registered) {
        WNDCLASSW wc{};
        wc.lpfnWndProc = name_prompt_proc;
        wc.hInstance = instance;
        wc.lpszClassName = L"WgxNamePrompt";
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        RegisterClassW(&wc);
        registered = true;
    }

    NamePrompt prompt{ title, safe_name(initial_name) };
    HWND dialog = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT,
                                  L"WgxNamePrompt", title,
                                  WS_CAPTION | WS_SYSMENU | WS_POPUP,
                                  CW_USEDEFAULT, CW_USEDEFAULT,
                                  scale_px(380), scale_px(150),
                                  owner, nullptr, instance, &prompt);
    if (!dialog)
        return false;

    center_window_on_owner(dialog, owner);
    EnableWindow(owner, FALSE);
    ShowWindow(dialog, SW_SHOW);
    MSG msg;
    while (IsWindow(dialog) && GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(dialog, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
    if (prompt.accepted)
        name = prompt.result;
    return prompt.accepted;
}

static void import_tunnel(HWND hwnd)
{
    wchar_t file[MAX_PATH] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"WireGuard config (*.conf)\0*.conf\0All files (*.*)\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn))
        return;

    std::wstring name;
    if (!prompt_tunnel_name(hwnd, L"Import Tunnel", file_stem(file), name))
        return;

    std::wstring target = unique_target_path_for_name(name);
    if (!CopyFileW(file, target.c_str(), TRUE)) {
        MessageBoxW(hwnd, L"Failed to import config.", L"wgx", MB_ICONERROR);
        return;
    }
    load_tunnels();
    refresh_list();
}

struct QrSelection {
    bool done = false;
    bool cancelled = false;
    bool dragging = false;
    POINT start{};
    POINT current{};
    RECT selected{};
};

static RECT normalized_rect(POINT a, POINT b)
{
    RECT rc{ std::min(a.x, b.x), std::min(a.y, b.y),
             std::max(a.x, b.x), std::max(a.y, b.y) };
    return rc;
}

static LRESULT CALLBACK qr_select_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    QrSelection *sel = (QrSelection *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE:
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)((CREATESTRUCTW *)lparam)->lpCreateParams);
        return 0;
    case WM_SETCURSOR:
        SetCursor(LoadCursorW(nullptr, IDC_CROSS));
        return TRUE;
    case WM_KEYDOWN:
        if (wparam == VK_ESCAPE && sel) {
            sel->cancelled = true;
            sel->done = true;
            return 0;
        }
        break;
    case WM_LBUTTONDOWN:
        if (sel) {
            sel->dragging = true;
            sel->start = POINT{ GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam) };
            sel->current = sel->start;
            SetCapture(hwnd);
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        break;
    case WM_MOUSEMOVE:
        if (sel && sel->dragging) {
            sel->current = POINT{ GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam) };
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        break;
    case WM_LBUTTONUP:
        if (sel && sel->dragging) {
            sel->dragging = false;
            ReleaseCapture();
            sel->current = POINT{ GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam) };
            sel->selected = normalized_rect(sel->start, sel->current);
            if (sel->selected.right - sel->selected.left < 8 ||
                sel->selected.bottom - sel->selected.top < 8)
                sel->cancelled = true;
            sel->done = true;
            return 0;
        }
        break;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(dc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
        if (sel && sel->dragging) {
            RECT box = normalized_rect(sel->start, sel->current);
            COLORREF key = RGB(255, 0, 255);
            HBRUSH clear = CreateSolidBrush(key);
            FillRect(dc, &box, clear);
            DeleteObject(clear);

            HBRUSH shade = CreateSolidBrush(RGB(255, 255, 255));
            RECT top{ box.left, box.top, box.right, box.top + std::max(1, scale_px(1)) };
            RECT bottom{ box.left, box.bottom - std::max(1, scale_px(1)), box.right, box.bottom };
            RECT left{ box.left, box.top, box.left + std::max(1, scale_px(1)), box.bottom };
            RECT right{ box.right - std::max(1, scale_px(1)), box.top, box.right, box.bottom };
            FillRect(dc, &top, shade);
            FillRect(dc, &bottom, shade);
            FillRect(dc, &left, shade);
            FillRect(dc, &right, shade);
            DeleteObject(shade);

            HPEN pen = CreatePen(PS_SOLID, std::max(1, scale_px(2)), RGB(0, 120, 215));
            HGDIOBJ old_pen = SelectObject(dc, pen);
            HGDIOBJ old_brush = SelectObject(dc, GetStockObject(HOLLOW_BRUSH));
            Rectangle(dc, box.left, box.top, box.right, box.bottom);
            SelectObject(dc, old_brush);
            SelectObject(dc, old_pen);
            DeleteObject(pen);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static bool select_screen_region(HWND owner, RECT *selected)
{
    HINSTANCE instance = GetModuleHandleW(nullptr);
    static bool registered = false;
    if (!registered) {
        WNDCLASSW wc{};
        wc.lpfnWndProc = qr_select_proc;
        wc.hInstance = instance;
        wc.lpszClassName = L"WgxQrSelectOverlay";
        wc.hCursor = LoadCursorW(nullptr, IDC_CROSS);
        wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        RegisterClassW(&wc);
        registered = true;
    }

    int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    QrSelection selection{};
    HWND overlay = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED,
                                   L"WgxQrSelectOverlay", L"",
                                   WS_POPUP, x, y, w, h,
                                   owner, nullptr, instance, &selection);
    if (!overlay)
        return false;

    SetLayeredWindowAttributes(overlay, RGB(255, 0, 255), 96, LWA_ALPHA | LWA_COLORKEY);
    ShowWindow(overlay, SW_SHOW);
    SetForegroundWindow(overlay);
    SetFocus(overlay);

    MSG msg;
    while (!selection.done && GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    DestroyWindow(overlay);
    Sleep(80);
    SetForegroundWindow(owner);
    if (selection.cancelled)
        return false;

    OffsetRect(&selection.selected, x, y);
    *selected = selection.selected;
    return true;
}

static bool capture_screen_gray(const RECT &rc, std::vector<uint8_t> &gray, int &width, int &height)
{
    width = rc.right - rc.left;
    height = rc.bottom - rc.top;
    if (width <= 0 || height <= 0)
        return false;

    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    BITMAPINFO bmi{};
    bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    void *bits = nullptr;
    HBITMAP bitmap = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!bitmap) {
        DeleteDC(mem);
        ReleaseDC(nullptr, screen);
        return false;
    }

    HGDIOBJ old = SelectObject(mem, bitmap);
    BOOL ok = BitBlt(mem, 0, 0, width, height, screen, rc.left, rc.top, SRCCOPY | CAPTUREBLT);
    GdiFlush();
    SelectObject(mem, old);
    if (!ok) {
        DeleteObject(bitmap);
        DeleteDC(mem);
        ReleaseDC(nullptr, screen);
        return false;
    }

    gray.resize((size_t)width * (size_t)height);
    uint8_t *bgra = (uint8_t *)bits;
    for (int i = 0; i < width * height; ++i) {
        uint8_t b = bgra[i * 4 + 0];
        uint8_t g = bgra[i * 4 + 1];
        uint8_t r = bgra[i * 4 + 2];
        gray[(size_t)i] = (uint8_t)((299 * r + 587 * g + 114 * b) / 1000);
    }

    DeleteObject(bitmap);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
    return true;
}

static void make_qr_attempt_image(const std::vector<uint8_t> &gray, int width, int height,
                                  int scale, int border, std::vector<uint8_t> &out,
                                  int &out_width, int &out_height, bool invert, int threshold)
{
    out_width = width * scale + border * 2;
    out_height = height * scale + border * 2;
    out.assign((size_t)out_width * (size_t)out_height, 255);

    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            uint8_t v = gray[(size_t)y * (size_t)width + (size_t)x];
            if (threshold >= 0)
                v = v < threshold ? 0 : 255;
            if (invert)
                v = (uint8_t)(255 - v);
            for (int sy = 0; sy < scale; ++sy) {
                uint8_t *row = &out[(size_t)(border + y * scale + sy) * (size_t)out_width + (size_t)border + (size_t)x * (size_t)scale];
                for (int sx = 0; sx < scale; ++sx)
                    row[sx] = v;
            }
        }
    }
}

static bool decode_qr_payload_once(const std::vector<uint8_t> &gray, int width, int height, std::string &payload)
{
    struct quirc *qr = quirc_new();
    if (!qr)
        return false;
    if (quirc_resize(qr, width, height) < 0) {
        quirc_destroy(qr);
        return false;
    }

    int qr_w = 0;
    int qr_h = 0;
    uint8_t *image = quirc_begin(qr, &qr_w, &qr_h);
    if (!image || qr_w != width || qr_h != height) {
        quirc_destroy(qr);
        return false;
    }
    std::memcpy(image, gray.data(), gray.size());
    quirc_end(qr);

    int count = quirc_count(qr);
    for (int i = 0; i < count; ++i) {
        struct quirc_code code{};
        struct quirc_data data{};
        quirc_extract(qr, i, &code);
        quirc_decode_error_t err = quirc_decode(&code, &data);
        if (err != QUIRC_SUCCESS) {
            quirc_flip(&code);
            err = quirc_decode(&code, &data);
        }
        if (err == QUIRC_SUCCESS && data.payload_len > 0) {
            payload.assign((const char *)data.payload, (size_t)data.payload_len);
            quirc_destroy(qr);
            return true;
        }
    }

    quirc_destroy(qr);
    return false;
}

static bool decode_qr_payload(const std::vector<uint8_t> &gray, int width, int height, std::string &payload)
{
    if (decode_qr_payload_once(gray, width, height, payload))
        return true;

    const int scales[] = { 1, 2, 3 };
    for (int scale : scales) {
        int border = std::max(16, std::min(width, height) / 8) * scale;
        const int thresholds[] = { -1, 96, 128, 160 };
        const bool inverts[] = { false, true };
        for (bool invert : inverts) {
            for (int threshold : thresholds) {
                std::vector<uint8_t> attempt;
                int attempt_width = 0;
                int attempt_height = 0;
                make_qr_attempt_image(gray, width, height, scale, border, attempt, attempt_width, attempt_height, invert, threshold);
                if (decode_qr_payload_once(attempt, attempt_width, attempt_height, payload))
                    return true;
            }
        }
    }

    return false;
}

static std::string ascii_lower(std::string text)
{
    for (char &ch : text) {
        if (ch >= 'A' && ch <= 'Z')
            ch = (char)(ch - 'A' + 'a');
    }
    return text;
}

static bool looks_like_wireguard_config(const std::string &text)
{
    std::string lower = ascii_lower(text);
    return lower.find("[interface]") != std::string::npos &&
           lower.find("privatekey") != std::string::npos &&
           lower.find("[peer]") != std::string::npos &&
           lower.find("publickey") != std::string::npos;
}

static bool write_imported_tunnel(HWND hwnd, const std::string &config, const std::wstring &name)
{
    std::wstring target = unique_target_path_for_name(name);
    HANDLE file = CreateFileW(target.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        MessageBoxW(hwnd, L"Failed to create tunnel config.", L"wgx", MB_ICONERROR);
        return false;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(file, config.data(), (DWORD)config.size(), &written, nullptr);
    CloseHandle(file);
    if (!ok || written != (DWORD)config.size()) {
        DeleteFileW(target.c_str());
        MessageBoxW(hwnd, L"Failed to write tunnel config.", L"wgx", MB_ICONERROR);
        return false;
    }
    return true;
}

static void import_qr_tunnel(HWND hwnd)
{
    ShowWindow(hwnd, SW_MINIMIZE);
    Sleep(120);

    RECT selection{};
    if (!select_screen_region(hwnd, &selection)) {
        ShowWindow(hwnd, SW_RESTORE);
        return;
    }

    std::vector<uint8_t> gray;
    int width = 0;
    int height = 0;
    if (!capture_screen_gray(selection, gray, width, height)) {
        ShowWindow(hwnd, SW_RESTORE);
        MessageBoxW(hwnd, L"Failed to capture selected screen region.", L"wgx", MB_ICONERROR);
        return;
    }

    std::string payload;
    if (!decode_qr_payload(gray, width, height, payload)) {
        ShowWindow(hwnd, SW_RESTORE);
        MessageBoxW(hwnd,
                    L"No QR code was recognized in the selected region.\n\nSelect a slightly larger area around the QR code and try again.",
                    L"wgx",
                    MB_ICONWARNING);
        return;
    }

    if (!looks_like_wireguard_config(payload)) {
        ShowWindow(hwnd, SW_RESTORE);
        MessageBoxW(hwnd, L"The QR code does not contain a WireGuard tunnel config.", L"wgx", MB_ICONWARNING);
        return;
    }

    ShowWindow(hwnd, SW_RESTORE);
    SetForegroundWindow(hwnd);
    std::wstring name;
    if (!prompt_tunnel_name(hwnd, L"Import Tunnel from QR Code", L"qr-tunnel", name))
        return;

    if (write_imported_tunnel(hwnd, payload, name)) {
        load_tunnels();
        refresh_list();
    }
}

static void show_import_menu(HWND hwnd)
{
    HMENU menu = CreatePopupMenu();
    append_owner_draw_menu_item(menu, ID_IMPORT_FILE, &g_import_file_menu);
    append_owner_draw_menu_item(menu, ID_IMPORT_QR, &g_import_qr_menu);

    RECT rc;
    HWND button = GetDlgItem(hwnd, ID_IMPORT_BUTTON);
    GetWindowRect(button ? button : hwnd, &rc);
    TrackPopupMenu(menu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON,
                   rc.left, rc.bottom + scale_px(2), 0, hwnd, nullptr);
    DestroyMenu(menu);
}

static void toggle_selected_tunnel(HWND hwnd)
{
    if (is_selected_tunnel_running())
        stop_tunnel();
    else
        start_tunnel(hwnd);
}

static void show_about(HWND hwnd)
{
    MessageBoxW(hwnd,
                L"wgx for Windows\n\nNative WireGuard tunnel manager.",
                L"About wgx",
                MB_OK | MB_ICONINFORMATION);
}

static void create_main_menu(HWND hwnd)
{
    HMENU menubar = CreateMenu();
    HMENU file = CreatePopupMenu();
    HMENU about = CreatePopupMenu();

    append_owner_draw_menu_item(file, ID_IMPORT_FILE, &g_import_file_menu);
    append_owner_draw_menu_item(file, ID_IMPORT_QR, &g_import_qr_menu);
    AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
    append_owner_draw_menu_item(file, ID_FILE_EXIT, &g_exit_menu);

    AppendMenuW(about, MF_STRING, ID_ABOUT, L"About wgx");

    AppendMenuW(menubar, MF_POPUP, (UINT_PTR)file, L"File");
    AppendMenuW(menubar, MF_POPUP, (UINT_PTR)about, L"About");
    MENUITEMINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = MIIM_FTYPE;
    info.fType = MFT_STRING | MFT_RIGHTJUSTIFY;
    SetMenuItemInfoW(menubar, 1, TRUE, &info);
    SetMenu(hwnd, menubar);
}

static void start_tunnel(HWND hwnd)
{
    TunnelProfile *t = selected_tunnel();
    if (!t || g_running.count(t->name))
        return;

    std::wstring exe = exe_dir() + L"\\wgx-win.exe";
    if (GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(hwnd, L"wgx-win.exe was not found next to wgx-ui.exe.", L"wgx", MB_ICONERROR);
        return;
    }

    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE stdin_read = nullptr;
    HANDLE stdin_write = nullptr;
    if (!CreatePipe(&stdin_read, &stdin_write, &sa, 0))
        return;
    SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);

    HANDLE output_read = nullptr;
    HANDLE output_write = nullptr;
    if (!CreatePipe(&output_read, &output_write, &sa, 0)) {
        CloseHandle(stdin_read);
        CloseHandle(stdin_write);
        return;
    }
    SetHandleInformation(output_read, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = stdin_read;
    si.hStdOutput = output_write;
    si.hStdError = output_write;

    std::wstring cmd = L"\"" + exe + L"\" --config \"" + t->path + L"\" --name \"" + t->name + L"\"";
    BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, exe_dir().c_str(), &si, &pi);
    CloseHandle(stdin_read);
    CloseHandle(output_write);
    if (!ok) {
        CloseHandle(stdin_write);
        CloseHandle(output_read);
        MessageBoxW(hwnd, L"Failed to start wgx-win.exe.", L"wgx", MB_ICONERROR);
        return;
    }

    RunningTunnel running;
    running.pi = pi;
    running.stdin_write = stdin_write;
    running.output_read = output_read;
    running.started_tick = GetTickCount();
    g_running[t->name] = running;
    t->state = L"Connecting";
    t->last_log = L"Process started.";
    refresh_list();
    update_tray_icon();
}

static void drain_tunnel_output(TunnelProfile &t, RunningTunnel &running)
{
    if (!running.output_read)
        return;

    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(running.output_read, nullptr, 0, nullptr, &available, nullptr) || available == 0)
            return;

        char buf[1025];
        DWORD to_read = std::min<DWORD>(available, sizeof(buf) - 1);
        DWORD read = 0;
        if (!ReadFile(running.output_read, buf, to_read, &read, nullptr) || read == 0)
            return;
        buf[read] = '\0';
        append_log(t, trim(utf8_to_wide(std::string(buf, read))));
    }
}

static void stop_tunnel()
{
    TunnelProfile *t = selected_tunnel();
    if (!t)
        return;
    auto it = g_running.find(t->name);
    if (it == g_running.end())
        return;

    const char stop[] = "stop\n";
    DWORD written = 0;
    WriteFile(it->second.stdin_write, stop, sizeof(stop) - 1, &written, nullptr);
    WaitForSingleObject(it->second.pi.hProcess, 1500);
    DWORD code = STILL_ACTIVE;
    GetExitCodeProcess(it->second.pi.hProcess, &code);
    if (code == STILL_ACTIVE)
        TerminateProcess(it->second.pi.hProcess, 1);
    drain_tunnel_output(*t, it->second);

    CloseHandle(it->second.stdin_write);
    CloseHandle(it->second.output_read);
    CloseHandle(it->second.pi.hThread);
    CloseHandle(it->second.pi.hProcess);
    g_running.erase(it);
    t->state = L"Stopped";
    append_log(*t, L"Process stopped.");
    refresh_list();
    update_tray_icon();
}

static void check_running_processes()
{
    bool changed = false;
    for (auto it = g_running.begin(); it != g_running.end();) {
        TunnelProfile *profile = nullptr;
        for (TunnelProfile &t : g_tunnels) {
            if (t.name == it->first) {
                profile = &t;
                break;
            }
        }
        if (profile)
            drain_tunnel_output(*profile, it->second);

        DWORD code = STILL_ACTIVE;
        GetExitCodeProcess(it->second.pi.hProcess, &code);
        if (code == STILL_ACTIVE) {
            if (profile && profile->state == L"Connecting" &&
                GetTickCount() - it->second.started_tick > 1500) {
                profile->state = L"Running";
                changed = true;
            }
            ++it;
            continue;
        }

        if (profile) {
            profile->state = code == 0 ? L"Stopped" : L"Failed";
            append_log(*profile, L"Process exited with code " + std::to_wstring(code) + L".");
            changed = true;
        }
        CloseHandle(it->second.stdin_write);
        CloseHandle(it->second.output_read);
        CloseHandle(it->second.pi.hThread);
        CloseHandle(it->second.pi.hProcess);
        it = g_running.erase(it);
    }
    if (changed) {
        refresh_list();
        update_tray_icon();
    } else {
        refresh_detail();
    }
}

static void delete_tunnel(HWND hwnd)
{
    TunnelProfile *t = selected_tunnel();
    if (!t)
        return;
    std::wstring name = t->name;
    std::wstring path = t->path;
    std::wstring message = L"Delete tunnel \"" + name + L"\"?\n\nThis cannot be undone.";
    int result = MessageBoxW(hwnd, message.c_str(), L"Delete Tunnel",
                             MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    if (result != IDYES)
        return;

    stop_tunnel();
    if (!DeleteFileW(path.c_str())) {
        MessageBoxW(hwnd, L"Failed to delete tunnel config.", L"wgx", MB_ICONERROR);
        return;
    }
    load_tunnels();
    refresh_list();
}

static void edit_tunnel(HWND hwnd)
{
    TunnelProfile *t = selected_tunnel();
    if (!t)
        return;

    std::wstring params = L"\"" + t->path + L"\"";
    HINSTANCE result = ShellExecuteW(hwnd, L"open", L"notepad.exe", params.c_str(), nullptr, SW_SHOWNORMAL);
    if ((INT_PTR)result <= 32)
        MessageBoxW(hwnd, L"Failed to open tunnel config.", L"wgx", MB_ICONERROR);
}

static void append_owner_draw_menu_item(HMENU menu, UINT id, OwnerDrawMenuItem *data)
{
    MENUITEMINFOW item{};
    item.cbSize = sizeof(item);
    item.fMask = MIIM_FTYPE | MIIM_ID | MIIM_DATA;
    item.fType = MFT_OWNERDRAW;
    item.wID = id;
    item.dwItemData = (ULONG_PTR)data;
    InsertMenuItemW(menu, GetMenuItemCount(menu), TRUE, &item);
}

static bool is_context_menu_item(const MEASUREITEMSTRUCT *item)
{
    return item && item->CtlType == ODT_MENU &&
           (item->itemID == ID_EDIT || item->itemID == ID_DELETE ||
            item->itemID == ID_IMPORT_FILE || item->itemID == ID_IMPORT_QR ||
            item->itemID == ID_FILE_EXIT) &&
           item->itemData;
}

static bool is_context_menu_item(const DRAWITEMSTRUCT *item)
{
    return item && item->CtlType == ODT_MENU &&
           (item->itemID == ID_EDIT || item->itemID == ID_DELETE ||
            item->itemID == ID_IMPORT_FILE || item->itemID == ID_IMPORT_QR ||
            item->itemID == ID_FILE_EXIT) &&
           item->itemData;
}

static void measure_context_menu_item(HWND hwnd, MEASUREITEMSTRUCT *item)
{
    OwnerDrawMenuItem *data = (OwnerDrawMenuItem *)item->itemData;
    HDC dc = GetDC(hwnd);
    HFONT old_font = (HFONT)SelectObject(dc, g_ui_font);
    SIZE text_size{};
    GetTextExtentPoint32W(dc, data->text, (int)wcslen(data->text), &text_size);
    SelectObject(dc, old_font);
    ReleaseDC(hwnd, dc);

    int icon = GetSystemMetrics(SM_CXSMICON);
    int check = GetSystemMetrics(SM_CXMENUCHECK);
    item->itemWidth = MulDiv(check + icon + scale_px(18) + text_size.cx, 3, 2);
    item->itemHeight = std::max(GetSystemMetrics(SM_CYMENU), icon + scale_px(8));
}

static void draw_context_menu_item(const DRAWITEMSTRUCT *item)
{
    OwnerDrawMenuItem *data = (OwnerDrawMenuItem *)item->itemData;
    bool selected = (item->itemState & ODS_SELECTED) != 0;
    COLORREF bg = GetSysColor(selected ? COLOR_HIGHLIGHT : COLOR_MENU);
    COLORREF text = GetSysColor(selected ? COLOR_HIGHLIGHTTEXT : COLOR_MENUTEXT);
    HBRUSH brush = CreateSolidBrush(bg);
    FillRect(item->hDC, &item->rcItem, brush);
    DeleteObject(brush);

    int icon_size = GetSystemMetrics(SM_CXSMICON);
    int icon_x = item->rcItem.left + GetSystemMetrics(SM_CXMENUCHECK);
    int icon_y = item->rcItem.top + ((item->rcItem.bottom - item->rcItem.top) - icon_size) / 2;
    if (data->resource_icon) {
        HICON icon = (HICON)LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(data->resource_icon),
                                       IMAGE_ICON, icon_size, icon_size, LR_DEFAULTCOLOR);
        if (icon) {
            DrawIconEx(item->hDC, icon_x, icon_y, icon, icon_size, icon_size, 0, nullptr, DI_NORMAL);
            DestroyIcon(icon);
        }
    } else if (data->close_icon) {
        int pad = std::max(3, scale_px(4));
        HPEN pen = CreatePen(PS_SOLID, std::max(1, scale_px(2)), text);
        HGDIOBJ old_pen = SelectObject(item->hDC, pen);
        MoveToEx(item->hDC, icon_x + pad, icon_y + pad, nullptr);
        LineTo(item->hDC, icon_x + icon_size - pad, icon_y + icon_size - pad);
        MoveToEx(item->hDC, icon_x + icon_size - pad, icon_y + pad, nullptr);
        LineTo(item->hDC, icon_x + pad, icon_y + icon_size - pad);
        SelectObject(item->hDC, old_pen);
        DeleteObject(pen);
    } else if (data->icon != SIID_INVALID) {
        SHSTOCKICONINFO icon{};
        icon.cbSize = sizeof(icon);
        if (SUCCEEDED(SHGetStockIconInfo(data->icon, SHGSI_ICON | SHGSI_SMALLICON, &icon))) {
            DrawIconEx(item->hDC, icon_x, icon_y, icon.hIcon, icon_size, icon_size, 0, nullptr, DI_NORMAL);
            DestroyIcon(icon.hIcon);
        }
    }

    RECT text_rc = item->rcItem;
    text_rc.left = icon_x + icon_size + scale_px(10);
    SetBkMode(item->hDC, TRANSPARENT);
    SetTextColor(item->hDC, text);
    HFONT old_font = (HFONT)SelectObject(item->hDC, g_ui_font);
    DrawTextW(item->hDC, data->text, -1, &text_rc, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX);
    SelectObject(item->hDC, old_font);
}

static void draw_empty_import_button(const DRAWITEMSTRUCT *item)
{
    bool pressed = (item->itemState & ODS_SELECTED) != 0;
    bool focused = (item->itemState & ODS_FOCUS) != 0;
    bool disabled = (item->itemState & ODS_DISABLED) != 0;
    RECT rc = item->rcItem;
    InflateRect(&rc, -1, -1);

    COLORREF fill = pressed ? RGB(224, 236, 250) :
                    g_empty_import_hover ? RGB(242, 247, 252) : GetSysColor(COLOR_WINDOW);
    COLORREF border = GetSysColor((focused || g_empty_import_hover) ? COLOR_HIGHLIGHT : COLOR_ACTIVEBORDER);
    COLORREF text = GetSysColor(disabled ? COLOR_GRAYTEXT : COLOR_WINDOWTEXT);

    HBRUSH fill_brush = CreateSolidBrush(fill);
    HPEN border_pen = CreatePen(PS_SOLID, std::max(1, scale_px(1)), border);
    HGDIOBJ old_brush = SelectObject(item->hDC, fill_brush);
    HGDIOBJ old_pen = SelectObject(item->hDC, border_pen);
    int radius = scale_px(18);
    RoundRect(item->hDC, rc.left, rc.top, rc.right, rc.bottom, radius, radius);
    SelectObject(item->hDC, old_pen);
    SelectObject(item->hDC, old_brush);
    DeleteObject(border_pen);
    DeleteObject(fill_brush);

    SetBkMode(item->hDC, TRANSPARENT);
    SetTextColor(item->hDC, text);
    HFONT old_font = (HFONT)SelectObject(item->hDC, g_ui_font);
    DrawTextW(item->hDC, L"Import Tunnel", -1, &rc, DT_SINGLELINE | DT_CENTER | DT_VCENTER | DT_NOPREFIX);
    SelectObject(item->hDC, old_font);
}

static void show_tunnel_context_menu(HWND list, int index, POINT screen_pt)
{
    if (index < 0 || index >= (int)g_tunnels.size())
        return;

    ListView_SetItemState(list, index, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    refresh_detail();

    OwnerDrawMenuItem edit_item{ L"Edit", SIID_INVALID, IDI_MENU_EDIT, false };
    OwnerDrawMenuItem delete_item{ L"Delete", SIID_INVALID, IDI_MENU_REMOVE, false };
    HMENU menu = CreatePopupMenu();
    append_owner_draw_menu_item(menu, ID_EDIT, &edit_item);
    append_owner_draw_menu_item(menu, ID_DELETE, &delete_item);

    HWND parent = GetParent(list);
    SetForegroundWindow(parent);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, screen_pt.x, screen_pt.y, 0, parent, nullptr);
    DestroyMenu(menu);
}

static LRESULT CALLBACK list_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (msg == WM_LBUTTONDOWN) {
        POINT pt{ GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam) };
        LVHITTESTINFO hit{};
        hit.pt = pt;
        if (ListView_HitTest(hwnd, &hit) < 0) {
            SetFocus(hwnd);
            return 0;
        }
    } else if (msg == WM_RBUTTONDOWN) {
        POINT pt{ GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam) };
        LVHITTESTINFO hit{};
        hit.pt = pt;
        if (ListView_HitTest(hwnd, &hit) < 0)
            return 0;
    } else if (msg == WM_RBUTTONUP) {
        POINT pt{ GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam) };
        LVHITTESTINFO hit{};
        hit.pt = pt;
        int index = ListView_HitTest(hwnd, &hit);
        if (index >= 0) {
            POINT screen_pt = pt;
            ClientToScreen(hwnd, &screen_pt);
            show_tunnel_context_menu(hwnd, index, screen_pt);
            return 0;
        }
    } else if (msg == WM_CONTEXTMENU) {
        POINT screen_pt{ GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam) };
        if (screen_pt.x == -1 && screen_pt.y == -1) {
            int index = selected_index();
            if (index >= 0) {
                RECT rc{};
                ListView_GetItemRect(hwnd, index, &rc, LVIR_BOUNDS);
                screen_pt.x = rc.left + scale_px(24);
                screen_pt.y = rc.top + (rc.bottom - rc.top) / 2;
                ClientToScreen(hwnd, &screen_pt);
                show_tunnel_context_menu(hwnd, index, screen_pt);
            }
            return 0;
        }

        POINT client_pt = screen_pt;
        ScreenToClient(hwnd, &client_pt);
        LVHITTESTINFO hit{};
        hit.pt = client_pt;
        int index = ListView_HitTest(hwnd, &hit);
        if (index >= 0) {
            show_tunnel_context_menu(hwnd, index, screen_pt);
            return 0;
        }
    } else if (msg == WM_NCDESTROY) {
        SetWindowLongPtrW(hwnd, GWLP_WNDPROC, (LONG_PTR)g_list_proc);
    }

    return CallWindowProcW(g_list_proc, hwnd, msg, wparam, lparam);
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_CREATE: {
        g_dpi = window_dpi(hwnd);
        g_sidebar_width = scale_px(300);
        recreate_fonts();
        create_main_menu(hwnd);
        g_app_icon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_WGX_APP));
        g_tray_unlock_icon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_SYSTRAY_UNLOCK));
        g_tray_lock_icon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_SYSTRAY_LOCK));
        load_status_icons();
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)g_app_icon);
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)g_app_icon);
        g_list = CreateWindowW(WC_LISTVIEWW, nullptr,
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL |
                               LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOCOLUMNHEADER,
                               0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)ID_TUNNEL_LIST, nullptr, nullptr);
        SetWindowTheme(g_list, L"Explorer", nullptr);
        SendMessageW(g_list, WM_SETFONT, (WPARAM)g_ui_font, TRUE);
        ListView_SetBkColor(g_list, GetSysColor(COLOR_WINDOW));
        ListView_SetTextBkColor(g_list, CLR_NONE);
        ListView_SetTextColor(g_list, GetSysColor(COLOR_WINDOWTEXT));
        ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_INFOTIP);
        g_list_proc = (WNDPROC)SetWindowLongPtrW(g_list, GWLP_WNDPROC, (LONG_PTR)list_proc);
        LVCOLUMNW col{};
        col.mask = LVCF_WIDTH;
        col.cx = g_sidebar_width - 8;
        ListView_InsertColumn(g_list, 0, &col);
        recreate_status_images();
        g_path = value(hwnd, 0, 0, 0, 0);
        g_toggle_button = button(hwnd, L"Start", ID_TOGGLE_TUNNEL);
        g_empty_import_button = rounded_button(hwnd, L"Import Tunnel", ID_IMPORT_BUTTON);
        g_address = value(hwnd, 0, 0, 0, 0);
        g_dns = value(hwnd, 0, 0, 0, 0);
        g_peer = value(hwnd, 0, 0, 0, 0);
        g_endpoint = value(hwnd, 0, 0, 0, 0);
        g_allowed_ips = value(hwnd, 0, 0, 0, 0);
        g_log = CreateWindowW(L"EDIT", nullptr, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
                              0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
        SetWindowTheme(g_log, L"Explorer", nullptr);
        SendMessageW(g_log, WM_SETFONT, (WPARAM)g_ui_font, TRUE);
        add_tray(hwnd);
        SetTimer(hwnd, 1, 1000, nullptr);
        load_tunnels();
        refresh_list();
        return 0;
    }
    case WM_SIZE:
        relayout_and_repaint(hwnd);
        return 0;
    case WM_DPICHANGED: {
        g_dpi = HIWORD(wparam);
        RECT *suggested = (RECT *)lparam;
        if (suggested) {
            SetWindowPos(hwnd, nullptr, suggested->left, suggested->top,
                         suggested->right - suggested->left,
                         suggested->bottom - suggested->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
        }
        recreate_fonts();
        recreate_status_images();
        load_status_icons();
        apply_fonts();
        relayout_and_repaint(hwnd);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_MEASUREITEM:
        if (is_context_menu_item((MEASUREITEMSTRUCT *)lparam)) {
            measure_context_menu_item(hwnd, (MEASUREITEMSTRUCT *)lparam);
            return TRUE;
        }
        break;
    case WM_DRAWITEM:
        if (is_context_menu_item((DRAWITEMSTRUCT *)lparam)) {
            draw_context_menu_item((DRAWITEMSTRUCT *)lparam);
            return TRUE;
        }
        if (((DRAWITEMSTRUCT *)lparam)->CtlType == ODT_BUTTON &&
            ((DRAWITEMSTRUCT *)lparam)->CtlID == ID_IMPORT_BUTTON) {
            draw_empty_import_button((DRAWITEMSTRUCT *)lparam);
            return TRUE;
        }
        break;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(dc, &rc, (HBRUSH)(COLOR_WINDOW + 1));
        RECT sidebar_title{ scale_px(16), scale_px(14), g_sidebar_width - scale_px(16), scale_px(44) };
        HFONT old_font = (HFONT)SelectObject(dc, g_sidebar_title_font);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
        DrawTextW(dc, L"Tunnels", -1, &sidebar_title, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX);
        SelectObject(dc, old_font);

        int detail_x = g_sidebar_width + scale_px(kSplitterWidth) + scale_px(18);
        if (!g_tunnels.empty()) {
            int right_w = rc.right - detail_x - scale_px(18);
            int title_icon_size = scale_px(24);
            HICON state_icon = status_icon_for_state(detail_state());
            if (state_icon)
                DrawIconEx(dc, detail_x, scale_px(22), state_icon, title_icon_size, title_icon_size, 0, nullptr, DI_NORMAL);
            RECT title_rc{ detail_x + scale_px(34), scale_px(18),
                           detail_x + right_w - scale_px(140), scale_px(52) };
            HFONT old_title_font = (HFONT)SelectObject(dc, g_title_font);
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
            std::wstring title = detail_title_text();
            DrawTextW(dc, title.c_str(), -1, &title_rc, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX | DT_END_ELLIPSIS);
            SelectObject(dc, old_title_font);

            int label_y = scale_px(104);
            int label_row = scale_px(34);
            const wchar_t *detail_labels[] = { L"Interface", L"DNS", L"Peer", L"Endpoint", L"Allowed IPs" };
            HFONT old_detail_font = (HFONT)SelectObject(dc, g_ui_font);
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
            for (const wchar_t *text : detail_labels) {
                RECT label_rc{ detail_x, label_y, detail_x + scale_px(120), label_y + scale_px(24) };
                DrawTextW(dc, text, -1, &label_rc, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX);
                label_y += label_row;
            }
            SelectObject(dc, old_detail_font);
        }

        RECT splitter_hit = splitter_rect(hwnd);
        RECT splitter_line = splitter_hit;
        int visual_width = std::max(1, scale_px(kSplitterVisualWidth));
        splitter_line.left += (scale_px(kSplitterWidth) - visual_width) / 2;
        splitter_line.right = splitter_line.left + visual_width;
        FillRect(dc, &splitter_line,
                 (HBRUSH)((g_splitter_hover || g_splitter_dragging) ? COLOR_HIGHLIGHT + 1 : COLOR_3DLIGHT + 1));
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_SETCURSOR: {
        POINT pt;
        GetCursorPos(&pt);
        ScreenToClient(hwnd, &pt);
        if (hit_splitter(pt.x)) {
            SetCursor(LoadCursorW(nullptr, IDC_SIZEWE));
            return TRUE;
        }
        break;
    }
    case WM_LBUTTONDOWN: {
        int x = GET_X_LPARAM(lparam);
        if (hit_splitter(x)) {
            g_splitter_dragging = true;
            g_splitter_hover = true;
            SetCapture(hwnd);
            SetCursor(LoadCursorW(nullptr, IDC_SIZEWE));
            invalidate_splitter(hwnd);
            return 0;
        }
        break;
    }
    case WM_MOUSEMOVE:
        if (g_splitter_dragging) {
            RECT rc;
            GetClientRect(hwnd, &rc);
            int max_width = std::min(scale_px(kSidebarMax), std::max(scale_px(kSidebarMin), (int)rc.right - scale_px(380)));
            g_sidebar_width = std::min(std::max(GET_X_LPARAM(lparam), scale_px(kSidebarMin)), max_width);
            relayout_and_repaint(hwnd);
            return 0;
        }
        {
            bool hover = hit_splitter(GET_X_LPARAM(lparam));
            if (hover != g_splitter_hover) {
                g_splitter_hover = hover;
                invalidate_splitter(hwnd);
                TRACKMOUSEEVENT track{};
                track.cbSize = sizeof(track);
                track.dwFlags = TME_LEAVE;
                track.hwndTrack = hwnd;
                TrackMouseEvent(&track);
            }
        }
        break;
    case WM_MOUSELEAVE:
        if (g_splitter_hover && !g_splitter_dragging) {
            g_splitter_hover = false;
            invalidate_splitter(hwnd);
            return 0;
        }
        break;
    case WM_LBUTTONUP:
        if (g_splitter_dragging) {
            g_splitter_dragging = false;
            ReleaseCapture();
            invalidate_splitter(hwnd);
            return 0;
        }
        break;
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case ID_IMPORT_BUTTON:
            show_import_menu(hwnd);
            return 0;
        case ID_IMPORT_QR:
            import_qr_tunnel(hwnd);
            return 0;
        case ID_IMPORT_FILE:
            import_tunnel(hwnd);
            return 0;
        case ID_FILE_EXIT:
            DestroyWindow(hwnd);
            return 0;
        case ID_ABOUT:
            show_about(hwnd);
            return 0;
        case ID_EDIT:
            edit_tunnel(hwnd);
            return 0;
        case ID_TOGGLE_TUNNEL:
            toggle_selected_tunnel(hwnd);
            return 0;
        case ID_DELETE:
            delete_tunnel(hwnd);
            return 0;
        case ID_TRAY_SHOW:
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
            return 0;
        case ID_TRAY_EXIT:
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_NOTIFY: {
        NMHDR *hdr = (NMHDR *)lparam;
        if (hdr->idFrom == ID_TUNNEL_LIST && hdr->code == LVN_ITEMCHANGED) {
            NMLISTVIEW *lv = (NMLISTVIEW *)lparam;
            if ((lv->uChanged & LVIF_STATE) &&
                (lv->uNewState & LVIS_SELECTED) &&
                !(lv->uOldState & LVIS_SELECTED)) {
                refresh_detail();
            }
            return 0;
        }
        break;
    }
    case WM_TIMER:
        check_running_processes();
        return 0;
    case WGX_TRAY_MESSAGE:
        if (lparam == WM_LBUTTONDBLCLK) {
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
        } else if (lparam == WM_RBUTTONUP) {
            show_tray_menu(hwnd);
        }
        return 0;
    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    case WM_DESTROY:
        for (auto &entry : g_running) {
            const char stop[] = "stop\n";
            DWORD written = 0;
            WriteFile(entry.second.stdin_write, stop, sizeof(stop) - 1, &written, nullptr);
            CloseHandle(entry.second.stdin_write);
            CloseHandle(entry.second.output_read);
            CloseHandle(entry.second.pi.hThread);
            CloseHandle(entry.second.pi.hProcess);
        }
        g_running.clear();
        KillTimer(hwnd, 1);
        remove_tray();
        if (g_ui_font)
            DeleteObject(g_ui_font);
        if (g_title_font)
            DeleteObject(g_title_font);
        if (g_sidebar_title_font)
            DeleteObject(g_sidebar_title_font);
        if (g_status_images)
            ImageList_Destroy(g_status_images);
        if (g_status_dot_stopped)
            DeleteObject(g_status_dot_stopped);
        if (g_status_dot_running)
            DeleteObject(g_status_dot_running);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
    enable_dpi_awareness();

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSW wc{};
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = instance;
    wc.lpszClassName = L"WgxWindowsMainWindow";
    wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_WGX_APP));
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&wc);

    g_main_window = CreateWindowW(wc.lpszClassName, L"wgx for Windows",
                                  WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT,
                                  980, 640, nullptr, nullptr, instance, nullptr);
    ShowWindow(g_main_window, show);
    UpdateWindow(g_main_window);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
