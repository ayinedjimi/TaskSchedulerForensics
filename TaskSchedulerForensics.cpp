/*
 * TaskSchedulerForensics - Analyseur forensics des tâches planifiées Windows
 * Partie de WinToolsSuite v3.0
 *
 * Parse et analyse les tâches Task Scheduler pour détecter :
 * - Persistence via tâches cachées
 * - Actions suspectes (PowerShell encodé, scripts, downloads)
 * - Élévation de privilèges (RunLevel=HighestAvailable)
 * - Triggers anormaux
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <commctrl.h>
#include <taskschd.h>
#include <comdef.h>
#include <wincrypt.h>
#include <softpub.h>
#include <vector>
#include <string>
#include <fstream>
#include <memory>
#include <algorithm>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// IDs des contrôles
#define IDC_LISTVIEW        1001
#define IDC_BTN_ENUMERATE   1002
#define IDC_BTN_EXPORT      1003
#define IDC_BTN_DISABLE     1004
#define IDC_STATUS          1005

// Colonnes ListView
enum {
    COL_NAME = 0,
    COL_PATH,
    COL_TRIGGER,
    COL_ACTION,
    COL_PRINCIPAL,
    COL_HIDDEN,
    COL_SUSPECT,
    COL_NOTES
};

// Structure pour une tâche
struct TaskItem {
    std::wstring name;
    std::wstring path;
    std::wstring trigger;
    std::wstring action;
    std::wstring principal;
    bool hidden;
    bool suspect;
    std::wstring notes;
    std::wstring xmlDefinition;
};

// Variables globales
HWND g_hListView = nullptr;
HWND g_hStatus = nullptr;
std::vector<TaskItem> g_tasks;
HFONT g_hFont = nullptr;

// RAII pour COM
class COMInitializer {
public:
    COMInitializer() {
        m_hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    }
    ~COMInitializer() {
        if (SUCCEEDED(m_hr)) {
            CoUninitialize();
        }
    }
    bool IsInitialized() const { return SUCCEEDED(m_hr); }
private:
    HRESULT m_hr;
};

// Vérification signature digitale
bool IsFileSigned(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();

    GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(nullptr, &actionGUID, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &actionGUID, &trustData);

    return (status == ERROR_SUCCESS);
}

// Extraction BSTR safe
std::wstring SafeBSTR(BSTR bstr) {
    if (bstr == nullptr) return L"";
    return std::wstring(bstr);
}

// Détection de contenu suspect
bool IsSuspicious(const TaskItem& task, std::wstring& notes) {
    bool suspect = false;
    notes.clear();

    // Tâche cachée
    if (task.hidden) {
        suspect = true;
        notes += L"Tâche cachée; ";
    }

    // Principal avec élévation
    if (task.principal.find(L"HighestAvailable") != std::wstring::npos ||
        task.principal.find(L"SYSTEM") != std::wstring::npos) {
        suspect = true;
        notes += L"Élévation privilèges; ";
    }

    // Actions suspectes
    std::wstring actionLower = task.action;
    std::transform(actionLower.begin(), actionLower.end(), actionLower.begin(), ::tolower);

    std::vector<std::wstring> suspiciousPatterns = {
        L"powershell", L"cmd.exe", L"wscript", L"cscript",
        L"base64", L"encodedcommand", L"downloadstring",
        L"invoke-expression", L"iex", L"hidden",
        L"bypass", L"regsvr32", L"rundll32", L"mshta",
        L"http://", L"https://", L"ftp://"
    };

    for (const auto& pattern : suspiciousPatterns) {
        if (actionLower.find(pattern) != std::wstring::npos) {
            suspect = true;
            notes += L"Pattern: " + pattern + L"; ";
        }
    }

    // Triggers fréquents
    if (task.trigger.find(L"DAILY") != std::wstring::npos ||
        task.trigger.find(L"HOURLY") != std::wstring::npos ||
        task.trigger.find(L"LOGON") != std::wstring::npos ||
        task.trigger.find(L"BOOT") != std::wstring::npos) {
        if (suspect) {
            notes += L"Trigger persistence; ";
        }
    }

    // Action longue (obfuscation)
    if (task.action.length() > 400) {
        suspect = true;
        notes += L"Commande très longue; ";
    }

    return suspect;
}

// Parse triggers
std::wstring ParseTriggers(ITaskDefinition* pTask) {
    ITriggerCollection* pTriggers = nullptr;
    HRESULT hr = pTask->get_Triggers(&pTriggers);
    if (FAILED(hr) || !pTriggers) return L"(aucun)";

    long count = 0;
    pTriggers->get_Count(&count);

    std::wstring result;
    for (long i = 1; i <= count; ++i) {
        ITrigger* pTrigger = nullptr;
        if (SUCCEEDED(pTriggers->get_Item(i, &pTrigger))) {
            TASK_TRIGGER_TYPE2 type;
            pTrigger->get_Type(&type);

            if (i > 1) result += L", ";

            switch (type) {
                case TASK_TRIGGER_BOOT: result += L"BOOT"; break;
                case TASK_TRIGGER_LOGON: result += L"LOGON"; break;
                case TASK_TRIGGER_DAILY: result += L"DAILY"; break;
                case TASK_TRIGGER_WEEKLY: result += L"WEEKLY"; break;
                case TASK_TRIGGER_MONTHLY: result += L"MONTHLY"; break;
                case TASK_TRIGGER_TIME: result += L"TIME"; break;
                case TASK_TRIGGER_EVENT: result += L"EVENT"; break;
                default: result += L"OTHER"; break;
            }

            pTrigger->Release();
        }
    }

    pTriggers->Release();
    return result.empty() ? L"(aucun)" : result;
}

// Parse actions
std::wstring ParseActions(ITaskDefinition* pTask) {
    IActionCollection* pActions = nullptr;
    HRESULT hr = pTask->get_Actions(&pActions);
    if (FAILED(hr) || !pActions) return L"(aucune)";

    long count = 0;
    pActions->get_Count(&count);

    std::wstring result;
    for (long i = 1; i <= count; ++i) {
        IAction* pAction = nullptr;
        if (SUCCEEDED(pActions->get_Item(i, &pAction))) {
            TASK_ACTION_TYPE type;
            pAction->get_Type(&type);

            if (type == TASK_ACTION_EXEC) {
                IExecAction* pExec = nullptr;
                if (SUCCEEDED(pAction->QueryInterface(IID_IExecAction, (void**)&pExec))) {
                    BSTR path = nullptr;
                    BSTR args = nullptr;
                    pExec->get_Path(&path);
                    pExec->get_Arguments(&args);

                    if (i > 1) result += L" | ";
                    result += SafeBSTR(path);
                    if (args && wcslen(args) > 0) {
                        result += L" " + SafeBSTR(args);
                    }

                    if (path) SysFreeString(path);
                    if (args) SysFreeString(args);
                    pExec->Release();
                }
            } else if (type == TASK_ACTION_COM_HANDLER) {
                result += L"[COM Handler]";
            }

            pAction->Release();
        }
    }

    pActions->Release();
    return result.empty() ? L"(aucune)" : result;
}

// Parse principal
std::wstring ParsePrincipal(ITaskDefinition* pTask) {
    IPrincipal* pPrincipal = nullptr;
    HRESULT hr = pTask->get_Principal(&pPrincipal);
    if (FAILED(hr) || !pPrincipal) return L"(inconnu)";

    BSTR userId = nullptr;
    TASK_RUNLEVEL_TYPE runLevel;
    pPrincipal->get_UserId(&userId);
    pPrincipal->get_RunLevel(&runLevel);

    std::wstring result = SafeBSTR(userId);
    if (runLevel == TASK_RUNLEVEL_HIGHEST) {
        result += L" (HighestAvailable)";
    }

    if (userId) SysFreeString(userId);
    pPrincipal->Release();

    return result;
}

// Vérifier si tâche cachée
bool IsTaskHidden(ITaskDefinition* pTask) {
    ITaskSettings* pSettings = nullptr;
    HRESULT hr = pTask->get_Settings(&pSettings);
    if (FAILED(hr) || !pSettings) return false;

    VARIANT_BOOL hidden = VARIANT_FALSE;
    pSettings->get_Hidden(&hidden);
    pSettings->Release();

    return (hidden == VARIANT_TRUE);
}

// Obtenir XML complet
std::wstring GetTaskXML(IRegisteredTask* pRegTask) {
    BSTR xml = nullptr;
    HRESULT hr = pRegTask->get_Xml(&xml);
    if (FAILED(hr) || !xml) return L"";

    std::wstring result = SafeBSTR(xml);
    SysFreeString(xml);
    return result;
}

// Énumération récursive des tâches
void EnumerateTasksRecursive(ITaskFolder* pFolder, std::vector<TaskItem>& tasks) {
    // Énumérer tâches dans ce dossier
    IRegisteredTaskCollection* pTaskCollection = nullptr;
    HRESULT hr = pFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskCollection);

    if (SUCCEEDED(hr) && pTaskCollection) {
        long count = 0;
        pTaskCollection->get_Count(&count);

        for (long i = 1; i <= count; ++i) {
            IRegisteredTask* pRegTask = nullptr;
            if (SUCCEEDED(pTaskCollection->get_Item(_variant_t(i), &pRegTask))) {
                TaskItem item;

                BSTR name = nullptr;
                BSTR path = nullptr;
                pRegTask->get_Name(&name);
                pRegTask->get_Path(&path);

                item.name = SafeBSTR(name);
                item.path = SafeBSTR(path);
                item.xmlDefinition = GetTaskXML(pRegTask);

                ITaskDefinition* pTask = nullptr;
                if (SUCCEEDED(pRegTask->get_Definition(&pTask))) {
                    item.trigger = ParseTriggers(pTask);
                    item.action = ParseActions(pTask);
                    item.principal = ParsePrincipal(pTask);
                    item.hidden = IsTaskHidden(pTask);

                    pTask->Release();
                }

                item.suspect = IsSuspicious(item, item.notes);

                tasks.push_back(item);

                if (name) SysFreeString(name);
                if (path) SysFreeString(path);
                pRegTask->Release();
            }
        }
        pTaskCollection->Release();
    }

    // Énumérer sous-dossiers
    ITaskFolderCollection* pFolders = nullptr;
    hr = pFolder->GetFolders(0, &pFolders);

    if (SUCCEEDED(hr) && pFolders) {
        long count = 0;
        pFolders->get_Count(&count);

        for (long i = 1; i <= count; ++i) {
            ITaskFolder* pSubFolder = nullptr;
            if (SUCCEEDED(pFolders->get_Item(_variant_t(i), &pSubFolder))) {
                EnumerateTasksRecursive(pSubFolder, tasks);
                pSubFolder->Release();
            }
        }
        pFolders->Release();
    }
}

// Thread d'énumération
DWORD WINAPI EnumerateThread(LPVOID lpParam) {
    SetWindowTextW(g_hStatus, L"Initialisation COM...");

    COMInitializer com;
    if (!com.IsInitialized()) {
        SetWindowTextW(g_hStatus, L"Erreur: Initialisation COM échouée");
        return 1;
    }

    SetWindowTextW(g_hStatus, L"Connexion Task Scheduler...");

    ITaskService* pService = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_TaskScheduler,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        (void**)&pService
    );

    if (FAILED(hr)) {
        SetWindowTextW(g_hStatus, L"Erreur: Création ITaskService échouée");
        return 1;
    }

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        SetWindowTextW(g_hStatus, L"Erreur: Connexion Task Scheduler échouée");
        return 1;
    }

    ITaskFolder* pRootFolder = nullptr;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        pService->Release();
        SetWindowTextW(g_hStatus, L"Erreur: Accès dossier racine échoué");
        return 1;
    }

    g_tasks.clear();
    ListView_DeleteAllItems(g_hListView);

    SetWindowTextW(g_hStatus, L"Énumération des tâches planifiées...");
    EnumerateTasksRecursive(pRootFolder, g_tasks);

    pRootFolder->Release();
    pService->Release();

    // Affichage dans ListView
    for (size_t i = 0; i < g_tasks.size(); ++i) {
        const auto& task = g_tasks[i];

        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = static_cast<int>(i);

        lvi.iSubItem = COL_NAME;
        lvi.pszText = const_cast<LPWSTR>(task.name.c_str());
        ListView_InsertItem(g_hListView, &lvi);

        ListView_SetItemText(g_hListView, i, COL_PATH, const_cast<LPWSTR>(task.path.c_str()));
        ListView_SetItemText(g_hListView, i, COL_TRIGGER, const_cast<LPWSTR>(task.trigger.c_str()));

        std::wstring actionShort = task.action.length() > 80 ?
            task.action.substr(0, 77) + L"..." : task.action;
        ListView_SetItemText(g_hListView, i, COL_ACTION, const_cast<LPWSTR>(actionShort.c_str()));

        ListView_SetItemText(g_hListView, i, COL_PRINCIPAL, const_cast<LPWSTR>(task.principal.c_str()));
        ListView_SetItemText(g_hListView, i, COL_HIDDEN, task.hidden ? L"OUI" : L"Non");
        ListView_SetItemText(g_hListView, i, COL_SUSPECT, task.suspect ? L"OUI" : L"Non");
        ListView_SetItemText(g_hListView, i, COL_NOTES, const_cast<LPWSTR>(task.notes.c_str()));
    }

    wchar_t status[256];
    wsprintfW(status, L"Énumération terminée: %zu tâche(s) trouvée(s)", g_tasks.size());
    SetWindowTextW(g_hStatus, status);

    return 0;
}

// Export CSV
void ExportToCSV() {
    wchar_t szFile[MAX_PATH] = L"task_scheduler_forensics.csv";

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetParent(g_hListView);
    ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"csv";

    if (!GetSaveFileNameW(&ofn)) return;

    std::wofstream file(szFile, std::ios::out | std::ios::binary);
    if (!file) {
        MessageBoxW(GetParent(g_hListView), L"Impossible de créer le fichier",
                    L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    // BOM UTF-8
    file.put(0xEF);
    file.put(0xBB);
    file.put(0xBF);

    file.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));

    // En-tête
    file << L"Nom,Chemin,Trigger,Action,Principal,Caché,Suspect,Notes\n";

    // Données
    for (const auto& task : g_tasks) {
        file << L"\"" << task.name << L"\",";
        file << L"\"" << task.path << L"\",";
        file << L"\"" << task.trigger << L"\",";
        file << L"\"" << task.action << L"\",";
        file << L"\"" << task.principal << L"\",";
        file << (task.hidden ? L"OUI" : L"Non") << L",";
        file << (task.suspect ? L"OUI" : L"Non") << L",";
        file << L"\"" << task.notes << L"\"\n";
    }

    file.close();

    SetWindowTextW(g_hStatus, L"Export CSV réussi");
    MessageBoxW(GetParent(g_hListView), L"Export réussi", L"Information", MB_OK | MB_ICONINFORMATION);
}

// Procédure fenêtre principale
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            g_hFont = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

            g_hListView = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                WC_LISTVIEWW,
                L"",
                WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                10, 10, 1360, 500,
                hwnd, (HMENU)IDC_LISTVIEW, GetModuleHandle(nullptr), nullptr
            );

            ListView_SetExtendedListViewStyle(g_hListView,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

            SendMessageW(g_hListView, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            // Colonnes
            LVCOLUMNW lvc = {};
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;

            lvc.pszText = const_cast<LPWSTR>(L"Nom");
            lvc.cx = 180;
            ListView_InsertColumn(g_hListView, COL_NAME, &lvc);

            lvc.pszText = const_cast<LPWSTR>(L"Chemin");
            lvc.cx = 200;
            ListView_InsertColumn(g_hListView, COL_PATH, &lvc);

            lvc.pszText = const_cast<LPWSTR>(L"Trigger");
            lvc.cx = 120;
            ListView_InsertColumn(g_hListView, COL_TRIGGER, &lvc);

            lvc.pszText = const_cast<LPWSTR>(L"Action");
            lvc.cx = 280;
            ListView_InsertColumn(g_hListView, COL_ACTION, &lvc);

            lvc.pszText = const_cast<LPWSTR>(L"Principal");
            lvc.cx = 180;
            ListView_InsertColumn(g_hListView, COL_PRINCIPAL, &lvc);

            lvc.pszText = const_cast<LPWSTR>(L"Caché");
            lvc.cx = 60;
            ListView_InsertColumn(g_hListView, COL_HIDDEN, &lvc);

            lvc.pszText = const_cast<LPWSTR>(L"Suspect");
            lvc.cx = 70;
            ListView_InsertColumn(g_hListView, COL_SUSPECT, &lvc);

            lvc.pszText = const_cast<LPWSTR>(L"Notes");
            lvc.cx = 240;
            ListView_InsertColumn(g_hListView, COL_NOTES, &lvc);

            // Boutons
            HWND hBtn = CreateWindowW(
                L"BUTTON", L"Énumérer Tâches",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 520, 180, 30,
                hwnd, (HMENU)IDC_BTN_ENUMERATE, GetModuleHandle(nullptr), nullptr
            );
            SendMessageW(hBtn, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            hBtn = CreateWindowW(
                L"BUTTON", L"Désactiver (Admin)",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                200, 520, 160, 30,
                hwnd, (HMENU)IDC_BTN_DISABLE, GetModuleHandle(nullptr), nullptr
            );
            SendMessageW(hBtn, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            hBtn = CreateWindowW(
                L"BUTTON", L"Exporter CSV",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                370, 520, 150, 30,
                hwnd, (HMENU)IDC_BTN_EXPORT, GetModuleHandle(nullptr), nullptr
            );
            SendMessageW(hBtn, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            g_hStatus = CreateWindowExW(
                0, L"STATIC", L"Prêt - Cliquez sur 'Énumérer Tâches'",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                10, 560, 1360, 20,
                hwnd, (HMENU)IDC_STATUS, GetModuleHandle(nullptr), nullptr
            );
            SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            return 0;
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_BTN_ENUMERATE:
                    CreateThread(nullptr, 0, EnumerateThread, nullptr, 0, nullptr);
                    break;

                case IDC_BTN_DISABLE:
                    MessageBoxW(hwnd,
                        L"Utilisez PowerShell ou Task Scheduler GUI:\n"
                        L"Disable-ScheduledTask -TaskName \"NomTâche\"",
                        L"Information", MB_OK | MB_ICONINFORMATION);
                    break;

                case IDC_BTN_EXPORT:
                    ExportToCSV();
                    break;
            }
            return 0;
        }

        case WM_DESTROY:
            if (g_hFont) DeleteObject(g_hFont);
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// Point d'entrée
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"TaskSchedulerForensicsClass";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"Échec RegisterClassExW", L"Erreur", MB_ICONERROR);
        return 1;
    }

    HWND hwnd = CreateWindowExW(
        0,
        wc.lpszClassName,
        L"Task Scheduler Forensics - WinToolsSuite v3.0",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1400, 640,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!hwnd) {
        MessageBoxW(nullptr, L"Échec CreateWindowExW", L"Erreur", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}
