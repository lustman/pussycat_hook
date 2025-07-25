#include <array>
#include <cstdio>
#include <iostream>
#include <string>
#include <thread>
#include <Windows.h>

#include "MinHook.h"
#include "scanner/scan.hpp""


void prepare_console() {
    if (!GetConsoleWindow()) {
        AllocConsole();
        std::freopen("CONOUT$", "w", stdout);
    }
    SetConsoleTitleA("Hello ^^");
}


namespace vmp {
    bool g_oep_hit = false;

    void (WINAPI *oep_t)(LPFILETIME lpSystemTimeAsFileTime);

    void WINAPI oep_proxy(LPFILETIME lpSystemTimeAsFileTime) {
        if (!g_oep_hit) g_oep_hit = true;

        return oep_t(lpSystemTimeAsFileTime);
    }

    void setup_hook() {
        const auto kernel32_handle = GetModuleHandleA("kernel32.dll");
        void *oep_m = GetProcAddress(kernel32_handle, "GetSystemTimeAsFileTime");

        MH_CreateHook(oep_m, reinterpret_cast<void *>(oep_proxy),
                      reinterpret_cast<void **>(&oep_t));
        MH_EnableHook(oep_m);
    }

    void unhook_ntvp() {
        DWORD old_protect = 0;
        const auto ntdll = GetModuleHandleA("ntdll.dll");
        const auto nt_vp = reinterpret_cast<std::uint8_t *>(GetProcAddress(ntdll, "NtProtectVirtualMemory"));

        std::array<std::uint8_t, 5> restore = {0x4C, 0x8B, 0xD1, 0xB8};
        restore[4] = reinterpret_cast<std::uint8_t *>(GetProcAddress(ntdll, "NtQuerySection"))[4] - 1;

        VirtualProtect(nt_vp, restore.size(), PAGE_EXECUTE_READWRITE, &old_protect);
        std::ranges::copy(restore, nt_vp);
        VirtualProtect(nt_vp, restore.size(), old_protect, &old_protect);
    }
}


namespace keyauth_api {
    std::string & (__fastcall*apirequest_t)(std::int64_t a1, std::string &a2, std::string &a3);

    std::string & __fastcall apirequest_proxy(std::int64_t a1, std::string &a2, std::string &a3) {
        if (a2.starts_with("type=log")) {
            a2 = "";
        }

        return apirequest_t(a1, a2, a3);
    }

    void setup_hook() {
        const auto apirequest_m = scanner::scan(
            "48 89 5C 24 20 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 A0 48 81 EC 60 01 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 58 49 8B F8 4C 89 45 98 4C 8B E2 48 89 55 A0 4C 8B F9 48 89 4D A8 45 33 ED",
            "api_request",
            GetModuleHandleA(nullptr)
        );

        MH_CreateHook(apirequest_m, reinterpret_cast<void *>(apirequest_proxy),
                      reinterpret_cast<void **>(&apirequest_t));
        MH_EnableHook(apirequest_m);
    }
}


namespace keyauth_license {
    std::size_t (__fastcall*callback_t)(const void *content, std::size_t size, std::size_t nmemb,
                                        std::string &userp);

    std::size_t __fastcall callback_proxy(const void *content, std::size_t size, std::size_t nmemb,
                                          std::string &userp) {
        const auto result = callback_t(content, size, nmemb, userp);

        if (userp.contains("Invalid license key")) {
            userp =
                    R"({"nonce":"00000000-0000-0000-0000-00000000000","ownerid":"hQTXJS8Gws","message":"License validated successfully","code":68,"success":true,"info":{"username":"admin","ip":"1.1.1.1","hwid":"AAAAAAAAAAAAAAAA","createdate":"915148800","lastlogin":"2025-07-23T12:34:56Z","subscriptions":[{"subscription":"premium","expiry":"2051222400"}]}})";
        }

        return result;
    }

    int __fastcall verify_proxy(std::string a1, std::string a2, std::string a3) {
        int value = 42 ^ 0xA5A5;
        return value & 0xFFFF;
    }

    std::string gethwid_proxy() {
        return "AAAAAAAAAAAAAAAA";
    }

    void setup_hook() {
        const auto callback_m = scanner::scan(
            "40 53 48 83 EC 20 48 8B DA 48 8B D1 49 0F AF D8 49 8B C9 4C 8B C3 E8 ? ? ? ? 48 8B C3 48 83 C4 20 5B C3",
            "callback",
            GetModuleHandleA(nullptr));

        void *verify_m = scanner::scan(
            "40 53 55 56 57 41 54 41 56 41 57 48 81 EC 00 01 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 F0 00 00 00 49 8B F8 48 8B DA 48 8B F1 48 89 4C 24 50 48 89 54 24 58 4C 89 44 24 60 45 33 E4 55 E8 ? ? ? ?",
            "verify",
            GetModuleHandleA(nullptr));

        void *gethwid_m = scanner::scan(
            "40 55 57 41 54 41 56 41 57 48 81 EC 90 01 00 00 48 8D 6C 24 30 48 89 9D 98 01 00 00 48 89 B5 A0 01 00 00 48 8B 05 ? ? ? ? 48 33 C5 48 89 85 50 01 00 00 4C 8B F1 48 89 4D 00 45 33 FF 0F 57 C0",
            "get_hwid",
            GetModuleHandleA(nullptr));


        MH_CreateHook(callback_m, reinterpret_cast<void *>(callback_proxy),
                      reinterpret_cast<void **>(&callback_t));
        MH_EnableHook(callback_m);

        MH_CreateHook(verify_m, reinterpret_cast<void *>(verify_proxy), nullptr);
        MH_EnableHook(verify_m);

        MH_CreateHook(gethwid_m, reinterpret_cast<void *>(gethwid_proxy), nullptr);
        MH_EnableHook(gethwid_m);
    }
}


DWORD WINAPI entrypoint(PVOID) {
    prepare_console();
    vmp::unhook_ntvp();


    MH_Initialize();
    vmp::setup_hook();
    while (!vmp::g_oep_hit) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }


    keyauth_api::setup_hook();
    keyauth_license::setup_hook();

    return TRUE;
}


BOOL APIENTRY DllMain(HMODULE, const DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        CreateThread(nullptr, 0, &entrypoint, nullptr, 0, nullptr);
    }

    return TRUE;
}
