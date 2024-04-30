#pragma once
#include <Windows.h>
#include <string>

static std::wstring ToWString(const std::string& input) {
    if (input.empty()) {
        return std::wstring();
    }

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), (int)input.size(), nullptr, 0);
    std::wstring wstrTo(size_needed, 0);

    MultiByteToWideChar(CP_UTF8, 0, input.c_str(), (int)input.size(), &wstrTo[0], size_needed);

    return wstrTo;
}
