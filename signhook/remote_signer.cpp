#include "pch.h"

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <charconv>
#include <fstream>
#include <filesystem>

#include "remote_signer.h"
#include "json.hpp"
#include "string_util.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

/**
 * @class HttpCommunicator
 * @brief Represents an HTTP communicator for sending POST requests.
 */
class HttpCommunicator {
public:
    /**
     * @brief Constructs an HttpCommunicator object with the specified server name and port.
     * @param server_name The server name.
     * @param server_port The server port.
     */
    HttpCommunicator(const std::wstring& server_name, INTERNET_PORT server_port)
        : server_name_(server_name), server_port_(server_port) {}

    /**
     * @brief Destructor for the HttpCommunicator class.
     */
    ~HttpCommunicator() {
        CleanupHttpHandles();
    }

    /**
     * @brief Sends a POST request to the specified endpoint with the provided data.
     * @param endpoint The endpoint to send the request to.
     * @param data The data to send in the request.
     * @param size The size of the data.
     * @return The response received from the server.
     * @throws std::runtime_error if any of the WinHttp functions fail.
     */
    std::string Post(const std::wstring& endpoint, const BYTE* data, DWORD size) {
        if (!InitializeHttpHandles(endpoint, L"POST")) {
            throw std::runtime_error("InitializeHttpHandles failed");
        }
        if (!WinHttpSendRequest(request_, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)data, size, size, 0)) {
            throw std::runtime_error("WinHttpSendRequest failed");
        }
        if (!WinHttpReceiveResponse(request_, nullptr)) {
            throw std::runtime_error("WinHttpReceiveResponse failed");
        }
        DWORD dwSize = 0;
        if (!WinHttpQueryDataAvailable(request_, &dwSize)) {
            throw std::runtime_error("WinHttpQueryDataAvailable failed");
        }
        std::vector<BYTE> pBuffer(dwSize);
        DWORD dwDownloaded = 0;
        if (!WinHttpReadData(request_, pBuffer.data(), dwSize, &dwDownloaded)) {
            throw std::runtime_error("WinHttpReadData failed");
        }

        return std::string(pBuffer.begin(), pBuffer.end());
    }

private:
    HINTERNET session_ = nullptr, connect_ = nullptr, request_ = nullptr;
    std::wstring server_name_;
    INTERNET_PORT server_port_;

    /**
     * @brief Initializes the HTTP handles for the request.
     * @param endpoint The endpoint to send the request to.
     * @param pszMethod The HTTP method to use.
     * @return true if the handles were successfully initialized, false otherwise.
     */
    bool InitializeHttpHandles(const std::wstring& endpoint, LPCWSTR pszMethod) {
        session_ = WinHttpOpen(L"User Agent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (session_ == nullptr) {
            return false;
        }
        connect_ = WinHttpConnect(session_, server_name_.c_str(), server_port_, 0);
        if (connect_ == nullptr) {
            return false;
        }
        request_ = WinHttpOpenRequest(connect_, pszMethod, endpoint.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (request_ == nullptr) {
            return false;
        }
        return true;
    }

    /**
     * @brief Cleans up the HTTP handles.
     */
    void CleanupHttpHandles() {
        if (request_) WinHttpCloseHandle(request_);
        if (connect_) WinHttpCloseHandle(connect_);
        if (session_) WinHttpCloseHandle(session_);
    }
};

/**
* @brief Constructs a RemoteSigner object with the specified JSON string.
* @param json_string The JSON string containing the configuration data.
* @throws std::runtime_error if the JSON string parsing fails.
*/
RemoteSigner::RemoteSigner(const std::string& json_string)
{
    try {
        auto json_data = nlohmann::json::parse(json_string);
        auto host = ToWString(json_data["host"].get<std::string>());
        auto port = (INTERNET_PORT)json_data["port"].get<double>();

        communicator_ = std::make_unique<HttpCommunicator>(host, port);
    }
    catch (const std::exception& e) {
        throw std::runtime_error("Setting file parse failed: " + std::string(e.what()));
    }
}

/**
 * @brief Signs the given digest using the specified digest algorithm.
 * @param digest_algorithm The digest algorithm to use for signing.
 * @param to_be_signed_digest The digest to be signed.
 * @return The signing data.
 */
SignedData RemoteSigner::Sign(
    const std::wstring& digest_algorithm,
    const std::vector<unsigned char>& to_be_signed_digest
) {
    std::wstring endpoint = std::wstring(L"/sign?digest_algorithm=") + digest_algorithm.c_str();
    auto response = communicator_->Post(endpoint, to_be_signed_digest.data(), (DWORD)to_be_signed_digest.size());
    return SignedData::LoadFromString(response);
}
