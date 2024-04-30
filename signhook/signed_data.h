#pragma once
#include <windows.h>
#include <vector>
#include <string>

class SignedData
{
private:
    std::vector<BYTE> signed_digest_;
    std::vector<BYTE> encoded_cert_;
    DWORD cert_encoding_type_;

public:
    SignedData();
    SignedData(const std::vector<BYTE>& digest, const std::vector<BYTE>& encoded_cert, DWORD cert_encoding_type);
    const std::vector<BYTE>& GetDigest() const { return signed_digest_; }
    const std::vector<BYTE>& GetEncodedCert() const { return encoded_cert_; }
    DWORD GetCertEncodingType() const { return cert_encoding_type_; }
    static SignedData LoadFromString(const std::string& json_string);
};
