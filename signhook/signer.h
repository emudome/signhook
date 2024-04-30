#pragma once
#include <string>
#include <vector>

class SignedData;

class ISigner {
public:
    virtual SignedData Sign(const std::wstring& digest_algorithm, const std::vector<unsigned char>& to_be_signed_digest) = 0;
    virtual ~ISigner() {}
};
