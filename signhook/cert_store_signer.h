#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include "signer.h"
#include "signed_data.h"

class CertStoreSigner : public ISigner {
private:
    std::string cert_subject_;
public:
	CertStoreSigner(const std::string& json_string);
    SignedData Sign(
		const std::wstring& digest_algorithm,
		const std::vector<unsigned char>& to_be_signed_digest
	) override;
};
