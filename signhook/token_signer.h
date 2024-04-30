#pragma once
#include <vector>
#include <string>
#include "pkcs11.h"
#include "signer.h"
#include "signed_data.h"

class TokenSigner : public ISigner {
private:
	HMODULE lib_;
	CK_FUNCTION_LIST_PTR functions_;
	CK_SESSION_HANDLE session_;
	CK_OBJECT_HANDLE private_key_;
	std::vector<unsigned char> cert_value_;
	std::string dll_path_;
	int slot_number_;
	std::string pin_;
	std::string key_label_;
	std::string cert_label_;

public:
	TokenSigner(const std::string& json_string);
	virtual ~TokenSigner();
	SignedData Sign(
		const std::wstring& digest_algorithm,
		const std::vector<unsigned char>& to_be_signed_digest
	) override;

private:
	void InitializeLibrary();
	void FinalizeLibrary();
};
