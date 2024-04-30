#include "pch.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>
#include <wincrypt.h>

#include "token_signer.h"
#include "pkcs11.h"
#include "json.hpp"

/**
 * @brief Constructs a TokenSigner object.
 *
 * @param json_string The JSON string containing the configuration settings.
 * @throws std::runtime_error if the setting file parse fails.
 */
TokenSigner::TokenSigner(const std::string& json_string)
{
	auto json_data = nlohmann::json::parse(json_string);
	dll_path_ = json_data["dll_path"].get<std::string>();
	slot_number_ = (int)json_data["slot_number"].get<double>();
	pin_ = json_data["pin"].get<std::string>();
	key_label_ = json_data["key_label"].get<std::string>();
	cert_label_ = json_data["cert_label"].get<std::string>();

	lib_ = nullptr;
	functions_ = nullptr;
	session_ = 0;

	try {
		InitializeLibrary();
	}
	catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		FinalizeLibrary();
		throw;
	}
}

/**
 * @brief Destructs the TokenSigner object.
 *
 * This destructor is responsible for finalizing the PKCS#11 library and cleaning up any resources used by the TokenSigner object.
 */
TokenSigner::~TokenSigner() {

	FinalizeLibrary();
}

/**
 * @brief Initializes the PKCS#11 library and sets up the session for the TokenSigner object.
 *
 * This function loads the PKCS#11 library, retrieves the function list, initializes the library,
 * opens a session, logs in, searches for the private key and certificate, and retrieves the certificate value.
 *
 * @throws std::runtime_error if any of the initialization steps fail.
 */
void TokenSigner::InitializeLibrary() {
	// Load PKCS#11 library
	lib_ = LoadLibraryA(dll_path_.c_str());
	if (lib_ == nullptr) {
		throw std::runtime_error("Failed to load PKCS#11 library");
	}

	// Get function list
	CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(lib_, "C_GetFunctionList");
	if (C_GetFunctionList == nullptr) {
		throw std::runtime_error("Failed to get function list");
	}

	auto rv = C_GetFunctionList(&functions_);
	if (rv != CKR_OK) {
		throw std::runtime_error("Failed to get function list");
	}

	// Initialize
	rv = functions_->C_Initialize(nullptr);
	if (rv != CKR_OK) {
		throw std::runtime_error("Failed to initialize PKCS#11 library");
	}

	// Open session
	rv = functions_->C_OpenSession(slot_number_, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &session_);
	if (rv != CKR_OK) {
		functions_->C_Finalize(nullptr);
		throw std::runtime_error("Failed to open session");
	}

	// Login
	rv = functions_->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)pin_.c_str(), (ULONG)pin_.size());
	if (rv != CKR_OK) {
		functions_->C_CloseSession(session_);
		functions_->C_Finalize(nullptr);
		throw std::runtime_error("Failed to login");
	}

	// Search private key
	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE template_data[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_LABEL, (void*)key_label_.c_str(), (ULONG)key_label_.size()}
	};
	rv = functions_->C_FindObjectsInit(session_, template_data, 2);
	if (rv != CKR_OK) {
		throw std::runtime_error("Failed to initialize object search");
	}

	CK_ULONG object_count;
	rv = functions_->C_FindObjects(session_, &private_key_, 1, &object_count);
	functions_->C_FindObjectsFinal(session_);
	if (rv != CKR_OK || object_count == 0) {
		
		throw std::runtime_error("Private key search failed");
	}

	// Get certificate
	CK_OBJECT_HANDLE certificate;
	CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE cert_template[] = {
		{CKA_CLASS, &cert_class, sizeof(cert_class)},
		{CKA_LABEL, (void*)cert_label_.c_str(), (ULONG)cert_label_.size()}
	};
	rv = functions_->C_FindObjectsInit(session_, cert_template, 2);
	if (rv != CKR_OK) {
		throw std::runtime_error("Failed to initialize certificate search");
	}

	rv = functions_->C_FindObjects(session_, &certificate, 1, &object_count);
	functions_->C_FindObjectsFinal(session_);
	if (rv != CKR_OK || object_count == 0) {
		throw std::runtime_error("Certificate not found");
	}
	

	CK_ATTRIBUTE value_template = { CKA_VALUE, nullptr, 0 };
	rv = functions_->C_GetAttributeValue(session_, certificate, &value_template, 1);
	if (rv != CKR_OK) {
		throw std::runtime_error("Failed to get certificate value");
	}

	cert_value_.resize(value_template.ulValueLen);
	value_template.pValue = &cert_value_[0];
	rv = functions_->C_GetAttributeValue(session_, certificate, &value_template, 1);
	if (rv != CKR_OK) {
		throw std::runtime_error("Failed to get certificate value data");
	}
}

/**
 * @brief Finalizes the PKCS#11 library and cleans up any resources used by the TokenSigner object.
 *
 * This function is responsible for logging out from the session, closing the session, finalizing the PKCS#11 library,
 * and freeing the library handle.
 */
void TokenSigner::FinalizeLibrary() {
	if (lib_ != nullptr) {
		if (functions_ != nullptr) {
			if (session_ != 0) {
				functions_->C_Logout(session_);
				functions_->C_CloseSession(session_);
			}
			functions_->C_Finalize(nullptr);
		}
		FreeLibrary(lib_);
	}
}

/**
 * @brief Signs the given digest using the specified digest algorithm.
 *
 * This function initializes the signing mechanism based on the digest algorithm,
 * signs the digest using the private key, and returns the signing data.
 *
 * @param digest_algorithm The digest algorithm to use for signing.
 * @param to_be_signed_digest The digest to be signed.
 * @return The signing data.
 * @throws std::runtime_error if any of the signing steps fail.
 */
SignedData TokenSigner::Sign(
	const std::wstring& digest_algorithm,
	const std::vector<unsigned char>& to_be_signed_digest
) {
	// Select mechanism
	static const std::map<std::wstring, DWORD> algorithm_to_mechanism = {
		{BCRYPT_SHA1_ALGORITHM, CKM_SHA1_RSA_PKCS},
		{BCRYPT_SHA256_ALGORITHM, CKM_SHA256_RSA_PKCS},
		{BCRYPT_SHA384_ALGORITHM, CKM_SHA384_RSA_PKCS},
		{BCRYPT_SHA512_ALGORITHM, CKM_SHA512_RSA_PKCS}
	};
	auto mechanism_type = algorithm_to_mechanism.at(digest_algorithm);
	CK_MECHANISM mechanism = { mechanism_type, nullptr, 0 };

	// Sign digest
	auto rv = functions_->C_SignInit(session_, &mechanism, private_key_);
	if (rv != CKR_OK) {
		throw std::runtime_error("Failed to initialize signing");
	}

	CK_ULONG digest_len = 0;
	rv = functions_->C_Sign(session_, (CK_BYTE_PTR)&to_be_signed_digest[0], (ULONG)to_be_signed_digest.size(), nullptr, &digest_len);
	if (rv != CKR_BUFFER_TOO_SMALL) {
		throw std::runtime_error("Get signing size failed");
	}

	std::vector<unsigned char> digest(digest_len);
	rv = functions_->C_Sign(session_, (CK_BYTE_PTR)&to_be_signed_digest[0], (ULONG)to_be_signed_digest.size(), &digest[0], &digest_len);
	if (rv != CKR_OK) {
		throw std::runtime_error("Signing failed");
	}

	return SignedData(digest, cert_value_, X509_ASN_ENCODING);
}
