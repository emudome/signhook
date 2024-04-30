#include "pch.h"
#include "cert_store_signer.h"

#include <windows.h>
#include <winhttp.h>
#include <Wincrypt.h>
#include <ncrypt.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <string>

#include "json.hpp"
#include "string_util.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")


/**
 * Retrieves a certificate from the certificate store based on the specified subject.
 *
 * @param pszSubject The subject of the certificate to retrieve.
 * @return A pointer to the certificate context if found, or nullptr if not found or an error occurred.
 */
PCCERT_CONTEXT GetCertificateFromStore(LPCTSTR pszSubject)
{
	HCERTSTORE cert_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
	if (cert_store == nullptr) {
		return nullptr;
	}
	PCCERT_CONTEXT cert_context = CertFindCertificateInStore(cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, pszSubject, nullptr);
	CertCloseStore(cert_store, 0);

	return cert_context;
}

/**
 * Signs the given data with the specified certificate context using the CNG (Cryptography Next Generation) API.
 *
 * @param context The certificate context to use for signing.
 * @param digest_algorithm The digest algorithm to use for signing.
 * @param to_be_signed_digest The data to be signed.
 * @return The signed digest.
 * @throws std::runtime_error if signing fails.
 */
std::vector<BYTE> SignDataWithCNG(
	PCCERT_CONTEXT context,
	const std::wstring& digest_algorithm,
	const std::vector<BYTE>& to_be_signed_digest
) {
	NCRYPT_KEY_HANDLE key = 0;
	DWORD key_spec;
	BOOL caller_free_prov_or_ncrypt_key;

	if (!CryptAcquireCertificatePrivateKey(context, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, nullptr, &key, &key_spec, &caller_free_prov_or_ncrypt_key)) {
		throw std::runtime_error("CryptAcquireCertificatePrivateKey failed");
	}

	BCRYPT_PKCS1_PADDING_INFO padding_info = { digest_algorithm.c_str() };
	DWORD required_size = 0;

	HRESULT result = NCryptSignHash(key, &padding_info, (BYTE*)to_be_signed_digest.data(), (DWORD)to_be_signed_digest.size(), nullptr, 0, &required_size, BCRYPT_PAD_PKCS1);
	if (result != ERROR_SUCCESS) {
		if (caller_free_prov_or_ncrypt_key) {
			NCryptFreeObject(key);
		}
		throw std::runtime_error("NCryptSignHash failed");
	}

	std::vector<BYTE> signed_digest;
	signed_digest.resize(required_size);

	result = NCryptSignHash(key, &padding_info, (BYTE*)to_be_signed_digest.data(), (DWORD)to_be_signed_digest.size(), signed_digest.data(), (DWORD)signed_digest.size(), &required_size, BCRYPT_PAD_PKCS1);
	if (result != ERROR_SUCCESS) {
		if (caller_free_prov_or_ncrypt_key) {
			NCryptFreeObject(key);
		}
		throw std::runtime_error("NCryptSignHash failed");
	}

	return signed_digest;
}

/**
 * Constructs a CertStoreSigner object with the specified JSON string.
 *
 * @param json_string The JSON string containing the certificate subject.
 * @throws std::runtime_error if the JSON parsing fails.
 */
CertStoreSigner::CertStoreSigner(const std::string& json_string)
{
	auto json_data = nlohmann::json::parse(json_string);
	cert_subject_ = json_data["cert_subject"].get<std::string>();
}

/**
 * Signs the given data with the specified certificate context using the CNG (Cryptography Next Generation) API.
 *
 * @param digest_algorithm The digest algorithm to use for signing.
 * @param to_be_signed_digest The data to be signed.
 * @return The signed digest.
 * @throws std::runtime_error if signing fails.
 */
SignedData CertStoreSigner::Sign(
	const std::wstring& digest_algorithm,
	const std::vector<unsigned char>& to_be_signed_digest
) {
	auto context = GetCertificateFromStore(ToWString(cert_subject_).c_str());
	if (context == nullptr)
		throw std::runtime_error("GetCertificateFromStore failed");

	auto cert = std::vector<BYTE>(context->pbCertEncoded, context->pbCertEncoded + context->cbCertEncoded);
	auto digest = SignDataWithCNG(context, digest_algorithm, to_be_signed_digest);

	return SignedData(digest, cert, context->dwCertEncodingType);
}
