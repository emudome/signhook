#include "pch.h"
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <charconv>
#include <fstream>
#include <filesystem>

#include "json.hpp"
#include "remote_signer.h"
#include "cert_store_signer.h"
#include "token_signer.h"
#include "signed_data.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

// Usage: signtool sign /v /debug /tr http://timestamp.acs.microsoft.com /td sha256 /fd sha256 /dlib "signhook.dll" /dmdf "setting.json" *.exe

std::shared_ptr<ISigner> CreateSigner(const std::string& json_string) {
	auto json_data = nlohmann::json::parse(json_string);
	auto sign_mode = json_data.at("sign_mode").get<std::string>();

	if (sign_mode == "remote") {
		return std::make_shared<RemoteSigner>(json_string);
	}
	else if (sign_mode == "cert_store") {
		return std::make_shared<CertStoreSigner>(json_string);
	}
	else if (sign_mode == "token") {
		return std::make_shared<TokenSigner>(json_string);
	}
	else {
		throw std::invalid_argument("mode error");
	}
}

/**
 * Applies the result of signing to the provided data structures.
 *
 * @param signed_digest The signed digest.
 * @param encoded_cert The encoded certificate.
 * @param p_signed_digest_blob Pointer to the signed digest data blob.
 * @param cert_encoding_type The encoding type of the certificate.
 * @param pp_signer_cert Pointer to the signer certificate.
 * @throws std::bad_alloc If memory allocation fails.
 * @throws std::runtime_error If memcpy_s fails or CertCreateCertificateContext fails.
 * @throws std::invalid_argument If p_signed_digest_blob or pp_signer_cert is null.
 */
void ApplyResult(
	const std::vector<BYTE>& signed_digest,
	const std::vector<BYTE>& encoded_cert,
	PCRYPT_DATA_BLOB p_signed_digest_blob,
	DWORD cert_encoding_type,
	PCCERT_CONTEXT* pp_signer_cert
) {
	// HeapAlloc(GetProcessHeap())で確保せよとのMSDNのドキュメントによる指示
	auto digestMem = (BYTE*)HeapAlloc(GetProcessHeap(), 0, encoded_cert.size());
	if (digestMem == nullptr) {
		throw std::bad_alloc();
	}
	if (0 != memcpy_s(digestMem, signed_digest.size(), signed_digest.data(), signed_digest.size())) {
		throw std::runtime_error("memcpy_s failed");
	}

	if (p_signed_digest_blob == nullptr) {
		throw std::invalid_argument("p_signed_digest_blob is null");
	}

	p_signed_digest_blob->pbData = digestMem;
	p_signed_digest_blob->cbData = (DWORD)signed_digest.size();

	if (pp_signer_cert == nullptr) {
		throw std::invalid_argument("pp_signer_cert is null");
	}

	*pp_signer_cert = CertCreateCertificateContext(cert_encoding_type, encoded_cert.data(), (DWORD)encoded_cert.size());
	if (*pp_signer_cert == nullptr) {
		throw std::runtime_error("CertCreateCertificateContext failed");
	}
}

extern "C" HRESULT WINAPI AuthenticodeDigestSignEx(
	_In_opt_ PCRYPT_DATA_BLOB pMetadataBlob,
	_In_ ALG_ID digestAlgId,
	_In_ PBYTE pbToBeSignedDigest,
	_In_ DWORD cbToBeSignedDigest,
	_Out_ PCRYPT_DATA_BLOB pSignedDigest,
	_Out_ PCCERT_CONTEXT * ppSignerCert,
	_Inout_ HCERTSTORE hCertChainStore
) {
	// Check if metadata is specified
	if (pMetadataBlob == nullptr || pMetadataBlob->pbData == nullptr) {
		// if metadata is not specified, return E_FAIL
		printf("Specify config.json by /dmdf option.\n");
		printf("%s\n", R"(
  "-------- SIGNER_SELECT(remote, cert_store, token) ---------": "",
  "sign_mode": "remote",

  "-------- SETTING_FOR_REMOTE_SIGNER ---------": "",
  "host": "127.0.0.1",
  "port": 5000,

  "-------- SETTING_FOR_CERT_STORE_SIGNER ---------": "",
  "cert_subject": "Your_Cert_Subject",

  "-------- SETTING_FOR_TOKEN_SIGNER ---------": "",
  "dll_path": "C:\\Windows\\System32\\eTPKCS11.dll",
  "slot_number": 0,
  "pin": "your_pin",
  "key_label": "Your_Key_Label",
  "cert_label": "Your_Cert_Label"
}
)");
		return E_INVALIDARG;
	}
	try {
		static const std::map<DWORD, std::wstring> id_to_algorithm = {
			{CALG_SHA1,    BCRYPT_SHA1_ALGORITHM},
			{CALG_SHA_256, BCRYPT_SHA256_ALGORITHM},
			{CALG_SHA_384, BCRYPT_SHA384_ALGORITHM},
			{CALG_SHA_512, BCRYPT_SHA512_ALGORITHM}
		};
		auto digest_algorithm = id_to_algorithm.at(digestAlgId);
		std::vector<BYTE> to_be_signed_digest(pbToBeSignedDigest, pbToBeSignedDigest + cbToBeSignedDigest);

		std::string json_string((LPCSTR)pMetadataBlob->pbData);

		auto signer = CreateSigner(json_string);
		auto signing_data = signer->Sign(digest_algorithm, to_be_signed_digest);

		ApplyResult(signing_data.GetDigest(), signing_data.GetEncodedCert(), pSignedDigest, signing_data.GetCertEncodingType(), ppSignerCert);
	}
	catch (...) {
		return E_FAIL;
	}
	return S_OK;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
