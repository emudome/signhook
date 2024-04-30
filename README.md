# Remote Signer

This project is a toolkit for remotely conducting code signing on Windows.

It consists of two components:

- **signserver**
  - This is a signing server created with Python+Flask. It supports signing with certificates in the Windows certificate store and with USB tokens. The operating environment is supported on Windows only.
- **signhook**
  - This is a DLL used with the /dlib option of signtool.exe. It facilitates signing via the remotesign server. Additionally, it allows for signing using the local Windows certificate store or USB token without going through remotesign.

## signserver

Start the server with the following commands:

```bash
cd signserver
pip install -r requirements.txt
python main.py
```

Configure `setting.json` according to the following:

| Item         | Description                                                                                                       |
| ------------ | ----------------------------------------------------------------------------------------------------------------- |
| sign_mode    | Specifies the signing method. Use `cert_store` for using the Windows certificate store, and `token` for USB tokens. |
| cert_subject | Specifies the name of the certificate. Used only if `sign_mode` is `cert_store`.                                 |
| dll_path     | Specifies the path to the PKCS#11 compliant DLL for accessing the USB token. Used only if `sign_mode` is `token`. |
| slot_number  | Specifies the slot number of the USB token. Used only if `sign_mode` is `token`.                                  |
| pin          | Specifies the PIN (password) of the USB token. Used only if `sign_mode` is `token`.                              |
| key_label    | Specifies the label of the private key. Used only if `sign_mode` is `token`.                                       |
| cert_label   | Specifies the label of the certificate. Used only if `sign_mode` is `token`.                                       |

```json
{
  "-------- SIGNER_SELECT(cert_store, token) ---------": "",
  "sign_mode": "cert_store",

  "-------- SETTING_FOR_CERT_STORE_SIGNER ---------": "",
  "cert_subject": "Your_Cert_Subject",

  "-------- SETTING_FOR_TOKEN_SIGNER ---------": "",
  "dll_path": "C:\\Windows\\System32\\eTPKCS11.dll",
  "slot_number": 0,
  "pin": "your_pin",
  "key_label": "Your_Key_Label",
  "cert_label": "Your_Cert_Label"
}
```

## signhook

Specify the paths to signhook.dll and config.json with the /dlib option of signtool.exe sign as follows:

```bash
signtool.exe sign /tr http://timestamp.acs.microsoft.com /td sha256 /fd sha256 /dlib "C:\path\to\rsignhook.dll" /dmdf "C:\path\to\config.json" "C:\path\to\*.exe" 
```

Configure `setting.json` according to the following:

| Item         | Description                                                                                                             |
| ------------ | ----------------------------------------------------------------------------------------------------------------------- |
| sign_mode    | Specifies the signing method. Use `signserver` to use the signing server, `cert_store` for the local Windows certificate store, and `token` for local USB tokens. |
| cert_subject | Specifies the name of the certificate. Used only if `sign_mode` is `cert_store`.                                         |
| host         | Specifies the hostname or IP address of the PC running the signserver. Used only if `sign_mode` is `signserver`.           |
| port         | Specifies the port number of the signserver. Used only if `sign_mode` is `signserver`.                                    |
| dll_path     | Specifies the path to the PKCS#11 compliant DLL for accessing the USB token. Used only if `sign_mode` is `token`.     |
| slot_number  | Specifies the slot number of the USB token. Used only if `sign_mode` is `token`.                                          |
| pin          | Specifies the PIN (password) of the USB token. Used only if `sign_mode` is `token`.                                      |
| key_label    | Specifies the label of the private key. Used only if `sign_mode` is `token`.                                               |
| cert_label   | Specifies the label of the certificate. Used only if `sign_mode` is `token`.                                               |

```json
{
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
```

## About the Tool

This tool has two functionalities: local signing and signing via a remote signing server using a DLL. Local signing implements regular signing (implementing the same process as executing signtool) and signing with USB tokens using the PKCS#11 interface. Remote signing is designed to execute similar processes on the Flask server side as local signing. As USB token signing has not been actually implemented, it is unclear if it works.

## Usage

```bash
signtool.exe sign /v /debug /tr http://timestamp.acs.microsoft.com /td sha256 /fd sha256 /dlib "C:\hoge\certhook.dll" /dmdf "C:\hoge\config.json" "C:\hoge\*.exe" 
```

When using the /dlib option, options like /n or /a are ignored as they are used to specify the certificate used on the DLL side.

Below is an example of config.json:

```json
{
  "-------- SIGNER_SELECT(remote, cert_store, token) ---------": "",
  "mode": "remote",

  "-------- SETTING_FOR_REMOTE_SIGNER ---------": "",
  "host": "127.0.0.1",
  "port": 5000,

  "-------- SETTING_FOR_CERT_STORE_SIGNER ---------": "",
  "cert_subject": "Cert_Subject_Name",

  "-------- SETTING_FOR_TOKEN_SIGNER ---------": "",
  "dll_path": "C:\\Windows\\System32\\eTPKCS11.dll",
  "slot_number": 0,
  "pin": "your_pin",
  "key_label": "Your_Key_Label",
  "cert_label": "Your_Cert_Label"
}
```

## External Libraries

- [pkcs11.h](https://github.com/OpenSC/libp11/tree/libp11-0.4.12/src/pkcs11.h)
- [json.hpp](https://github.com/nlohmann/json/blob/v3.11.3/single_include/nlohmann/json.hpp)

## Implementation Explanation

The functionality of remote signing is achieved using the /dlib option of signtool.exe sign.

The implementation is inspired by the mechanism of [Trusted Signing](https://learn.microsoft.com/en-us/azure/trusted-signing/how-to-signing-integrations). In Azure Trusted Signing, Azure.CodeSigning.Dlib.dll is used with

 the /dlib option, and this DLL exports AuthenticodeDigestSignExWithFileHandle.

While signtool.exe sign's help mentions AuthenticodeDigestSign or AuthenticodeDigestSignEx, note that only DLLs implementing AuthenticodeDigestSignEx or AuthenticodeDigestSignExWithFileHandle are loaded with the /dlib option.

```plaintext
/dlib <dll>  Specifies the DLL implementing the AuthenticodeDigestSign or
             AuthenticodeDigestSignEx function to sign the digest with. This
             option is equivalent to using SignTool separately with the
             /dg, /ds, and /di switches, except this option invokes all three
             as one atomic operation.
```

Please refer to [PFN_AUTHENTICODE_DIGEST_SIGN_EX callback function](https://learn.microsoft.com/en-us/windows/win32/seccrypto/pfn-authenticode-digest-sign-ex) and [PFN_AUTHENTICODE_DIGEST_SIGN_EX_WITHFILEHANDLE callback function](https://learn.microsoft.com/en-us/windows/win32/seccrypto/pfn-authenticode-digest-sign-ex-withfilehandle) for the parameters of each function.

The parameters for AuthenticodeDigestSignEx are as follows:

```plaintext
    _In_opt_ PCRYPT_DATA_BLOB pMetadataBlob,         
    _In_ ALG_ID digestAlgId,                                 
    _In_ PBYTE pbToBeSignedDigest, 
    _In_ DWORD cbToBeSignedDigest,                           
    _Out_ PCRYPT_DATA_BLOB pSignedDigest,                    
    _Out_ PCCERT_CONTEXT* ppSignerCert,                      
    _Inout_ HCERTSTORE hCertChainStore     
```

| Item               | Description                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------------- |
| pMetadataBlob      | Not used.                                                                                         |
| digestAlgId        | If SHA1 is specified with /fd option, CALG_SHA1 is passed; if SHA256 is specified, CALG_SHA_256 is passed. |
| pbToBeSignedDigest | The digest value generated by the specified digest algorithm with /fd.                              |
| cbToBeSignedDigest | The size of pbToBeSignedDigest. If SHA1 is specified with /fd, it is 20 bytes; for SHA256, it is 32 bytes. |
| pSignedDigest      | The result of signing the digest (signed digest value).                                             |
| ppSignerCert       | The context used for signing (certificate information, etc.).                                        |
| hCertChainStore    | Not used.                                                                                         |

AuthenticodeDigestSignEx is a function to sign the received digest value (file hash value). Since the structure of the data is unknown when signing, it also uses the type of digest algorithm used.

When signing with a certificate from the Windows certificate store, it obtains the context (certificate data) with the certificate name specified by CertOpenStore and CertFindCertificateInStore, and generates the signed digest value from the digest value with NCryptSignHash.

For USB tokens, it follows the PKCS#11 API to obtain the handle of the private key, specifies the private key handle, digest value, and digest algorithm to C_SignInit/C_Sign function, and generates the signed digest value. Additional certificate data is obtained to return to AuthenticodeDigestSignEx.
