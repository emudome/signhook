# Remote Signer

このプロジェクトはWindowsのコードサイニングをリモートで実施するためのツールセットです。

以下の２つで構成されます。

- signserver
  - Python+Flaskで作成された署名サーバーです。Windows証明書ストアにある証明書での署名とUSBトークンでの署名に対応しています。動作環境はWindowsのみをサポートしています。
- signhook
  - singtool.exeの/dlibオプションで使用するDLLです。このDLLを経由してremotesignサーバーで署名します。
  - remotesignを経由せず、ローカルのWindows証明書ストアやUSBトークンを使用した署名もできます。

## signserver

サーバーは下記コマンドで起動します。

```
cd signserver
pip install -r requirements.txt
python main.py
```

`setting.json`は下記に従って設定してください。


| 項目 | 内容 |
| ---- | ---- |
| sign_mode | 署名の方法を指定します。Windows証明書ストアを使用する場合は`cert_store`、USBトークンの場合は`token`を指定します。 |
| cert_subject | 証明書の名前を指定します。`sign_mode`が`cert_store`の場合のみ使用されます。 |
| dll_path | USBトークンにアクセスするためのPKCS#11準拠のDLLパスを指定します。`sign_mode`が`token`の場合のみ使用されます。 |
| slot_number | USBトークンのスロットナンバーを指定します。`sign_mode`が`token`の場合のみ使用されます。 |
| pin | USBトークンのPIN(パスワード)を指定します。`sign_mode`が`token`の場合のみ使用されます。|
| key_label | 秘密鍵ラベルを指定します。`sign_mode`が`token`の場合のみ使用されます。 |
| cert_label | 証明書ラベルを指定します。`sign_mode`が`token`の場合のみ使用されます。 |

```
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

下記のようにsignhook.dllとconfig.jsonのパスをsigntool.exe signのオプションで指定してください。

```
signtool.exe sign /tr http://timestamp.acs.microsoft.com /td sha256 /fd sha256 /dlib "C:\path\to\rsignhook.dll" /dmdf "C:\path\to\config.json" "C:\path\to\*.exe" 
```

`setting.json`は下記に従って設定してください。


| 項目 | 内容 |
| ---- | ---- |
| sign_mode | 署名の方法を指定します。署名サーバーを使用する場合は`signserver`、ローカルのWindows証明書ストアを使用する場合は`cert_store`、ローカルのUSBトークンの場合は`token`を指定します。 |
| cert_subject | 証明書の名前を指定します。`sign_mode`が`cert_store`の場合のみ使用されます。 |
| host | signserverを実行しているPCのホスト名またはIPアドレスを指定します。`sign_mode`が`signserver`の場合のみ使用されます。 |
| port | signserverのポート番号を指定します。`sign_mode`が`signserver`の場合のみ使用されます。 |
| dll_path | USBトークンにアクセスするためのPKCS#11準拠のDLLパスを指定します。`sign_mode`が`token`の場合のみ使用されます。 |
| slot_number | USBトークンのスロットナンバーを指定します。`sign_mode`が`token`の場合のみ使用されます。 |
| pin | USBトークンのPIN(パスワード)を指定します。`sign_mode`が`token`の場合のみ使用されます。|
| key_label | 秘密鍵ラベルを指定します。`sign_mode`が`token`の場合のみ使用されます。 |
| cert_label | 証明書ラベルを指定します。`sign_mode`が`token`の場合のみ使用されます。 |

```
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

## ツールについて

このツールには、ローカルで署名する機能と、DLLを介してリモートの署名サーバーに接続して署名する2つの機能があります。ローカル署名は、通常の署名（signtoolを実行するのと同じ処理をDLLで実装）とPKCS#11のインターフェースを使用してUSBトークンでの署名を実装しています。リモート署名は、ローカル署名と同様の処理をFlaskサーバー側で実行するように設計されています。USBトークンの署名は実際には動作させていないため、その動作が確認できるかどうかは不明です。

## 使い方

```
signtool.exe sign /v /debug /tr http://timestamp.acs.microsoft.com /td sha256 /fd sha256 /dlib "C:\hoge\certhook.dll" /dmdf "C:\hoge\config.json" "C:\hoge\*.exe" 
```

/dlibオプションを使用する場合は、DLL側で使用する証明書を指定するため、/nや/aなどのオプションは無視されます。

以下はconfig.jsonの例です。
```
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

## 外部ライブラリ

- [pkcs11.h](https://github.com/OpenSC/libp11/tree/libp11-0.4.12/src/pkcs11.h)
- [json.hpp](https://github.com/nlohmann/json/blob/v3.11.3/single_include/nlohmann/json.hpp)

## 実装内容解説

signtool.exe signの/dlibオプションを使ってリモート署名の機能を実現しています。

実装に当たっては、[Trusted Signing](https://learn.microsoft.com/en-us/azure/trusted-signing/how-to-signing-integrations)の仕組みを参考にしています。AzureのTrusted SigningではAzure.CodeSigning.Dlib.dllを/dlibオプションで使用しており、このDLLはAuthenticodeDigestSignExWithFileHandleをエクスポートしています。

signtool.exe signのヘルプではAuthenticodeDigestSignまたはAuthenticodeDigestSignExを実装と書かれていますが、AuthenticodeDigestSignExまたはAuthenticodeDigestSignExWithFileHandleを実装したDLLでないと/dlibオプションでロードされないのに注意してください。

```
/dlib <dll>  Specifies the DLL implementing the AuthenticodeDigestSign or
             AuthenticodeDigestSignEx function to sign the digest with. This
             option is equivalent to using SignTool separately with the
             /dg, /ds, and /di switches, except this option invokes all three
             as one atomic operation.
```

各関数のパラメータについては[PFN_AUTHENTICODE_DIGEST_SIGN_EX callback function](https://learn.microsoft.com/en-us/windows/win32/seccrypto/pfn-authenticode-digest-sign-ex)と[PFN_AUTHENTICODE_DIGEST_SIGN_EX_WITHFILEHANDLE callback function](https://learn.microsoft.com/en-us/windows/win32/seccrypto/pfn-authenticode-digest-sign-ex-withfilehandle)を参考にしてください。

AuthenticodeDigestSignExのパラメータは下記を指定します。

```
    _In_opt_ PCRYPT_DATA_BLOB pMetadataBlob,         
    _In_ ALG_ID digestAlgId,                                 
    _In_ PBYTE pbToBeSignedDigest, 
    _In_ DWORD cbToBeSignedDigest,                           
    _Out_ PCRYPT_DATA_BLOB pSignedDigest,                    
    _Out_ PCCERT_CONTEXT* ppSignerCert,                      
    _Inout_ HCERTSTORE hCertChainStore     
```

| 項目 | 内容 |
| ---- | ---- |
| pMetadataBlob | 使用していません。 |
| digestAlgId | /fdオプションでSHA1を指定した場合はCALG_SHA1、SHA256を指定した場合はCALG_SHA_256が渡されます。 |
| pbToBeSignedDigest | /fdで指定したダイジェストアルゴリズムによって生成された署名対象のファイルハッシュ値が渡されます。以降はこの情報をダイジェストと呼びます。|
| cbToBeSignedDigest | pbToBeSignedDigestのサイズが渡されます。/fdでSHA1を指定した場合は20バイト、SHA256を指定した場合は32バイトになります。 |
| pSignedDigest | ダイジェストに対して署名した結果(署名済みダイジェスト値)を渡します。 |
| ppSignerCert | 署名に使用したコンテキスト(証明書情報など)を渡します。 |
| hCertChainStore | 使用していません。 |

AuthenticodeDigestSignExは、受け取ったダイジェスト値(ファイルハッシュ値)に対して署名する関数です。ダイジェスト値は/fdで指定したダイジェストアルゴリズムに従って生成されており、署名する際にはダイジェストのデータだけではデータ構造が不明なため、ダイジェストアルゴリズムの種類も使用しています。

Windows証明書ストアの証明書で署名する際には、CertOpenStoreとCertFindCertificateInStoreから指定された名前の証明書でコンテキスト(証明書データ)を取得し、NCryptSignHashでダイジェスト値から署名済みダイジェスト値を生成します。

USBトークンの場合は、PKCS#11のAPIにしたがって秘密鍵ハンドルの取得をした後、秘密鍵ハンドルとダイジェスト値とダイジェストアルゴリズムをC_SignInit/C_Sign関数へ指定して署名済みダイジェスト値を生成します。AuthenticodeDigestSignExへ返却する必要があるため、別途証明書データを取得しています。