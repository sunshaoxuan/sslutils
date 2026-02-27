# SSL Certificate Management Tools

言語:
- 中文: README.md
- 日本語: README.ja.md
- English: README.en.md

## 概要
証明書・秘密鍵・CSR を扱う PowerShell スクリプト集です。多機関対応と多言語対応を前提にしています。

## バージョン (v1.4.0)
- **言語の設定化**: 対応言語は `resources/strings.*.psd1` から自動検出。新言語の追加はリソースファイルの追加のみで完了（コード変更不要）。
- **言語の永続化**: メインメニューで言語を切換えると `.toolkit_lang` に自動保存し、次回起動時に復元。
- **4枚結合チェーン**: サーバー ＋ 中間 ＋ 交差ルート ＋ ルートCA の 4 枚結合に対応（3 枚結合が推奨デフォルト）。
- **PFX 強化**: PFX のチェーン構造を完全表示、顧客提供 PFX の検出と再利用プロンプト、レガシー暗号方式の自動回退。
- **チェーン詳細**: 証明書チェーンの各ブロックにソースファイル名を表示（例: `[nii-odca4g8rsa-pem.cer]`）。
- **PS7 バージョンチェック**: 全エントリースクリプトで PowerShell 7.x 以上を必須化。
- **メニュー改善**: 自己署名関連を1つのサブメニューに統合。

## 事前準備
- **PowerShell 7.x** 以上（スクリプト起動時に自動チェック、未満の場合はエラー終了）
- OpenSSL（既定: `C:\Program Files\Git\usr\bin\openssl.exe`）
- 必要なら `passphrase.txt`（暗号化鍵用）

## フォルダ構成
```
ssl_maker/
├── old/                    # 旧証明書・鍵・CSR
├── new/                    # 新規生成 CSR・鍵
├── output/                 # 出力ルート
│   ├── merged/             # 結合済みチェーン & PFX
│   └── self-signed/        # 自己署名証明書の出力
├── CertStore/              # ルート証明書・中間証明書ストア
├── resources/              # リソースファイル（言語パック）
│   ├── strings.ja.psd1     # 日本語
│   ├── strings.zh.psd1     # 中国語
│   └── strings.en.psd1     # 英語
├── CertConfig.psd1         # 証明書マッチングルール
├── Invoke-SSLToolkit.ps1   # [入口] メインメニュー
└── utils/                  # 各独立スクリプト
```

## クイックスタート

```powershell
.\Invoke-SSLToolkit.ps1
```

初回起動は日本語です。メインメニューの **Language** から言語を切換えできます（選択は自動保存）。

起動パラメータで言語を指定することも可能：
```powershell
.\Invoke-SSLToolkit.ps1 -Lang ja  # 日本語
.\Invoke-SSLToolkit.ps1 -Lang zh  # 中文
.\Invoke-SSLToolkit.ps1 -Lang en  # English
```

## スクリプト一覧と使い方

1) `Get-CertificateInfo.ps1`
証明書・秘密鍵・CSR の情報を表示。多段チェーンの各ブロック詳細やソースファイル名を表示。
```powershell
.\utils\Get-CertificateInfo.ps1
.\utils\Get-CertificateInfo.ps1 -Path .\new\example.com\example.com.cer -Table
.\utils\Get-CertificateInfo.ps1 -Lang ja
```

2) `Merge-CertificateChain.ps1`
fullchain を生成（証明書 + 中間）。3枚結合（推奨）または 4枚結合（ルートCA含む）に対応。
```powershell
.\utils\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer
.\utils\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer -RootCert .\cross-root.cer
```

3) `Convert-KeyToPlaintext.ps1`
暗号化鍵を平文に変換。
```powershell
.\utils\Convert-KeyToPlaintext.ps1 -Path .\new\example.com\server.key
.\utils\Convert-KeyToPlaintext.ps1 -Path .\new -Recurse -Overwrite
```

4) `New-CertificateSigningRequest.ps1`
CSR と秘密鍵を生成。
```powershell
.\utils\New-CertificateSigningRequest.ps1 -CN example.com -C JP -ST Tokyo -L Tokyo -O "Example Corp"
```

5) `Export-CertificateModulus.ps1`
証明書/鍵の Modulus を一覧出力。
```powershell
.\utils\Export-CertificateModulus.ps1 -RootDir .\old
```

6) `New-CertificateSigningRequestFromOld.ps1`
旧証明書情報から新 CSR/鍵を生成。
```powershell
.\utils\New-CertificateSigningRequestFromOld.ps1
```

7) `Request-LetsEncryptCertificate.ps1`
Docker + certbot で Let's Encrypt を申請。
```powershell
.\utils\Request-LetsEncryptCertificate.ps1 -Domain example.com -Email admin@example.com
```

8) `Request-SelfSignedCertificate.ps1`
10年有効の自己署名証明書を生成。
```powershell
.\utils\Request-SelfSignedCertificate.ps1 -CN internal.example.local -Lang ja
```

9) `Repair-PemFile.ps1`
PEM の修復・正規化。
```powershell
.\utils\Repair-PemFile.ps1 -Fullchain .\fullchain.pem -Privkey .\privkey.pem
```

## 🌐 多言語拡張

新しい言語を追加するには `resources/strings.xx.psd1`（xx は言語コード）を作成し、`Language.DisplayName` キーと全翻訳キーを含めるだけです。コード変更は不要で、メインメニューの言語選択に自動的に表示されます。

## Apache / Tomcat 設定例

Apache（fullchain 方式）:
```apache
SSLCertificateFile      /path/to/fullchain.cer
SSLCertificateKeyFile   /path/to/server.key
```

Tomcat（PKCS#12 方式）:
```xml
<Connector port="8443"
  protocol="org.apache.coyote.http11.Http11NioProtocol"
  SSLEnabled="true"
  keystoreFile="/path/to/server.pfx"
  keystorePass=""
  keystoreType="PKCS12" />
```

## パスワードファイル
`passphrase.txt` の探索順序（最大 6 階層）:
鍵と同階層 → 上位 → 機関直下 → old/new 直下 → スクリプト直下 → 環境変数 `PASS_FILE`

## パス設定（config.json）
ディレクトリ名は `config.json` の `Paths` で設定できます（既定値）:

```json
"Paths": {
  "Old": "old",
  "New": "new",
  "OutputRoot": "output",
  "Merged": "output/merged",
  "SelfSigned": "output/self-signed",
  "Temp": "temp",
  "Resources": "resources",
  "CertConfig": "CertConfig.psd1"
}
```

---

## 📜 公開証明書ストア (CertStore)

ルート証明書・中間証明書を内蔵し、証明書チェーンの自動構築に使用します。詳細は [CertStore/README.md](CertStore/README.md) を参照。

| ファイル | 説明 | ダウンロード |
|----------|------|------------|
| gsgccr3dvtlsca2020.cer | GlobalSign GCC R3 DV TLS CA 2020 | [DL](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/GlobalSign/gsgccr3dvtlsca2020.cer) |
| nii-odca4g7rsa.cer | NII Open Domain CA - G7 RSA | [DL](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/NII/nii-odca4g7rsa.cer) |
| nii-odca4g8rsa-pem.cer | NII Open Domain CA - G8 RSA | [DL](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/NII/nii-odca4g8rsa-pem.cer) |
| SCRoot2caPem.cer | Security Communication RootCA2 (Root) | [DL](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/Secom/SCRoot2caPem.cer) |
| tlsrsarootca2024cross-pem.cer | SECOM TLS RSA Root CA 2024 (Cross-signed) | [DL](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/Secom/tlsrsarootca2024cross-pem.cer) |

詳細な変更履歴は [CHANGELOG.md](CHANGELOG.md) を参照してください。
