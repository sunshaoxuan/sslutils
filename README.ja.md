# SSL Certificate Management Tools

言語:
- English: [README.md](README.md)
- 中文: [README.zh.md](README.zh.md)
- 日本語: README.ja.md (このファイル)

## 概要
証明書・秘密鍵・CSR を扱う PowerShell スクリプト集です。多機関対応と多言語対応を前提にしています。

## バージョン (v1.5.3)
- **Let's Encrypt 出力整理**: 証明書は既定で `output/self-signed/lets-encrypt/<domain>` に出力され、一時作業は `temp/lets-encrypt/` に移動し、成功後に自動削除されます。
- **PEM 自動正規化**: 出力される `fullchain.pem` / `privkey.pem` は自動で改行・ヘッダを正規化し、そのまま利用しやすくなりました。
- **CAA SERVFAIL 自動再試行**: 一時的な DNS `CAA SERVFAIL` 失敗時に Let's Encrypt 申請を自動再試行します。
- **秘密鍵判定改善**: `Get-CertificateInfo.ps1` が PEM 秘密鍵をより正確に判定し、PKCS#8 / EC 鍵も読み取りやすくなりました。
- **詳細履歴**: [CHANGELOG.md](CHANGELOG.md) を参照。

## 事前準備
- **PowerShell 7.x** 以上（スクリプト起動時に自動チェック、未満の場合はエラー終了）
- OpenSSL（自動解決: `utils/bin/` → `config.json` → Git for Windows → システム PATH）
- 必要なら `passphrase.txt`（暗号化鍵用）

### OpenSSL セットアップ

システムに OpenSSL がない場合、セットアップスクリプトでポータブル版をダウンロードできます:

```powershell
.\utils\Install-Dependencies.ps1
```

`utils/bin/` に OpenSSL が自動インストールされます。`config.json` でカスタムパスも設定可能です:

```json
"Tools": {
    "OpenSsl": "C:\\path\\to\\openssl.exe"
}
```

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
├── config.json             # パス・ツール設定
├── Invoke-SSLToolkit.ps1   # [入口] メインメニュー
└── utils/                  # 各独立スクリプト
    ├── Install-Dependencies.ps1 # OpenSSL 自動ダウンロード
    └── bin/                # ポータブルツールバイナリ
```

## クイックスタート

```powershell
.\utils\Install-Dependencies.ps1   # 初回: OpenSSL セットアップ
.\Invoke-SSLToolkit.ps1
```

初回起動は英語です。メインメニューの **Language** から言語を切換えできます（選択は自動保存）。

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
パスフレーズ付き `.key` を、サーバー投入用の「パスワード不要 key」に変換します。既に `<元名>.decrypted.key` がある場合は、実行中にバックアップして上書きするか確認します。

4) `New-CertificateSigningRequest.ps1`
CSR と秘密鍵を生成。
```powershell
.\utils\New-CertificateSigningRequest.ps1 -CN example.com -C JP -ST Tokyo -L Tokyo -O "Example Corp"
```
対話モードでは、まず `CN` を入力し、その後に `C / ST / L / O` を確認してから SAN メニューへ進みます。既定ではいったん `new/<CN>/` に生成し、生成完了直後にそのドメインだけへフォルダ名自動変換ロジックを適用するため、次回起動を待たずに `組織名 (ホスト名)` 形式へ移行できます。

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
既定では証明書は `output/self-signed/lets-encrypt/<domain>` に出力されます。作業用ファイルは `temp/lets-encrypt/` に作成され、成功後に自動削除されます。現在の challenge 情報は作業ディレクトリ内の `current-challenge.txt` に保存されます。

8) `Request-SelfSignedCertificate.ps1`
自己署名証明書を生成（有効期間を選択可能: 90日 / 1年 / 3年 / 10年）。
```powershell
.\utils\Request-SelfSignedCertificate.ps1 -CN internal.example.local -Days 365 -Lang ja
```
対話メニューで有効期間を選択し、Quick モードまたは Custom モードで生成。

9) `Repair-PemFile.ps1`
PEM の修復・正規化。
```powershell
.\utils\Repair-PemFile.ps1 -Fullchain .\fullchain.pem -Privkey .\privkey.pem
```
引数を省略した場合は、まず `old`、`new`、`output/merged`、`output/self-signed` から対象領域を選び、その後に検出された PEM ペアを選択します。絶対パスの手入力は最後の手段です。

10) `New-ServerList.ps1`
証明書更新用 TSV を生成/保守（旧 TSV の項目継承と手修正値の保持に対応）。
```powershell
.\utils\New-ServerList.ps1 -Path .\new -OldPath .\old
```

## 📁 フォルダ命名規則（組織名の自動検出）

`old/`、`new/`、`output/merged/` 配下のサブフォルダを**ドメイン名**（例: `example.co.jp`）で命名すると、ツール起動時にそのドメインの組織名を自動的に調べ、フォルダのリネームを提案します。

**動作の仕組み：**

`Invoke-SSLToolkit.ps1` を起動するたびに `Rename-OrgFolders.ps1 -AutoYes` が自動実行されます：

1. `old/`、`new/`、`output/merged/` を走査し、ドメイン名に見えるフォルダ（`.` を含む名前）を検出
2. 以下の順序で組織名を照会：
   - **ローカル証明書**：フォルダ内の `.cer` ファイルから `O=`（Organization）を読み取り
   - **WHOIS (JPRS)**：`.jp` ドメインの場合、JPRS WHOIS レジストリから登録者名を取得
   - **Web サイト探索**：`https://<ドメイン>` に接続し、TLS 証明書の組織名またはページタイトルを取得
3. 組織名が見つかった場合、`example.co.jp` → `Example Corp (example)` のようにリネームを提案（組織名 + ホスト名）
4. 3つのディレクトリで同名フォルダを一括リネームし、整合性を維持

新規 CSR 作成時も同じリネーム処理を生成直後に再利用しますが、そのときは新しく作成したドメインフォルダだけを対象にするため、全体走査を待たずに最終的な組織名フォルダへ移せます。

**例：**

```
変更前:  old/mail.example.co.jp/   new/mail.example.co.jp/
変更後:  old/Example Corp (mail)/  new/Example Corp (mail)/
```

これにより、各証明書がどの組織に属するか一目で識別できます。リネーム済みのフォルダ（スペースと括弧を含む名前）は自動的にスキップされます。

## 🌐 多言語拡張

新しい言語を追加するには `resources/strings.xx.psd1`（xx は言語コード）を作成し、`Language.DisplayName` キーと全翻訳キーを含めるだけです。コード変更は不要で、メインメニューの言語選択に自動的に表示されます。

## Apache / Tomcat 設定例

Apache（fullchain 方式）:
```apache
SSLCertificateFile      /path/to/fullchain.cer
SSLCertificateKeyFile   /path/to/server.key
```

Tomcat（PEM: key + cert + chain）:
```xml
<Connector port="8443"
  protocol="org.apache.coyote.http11.Http11NioProtocol"
  SSLEnabled="true">
  <SSLHostConfig>
    <Certificate
      certificateFile="/path/to/server.cer"
      certificateKeyFile="/path/to/server.key"
      certificateChainFile="/path/to/chain.cer"
      type="RSA" />
  </SSLHostConfig>
</Connector>
```

Tomcat（PKCS#12 / PFX、任意）:
```xml
<Connector port="8443"
  protocol="org.apache.coyote.http11.Http11NioProtocol"
  SSLEnabled="true"
  keystoreFile="/path/to/server.pfx"
  keystorePass=""
  keystoreType="PKCS12" />
```

注:
- 納品物が `.key` + `.cer`（+ chain）の場合は PEM 構成が分かりやすいです。
- PFX は特定環境で有効ですが、実運用では証明書チェーン確認、権限設定、再読込手順など追加考慮が必要です。

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
