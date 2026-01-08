# SSL Certificate Management Tools

SSL/TLS 証明書・秘密鍵・CSR（証明書署名要求）を管理するための PowerShell スクリプト集です。

## 概要

このツールセットは、複数の機関（組織）の SSL/TLS 証明書を効率的に管理するために開発されました。
主に以下の用途で使用します：

- 証明書・秘密鍵・CSR の基本情報確認
- 証明書チェーン（中間証明書）の結合
- 暗号化鍵の復号化
- 新しい CSR と秘密鍵の生成
- 証明書と鍵の一致確認

## 機能

### 多言語対応

すべてのスクリプトは、日本語・中国語・英語の 3 言語に対応しています。
`-Lang` パラメータで言語を指定できます（既定: 日本語）。

```powershell
.\Get-CertificateInfo.ps1 -Lang ja  # 日本語
.\Get-CertificateInfo.ps1 -Lang zh  # 中国語
.\Get-CertificateInfo.ps1 -Lang en  # 英語
```

### 多機関対応

`old\` と `new\` の階層構造を自動認識し、複数の機関（組織）の証明書を同時に管理できます。

```
ssl_maker/
├── old/                    # 旧証明書・鍵・CSR
│   ├── org1/
│   │   ├── server.cer
│   │   ├── server.key
│   │   └── server.csr
│   └── org2/
│       └── ...
├── new/                    # 新規生成された CSR・鍵
│   ├── org1/
│   │   └── server.csr
│   └── org2/
│       └── ...
└── merged/                 # 結合済み証明書チェーン
    ├── old/
    └── new/
```

## 必要な環境

- **PowerShell 5.1 以上** または **PowerShell 7.x**
- **OpenSSL**（Git for Windows に含まれるものを使用可能）
  - 既定パス: `C:\Program Files\Git\usr\bin\openssl.exe`
  - カスタムパスは各スクリプトの `-OpenSsl` パラメータで指定可能

## インストール

1. このリポジトリをクローンまたはダウンロードします
2. PowerShell でスクリプトディレクトリに移動します

```powershell
cd C:\path\to\ssl_maker
```

## スクリプト一覧

### 1. Get-CertificateInfo.ps1

証明書・秘密鍵・CSR の基本情報を表示します。

**主な機能:**
- 証明書の有効期限、発行者、サブジェクトの表示
- 証明書チェーン（中間証明書同梱）の確認
- 秘密鍵の暗号化状態と無人運用可能性の判定
- CSR のサブジェクト情報表示

**使用例:**
```powershell
# old\ と new\ 配下を走査
.\Get-CertificateInfo.ps1

# 特定ファイルのみ表示
.\Get-CertificateInfo.ps1 -Path .\new\example.com\example.com.cer

# 表形式で表示
.\Get-CertificateInfo.ps1 -Table
```

### 2. Merge-CertificateChain.ps1

クライアント証明書と中間証明書を結合してフルチェーンを作成します。

**主な機能:**
- クライアント証明書と中間証明書の自動結合
- 中間証明書の自動選択（issuer/subject による一致判定）
- 既に結合済みの証明書の検出とスキップ
- 一括処理モード

**使用例:**
```powershell
# 一括処理（old\ と new\ 配下を自動走査）
.\Merge-CertificateChain.ps1

# 特定の証明書を結合
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer
```

### 3. Convert-KeyToPlaintext.ps1

暗号化された秘密鍵ファイルを復号化して平文鍵を作成します。

**主な機能:**
- 暗号化鍵の自動検出と復号化
- パスワードファイル（passphrase.txt）の自動探索
- 一括処理（ディレクトリ指定時の再帰処理）
- インプレース復号化オプション

**使用例:**
```powershell
# 特定の鍵ファイルを復号化
.\Convert-KeyToPlaintext.ps1 -Path .\new\example.com\server.key

# ディレクトリ配下を再帰的に処理
.\Convert-KeyToPlaintext.ps1 -Path .\new -Recurse -Overwrite

# インプレース復号化（元ファイルを上書き）
.\Convert-KeyToPlaintext.ps1 -Path .\encrypted.key -InPlace -Overwrite
```

### 4. New-CertificateSigningRequest.ps1

汎用的な CSR と秘密鍵を生成します。

**主な機能:**
- RSA 鍵の生成（鍵長指定可能、既定: 2048bit）
- CSR の生成（Subject と SAN 対応）
- 秘密鍵の暗号化オプション（AES-256）

**使用例:**
```powershell
# Subject を明示指定
.\New-CertificateSigningRequest.ps1 -CN example.com -Subject "/C=JP/ST=Tokyo/L=Tokyo/O=Example Corp/CN=example.com"

# 個別パラメータで指定
.\New-CertificateSigningRequest.ps1 -CN example.com -C JP -ST Tokyo -L Tokyo -O "Example Corp"

# 暗号化鍵で生成
.\New-CertificateSigningRequest.ps1 -CN example.com -PassFile .\passphrase.txt -Overwrite
```

### 5. Export-CertificateModulus.ps1

すべての証明書と秘密鍵の Modulus 値を一覧表示します。

**主な機能:**
- 証明書と秘密鍵の Modulus 値の抽出
- 暗号化鍵の自動処理（パスワードファイル対応）
- 一覧レポートの生成

**使用例:**
```powershell
# 指定ディレクトリ配下を処理
.\Export-CertificateModulus.ps1 -RootDir .\old

# パスワードファイルを指定
.\Export-CertificateModulus.ps1 -RootDir . -PassFile .\passphrase.txt
```

### 6. Test-CertificateKeyMatch.ps1

証明書・秘密鍵・CSR の Modulus 一致確認レポートを生成します。

**主な機能:**
- 証明書と秘密鍵の Modulus 一致確認
- 証明書と CSR の Modulus 一致確認
- 秘密鍵と CSR の Modulus 一致確認
- 詳細レポートの生成

**使用例:**
```powershell
# old\ と new\ の両方を確認
.\Test-CertificateKeyMatch.ps1 -Mode both

# old\ のみ確認
.\Test-CertificateKeyMatch.ps1 -Mode old -PassFile .\passphrase.txt
```

### 7. New-CertificateSigningRequestFromOld.ps1

旧証明書情報から新しい CSR と秘密鍵を生成します。

**主な機能:**
- 旧証明書からの Subject と SAN の自動抽出
- 旧秘密鍵からの鍵長（RSA bits）の自動検出
- 多機関対応（機関ごとの処理）
- 対話式メニュー（複数機関がある場合）

**使用例:**
```powershell
# 対話式メニューで機関を選択
.\New-CertificateSigningRequestFromOld.ps1

# 指定機関のみ処理
.\New-CertificateSigningRequestFromOld.ps1 -Org example.com -Overwrite

# すべての機関を処理
.\New-CertificateSigningRequestFromOld.ps1 -All -PassFile .\passphrase.txt
```

## パスワードファイル

暗号化された秘密鍵を処理する場合、パスワードファイル（`passphrase.txt`）が必要です。

**パスワードファイルの探索順序:**
1. 鍵ファイルと同じディレクトリ
2. 上位階層（最大 6 階層まで）
3. 機関ディレクトリ直下
4. `old\` または `new\` のルート
5. スクリプトのルートディレクトリ
6. 環境変数 `PASS_FILE`（設定されている場合）

**注意:** パスワードファイルは対話入力を行いません。無人運用を前提としています。

## バックアップ機能

すべてのスクリプトは、既存ファイルを上書きする前に自動的にバックアップを作成します。
バックアップファイル名の形式: `<元ファイル名>.bak_<タイムスタンプ>.<拡張子>`

例: `server.key` → `server.bak_20260108_113550.key`

## セキュリティに関する注意事項

- **証明書・秘密鍵・CSR ファイルは Git にコミットされません**（`.gitignore` で除外）
- **パスワードファイル（`passphrase.txt`）も Git にコミットされません**
- これらのファイルはローカル環境でのみ管理してください
- バックアップファイルも同様に、機密情報を含む可能性があるため Git に含まれません

## トラブルシューティング

### OpenSSL が見つからない

`-OpenSsl` パラメータで OpenSSL のパスを明示指定してください。

```powershell
.\Get-CertificateInfo.ps1 -OpenSsl "C:\path\to\openssl.exe"
```

### 暗号化鍵が読み取れない

パスワードファイル（`passphrase.txt`）が正しい場所に配置されているか確認してください。
環境変数 `PASS_FILE` を設定することもできます。

```powershell
$env:PASS_FILE = "C:\path\to\passphrase.txt"
```

### 文字化けが発生する

PowerShell の出力エンコーディングを UTF-8 に設定してください。

```powershell
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
```

## ライセンス

このプロジェクトは MIT ライセンスの下で公開されています。

## 貢献

バグ報告や機能要望は、GitHub の Issues でお知らせください。

## 更新履歴

- **2026-01-08**: 初版リリース
  - 多言語対応（日本語・中国語・英語）
  - 多機関対応
  - 証明書チェーン結合機能
  - 暗号化鍵復号化機能
