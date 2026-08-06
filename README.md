# GitHub Actions NPM Vulnerability Scanner

[![Go Report Card](https://goreportcard.com/badge/github.com/hokupod/actions-npm-scanner)](https://goreportcard.com/report/github.com/hokupod/actions-npm-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Go-based CLI tool that scans GitHub Actions workflows for vulnerable NPM packages, designed as a defense against NPM poisoning attacks.

## Background

This tool was developed in response to the [Shai-Hulud supply chain attack](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised) that compromised over 40 NPM packages in late 2024, including the widely-used `@ctrl/tinycolor` package (2+ million weekly downloads).

It also includes Mini Shai-Hulud indicators tracked by Socket as of May 12, 2026, covering 405 npm artifacts and the PyPI `lightning` package versions 2.6.2 and 2.6.3.

On August 4, 2026, Socket reported an active compromise that began in the `keyv` and `cacheable` npm namespaces and spread to packages owned by other maintainers. The catalog snapshot in this repository, refreshed on August 5, 2026, includes all 2,236 npm artifacts across 444 unique npm packages listed in Socket's campaign data at that time:

- [Socket technical analysis](https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain)
- [Socket campaign tracker and affected package list](https://socket.dev/supply-chain-attacks/keyv-and-cacheable-compromise)

Socket's campaign data also listed 24 Go artifacts across 8 modules. Go module scanning is outside this tool's current scope, so those entries are not included in the catalog.

The attack demonstrated sophisticated techniques including:
- Self-propagating malware across maintainer packages
- Credential harvesting from AWS, GCP, Azure, and GitHub
- GitHub Actions backdoors for persistent access
- Exfiltration of secrets to public repositories

This scanner helps identify these specifically compromised packages in your GitHub Actions workflows, providing defense against this and similar NPM poisoning attacks that target CI/CD environments.

In late 2025, the "Second Coming" NPM contamination campaign was discovered, which is detailed in this [blog post](https://research.jfrog.com/post/shai-hulud-the-second-coming/).

## Features

- 🔍 **Comprehensive Scanning**: Scans GitHub Actions workflow files (.yml/.yaml)
- 🚨 **Vulnerability Detection**: Identifies vulnerable NPM and PyPI packages in actions
- 📦 **Curated Package List**: Contains static NPM/PyPI indicators from Shai-Hulud, Mini Shai-Hulud, and the keyv/cacheable compromise
- 🧶 **npm Lockfile Coverage**: Scans `package.json`, `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` (lockfile v5 through v9)
- 🐍 **Python Lockfile Coverage**: Scans `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, and `uv.lock`
- 📂 **Flexible Input**: Supports both single file and directory scanning
- 💻 **Local Dependency Scanning**: Scans local dependency files or directories with `--local`
- 🌳 **Recursive by Default**: Walks subdirectories so a monorepo's lockfiles are found, skipping `node_modules`, `.git`, `vendor`, `.venv`, and `venv`
- ⚡ **Fast Performance**: Leverages Go concurrency for efficient scanning
- 🌐 **Git Integration**: Automatically clones and analyzes action repositories

## Installation

### From Source

```bash
git clone https://github.com/hokupod/actions-npm-scanner.git
cd actions-npm-scanner
go build
```

### Go Install

```bash
go install github.com/hokupod/actions-npm-scanner@latest
```

### Binary Releases

Binary releases will be available on the [releases page](https://github.com/hokupod/actions-npm-scanner/releases).

## Usage

### Scan a Single Workflow File

```bash
actions-npm-scanner workflow.yml
```

### Scan All Workflows in a Directory

```bash
actions-npm-scanner .github/workflows/
```

### Scan a Local Dependency File or Directory

```bash
# Scan a single dependency file
actions-npm-scanner --local package.json

# Scan a directory and its subdirectories
actions-npm-scanner --local .

# Scan only the dependency files directly under a directory
actions-npm-scanner --local --no-recursive .
```

A directory scan descends into subdirectories, so a monorepo whose lockfiles all live under `packages/` or `apps/` is covered by scanning the repository root. `node_modules`, `.git`, `vendor`, `.venv`, and `venv` are skipped, because they hold installed third-party artifacts rather than the project's own dependency declarations — the lockfile that produced them is scanned instead. A skipped directory is still scanned when you point the command at it directly.

Findings name the subdirectory they came from and the dependency file within it, so the summary tells you which package to fix. Pointing the command at a symlinked directory scans what the link points at; symlinks below the scan root are not followed, so a dependency file only reachable through one is not scanned.

### From Source

```bash
# Scan single file
go run . workflow.yml

# Scan directory
go run . .github/workflows/

# Scan local dependency file or directory
go run . --local package.json
```

### Run Manually in GitHub Actions

Create a workflow such as `.github/workflows/actions-npm-scanner.yml` and run it from the GitHub Actions UI when you want to check referenced actions and local dependency files.

```yaml
name: Scan GitHub Actions dependencies

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan-actions:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.25.1"

      - run: go install github.com/hokupod/actions-npm-scanner@latest

      - name: Scan referenced actions
        run: actions-npm-scanner .github/workflows/

      - name: Scan local dependencies
        run: actions-npm-scanner --local .
```

If either scan finds a vulnerability, that step exits with status code `1` and the job fails. Keeping the scans in separate steps makes it easier to see whether the failure came from a referenced action or a local dependency file.

`actions-npm-scanner --local .` scans the repository root and its subdirectories, so dependency files below the root no longer need a `run` step of their own. Add `--no-recursive` to scan only the files directly under the given directory.

Add `-v` or `--verbose` to show detailed per-action and per-file scan output before the summary.

`Dependency files scanned` in the summary reports how many dependency files were actually read. A clean result with a count of `0` means nothing was examined, not that nothing was found.

A dependency file that cannot be parsed is reported as a failed file, and the remaining files in the same directory are still scanned. Failed files are counted as `Files failed` in the summary and their details are written to stderr, so a pipeline that only greps stdout cannot mistake a partial scan for a clean one. Add `--fail-on-error` to exit with status code `2` when the scan reported at least one error. That covers more than `Files failed`: an action that could not be downloaded leaves `Files failed` at zero because none of its files were reached, and it is still counted as an error.

The command scans all requested targets before exiting. If any vulnerability is found, it exits with status code `1`; otherwise it exits with `0`.

## Sample Output

### Clean Scan (No Vulnerabilities)
```
✅ No vulnerabilities found.
Workflows scanned: 1
Actions scanned: 2
Dependency files scanned: 3
Vulnerabilities found: 0
Files failed: 0
Errors: 0
```

### Vulnerabilities Found
```
⚠️ Found vulnerabilities.
Workflows scanned: 1
Actions scanned: 2
Dependency files scanned: 3
Vulnerabilities found: 1
Files failed: 0
Errors: 0
Vulnerability details:
  - .github/workflows/ci.yml | some-user/vulnerable-action@v1: Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package.json (dependencies)
```

### Vulnerabilities Found in a Subdirectory
```
⚠️ Found vulnerabilities.
Workflows scanned: 0
Actions scanned: 0
Dependency files scanned: 2
Vulnerabilities found: 1
Files failed: 0
Errors: 0
Vulnerability details:
  - ./packages/foo: Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package-lock.json
```

### Verbose Output
```
Scanning workflow: .github/workflows/ci.yml
  Downloading action actions/checkout@v4...
  🔍 Scanning action actions/checkout@v4...
    🔍 Scanning package.json...
    🔍 Scanning package-lock.json...
       yarn.lock not found. Skipping.
       pnpm-lock.yaml not found. Skipping.
    ✅ No vulnerabilities found.
  Scan finished for action actions/checkout@v4.
  Downloading action some-user/vulnerable-action@v1...
  🔍 Scanning action some-user/vulnerable-action@v1...
    🔍 Scanning package.json...
       package-lock.json not found. Skipping.
       yarn.lock not found. Skipping.
       pnpm-lock.yaml not found. Skipping.
    🔍 Scanning packages/core/package-lock.json...
    ⚠️ Found vulnerabilities:
      -  packages/core: Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package-lock.json
  Scan finished for action some-user/vulnerable-action@v1.
⚠️ Found vulnerabilities.
Workflows scanned: 1
Actions scanned: 2
Dependency files scanned: 4
Vulnerabilities found: 1
Files failed: 0
Errors: 0
Vulnerability details:
  - .github/workflows/ci.yml | some-user/vulnerable-action@v1 | packages/core: Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package-lock.json
```

## How It Works

1. **YAML Parsing**: Parses GitHub Actions workflow files to extract action references
2. **Repository Cloning**: Downloads each referenced action repository using go-git
3. **Package Analysis**: Searches the repository and its subdirectories for npm and Python dependency files
4. **Vulnerability Matching**: Compares found packages against static Shai-Hulud, Mini Shai-Hulud, and keyv/cacheable compromise indicators
5. **Reporting**: Provides detailed output on any vulnerabilities discovered

Composer/Packagist indicators such as `intercom/intercom-php@5.0.2` are tracked as a follow-up area and are not scanned in the current implementation.

## Project Structure

- **main.go**: CLI entry point and workflow orchestration
- **parser.go**: YAML workflow parsing and action extraction
- **github.go**: GitHub repository downloading using go-git
- **scanner.go**: npm and Python dependency vulnerability detection
- **vulnerable_packages.go**: Static ecosystem-specific lists of compromised packages

## Development

### Building

```bash
go build
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run specific test
go test -run TestName
```

### Dependencies

- `gopkg.in/yaml.v3`: YAML parsing
- `github.com/go-git/go-git/v5`: Git repository operations
- `github.com/Masterminds/semver/v3`: Semantic version handling

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

# 日本語 (Japanese)

## 概要

このツールは、NPM汚染攻撃に対する防御ツールとして開発された、GitHub Actionsワークフロー内の脆弱なNPMパッケージをスキャンするGo製のCLIツールです。

## 背景

このツールは、2024年後半に発生した[Shai-Hulud サプライチェーン攻撃](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)への対応として開発されました。この攻撃では、週間200万以上のダウンロード数を誇る`@ctrl/tinycolor`を含む40以上のNPMパッケージが侵害されました。

2026年5月12日時点でSocketが追跡しているMini Shai-HuludのNPM 405 artifactsと、PyPI `lightning` 2.6.2/2.6.3も検出対象に含めています。

2026年8月4日、Socketは`keyv`と`cacheable`のnpm名前空間から始まり、他のメンテナが所有するパッケージにも拡大した進行中の侵害を報告しました。このリポジトリのカタログは2026年8月5日に更新され、その時点のSocketのキャンペーンデータに掲載されていたnpm 444パッケージ、2,236 artifactsをすべて収録しています。

- [Socketの技術分析](https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain)
- [Socketのキャンペーントラッカーと影響パッケージ一覧](https://socket.dev/supply-chain-attacks/keyv-and-cacheable-compromise)

Socketのキャンペーンデータには、Go 8モジュール、24 artifactsも掲載されていました。現在このツールはGoモジュールをスキャンしないため、これらはカタログに含めていません。

この攻撃では以下のような高度な技術が使用されました：
- メンテナパッケージ間での自己増殖型マルウェア
- AWS、GCP、Azure、GitHubからの認証情報窃取
- 永続的アクセスのためのGitHub Actionsバックドア
- パブリックリポジトリへのシークレット情報の流出

このスキャナーは、GitHub Actionsワークフロー内でこれらの特定の侵害されたパッケージを識別し、CI/CD環境を標的とするNPM汚染攻撃に対する防御を提供します。

2025年後半には、「Second Coming」と呼ばれるNPM汚染キャンペーンが発見されました。詳細については、こちらの[ブログ記事](https://research.jfrog.com/post/shai-hulud-the-second-coming/)で解説されています。

## 主な機能

- 🔍 **包括的スキャン**: GitHub Actionsワークフローファイル(.yml/.yaml)をスキャン
- 🚨 **脆弱性検出**: アクション内の脆弱なNPM/PyPIパッケージを特定
- 📦 **厳選されたパッケージリスト**: Shai-Hulud、Mini Shai-Hulud、keyv/cacheable侵害のNPM/PyPI静的IoCを収録
- 🧶 **npmロックファイル対応**: `package.json`、`package-lock.json`、`yarn.lock`、`pnpm-lock.yaml`（lockfile v5〜v9）をスキャン
- 🐍 **Pythonロックファイル対応**: `requirements*.txt`、`Pipfile.lock`、`poetry.lock`、`uv.lock`をスキャン
- 📂 **柔軟な入力**: 単一ファイルとディレクトリスキャンの両方をサポート
- 💻 **ローカル依存ファイルスキャン**: `--local`でローカルの依存ファイルまたはディレクトリをスキャン
- 🌳 **デフォルトで再帰**: サブディレクトリまで辿るためモノレポのロックファイルも検出。`node_modules`、`.git`、`vendor`、`.venv`、`venv`は除外
- ⚡ **高速パフォーマンス**: Goの並行処理を活用した効率的なスキャン
- 🌐 **Git統合**: アクションリポジトリの自動クローンと分析

## インストール

### ソースから

```bash
git clone https://github.com/hokupod/actions-npm-scanner.git
cd actions-npm-scanner
go build
```

### Go Install

```bash
go install github.com/hokupod/actions-npm-scanner@latest
```

## 使用方法

### 単一ワークフローファイルのスキャン

```bash
actions-npm-scanner workflow.yml
```

### ディレクトリ内の全ワークフローのスキャン

```bash
actions-npm-scanner .github/workflows/
```

### ローカル依存ファイルまたはディレクトリのスキャン

```bash
# 単一の依存ファイルをスキャン
actions-npm-scanner --local package.json

# ディレクトリとそのサブディレクトリをスキャン
actions-npm-scanner --local .

# ディレクトリ直下の対応依存ファイルだけをスキャン
actions-npm-scanner --local --no-recursive .
```

ディレクトリを指定したスキャンはサブディレクトリまで辿ります。ロックファイルが`packages/`や`apps/`の下にしかないモノレポでも、リポジトリルートを指定すれば対象になります。`node_modules`、`.git`、`vendor`、`.venv`、`venv`は除外します。これらはプロジェクト自身の依存宣言ではなくインストール済みの第三者成果物を置く場所であり、その元になったロックファイルの方をスキャンするためです。除外対象のディレクトリを直接指定した場合は、そのままスキャンします。

検出結果には見つかったサブディレクトリと、その中の依存ファイル名が付くため、サマリを見ればどのパッケージを直せばよいかがわかります。シンボリックリンクのディレクトリを指定した場合はリンク先をスキャンします。スキャン対象より下にあるシンボリックリンクは辿らないため、リンク経由でしか到達できない依存ファイルはスキャンしません。

### ソースから実行

```bash
# 単一ファイルをスキャン
go run . workflow.yml

# ディレクトリをスキャン
go run . .github/workflows/

# ローカル依存ファイルまたはディレクトリをスキャン
go run . --local package.json
```

### GitHub Actions で手動検知する

`.github/workflows/actions-npm-scanner.yml` のようなワークフローを作成し、必要な時だけGitHub Actions画面から手動実行します。

```yaml
name: Scan GitHub Actions dependencies

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan-actions:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.25.1"

      - run: go install github.com/hokupod/actions-npm-scanner@latest

      - name: Scan referenced actions
        run: actions-npm-scanner .github/workflows/

      - name: Scan local dependencies
        run: actions-npm-scanner --local .
```

どちらかのスキャンで脆弱性が見つかると、そのステップは終了コード`1`で失敗し、ジョブも失敗します。ステップを分けているため、参照アクションとローカル依存ファイルのどちらで検知したかをActionsログ上で確認しやすくなります。

`actions-npm-scanner --local .` はリポジトリルートとそのサブディレクトリを対象にするため、ルート以外にある依存ファイルのために `run` ステップを追加する必要はありません。指定したディレクトリの直下だけを見たい場合は `--no-recursive` を付けてください。

サマリの`Dependency files scanned`は、実際に読み込んだ依存ファイルの件数です。この値が`0`のcleanは「何も見つからなかった」ではなく「1件も検査していない」を意味します。

解析できなかった依存ファイルは失敗ファイルとして記録され、同じディレクトリの残りのファイルはそのままスキャンされます。失敗したファイル数はサマリの`Files failed`に表示され、詳細はstderrに出力されます。これにより、stdoutをgrepするだけの自動化が部分的なスキャン結果をcleanと取り違えることを防げます。エラーが1件以上あった場合に終了コード`2`で終了させるには`--fail-on-error`を付けてください。対象は`Files failed`より広く、ダウンロードできなかったアクションはファイルに到達していないため`Files failed`が0のままですが、エラーとしては計上されます。

コマンドは対象を最後までスキャンしてから終了します。脆弱性が1件以上見つかった場合は終了コード`1`、見つからない場合は`0`で終了します。

## 動作原理

1. **YAML解析**: GitHub Actionsワークフローファイルを解析してアクション参照を抽出
2. **リポジトリクローン**: go-gitを使用して各参照されたアクションリポジトリをダウンロード
3. **パッケージ分析**: リポジトリとそのサブディレクトリからnpmとPythonの依存関係ファイルを検索
4. **脆弱性マッチング**: 発見されたパッケージをShai-Hulud、Mini Shai-Hulud、keyv/cacheable侵害の静的IoCカタログと比較
5. **レポート**: 発見された脆弱性について詳細な出力を提供

## 開発

### ビルド

```bash
go build
```

### テスト実行

```bash
# 全テストを実行
go test ./...

# 詳細出力で実行
go test -v ./...
```

## ライセンス

このプロジェクトはMITライセンスの下でライセンスされています - 詳細は[LICENSE](LICENSE)ファイルを参照してください。
