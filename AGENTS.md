# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## プロジェクト概要

このプロジェクトは、Shai-Hulud / Mini Shai-Hulud 系のサプライチェーン攻撃への対応として開発されたGoベースのCLIツールです。GitHub Actionsワークフローで参照されるActionリポジトリを取得し、既知の侵害済みNPM/PyPIパッケージをチェックします。

参考: https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised

## 主要コマンド

### ビルド・実行
```bash
go build                    # バイナリをビルド
go run . <path>            # ソースから直接実行（パスはワークフローファイルまたはディレクトリ）
```

### テスト
```bash
go test                    # 全テストを実行
go test -v                 # 詳細出力でテストを実行
go test ./...              # すべてのパッケージのテストを実行
go test -run TestName      # 特定のテストを実行
```

### 依存関係管理
```bash
go mod tidy               # 依存関係を整理
go mod download           # 依存関係をダウンロード
```

### リリース・インストール確認
```bash
go install github.com/hokupod/actions-npm-scanner@latest
git tag --sort=-v:refname | head
git ls-remote origin refs/heads/main refs/tags/vX.Y.Z refs/tags/vX.Y.Z^{}
```

- `go install ...@latest` は最新のsemverタグを優先するため、mainにpushしただけでは利用者の`@latest`に反映されない
- 機能追加・依存更新・検出IoC更新を配布する場合は、変更コミットに新しいsemverタグ（例: `v0.2.0`）を作成してpushする
- タグpush後は `git ls-remote` でタグのpeeled commit（`refs/tags/vX.Y.Z^{}`）が意図したコミットを指すことを確認する
- `CLAUDE.md` は `AGENTS.md` へのsymlinkとして維持し、エージェント向け手順は `AGENTS.md` に集約する

## アーキテクチャ

### 主要コンポーネント

- **main.go**: CLIエントリーポイント。コマンドライン引数を処理し、全体の処理を協調させる
- **parser.go**: GitHub Actionsワークフロー（YAML）の解析とアクション抽出
- **github.go**: GitHubからアクションリポジトリのダウンロード（go-git使用）
- **scanner.go**: 複数のパッケージマネージャ（npm、yarn、pnpm、Bun、PyPI）の依存ファイルでの脆弱パッケージ検出。ハッシュマップ最適化、resolvedフィールドからの正確なNPMバージョン抽出、bun.lockのJSONC除去、Python requirements範囲指定の検出を含む
- **vulnerable_packages.go**: Shai-Hulud / Mini Shai-Hulud攻撃で侵害されたパッケージの静的カタログ。NPM/PyPIを`VulnerabilityCatalog`で分離する
- **docs/adr/**: アーキテクチャ上の判断記録。新しい検査対象・カタログ構造・大きな設計判断を追加する場合はADRを確認/更新する

### データフロー

1. YAMLワークフローファイルを解析してアクションを抽出
2. 各アクションのGitHubリポジトリを一時ディレクトリにクローン
3. 複数のパッケージマネージャファイルを検索：
   - package.json（npm）
   - package-lock.json（npm v1/v2/v3対応、resolvedフィールドからの正確なバージョン抽出）
   - yarn.lock（yarn）
   - pnpm-lock.yaml（pnpm）
   - bun.lock（Bun 1.2以降のテキストロックファイル。JSONCのためコメントと末尾カンマを除去してから解析）
   - bun.lockb（Bunのバイナリロックファイル。フォーマット非公開のため解析せず、失敗ファイルとして報告。解析に成功したbun.lockが併存する場合のみ報告しない）
   - requirements*.txt（PyPI、範囲指定の可能性検出を含む）
   - Pipfile.lock（PyPI）
   - poetry.lock（PyPI）
   - uv.lock（PyPI）
4. ハッシュマップによる最適化された脆弱パッケージ検索
5. 結果をコンソールに出力

### 主要な型定義

- `Action`: GitHubアクション（Owner, Repo, Version, Path）
- `VulnerablePackage`: 脆弱なパッケージ（Name, Versions）
- `VulnerabilityCatalog`: エコシステム別の脆弱パッケージカタログ（NpmPackages, PypiPackages）
- `VulnerablePackageMap`: パフォーマンス最適化のためのハッシュマップ型
- `Workflow`: GitHubワークフロー構造
- `PackageJSON`, `PackageLockJSON`, `PnpmLock`, `BunLock`: 各パッケージマネージャのファイル構造

## テストサンプル

プロジェクトには`workflow.yml`サンプルファイルが含まれており、テスト実行時の動作確認に使用できます。

## 依存関係

- `gopkg.in/yaml.v3`: YAMLパース
- `github.com/go-git/go-git/v5`: Gitリポジトリクローン
- `github.com/Masterminds/semver/v3`: セマンティックバージョニング処理と範囲指定の解析

## 最近の改善点

### バージョンマッチング精度向上
- package-lock.jsonの`resolved`フィールドから実際にダウンロードされたバージョンを抽出
- セマンティックバージョン範囲指定（^, ~, >=等）の正確な処理
- プレリリース版のサポート向上

### パフォーマンス最適化
- 脆弱パッケージリストのハッシュマップ化（O(n*m) → O(n)の計算量改善）
- 各パッケージマネージャ向けの最適化されたスキャン関数

### 包括的なテストカバレッジ
- resolved版処理のテスト
- ハッシュマップ最適化のテスト
- 複数パッケージマネージャの統合テスト
- Mini Shai-HuludのNPM/PyPI IoC検出テスト

### Bunロックファイル対応
- `bun.lock`をスキャン対象に追加。JSONCのため、文字列を認識する除去処理でコメントと末尾カンマを取り除いてから`encoding/json`でデコードする（`stripJSONC`）
- tarball依存は`left-pad@https://registry.npmjs.org/...`のように記録され、文字列中に`//`が日常的に現れる。除去処理を文字列非対応にすると文書が壊れるため、正規表現による置換は使わない
- パッケージ名とバージョンは、マップのキー（`chalk/supports-color`のようなインストールパス）ではなく各エントリ先頭のdescriptorから取得する。エントリの配列は解決方法ごとに要素数と型が変わるため、先頭以外は`json.RawMessage`のまま保持する
- descriptorの分割位置は先頭以外の最初の`@`。スコープ付き名（`@ctrl/tinycolor@4.1.1`）と、userinfoを含むtarball URLの両方を正しく扱うため
- npm alias（`"tc": "npm:@ctrl/tinycolor@3.6.1"`）はキー側にalias名、descriptor側に実パッケージ名とバージョンが入る。descriptorから取ることでalias経由の侵害パッケージも検出できる
- 未知の`lockfileVersion`（`maxKnownBunLockfileVersion`超）と`packages`欠落は解析エラーにする。どちらも構造体へのデコードは成功してしまい、放置すると「0件・エラーなし」のfalse cleanになるため
- `bun.lockb`は解析せず、`actionScanResult.FileErrors`経由で失敗ファイルとして報告する。抑止するのは`bun.lock`の解析が成功したときだけで、存在だけでは抑止しない。詳細は`docs/adr/2026-08-06-scan-bun-text-lockfile-and-report-binary-lockfile.md`

### Mini Shai-Hulud対応
- 2026年5月12日時点でSocketが追跡するMini Shai-Hulud NPM 405 artifactsを静的カタログに追加
- PyPI lightning 2.6.2/2.6.3を追加
- Composer/Packagist IoCは現時点では対象外

## 使用例

```bash
# 単一ワークフローファイルをスキャン
go run . workflow.yml

# ディレクトリ内の全YAMLファイルをスキャン
go run . .github/workflows/
```
