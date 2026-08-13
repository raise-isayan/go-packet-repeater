go packet repeter
=============
Language/[English](README.md)

# gopr

`gopr` はGoで書かれたTCPもしくはUDPのパケットを中継する機能を持ちます。主に以下の機能を持ちます。

* 指定したポートで待ち受け、指定した宛先へ通信を中継する。
* 中継の途中でTLSの終端・開始(相互TLS/mTLS含む)を行う。
* 簡易HTTPプロキシおよびSOCKS5プロキシとしての機能

## 特徴

- **TCP/UDP転送**: 片方だけ、または両方同時に転送可能。
- **TLS終端**(デコード: TLS→平文)と**TLS開始**(エンコード: 平文→TLS)、および**相互TLS(mTLS)**(終端側でのクライアント証明書要求・検証、開始側でのクライアント証明書提示)。
- **`-signca=`によるMITM型TLS終端**: 秘密鍵込みのCAから、接続ごとに(SNIまたは`-servername=`で決まる)ホスト名向けのサーバ証明書をその場で生成して終端する。
- **IPv4・IPv6・ホスト名**によるアドレス指定が可能。listen側はポート番号のみの省略記法にも対応(`8888` → `0.0.0.0:8888`)。
- 転送の代わりに動作する**HTTPプロキシ**・**SOCKS5プロキシ**モード。
- `--` 区切りで**1回の起動に複数のターゲットを指定**し、単一プロセス内で並行動作させることが可能。
- TLS証明書の検証をスキップする**`-verify=0`**(自己署名証明書でのテストなどに)。
- **段階式デバッグログ(`-d`/`-dd`/`-ddd`)**と、通信内容そのものをダンプする**`-v`**。
- 設定ファイル・デーモン化なし。コマンドライン引数のみで動作する静的バイナリ1つで完結。

## インストール / ビルド

Go 1.26以上が必要。

```bash
./gradlew build     # プロジェクトのルートにビルドOSのバイナリをビルド

```

### クロスコンパイルによるリリースビルド(Gradle)

ビルドは gradlew にて行う。

```bash
./gradlew goBuildAll     # dist/ に全ターゲットをビルド
./gradlew goReleaseAll   # dist/ の各バイナリを release/ にzip化
```
## 使い方

```
gopr [option] <target> <listen>

[option]
  [-key=<path>]          ; key file
  [-cert=<path>]         ; cert file
  [-ca=<path>]           ; ca file
  [-verify=<value>]      ; verify=0 Do not verify the TLS certificate.
  [-signca=<path>]       ; CA (cert + private key) to mint a per-connection
                         ; leaf certificate for TLS termination (MITM).
  [-servername=<value>]  ; hostname for the generated certificate.
  [-d | -dd | -ddd]      ; debug output (each extra d prints)
  [-v]                   ; dump relayed data content to stderr
  [-help]                ; show help
  [-version]             ; show version
```

- 位置引数は常に `<target>` → `<listen>` の順(転送先が先、待受アドレスが後)。
- オプションは位置引数より前に、任意の順で指定する。すべて省略可能。
- `-help` / `-version` はそれぞれの出力を表示して即座に終了し、位置引数は無視される。両方同時に指定した場合は `-help` が優先される。

### 複数ターゲットの指定(`--`)

`[option] <target> <listen>` の組を `--` で区切ることで、1つの `gopr` プロセス内で複数のターゲットを同時に動作させられる。

```bash
gopr 192.0.2.11:7777 8888 -- 192.0.2.11:5555 6666
```

これは以下の2つのコマンドを同時に実行するのと同等の挙動になる。

```bash
gopr 192.0.2.11:7777 8888
gopr 192.0.2.11:5555 6666
```

### アドレス表記

| 要素 | 表記 | 例 |
|---|---|---|
| IPv4 | `host:port` | `192.0.2.11:7777` |
| IPv6 | `[host]:port` | `[2001:db8::2]:7777` |
| ホスト名(FQDN) | `hostname:port` | `example.com:7777` |
| listen側のインターフェース省略 | `port` のみ | `8888` → `0.0.0.0:8888` で待受 |

`target` は(proxy/socksモードを除き)必ずポートを含む必要がある。`listen` はホストを省略でき、その場合IPv4ワイルドカードがデフォルトになる。全IPv6インターフェース(および多くの環境ではIPv4も同時に)で待ち受けたい場合は、明示的に `[::]:port` と書く。

### プロトコルサフィックス(`/tcp`, `/udp`, `/ssl`)

`listen` の末尾に `/tcp`・`/udp`・`/ssl` を、この順序で付与する。`/tcp`・`/udp` は `listen` 側のみで有効 — gopr が対応するのはTCP→TCP、UDP→UDPの転送のみでプロトコル変換は行わないため、`target` 側に `/tcp` や `/udp` を付与するとエラーになる。何も指定しない場合のデフォルトはTCPのみ。`/ssl` は必ず暗号化を話す側に付与する(終端なら `listen`、開始なら `target`)。`/ssl` は `/tcp`・`/udp` の指定場所に関わらず `target`・`listen` どちらにも付与でき、そのリレーで有効なTCP/UDPそれぞれに作用する — TCP側はTLS、UDP側は[pion/dtls](https://github.com/pion/dtls)によるDTLSで、どちらも同じ `-cert=`/`-key=`/`-ca=` を共有する。`-signca=`(MITM)はTCP専用で、`listen`側で`/udp/ssl`が有効な場合に併用するとエラーになる。

サフィックスのキーワードは全て大文字、または全て小文字(1トークン内での混在は不可)。コマンド内のトークン間での大文字/小文字の統一は不要。

### MITM型TLS終端(`-signca=`)

`-cert=`/`-key=`の代わりに、秘密鍵込みのCAファイル(`-signca=`)を使うと、接続ごとにその場でサーバ証明書を生成してTLS終端できる。

```bash
gopr -signca=/server/ca.pem 192.0.2.11:7777 8888/ssl
```

- 生成する証明書のホスト名は、`-servername=`が指定されていれば常にそれを使い、なければ接続ごとのSNIを使う(どちらも得られない接続はエラー)。
- 鍵はRSA 2048bit、有効期間は46日。同じホスト名への証明書はプロセス内でキャッシュされる。
- `-signca=`は`-key=`/`-cert=`とは併用不可、`listen`側の`/ssl`でのみ有効(`target`側の`/ssl`とは併用不可)。`-ca=`(mTLS)とは併用できる。
- `-servername=`は`-signca=`なしでは使えない。
- `-signca=`が対応するのはTCP(TLS)終端のみで、DTLS用の証明書は生成しない。そのため`listen`側で`/udp/ssl`も有効な場合は併用不可(エラー)。UDP側のDTLSには静的な`-cert=`/`-key=`を使うこと。

## 使用例

```bash
# 全IF:8888 -> 192.0.2.11:7777 へTCPのみ転送(デフォルト)
gopr 192.0.2.11:7777 8888

# UDPのみ
gopr 192.0.2.11:7777 8888/udp

# TCP・UDP両方
gopr 192.0.2.11:7777 8888/tcp/udp

# DTLS終端: 8888/udpで受けたDTLSを復号し、平文で転送先へ
gopr -key=/server/cert.key -cert=/server/cert.pem 192.0.2.11:7777 8888/udp/ssl

# TLS+DTLS終端を同時に: TCPはTLS、UDPはDTLS、同じ証明書を共有
gopr -key=/server/cert.key -cert=/server/cert.pem 192.0.2.11:7777 8888/tcp/udp/ssl

# ホスト名の転送先、全IPv6インターフェースで待受
gopr backend.internal:7777 [::]:8888

# TLS終端: 8888で受けたTLSを復号し、平文で転送先へ
gopr -key=/server/cert.key -cert=/server/cert.pem 192.0.2.11:7777 8888/ssl

# TLS終端、証明書ファイルに秘密鍵が含まれる場合(-key=省略)
gopr -cert=/server/cert.pem 192.0.2.11:7777 8888/ssl

# TLS終端 + 相互TLS(クライアント証明書を要求・検証)
gopr -key=/server/cert.key -cert=/server/cert.pem -ca=/client/client-ca.pem \
     192.0.2.11:7777 8888/ssl

# TLS開始: 8888で平文を受け、転送先へ暗号化して送信
gopr 192.0.2.11:7777/ssl 8888

# TLS開始 + クライアント証明書提示、CAで接続先サーバーを検証
gopr -key=/client/client.key -cert=/client/client.pem -ca=/server/ca.pem \
     192.0.2.11:7777/ssl 8888

# TLS証明書の検証をスキップ(自己署名証明書など)
gopr -verify=0 192.0.2.11:7777/ssl 8888

# TLS終端 + MITM(SNIから動的に証明書生成)
gopr -signca=/server/ca.pem 192.0.2.11:7777 8888/ssl

# TLS終端 + MITM(ホスト名を固定)
gopr -signca=/server/ca.pem -servername=example.com 192.0.2.11:7777 8888/ssl

# HTTPプロキシとして8888番で待受
gopr proxy 8888

# SOCKS5プロキシとして8888番で待受
gopr socks 8888

# HTTPプロキシとして8888番で待受け、上位のHTTPプロキシ(192.0.2.11:7777)へ転送
gopr 192.0.2.11:7777/proxy 8888

# SOCKS5プロキシとして8888番で待受け、上位のSOCKSプロキシ(192.0.2.11:7777)へ転送
gopr 192.0.2.11:7777/socks 8888

# 1プロセスで2つの転送を同時に実行(上記「複数ターゲットの指定」参照)
gopr 192.0.2.11:7777 8888 -- 192.0.2.11:5555 6666

gopr -help
gopr -version
```

## オプション一覧

| オプション | 意味 | 必須/省略可否 |
|---|---|---|
| `-key=<path>` | TLS/DTLSを話す側自身の秘密鍵 | `-cert=` に秘密鍵が同梱されていれば省略可 |
| `-cert=<path>` | TLS/DTLSを話す側自身の証明書 | `/ssl` 使用時は必須 |
| `-ca=<path>` | 相手(peer)の証明書を検証するCA証明書 | 任意 — 終端側ではmTLS要求、開始側では接続先検証用CAの指定に使う。`-signca=`と併用可 |
| `-verify=<value>` | `-verify=0` でTLS証明書の検証を完全に無効化 | 任意、省略時は検証する |
| `-signca=<path>` | 証明書+秘密鍵を含むCA。接続ごとにリーフ証明書を動的生成してTLS終端(MITM) | 任意。`-key=`/`-cert=`とは併用不可、`listen`側の`/ssl`でのみ有効 |
| `-servername=<value>` | 生成する証明書のホスト名。省略時は接続ごとのSNIを使う | `-signca=`使用時のみ有効 |
| `-d` / `-dd` / `-ddd` | デバッグ出力(段階的に詳細化。`-d`=接続ライフサイクル、`-dd`=+接続詳細・バイト数、`-ddd`=+チャンク/パケット単位トレース) | 任意、省略時はエラーのみ |
| `-v` | target/listen間の通信内容そのものをstderrへダンプ(`-d`とは独立) | 任意 |
| `-help` | ヘルプを表示して終了 | — |
| `-version` | バージョンを表示して終了 | — |

## proxy / socksモード

`target` の値が、ポートを伴わない単独のリテラル `proxy` または `socks`(大文字・小文字は統一されていれば可、例: `PROXY`)と完全一致する場合、`listen` はそれぞれHTTPプロキシ・SOCKS5プロキシの待受アドレスとして扱われ、通常の転送処理は行われない。
これらのモードは `-key=`/`-cert=`/`-ca=`/`-verify=`/`-signca=`/`-servername=` や `/tcp`・`/udp`・`/ssl` サフィックスとは併用できない(`-d`/`-dd`/`-ddd`/`-v` は併用可)。

### 上位プロキシへのチェーン(`<host:port>/proxy`, `<host:port>/socks`)

`target` を `<host:port>/proxy` または `<host:port>/socks` の形で指定すると、`listen` で受けた接続を直接宛先へダイヤルせず、指定した上位プロキシ/上位SOCKSサーバー経由で中継する。上位の種別は待受モードと常に同じになる(`/proxy` は上位もHTTPプロキシ、`/socks` は上位もSOCKSサーバー)— HTTPプロキシで待受けつつ上位をSOCKSにする、といった異種の組み合わせはサポートしない。

```bash
# HTTPプロキシとして8888番で待受け、上位のHTTPプロキシ(192.0.2.11:7777)へ転送
gopr 192.0.2.11:7777/proxy 8888

# SOCKS5プロキシとして8888番で待受け、上位のSOCKSプロキシ(192.0.2.11:7777)へ転送
gopr 192.0.2.11:7777/socks 8888
```

- `<host:port>` は通常の`target`と同様に必ずポートを含む(IPv4/IPv6/ホスト名いずれも可)。
- 単独の`proxy`/`socks`キーワード(上位なし・直接ダイヤル)と同じ制約が適用される: `-key=`/`-cert=`/`-ca=`/`-verify=`/`-signca=`/`-servername=` や `/tcp`・`/udp`・`/ssl` との併用は不可、`-d`/`-dd`/`-ddd`/`-v`は併用可。
- 上位プロキシ/上位SOCKSサーバーへの認証(Basic認証・SOCKS5ユーザー名パスワード認証)およびTLS接続(HTTPSプロキシ経由)は現時点では未対応。上位サーバーは認証なし・平文接続を前提とする。
- SOCKSは現行実装と同様CONNECTのみ対応(BIND・UDP ASSOCIATE非対応)。上位への転送でもこの制約は変わらない。

## 制限事項

- **`-signca=`(MITM)はTCP専用**。UDP側のDTLS終端には常に静的な `-cert=`/`-key=` が必要。
- 「IPv4は全インターフェース、IPv6は特定アドレスのみ」のような非対称な同時待受は1つの `gopr` プロセスでは表現できない — 複数プロセスを起動すること。

