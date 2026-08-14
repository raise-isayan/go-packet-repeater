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
- **`-M -signca=`によるMITM型TLS終端**: 秘密鍵込みのCAから、接続ごとに(SNIまたは`-servername=`で決まる)ホスト名向けのサーバ証明書をその場で生成して終端する。
- **両側で独立した証明書**: 同一リレーでTLS終端・開始の両方を行う場合、`-Q`(target側)と`-Z`/`-M`(listen側)でそれぞれ別々の証明書を指定できる。
- **IPv4・IPv6・ホスト名**によるアドレス指定が可能。listen側はポート番号のみの省略記法にも対応(`8888` → `0.0.0.0:8888`)。
- 転送の代わりに動作する**HTTPプロキシ**・**SOCKS5プロキシ**モード。
- `--` 区切りで**1回の起動に複数のターゲットを指定**し、単一プロセス内で並行動作させることが可能。
- 証明書の検証をスキップする**`-verify=0`**(`-Q`/`-Z`/`-M`配下。自己署名証明書でのテストなどに)。
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
./gradlew buildAll     # dist/ に全ターゲットをビルド
./gradlew releaseAll   # dist/ の各バイナリを release/ にzip化
```
## 使い方

```
gopr [option] <target> <listen>

[option]
  [-Q <SSL>]              ; SSL client option: targetへのTLS/DTLS開始。
                          ; <target>/SSL が必要。
  [-Z <SSL>]              ; SSL server option: listenでの静的証明書による
                          ; TLS/DTLS終端。<listen>/SSL が必要。-M とは
                          ; 併用不可。
  [-M <MITM>]             ; SSL server MITM option: listenでの接続ごとに
                          ; 動的生成した証明書によるTLS終端(-Zの静的証明書
                          ; の代わり)。<listen>/SSL が必要、TCP専用。
                          ; -Z とは併用不可。
  [-d | -dd | -ddd]      ; debug output (each extra d prints)
  [-v]                   ; dump relayed data content to stderr
  [-help]                ; show help
  [-version]             ; show version

<SSL>                     ; -Q / -Z のサブオプション。順序は不問。
  [-key=<path>]           ; 自分自身の秘密鍵
  [-cert=<path>]          ; 自分自身の証明書(-Qでは省略可、-Zでは-Mを
                          ; 使わない限り必須)
  [-ca=<path>]            ; 相手の証明書を検証するCA(-Qでは接続先の検証用、
                          ; -Zではクライアント証明書を要求・検証するmTLS用)
  [-verify=<value>]       ; verify=0: -Qでは接続先証明書を検証しない。
                          ; -Zではクライアント証明書は要求するが-ca=での
                          ; 検証はしない。

<MITM>                    ; -M のサブオプション。順序は不問。
  [-signca=<path>]        ; 接続ごとにリーフ証明書を生成する、秘密鍵込みの
                          ; 署名用CA
  [-servername=<value>]   ; 生成する証明書のホスト名(省略時は接続ごとのSNI)
  [-ca=<path>]            ; -Zの-ca=と同じ(mTLS)
  [-verify=<value>]       ; -Zの-verify=と同じ
```

- 位置引数は常に `<target>` → `<listen>` の順(転送先が先、待受アドレスが後)。
- `-Q`/`-Z`/`-M` はそれぞれ高々1回だけ指定できるブロックの開始トークンで、
  続く `-key=`/`-cert=`/`-ca=`/`-verify=`(`-M`配下ではさらに`-signca=`/
  `-servername=`)は、次の`-Q`/`-Z`/`-M`または位置引数が現れるまでそのブロック
  に属する。これらのサブオプションを単独で書くことはできない(エラー)。
  `-d`/`-dd`/`-ddd`/`-v`/`-help`/`-version`はグローバルでブロックの範囲に影響
  しない。
- オプションは位置引数より前に指定する。`-Q`/`-Z`/`-M`ブロック自体は任意の順で
  よく、すべて省略可能。
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

`listen` の末尾に `/tcp`・`/udp`・`/ssl` を、この順序で付与する。`/tcp`・`/udp` は `listen` 側のみで有効 — gopr が対応するのはTCP→TCP、UDP→UDPの転送のみでプロトコル変換は行わないため、`target` 側に `/tcp` や `/udp` を付与するとエラーになる。何も指定しない場合のデフォルトはTCPのみ。`/ssl` は必ず暗号化を話す側に付与する(終端なら`listen`、`-Z`/`-M`で設定。開始なら`target`、`-Q`で設定)。`target`・`listen` の**両方**に付与することもできる(後述「二重TLS」参照)。`/ssl` は `/tcp`・`/udp` の指定場所に関わらず付与でき、そのリレーで有効なTCP/UDPそれぞれに作用する — TCP側はTLS、UDP側は[pion/dtls](https://github.com/pion/dtls)によるDTLSで、それぞれのブロック内で同じ `-key=`/`-cert=`/`-ca=` を共有する。`-M`(MITM)はTCP専用で、`listen`側で`/udp/ssl`が有効な場合に併用するとエラーになる。

サフィックスのキーワードは全て大文字、または全て小文字(1トークン内での混在は不可)。コマンド内のトークン間での大文字/小文字の統一は不要。

### 二重TLS: 両側で別々の証明書

`target`・`listen` の両方に `/ssl` を付与すると、`listen` で受けたTLS/DTLSを終端し、それとは**別の証明書設定**で `target` へ改めてTLS/DTLSを開始する(`listen`側は`-Z`/`-M`、`target`側は`-Q`でそれぞれ独立に設定)。

```bash
# 8888で受けたTLSを復号し、クライアント証明書を提示してtargetへ改めてTLS接続
gopr -Q -key=/client/client.key -cert=/client/client.pem -ca=/server/ca.pem \
     -Z -key=/server/cert.key -cert=/server/cert.pem \
     192.0.2.11:7777/ssl 8888/ssl
```

`-Q` は省略してもよく、その場合target側はクライアント証明書なし・システムのルートCAプールでの検証というデフォルト設定でTLSを開始する。

### MITM型TLS終端(`-M`)

`-Z -cert=`/`-key=`の代わりに、秘密鍵込みのCAファイル(`-M -signca=`)を使うと、接続ごとにその場でサーバ証明書を生成してTLS終端できる。

```bash
gopr -M -signca=/server/ca.pem 192.0.2.11:7777 8888/ssl
```

- 生成する証明書のホスト名は、`-servername=`が指定されていれば常にそれを使い、なければ接続ごとのSNIを使う(どちらも得られない接続はエラー)。
- 鍵はRSA 2048bit、有効期間は46日。同じホスト名への証明書はプロセス内でキャッシュされる。
- `-M`は`-Z`とは併用不可(同じlistenに対する証明書の出所が静的/動的で競合するため)。`-Q`(target側の二重TLS)や`-ca=`/`-verify=`(mTLS)とは併用できる。
- `-servername=`は`-signca=`なしでは使えない。
- `-M`が対応するのはTCP(TLS)終端のみで、DTLS用の証明書は生成しない。そのため`listen`側で`/udp/ssl`も有効な場合は併用不可(エラー)。UDP側のDTLSには`-Z`で静的な`-cert=`/`-key=`を使うこと。

## 使用例

```bash
# 全IF:8888 -> 192.0.2.11:7777 へTCPのみ転送(デフォルト)
gopr 192.0.2.11:7777 8888

# UDPのみ
gopr 192.0.2.11:7777 8888/udp

# TCP・UDP両方
gopr 192.0.2.11:7777 8888/tcp/udp

# DTLS終端: 8888/udpで受けたDTLSを復号し、平文で転送先へ
gopr -Z -key=/server/cert.key -cert=/server/cert.pem 192.0.2.11:7777 8888/udp/ssl

# TLS+DTLS終端を同時に: TCPはTLS、UDPはDTLS、同じ証明書を共有
gopr -Z -key=/server/cert.key -cert=/server/cert.pem 192.0.2.11:7777 8888/tcp/udp/ssl

# ホスト名の転送先、全IPv6インターフェースで待受
gopr backend.internal:7777 [::]:8888

# TLS終端: 8888で受けたTLSを復号し、平文で転送先へ
gopr -Z -key=/server/cert.key -cert=/server/cert.pem 192.0.2.11:7777 8888/ssl

# TLS終端、証明書ファイルに秘密鍵が含まれる場合(-key=省略)
gopr -Z -cert=/server/cert.pem 192.0.2.11:7777 8888/ssl

# TLS終端 + 相互TLS(クライアント証明書を要求・検証)
gopr -Z -key=/server/cert.key -cert=/server/cert.pem -ca=/client/client-ca.pem \
     192.0.2.11:7777 8888/ssl

# TLS開始: 8888で平文を受け、転送先へ暗号化して送信(クライアント証明書不要)
gopr 192.0.2.11:7777/ssl 8888

# TLS開始 + クライアント証明書提示、CAで接続先サーバーを検証
gopr -Q -key=/client/client.key -cert=/client/client.pem -ca=/server/ca.pem \
     192.0.2.11:7777/ssl 8888

# TLS証明書の検証をスキップ(自己署名証明書など)
gopr -Q -verify=0 192.0.2.11:7777/ssl 8888

# TLS終端 + MITM(SNIから動的に証明書生成)
gopr -M -signca=/server/ca.pem 192.0.2.11:7777 8888/ssl

# TLS終端 + MITM(ホスト名を固定)
gopr -M -signca=/server/ca.pem -servername=example.com 192.0.2.11:7777 8888/ssl

# TLS終端 + TLS開始を別々の証明書で(二重TLS)
gopr -Q -key=/client/client.key -cert=/client/client.pem -ca=/server/ca.pem \
     -Z -key=/server/cert.key -cert=/server/cert.pem \
     192.0.2.11:7777/ssl 8888/ssl

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
| `-Q` | SSL clientブロックを開始: targetへのTLS/DTLS開始 | 任意。指定時は`<target>/SSL`が必要 |
| `-Z` | SSL serverブロックを開始: listenでの静的証明書によるTLS/DTLS終端 | 任意。指定時は`<listen>/SSL`が必要。`-M`とは併用不可 |
| `-M` | SSL server MITMブロックを開始: listenでの動的生成証明書によるTLS終端 | 任意。指定時は`<listen>/SSL`が必要、TCP専用。`-Z`とは併用不可 |
| `-key=<path>`(`-Q`/`-Z`配下) | その側自身の秘密鍵 | `-cert=` に秘密鍵が同梱されていれば省略可 |
| `-cert=<path>`(`-Q`/`-Z`配下) | その側自身の証明書 | `-Q`では任意、`-Z`では`-M`を使わない限り必須 |
| `-ca=<path>`(`-Q`/`-Z`/`-M`配下) | 相手(peer)の証明書を検証するCA証明書 | 任意 — `-Q`では接続先検証用、`-Z`/`-M`ではクライアント証明書を要求・検証(mTLS) |
| `-verify=<value>`(`-Q`/`-Z`/`-M`配下) | `verify=0`: `-Q`では接続先証明書を検証しない。`-Z`/`-M`ではクライアント証明書は要求するが`-ca=`での検証をしない | 任意、省略時は検証する |
| `-signca=<path>`(`-M`配下) | 証明書+秘密鍵を含むCA。接続ごとにリーフ証明書を動的生成 | `-M`使用時は必須 |
| `-servername=<value>`(`-M`配下) | 生成する証明書のホスト名。省略時は接続ごとのSNIを使う | `-signca=`使用時のみ有効 |
| `-d` / `-dd` / `-ddd` | デバッグ出力(段階的に詳細化。`-d`=接続ライフサイクル、`-dd`=+接続詳細・バイト数、`-ddd`=+チャンク/パケット単位トレース) | 任意、省略時はエラーのみ |
| `-v` | target/listen間の通信内容そのものをstderrへダンプ(`-d`とは独立) | 任意 |
| `-help` | ヘルプを表示して終了 | — |
| `-version` | バージョンを表示して終了 | — |

## proxy / socksモード

`target` の値が、ポートを伴わない単独のリテラル `proxy` または `socks`(大文字・小文字は統一されていれば可、例: `PROXY`)と完全一致する場合、`listen` はそれぞれHTTPプロキシ・SOCKS5プロキシの待受アドレスとして扱われ、通常の転送処理は行われない。
これらのモードは `-Q`/`-Z`/`-M`(およびそのサブオプション)や `/tcp`・`/udp`・`/ssl` サフィックスとは併用できない(`-d`/`-dd`/`-ddd`/`-v` は併用可)。

### 上位プロキシへのチェーン(`<host:port>/proxy`, `<host:port>/socks`)

`target` を `<host:port>/proxy` または `<host:port>/socks` の形で指定すると、`listen` で受けた接続を直接宛先へダイヤルせず、指定した上位プロキシ/上位SOCKSサーバー経由で中継する。上位の種別は待受モードと常に同じになる(`/proxy` は上位もHTTPプロキシ、`/socks` は上位もSOCKSサーバー)— HTTPプロキシで待受けつつ上位をSOCKSにする、といった異種の組み合わせはサポートしない。

```bash
# HTTPプロキシとして8888番で待受け、上位のHTTPプロキシ(192.0.2.11:7777)へ転送
gopr 192.0.2.11:7777/proxy 8888

# SOCKS5プロキシとして8888番で待受け、上位のSOCKSプロキシ(192.0.2.11:7777)へ転送
gopr 192.0.2.11:7777/socks 8888
```

- `<host:port>` は通常の`target`と同様に必ずポートを含む(IPv4/IPv6/ホスト名いずれも可)。
- 単独の`proxy`/`socks`キーワード(上位なし・直接ダイヤル)と同じ制約が適用される: `-Q`/`-Z`/`-M`(およびそのサブオプション)や `/tcp`・`/udp`・`/ssl` との併用は不可、`-d`/`-dd`/`-ddd`/`-v`は併用可。
- 上位プロキシ/上位SOCKSサーバーへの認証(Basic認証・SOCKS5ユーザー名パスワード認証)およびTLS接続(HTTPSプロキシ経由)は現時点では未対応。上位サーバーは認証なし・平文接続を前提とする。
- SOCKSは現行実装と同様CONNECTのみ対応(BIND・UDP ASSOCIATE非対応)。上位への転送でもこの制約は変わらない。

## 制限事項

- **`-M`(MITM)はTCP専用**。UDP側のDTLS終端には常に`-Z`で静的な `-cert=`/`-key=` が必要。
- 「IPv4は全インターフェース、IPv6は特定アドレスのみ」のような非対称な同時待受は1つの `gopr` プロセスでは表現できない — 複数プロセスを起動すること。

