# Utility-secutiry

セキュリティ関係のユーティリティ
（ISO27001対応作業の省力化等）

## インストール

動作確認環境
- Ubuntu Linux 24.04
- JDK 23
- Apache Maven 3.9.9

JDKおよびMavenのインストール方法は例えば以下のURLを参照(SDKMAN!で入れると簡単)
https://sc.ddbj.nig.ac.jp/guides/software/DevelopmentEnvironment/java/

コマンドラインの解析には `com.scivicslab:pluggable-cli` を使う。
これはMaven Centralに登録されているので、事前に手元でビルドする作業は要らない。

以前は `com.github.oogasawa:Utility-cli` の 3.1.0 に依存していたが、
このバージョンはMaven Centralにも `v3.1.0` タグにも存在せず(タグのpom.xmlは3.0.0を宣言している)、
依存を解決できずビルドが止まる状態だった。

## ビルド方法

``` 
git clone https://github.com/oogasawa/Utility-security
cd Utility-security
rm -rf target && mvn package
```

`mvn clean` は効かないため、ビルド前に `rm -rf target` を実行する。

これにより`Utility-security/target/Utility-security-VERSION.jar`という名前で
fat-jarファイル(依存ライブラリがすべて入った単一のjarファイル)が作られる。

この単一のfat-jarファイルだけあれば以下の実行が可能。(必要に応じて適当な場所にコピーするなどして使用する。)


## 使用方法

引数なしで実行すると使い方が表示される。

``` bash
$ java -jar target/Utility-security-1.6.0.jar

## Usage

java -jar Utility-security-<VERSION>.jar <command> <options>


## Log utilities

log:rename      Rename and relocate collected log files.


## Ubuntu security commands

ubuntu:append-xlsx  Add a report to the patch history workbook, writing a new file.
ubuntu:fetch-digest Fetch ubuntu-security-announce digests from Gmail within the date range.
ubuntu:livepatch-report Create a report of Kernel Live Patch Security Notices in TSV format.
ubuntu:report   Create a report of Ubuntu Security Notices in TSV or JSON format.
```

### `ubuntu:report`コマンド

対応が必要なUbuntu Security Noticeを選び出し、タブ区切り形式(TSV)またはJSONで出力する。
データはUbuntu Security APIから直接取得するので、メーリングリストへの登録も、
届いたメールを1つのファイルに連結する作業も要らない。

#### 期間を指定して実行する

``` bash
java -jar target/Utility-security-1.6.0.jar ubuntu:report \
  --start 2026-08-24 --end 2026-08-31 | tee ubuntu-security.2026W35.tsv
```

| オプション | 意味 |
|---|---|
| `-S`, `--start` | 取得する公開日の下限(その日を含む)。ISO形式(`YYYY-MM-DD`)。 |
| `-E`, `--end` | 取得する公開日の上限(その日を含む)。ISO形式。 |
| `-r`, `--release` | 対象とするUbuntuリリースのコードネーム。既定は`noble`(24.04 LTS)。 |
| `-f`, `--format` | 出力形式(`tsv`または`json`)。既定は`tsv`。 |
| `-i`, `--infile` | Ubuntu Security APIの代わりに、連結済みのメールを入力とする(後述)。 |

標準出力にTSV形式のデータが、標準エラー出力に実行時のログが出力される。

実行例

``` bash
$ java -jar target/Utility-security-1.6.0.jar ubuntu:report --start 2026-04-01 --end 2026-09-01
INFO c.g.o.u.s.u.UsnApiFetcher  Requesting notices 1 to 20 for release noble
INFO c.g.o.u.s.u.UsnApiFetcher  Fetched 418 notices for release noble between 2026-04-01 and 2026-09-01
INFO c.g.o.u.s.u.USNJsonExporter Merged 364 notices into 337 by their USN number
INFO c.g.o.u.s.u.USNJsonExporter Final entries after keeping only the kernels in use: 337
INFO c.g.o.u.s.u.USNJsonExporter storedPriority: Medium, CVE-2026-33056
INFO c.g.o.u.s.u.USNJsonExporter rawPriority: High, CVE-2026-43406
INFO c.g.o.u.s.u.USNJsonExporter Assigned severity 'Critical' to USN-8574-2 based on 913 CVEs, 12 of them High or above
... 以下略
```

実行結果

```
id	title	published_date	summary	severity	reboot	livepatch	severe_cves
USN-8138-1	Vim vulnerability	2026-04-01	Vim could be made to crash.	Medium	no	NA	
USN-8147-1	libarchive vulnerabilities	2026-04-02	Several security issues were fixed in libarchive.	Medium	no	NA	
USN-8155-1	Linux kernel vulnerabilities	2026-04-06	Several security issues were fixed in the Linux kernel.	High	yes	no	CVE-2026-21823
```

2026-04-01から2026-09-01までのUbuntu Security Noticeは344件で、
severityの内訳はCritical 16、High 35、Medium 279、Low 7、`NoCve` 7である。

#### 実行にかかる時間

ubuntu.comへの要求は10秒以上の間隔を空けて出す。
間隔を空けずに要求を連続して出すと、サーバはHTTP 503を返し、
やがてそのホストからの要求そのものに応答しなくなる。
このため要求間隔は`UbuntuSecurityHttpClient`に組み込んであり、短縮するオプションは設けていない。

5か月分(Ubuntu Security Notice 344件)を、保存済みのUbuntu priorityが無い状態から作ると、
CVEを3400件あまり取得することになり、19時間かかった。
保存済みのUbuntu priorityが揃っていれば、同じ期間が5分前後で終わる。

要求が失敗した場合は最大10回まで試し、待ち時間を1回ごとに10秒ずつ延ばす。

| 試行回数 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| 待ち時間(秒) | 10 | 20 | 30 | 40 | 50 | 60 | 70 | 80 | 90 | 100 |

10回を使い切ると待ち時間の合計は550秒になる。
待ち時間を長く取るのは、機械の時間と人の時間のどちらを使うかの選択だからである。
報告書の作成に一晩かかっても、それを待っている人はいない。
一方、Ubuntu priorityが取れなかったCVEは人が手で調べることになり、
その手間は報告書を作るたびに発生する。

応答を待つ上限は120秒である。30秒にしていたときは、失敗51回のうち39回が読み取りの打ち切りだった。
120秒にすると打ち切りは0回になり、失敗はすべてサーバが返すHTTP 503とHTTP 504になった。
つまり待ちきれずに諦めていた分は無くなった。

#### CVE 1件あたりの実測値

1073件の新規取得に6.6時間かかった。取得できた割合は次のとおりで、
数え方によって値が大きく違うので、どれを指しているかを明示する。

| 数え方 | 値 |
|---|---|
| CVE単位(Ubuntu priorityが取れたCVE / 取得を試みたCVE) | 1073 / 1075 = 99.8% |
| 要求単位(応答が返った要求 / 全要求) | 1206 / 1753 = 69% |

運用上意味を持つのはCVE単位である。目的はUbuntu priorityを得ることで、
そのために何回要求したかは手段だからである。
4回に1回の要求が失敗していても、失敗した要求は再試行され、
そのほとんどが次かその次で成功するので、CVEそのものはほぼ全部取れる。

#### 応答は必要なところまで読んで打ち切る

CVEのページは約85キロバイトあり、Ubuntu priorityはその25%の位置(21217バイト目)にある。
1行ずつ読み、優先度アイコンが見つかった行で読むのをやめる。

以前は応答本体を全部読んでから探していた。この形だと、優先度が届いた後の残り75%の受信中に
制限時間を超えると、手元にある答えを捨てて失敗として扱ってしまう。

#### CVEのpriorityはJSONエンドポイントからは取れない

Ubuntu Security APIは同じ値を`/security/cves/<CVE番号>.json`の`priority`フィールドでも公開しているが、
このエンドポイントは長時間にわたってHTTP 503とHTTP 504を返す。
同じ`CVE-2026-66484`について、JSONが10回の試行すべてに失敗している間、
`https://ubuntu.com/security/CVE-2026-66484`のページはHTTP 200を即座に返した。
このためpriorityはページから読む。

#### severityの決め方

Ubuntuが重要度を付ける対象は個々のCVEであって、Ubuntu Security Noticeではない。
このコマンドはUbuntu Security Noticeが参照する全CVEのUbuntu priorityを取得し、
その最大値をそのUbuntu Security Noticeのseverityとする。

| severity | 意味 | 読み手が取る行動 |
|---|---|---|
| `Low` `Medium` `High` `Critical` | 参照する全CVEのUbuntu priorityのうち最大のもの | 値に応じて対応する |
| `LookupFailed` | いずれかのCVEのUbuntu priorityを取得できなかった | 報告書が不完全である。手で確認する |
| `Unrated` | 参照するCVEのどれにもUbuntuが順位を付けていない | Ubuntu側の判定待ちである |
| `NoCve` | CVEが1件も割り当てられていない | CVE以外の情報(Launchpadのバグ等)を見る |

順位の付かないCVEが混ざっていても、順位の付いたCVEが1件でもあれば、その最大値を書く。
Ubuntuが各CVEを見た上で一部をまだ判定していないだけであり、
判定済みの順位は報告に値する事実だからである。
Criticalと分かっているCVEを含むUbuntu Security Noticeは、
未判定のCVEが何であろうとCriticalである。

`LookupFailed`だけは扱いが違う。こちらが取得できなかった場合であり、
そのCVEのUbuntu priorityが何であるかを一切知らない。
順位の付いたCVEがあっても、取得できなかったCVEがそれより深刻でないとは言えないので、
最大値は書かず`LookupFailed`とする。

#### severe_cves列

Ubuntu priorityがHigh以上のCVE番号を空白区切りで並べる。
severityは最悪の値がいくつかを示すが、それがどのCVEかを示さない。
今夜対応するか次の定期メンテナンスまで待つかを判断する読み手は、
その深刻なCVEを調べる必要がある。

#### CVEの取得を途中で打ち切らない

1件のCVEが取得できなくても、そのUbuntu Security Noticeが参照する残りのCVEを最後まで取得する。

以前は最初に取得できなかったCVEの時点で打ち切っていた。
その時点でそのUbuntu Security Noticeのseverityは`LookupFailed`と決まるので、
残りを引く意味がないという理由だった。
これは目の前の実行では要求を節約するが、次回以降により大きな代償を払う。
一度取得したUbuntu priorityは保存され二度と要求しないので、
到達しなかったCVEは次回の実行でも取得されないままである。
1件で数百のCVEを参照するカーネルのUbuntu Security Noticeでこれが起きると、
次の実行も同じ場所で打ち切られ、何度流しても先へ進まない。
実際に1回の実行で16件のUbuntu Security Noticeがこの状態になり、
1074件のCVEが未取得のまま残った。

#### Ubuntu Security Noticeの一覧の保存

一度読んだUbuntu Security Noticeは`$HOME/.cache/Utility-security/notices-<リリース名>.jsonl`に
1行1件のJSONとして保存し、次回以降は要求を出さずに読む。

`/security/notices.json`は期間で絞れないので、古い日付を指定すると
それより新しい分を全部めくることになる。
2025年8月まで遡る実行では、一覧の取得だけで146回の要求を出し、24分かかった。
Ubuntu Security Noticeの内容は公開後に変わらない(訂正は別のUSN番号で公開される)ので、
CVEのpriorityと同じく保存できる。

保存があっても毎回、新しい方のページから読む。
1ページ分が全て保存済みで、かつ保存済みの範囲が指定した期間の開始日まで届いていれば、
そこで読むのをやめる。前回の実行以降に公開されたものはこの方法で拾える。
保存済みの範囲が開始日に届いていなければ、従来どおり開始日まで遡る。

1ページ届くごとに追記するので、途中で止めてもそれまでに読んだ分は残る。
ファイルを消せば次回は全ページを読み直す。

#### CVEのpriorityの保存

一度取得したCVEのpriorityは次のファイルに保存し、次回以降は要求を出さずに読む。

```
$HOME/.cache/Utility-security/cve-priority.tsv
```

CVE識別子とpriorityをタブ区切りで並べた表で、CVE識別子で整列してある。
同じCVEは複数の記事から参照され、翌週以降の報告書にも現れるので、
保存しておくと実行時間が大きく縮む。
このファイルを削除すると、次回の実行で全てのCVEを取得し直す。

保存するのは`Low` `Medium` `High` `Critical`の4つだけである。
Ubuntuが順位を付けていないCVEや、取得に失敗したCVEは保存しない。
前者は後から順位が付くことがあり、保存すると新しい判定を二度と見なくなるためである。

#### 表に載せるUbuntu Security Noticeの選び方

`--release`で指定したUbuntuリリースに該当するものだけを、Ubuntu Security APIの側で絞り込む。

その上で、対象の計算機が使っているカーネル以外のUbuntu Security Noticeを除く。
残すのは、タイトルがカーネルのflavourを名乗らないもの(汎用カーネル)と、
括弧の中身が`NVIDIA`と完全に一致するものだけである。
`NVIDIA Tegra`や`Low Latency NVIDIA`は別のカーネルなので残さない。

残すflavourを列挙する方式にしてある。除外する語を並べる方式だと、
Canonicalがflavourを追加するたびに漏れる。
実際に`Oracle`・`FIPS`・`HWE`・`Xilinx`・`GCP`・`Low Latency`の17件が漏れて表に載っていた。

Ubuntu Security APIは、Kernel Live Patch Security Notice(`LSN-`で始まるもの)を
Ubuntu Security Noticeと同じ一覧に入れて返す。このコマンドは`type`が`USN`のものだけを残す。

#### 同じUSN番号のものを1行にまとめる

Canonicalは同じ修正をカーネルのflavourごと・Ubuntuリリースごとに出し直し、
同じUSN番号に異なる枝番を付ける(`USN-8643-1`と`USN-8643-5`)。
記録簿は修正1件につき1行なので、同じUSN番号のものは1行にまとめる。

代表にするのは、タイトルがカーネルのflavourを名乗らないもののうち最も古く公開されたものである。
`USN-8574-1`が`Linux kernel (GCP FIPS)`で`-2`と`-3`が汎用の場合、`-2`を代表とする。
古い方を機械的に選ぶと、汎用の修正がGCP FIPSの見出しで記録されてしまう。
まとめられた側のCVEと対象リリースは代表に足し込むので、severityの判断材料は失われない。

#### 並び順

公開日の昇順に並べる。記録簿が古い順に読める形になっているためである。
Ubuntu Security APIは新しい順に返すので、出力前に並べ替える。
同じ日に公開されたものはUSN番号の順にする。同じ期間を2回実行しても同じ並びになる。

#### アーカイブしたメールから作る

過去に受信して保存してあるメールから報告書を作る場合は`--infile`を渡す。
この経路はメール本文を解析し、更新方法はUSNのHTMLページから取得する。
このHTMLページへの要求も`UbuntuSecurityHttpClient`を通るので、同じ10秒間隔が適用される。
記事1件につき1回の要求が出るため、こちらも記事の件数に応じて時間がかかる。

``` bash
java -jar target/Utility-security-1.6.0.jar ubuntu:report -i ubuntu-security.2505A.txt | tee 2505A.tsv
```

#### ヘルプの表示

`-h`を付けるとエラー行が1行出た後にヘルプが表示される。

``` bash
$ java -jar target/Utility-security-1.6.0.jar ubuntu:report -h
Error: Failed to parse the command. Reason: Unrecognized option: -h
See the help below for correct usage:
Usage:
  usage: ubuntu:report [-E <YYYY-MM-DD>] [-f <format>] [-i <infile>] [-r <codename>] [-S <YYYY-MM-DD>]
...
```

先頭のエラー行は`pluggable-cli` 1.0.0の挙動である。
`-h`を受け取った時点でオプションの解析を打ち切る修正は、`pluggable-cli`側の未公開の変更として存在する。

### `ubuntu:livepatch-report`コマンド

Kernel Live Patch Security Noticeを1件1行で出力する。
無停止でカーネルを修正できるかどうかを判断するための表である。

``` bash
java -jar target/Utility-security-1.6.0.jar ubuntu:livepatch-report \
  --start 2026-04-01 --end 2026-09-01 --release noble | tee livepatch.2026.tsv
```

```
id	published_date	summary	severity	flavours	patch_version	kernel_version	cve_count	severe_cves
LSN-0119-1	2026-04-13	Several security issues were fixed in the kernel.	High	linux	119.1	6.8.0-1	8	CVE-2025-21704 ...
LSN-120-1	2026-06-01	Several security issues were fixed in the kernel.	High	linux	120.2	6.8.0-1	3	CVE-2026-31431 ...
LSN-0121-1	2026-08-27	Several security issues were fixed in the kernel.	Critical	linux	121.7	6.8.0-1	34	CVE-2026-43406 ...
```

| 列 | 意味 |
|---|---|
| `flavours` | 無停止修正が出ているカーネルのflavourのうち、対象の計算機が使っているもの |
| `patch_version` | live patch自体の版 |
| `kernel_version` | 適用先のカーネルの版 |
| `cve_count` | そのKernel Live Patch Security Noticeが直すCVEの件数 |

`flavours`が空の行は、そのlive patchが対象の計算機のカーネルを含んでいないことを示す。

2026年4月から9月のnobleでlive patchが出ているflavourは
`aws` `azure` `gcp` `gke` `ibm` `linux` `oracle`の7つで、`nvidia`は1件も出ていない。
NVIDIAカーネルを使う計算機は、カーネル更新のたびに再起動が要る。

Canonicalはこれを2か月に1回ほどまとめて出す。
同じ期間のカーネル向けUbuntu Security Noticeが29件あるのに対し、
Kernel Live Patch Security Noticeは3件である。

`ubuntu:report`が出力する`livepatch`列とは別のものである。
`livepatch`列は各Ubuntu Security Noticeの更新方法の文に
`canonical livepatch is available`という文字列があるかどうかで判定するが、
Canonicalはこの文言を削除しており、2025年5月以降`yes`が1件も出ていない。

### `ubuntu:append-xlsx`コマンド

`ubuntu:report`または`ubuntu:livepatch-report`が出したTSVを、
記録簿`【C-19】セキュリティパッチ対策履歴.xlsx`のシートへ追記する。

``` bash
java -jar target/Utility-security-1.6.0.jar ubuntu:append-xlsx \
  --infile report_2026.tsv \
  --xlsx  "【C-19】セキュリティパッチ対策履歴.xlsx" \
  --outfile "【C-19】セキュリティパッチ対策履歴_2026追記.xlsx" \
  --sheet 2026 --kind usn
```

| オプション | 意味 |
|---|---|
| `-i`, `--infile` | 追記するTSV |
| `-x`, `--xlsx` | 読み込む記録簿。書き換えない |
| `-o`, `--outfile` | 書き出すファイル。`--xlsx`と同じパスは受け付けない |
| `-s`, `--sheet` | 追記先のシート。無ければ作る |
| `-k`, `--kind` | `usn`または`livepatch`。既定は`usn` |

**このコマンドは読み込んだファイルを書き換えない。** `--xlsx`で指定した記録簿を開き、
行を足した別のファイルを`--outfile`へ書き出す。同じパスを両方に指定すると受け付けない。
原本を置き換えるかどうかはこのコマンドの外で決める。
`bin/update-patch-history.sh`はこれを毎回控えを取ってから置き換える(後述)。

記録簿のどこかに既に載っているUSN番号・LSN番号は書かない。二度実行しても増えない。

ただし`severity`が`LookupFailed`の行は書き直す。
この値はUbuntu Security Noticeについての事実ではなく、
ubuntu.comが応答しなかったという実行時の事情を記録したものだからである。
書き直すのはプログラムが埋める8列だけで、人が埋める9列には触れない。
`LookupFailed`以外のseverityを持つ行は、値が変わっていても書き直さない。

作ったシートには`2025`シートと同じ書式を設定する。
見出し行の固定、列幅、フォント(Arial)、見出しの色(プログラムが埋める列は緑`93C47D`、
人が埋める列は橙`FCE5CD`)、対策日欄の`yyyy-mm-dd`表示形式である。
全セルを上揃えかつ文字列の折り返し表示にする。
`summary`が数行になる行で、隣の短いセルの文字が下端に沈むのを避けるためである。

人が埋める9列(対策内容・対策日・確認完了日・確認者・備考)は空のままにする。

### 定期実行

`bin/update-patch-history.sh`は、上の3つのコマンドを順に実行して記録簿そのものを更新する。
cronから週に1回呼ぶことを想定している。

``` bash
$ crontab -l
30 10 * * 5 /home/devteam/works/Utility-security/bin/update-patch-history.sh
```

金曜の午前に実行する。月曜にセキュリティの報告をするので、その前に記録簿が揃っている必要がある。
午前にするのは、ubuntu.comの応答が日中の方が速いことが多く、失敗しても金曜のうちに再試行が終わるためである。
ただし終日遅い日もあり、日中であることは速さを保証しない。

1回の実行は次の4つの状態を順に通る。
どの状態で失敗しても記録簿は元のままである。

| 状態 | 意味 |
|---|---|
| Alone | ロックを取得した。他の実行が走っていない |
| Reported | 2つの報告書をTSVとして書き終えた |
| Candidate | 新しい行を持つ記録簿の複製が、記録簿の隣にできた |
| Recorded | 元の記録簿を控えの置き場へ移し、複製を記録簿の位置に置いた |

対象期間は実行日から30日前までとする。
実行が失敗した週の分を次の実行が拾うためであり、
既に載っている番号は書かないので期間が重なっても行は増えない。
1月の実行では開始日を1月1日に切り上げる。前年に公開されたものは前年のシートに載るからである。

| ファイル | 位置 |
|---|---|
| 記録簿 | `$HOME/Downloads/【C-19】セキュリティパッチ対策履歴.xlsx` |
| 実行記録 | `$HOME/logs-security/patch-history/update-patch-history.log` |
| 報告書のTSV | `$HOME/logs-security/patch-history/usn-<日時>.tsv`, `lsn-<日時>.tsv` |
| 置き換える前の記録簿 | `$HOME/logs-security/patch-history/backup/`に12世代 |

記録簿の位置は環境変数`PATCH_HISTORY_RECORD`で、
jarの位置は`UTILITY_SECURITY_JAR`で、対象リリースは`UBUNTU_RELEASE`で変えられる。

次の場合は記録簿を置き換えずに終わる。

- 他の実行がロックを持っている(何もせず終了ステータス0で終わる)
- `ubuntu:report`が見出し行を書かなかった。引数が受け付けられなかった場合である
- 30日間のUbuntu Security Noticeが0件だった。Canonicalは週に数件公開するので、
  0件は「公開が無かった」ではなく「読めなかった」を意味する
- 書き出した複製が元の記録簿より小さい。行は増える一方なので、小さいのは何かを失っている

Kernel Live Patch Security Noticeは数週間に1件なので、30日間で0件でも実行を続ける。

**記録簿の`表紙・文書履歴`シートは書き換えない。**
バージョンと最終更新日の記入は人が行う。

### Ubuntu Security APIに到達できるかの確認

`UbuntuSecurityApiLiveCheck`は、報告書が使う2つのエンドポイントに1回ずつ要求を出し、
応答が返るかを確かめるプログラムである。ユニットテストではないので`mvn test`では実行されない。
外部サービスへの要求をビルドのたびに出さないためである。

``` bash
$ java -cp target/Utility-security-1.6.0.jar \
    com.github.oogasawa.utility.security.usn.UbuntuSecurityApiLiveCheck
notices endpoint: USN-8643-5, published 2026-08-27T21:29:15.524720, type USN, 4 CVEs
cve endpoint: CVE-2025-4207 has priority Medium
PASS: both endpoints of the Ubuntu Security API answered.
```

両方のエンドポイントが応答すれば終了ステータス0、そうでなければ1を返す。

### `ubuntu:fetch-digest`コマンド

`ubuntu-security-announce Digest, Vol...` のメールを Gmail の IMAP から取得し、指定した期間の本文を 1 つのテキストファイルにまとめる。週次でまとめ作業を自動化したい場合に利用する。

1. Gmail アカウントでアプリパスワードを発行し、以下の環境変数を設定する。

   ```bash
   export GMAIL_USERNAME='youraccount@gmail.com'
   export GMAIL_APP_PASSWORD='16桁のアプリパスワード'
   ```

2. 取得したい期間（ISO 形式の日付）と出力ファイルを指定して実行する。

   ```bash
   java -jar target/Utility-security-1.6.0.jar ubuntu:fetch-digest \
     --start 2025-05-01 --end 2025-05-07 \
     --outfile ~/logs-security/ubuntu-security.2025W18.txt
   ```

   - `--start`, `--end`: 期間の開始・終了日。`--end` は `--start` 以上の日付で指定する。
   - `--outfile`: 連結結果を書き出すテキストファイル。既に存在する場合は上書きされる。
   - 取得対象は送信元 `security-announce@lists.ubuntu.com` かつ件名に `ubuntu-security-announce Digest, Vol` を含むメールのみ。


## 更新履歴

v1.0.0
- ubuntu:reportコマンドで、Ubuntu 24.04に関連する情報だけ絞り、多数のCVEに対するubuntu priorityを集計して最大のpriorityをUSN-IDに割り当てる作業を自動化すること、必要な情報を取り出して要約する作業を自動化することで人で作業を省力化できるようにした。

v1.1.0
- ubuntu:reportコマンドでUbuntu Priorityの判定を単純な正規表現から、DOMベースの文字列マッチに変更し判定精度を向上させた。

v1.2.0 
- ubuntu:reportコマンドでUbuntu Priorityの判定を単純な正規表現から、DOMベースで画像ファイル名のマッチに変更し判定精度をさらに向上させた。
- ubuntu:reportコマンドで、多数のCVEについてのpriority判定でUnknownが一つでもあったらUSNのpriorityをUnknownとするように厳格化した。

v1.4.0
- HTTP通信の信頼性を向上させるため、自動リトライ機能（最大3回、指数バックオフ付き）を実装
- タイムアウト設定を30秒に延長し、ネットワーク遅延への耐性を強化
- エラーログを改善し、ネットワークエラーの原因を特定しやすく改良
- 404エラー（CVEが存在しない場合）の適切な処理を追加
- これらの改善により、severityがUnknownとなる頻度を大幅に削減

v1.5.0
- Gmail IMAP を利用した `ubuntu:fetch-digest` コマンドを追加し、Digest メールの取得と連結を自動化
- README に新コマンドの環境変数設定と実行例を追記
- コード全体に Javadoc を整備して保守性を向上

v1.6.0
- `ubuntu:report` の入手元を、Gmail から取得したメール本文から Ubuntu Security API (`https://ubuntu.com/security/notices.json`) へ変更した。`--start` と `--end` で期間を指定する。`--infile` を渡せば従来どおりメールからも作れる
- CVE の Ubuntu priority の入手元は `https://ubuntu.com/security/<CVE番号>` の HTML のままとした。同じ値を返す JSON エンドポイントは HTTP 503 と 504 を長時間返すため使わない
- 一度取得した Ubuntu priority を `$HOME/.cache/Utility-security/cve-priority.tsv` に保存し、次回以降は要求を出さずに読むようにした。取得した時点で1件ずつ追記するので、途中で止めても失われない
- CVE を1件取得できなくても、残りの CVE を最後まで取得するようにした。以前は打ち切っており、到達しなかった CVE が保存されないため、何度実行しても同じ場所で止まっていた
- 順位の付かない CVE が混ざっていても、順位の付いた CVE があればその最大値を severity に書くようにした
- severity が定まらない場合を `LookupFailed`(取得に失敗)・`Unrated`(Ubuntu が1件も順位を付けていない)・`NoCve`(CVE が無い)の3つに分けた。以前はすべて `Unknown` だった
- Ubuntu priority が High 以上の CVE 番号を並べる `severe_cves` 列を追加した
- 同じ USN 番号の枝番を1行にまとめるようにした
- 表に載せるカーネルの flavour を、汎用と `NVIDIA` の完全一致だけに絞った。以前は除外する語を並べる方式で、`Oracle`・`FIPS`・`HWE` 等が漏れていた
- 出力を公開日の昇順に並べるようにした
- ubuntu.com への要求を `UbuntuSecurityHttpClient` に集約し、10秒以上の間隔、最大10回の再試行(待ち時間は10秒ずつ増加)、応答待ち120秒を全経路に適用した
- 応答を1行ずつ読み、必要な値が見つかった時点で読むのをやめるようにした
- Kernel Live Patch Security Notice を1件1行で出す `ubuntu:livepatch-report` コマンドを追加した
- 報告書を記録簿の xlsx へ追記する `ubuntu:append-xlsx` コマンドを追加した。原本は書き換えず別ファイルに書き出す
- 依存する CLI ライブラリを `com.github.oogasawa:Utility-cli` 3.1.0 から `com.scivicslab:pluggable-cli` 1.0.0 へ変更した。前者はどこにも存在せず依存を解決できなかった
- `severity` が `LookupFailed` の行を後の実行で書き直すようにした。この値は Ubuntu Security Notice についての事実ではなく、ubuntu.com が応答しなかったという実行時の事情だからである。書き直すのはプログラムが埋める8列だけで、人が埋める9列には触れない
- 報告書の作成から記録簿への追記までを cron から週に1回実行する `bin/update-patch-history.sh` を追加した。置き換える前の記録簿は12世代を控えとして残す
- 一度読んだ Ubuntu Security Notice を `$HOME/.cache/Utility-security/notices-<リリース名>.jsonl` に保存し、次回以降は新しい方のページだけを読むようにした。2025年8月まで遡る実行では一覧の取得だけで146回の要求・24分かかっていた
- ユニットテストを129件に増やし、いずれも外部サービスに接続しないようにした。ubuntu.com へ実際に届くかの確認は `UbuntuSecurityApiLiveCheck` として `main()` を持つプログラムに分離した
