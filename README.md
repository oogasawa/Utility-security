# Utility-secutiry

セキュリティ関係のユーティリティ
（ISO27001対応作業の省力化等）

## インストール

動作確認環境
- Ubuntu Linux 24.04
- JDK 23
- Apache Maven 3.9.9
- Utility-cli 3.1.0 https://github.com/oogasawa/Utility-cli

JDKおよびMavenのインストール方法は例えば以下のURLを参照(SDKMAN!で入れると簡単)
https://sc.ddbj.nig.ac.jp/guides/software/DevelopmentEnvironment/java/

Utilit-cliはMaven Repositoryには登録されていないので、
以下のようにしてあらかじめビルドする計算機のローカルリポジトリ`$HOME/.m2/`にインストールしておく必要がある。

``` 
git clone https://github.com/oogasawa/Utility-cli
cd Utility-cli
mvn clean install
```

## ビルド方法

``` 
git clone https://github.com/oogasawa/Utility-security
cd Utility-security
mvn clean package
```

これにより`Utility-security/target/Utility-security-VERSION.jar`という名前で
fat-jarファイル(依存ライブラリがすべて入った単一のjarファイル)が作られる。

この単一のfat-jarファイルだけあれば以下の実行が可能。(必要に応じて適当な場所にコピーするなどして使用する。)


## 使用方法

引数なしで実行すると使い方が表示される。
今のところ一つのコマンド(`ubuntu:report`)しか実装されていない。

``` bash
$ java -jar target/Utility-security-1.0.0.jar 

## Usage

java -jar Utility-security-<VERSION>.jar <command> <options>

## Ubuntu security commands

ubuntu:report   Create TSV format report.

$ java -jar target/Utility-security-1.0.0.jar ubuntu:report -h
Error: Failed to parse the command. Reason: Unrecognized option: -h
See the help below for correct usage:
usage: ubuntu:report
 -f,--format <format>   The format of the report (tsv or json)
 -i,--infile <infile>   An input file of ubuntu security report.


## Description

Create TSV format report.
```

### `ubuntu:report`コマンド

このコマンドは、ubuntu-security-announceから必要な情報だけを取り出しタブ区切り形式(TSV)で出力するものである。

使用方法は以下のとおり。

1. 以下のURLからubuntu-security-announce mailing listに登録する。
https://lists.ubuntu.com/mailman/listinfo/ubuntu-security-announce

2. 上記mailing listから送られてきた多数のメールをそのまま1つのテキストファイルに全部つなげて(concatenateして)保存しておく。
例えば ubuntu-security.2505A.txtに5月第一週に来たメールを保存するなど。

3. 以下のようにコマンドを実行する

``` bash
java -jar Ubuntu-security-1.0.0-jar ubuntu:report -i ubuntu-security.2505A.txt | tee ubuntu-security.2505A.tsv
```

- 標準出力にTSV形式のデータが出力される。
- 標準エラー出力に実行時のログが出力される。


実行例

``` bash
$ java -jar target/Utility-security-1.0.0.jar ubuntu:report -i ubuntu-security.2505D.txt | tee 2505D.tsv
2025-05-22 10:02:03,040 INFO [main] c.g.o.u.s.u.USNJsonExporter [USNJsonExporter.java:134] USN-7520-1, PostgreSQL vulnerability, [CVE-2025-4207]
2025-05-22 10:02:04,794 INFO [main] c.g.o.u.s.u.USNJsonExporter [USNJsonExporter.java:219] rawPriority: Medium, CVE-2025-4207
2025-05-22 10:02:04,800 INFO [main] c.g.o.u.s.u.USNJsonExporter [USNJsonExporter.java:139] levels.size() = 1
2025-05-22 10:02:05,818 INFO [main] c.g.o.u.s.u.USNJsonExporter [USNJsonExporter.java:134] USN-7522-1, Linux kernel (Azure, N-Series) vulnerabilities, [CVE-2024-56653, CVE-2024-57932, CVE-2024-54455, CVE-2024-57938, CVE-2024-57896, CVE-2024-53179, CVE-2024-57903, CVE-2025-21640, CVE-2024-56654, CVE-2024-57906, CVE-2024-53690, CVE-2025-21648, CVE-2024-57913, CVE-2025-21655, CVE-2024-57907, CVE-2025-21634, CVE-2024-57926, CVE-2025-21659, CVE-2024-54460, CVE-2024-57898, CVE-2024-56769, CVE-2024-36476, CVE-2025-21938, CVE-2025-21637, CVE-2024-57888, CVE-2024-57901, CVE-2024-57887, CVE-2024-57940, CVE-2024-49571, CVE-2024-57889, CVE-2024-55639, CVE-2024-57899, CVE-2024-56759, CVE-2024-41013, CVE-2024-57895, CVE-2024-57933, CVE-2024-56662, CVE-2024-56767, CVE-2025-21639, CVE-2024-56715, CVE-2024-57883, CVE-2025-21636, CVE-2024-57931, CVE-2025-21642, CVE-2024-53685, CVE-2024-56659, CVE-2025-21971, CVE-2024-56716, CVE-2025-21652, CVE-2024-57792, CVE-2025-21638, CVE-2024-56764, CVE-2024-55916, CVE-2024-57916, CVE-2024-56718, CVE-2024-57929, CVE-2024-57900, CVE-2025-21660, CVE-2024-57879, CVE-2024-56758, CVE-2024-57908, CVE-2025-21664, CVE-2024-56652, CVE-2024-57882, CVE-2024-39282, CVE-2025-21663, CVE-2024-47736, CVE-2024-54193, CVE-2025-21650, CVE-2024-56665, CVE-2024-57793, CVE-2024-58087, CVE-2025-21658, CVE-2025-21643, CVE-2024-54683, CVE-2024-56667, CVE-2024-56664, CVE-2024-56770, CVE-2024-57946, CVE-2024-57904, CVE-2024-56709, CVE-2024-56369, CVE-2024-58237, CVE-2024-57885, CVE-2024-56763, CVE-2024-56657, CVE-2025-21645, CVE-2024-57893, CVE-2025-21631, CVE-2024-57791, CVE-2024-57910, CVE-2024-57902, CVE-2024-57806, CVE-2025-21656, CVE-2024-53125, CVE-2024-56761, CVE-2024-56717, CVE-2024-47408, CVE-2025-21654, CVE-2025-21649, CVE-2024-57807, CVE-2024-56675, CVE-2025-21653, CVE-2024-57897, CVE-2024-53687, CVE-2024-56760, CVE-2025-21635, CVE-2025-21632, CVE-2024-57890, CVE-2025-21647, CVE-2024-57917, CVE-2024-56372, CVE-2024-56656, CVE-2024-57912, CVE-2024-57841, CVE-2025-21953, CVE-2024-56710, CVE-2024-57884, CVE-2024-57804, CVE-2025-21888, CVE-2024-56660, CVE-2024-57805, CVE-2024-57801, CVE-2024-38608, CVE-2024-57945, CVE-2024-55881, CVE-2024-57802, CVE-2024-57892, CVE-2025-21646, CVE-2024-56670, CVE-2025-21651, CVE-2024-57939, CVE-2024-57925, CVE-2024-57911, CVE-2025-21662, CVE-2024-49568]
2025-05-22 10:02:07,133 INFO [main] c.g.o.u.s.u.USNJsonExporter [USNJsonExporter.java:219] rawPriority: High, CVE-2024-56653
2025-05-22 10:02:08,400 INFO [main] c.g.o.u.s.u.USNJsonExporter [USNJsonExporter.java:219] rawPriority: Medium, CVE-2024-57932
2025-05-22 10:02:10,037 INFO [main] c.g.o.u.s.u.USNJsonExporter [USNJsonExporter.java:219] rawPriority: Medium, CVE-2024-54455
2025-05-22 10:02:11,475 INFO [main] c.g.o.u.s.u.USNJsonExporter [USNJsonExporter.java:219] rawPriority: Medium, CVE-2024-57938
2025-05-22 10:02:12,862 INFO [main] c.g.o.u.s.u.USNJsonExporter [USNJsonExporter.java:219] rawPriority: Medium, CVE-2024-57896
2025-05-22 10:02:14,196 INFO [main] c.g.o.u.s.u.USNJsonExporter [USNJsonExporter.java:219] rawPriority: Medium, CVE-2024-53179
2025-05-22 10:02:15,644 INFO [main] c.g.o.u.s.u.USNJsonExporter [USNJsonExporter.java:219] rawPriority: Medium, CVE-2024-57903
2025-05-22 10:02:17,006 INFO [main] c.g.o.u.s.u.USNJsonExporter [USNJsonExporter.java:219] rawPriority: Medium, CVE-2025-21640
2025-05-22 10:02:18,333 INFO [main] c.g.o.u.s.u.USNJsonExporter [USNJsonExporter.java:219] rawPriority: Medium, CVE-2024-56654
... 以下略
```

実行結果

```

```
