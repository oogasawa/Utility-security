# Utility-secutiry

セキュリティ関係の自作ユーティリティ

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
例えば ubuntu-security.202505A.txtに5月第一週に来たメールを保存するなど。

3. 以下のようにコマンドを実行する

``` bash
java -jar Ubuntu-security-1.0.0-jar ubuntu:report -i ubuntu-security.202505A.txt | tee ubuntu-security.202505A.tsv
```

- 標準出力にTSV形式のデータが出力される。
- 標準エラー出力に実行時のログが出力される。

