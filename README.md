# bind2other

named.conf から、それとなるべく同等の動きをする NSD, Unbound, dnsdist のコンフィグを作る

  - [Internet Week 2016 DNSOPS.JP BoF プレゼン資料](http://dnsops.jp/bof/20161201/bind2other.pdf)

## 使い方

```
./bind2other.py named.conf
```

同じディレクトリに nsd.conf, unbound.conf, dnsdist.conf ができるので、それらを使ってnsd, unbound, dnsdistを起動する。

```
sudo nsd -c nsd.conf
sudo unbound -c unbound.conf
sudo dnsdist -C dnsdist.conf -d

dig @127.0.0.1 example.com    # ローカルゾーン
dig @127.0.0.1 www.google.com # ローカルゾーン以外
```

## 必要なもの
  - Python 2.6
  - dnsdist 1.0.0
  - NSD4
  - Unbound

## どのようなコンフィグができるか?

  - 元の [named.conf](https://github.com/hdais/bind2other/blob/master/example/named.conf)
  - 生成されるコンフィグファイル
    - [dnsdist.conf](https://github.com/hdais/bind2other/blob/master/example/dnsdist.conf)
    - [nsd.conf](https://github.com/hdais/bind2other/blob/master/example/nsd.conf)
    - [unbound.conf](https://github.com/hdais/bind2other/blob/master/example/unbound.conf)
  

### 基本的な動作

```
クライアント ---(クエリ受信)--> [dnsdist]
                                |
                                +--(qnameがローカルゾーン)---> [NSD]
                                |
                                +--(ローカルゾーン以外)---> [Unbound]
```

dnsdist はクライアントからクエリ受信するために 0.0.0.0:53, [::]:53 で待ち受ける。
クライアントからDNSクエリを受信したら、

  - ローカルゾーン (named.conf に書かれている zone) ならば NSD (127.0.0.1:40000)
  - ローカルゾーン以外なら、Unbound (127.0.0.1:40001)

へフォーワードする。

NSDは、通常の権威サーバとして nsd.conf に書かれたゾーンを読み込み (またはゾーン転送をして)、127.0.0.1:40000でクエリを待ち受ける。

Unboundは、通常のDNSリゾルバとして動作し、127.0.0.1:40001でクエリを待ち受ける。

### アクセス制限

  - allow-query にマッチしないソースIPのクエリは常にREFUSED
  - ローカルゾーンへのクエリの場合、NSDにフォワードする。ただし、クエリタイプがAXFR/IXFRの場合は、allow-transfer (options、または各 zone) に従って許可・拒否を行う。
  - ローカルソーン宛てではない、かつ allow-recursion にマッチするソースIPのクエリのみ、Unboundにフォワードされる。
  
## 対応する named.conf の機能

BIND9のごく一部の機能のみ対応する

### ACL
```
acl mynetwork1 { 10.0.0.0/8; 192.168.0.0/16; };
acl mynetwork2 { 192.0.2.1; };
acl ournetwork { mynetwork1; mynetwork2; }; # ACLのネストもOK
```
#### ACLでは否定の ! は使用不可
```
# acl evil_in_the_internet { 0.0.0.0/0; ! 1.1.1.1; }; # "!" は不可
```

### options
```
options {
  directory "/etc";
  allow-query { any; };                    # デフォルトは ANY (BIND9と同じ) 
  allow-recursion { ournetwork; };         # デフォルトは none (BIND9は localhost; localnets) 
  allow-transfer { mynetwork1; 1.1.1.1; }; # デフォルトは none (BIND9は any)
};
```

### zone

masterゾーンと slaveゾーンのみ。アクセス制限は allow-transfer のみ指定可。
```
zone "example.com" {
  type master;
  file "example.com.zone";
  allow-transfer { none; };  # optionsの allow-transferより優先
};

zone "example2.com" {
  type slave;
  masters { 10.0.0.1; 192.0.2.1; };
  allow-transfer { mynetwork2; 127.0.0.1; }; # optionsの allow-transferより優先
};
```

### view

match-clients のみ対応。

  - 元の [named.conf](https://github.com/hdais/bind2other/blob/master/example/view/named.conf)
  - 生成されるコンフィグファイル
    - [dnsdist.conf](https://github.com/hdais/bind2other/blob/master/example/view/dnsdist.conf)
    - internal view用 nsd/unboundコンフィグ
      - [nsd_internal.conf](https://github.com/hdais/bind2other/blob/master/example/view/nsd_internal.conf)
      - [unbound_internal.conf](https://github.com/hdais/bind2other/blob/master/example/view/unbound_internal.conf)
    - external view用 nsd/unboundコンフィグ
      - [nsd_external.conf](https://github.com/hdais/bind2other/blob/master/example/view/nsd_external.conf)
      - [unbound_external.conf](https://github.com/hdais/bind2other/blob/master/example/view/unbound_external.conf)
    - デフォルトview用 nsd/unboundコンフィグ　
      - [nsd.conf](https://github.com/hdais/bind2other/blob/master/example/view/nsd.conf)
      - [unbound.conf](https://github.com/hdais/bind2other/blob/master/example/view/unbound.conf)

#### 起動方法
dnsdist.confでdnsdistを、各viewに対応するコンフィグでnsd/unboundを起動

```
sudo nsd -c nsd.conf
sudo nsd -c nsd_external.conf
sudo nsd -c nsd_internal.conf

sudo unbound -c unbound.conf
sudo unbound -c unbound_external.conf
sudo unbound -c unbound_internal.conf

sudo dnsdist -C dnsdist.conf -d
```
