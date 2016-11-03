# bind2other

named.conf から、それとなるべく同等の動きをする NSD, Unbound, dnsdist のコンフィグを作る

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
## どのようなコンフィグができるか?

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

  - ローカルゾーン (named.conf に書かれている zone) ならば NSD (127.0.0.1:10053)
  - ローカルゾーン以外なら、Unbound (127.0.0.1:10054)

へフォーワードする。

NSDは、通常の権威サーバとして nsd.conf に書かれたゾーンを読み込み (またはゾーン転送をして)、127.0.0.1:10053でクエリを待ち受ける。

Unboundは、通常のDNSリゾルバとして動作し、127.0.0.1:10054でクエリを待ち受ける。

### アクセス権限について

  - 最初に、allow-query にマッチしないソースIPのクエリはREFUSED
  - ローカルゾーンへのクエリの場合、NSDにフォワードする。ただし、クエリタイプがAXFR/IXFRの場合は、allow-transfer (options、または各 zone) に従って許可・拒否を行う。
  - ローカルソーン宛てではない、かつ allow-recursion にマッチするソースIPのクエリのみ、Unboundにフォワードされる。
  
## いまのところ使える named.conf の機能

BIND9のごく一部の機能のみ対応する。viewなどは未対応だが、キャッシュと権威の同居等は可能。

### ACL
```
acl mynetwork1 { 10.0.0.0/8; 192.168.0.0/16 };
acl mynetwork2 { 192.0.2.1; };
acl ournetwork { mynetwork1; mynetwork2; }; # ACLのネストもOK
```
#### ACLでは否定の ! は使用不可
```
# acl evil_in_theinternet { 0.0.0.0/0; ! 1.1.1.1; }; 
```

### options文で使える文
```
options {
  directory "/etc";
  allow-query { any; };                    # デフォルトは ANY (BIND9と同じ) 
  allow-recursion { ournetwork; };         # デフォルトは none (BIND9は localhost; localnets) 
  allow-transfer { mynetwork1; 1.1.1.1; }; # デフォルトは none (BIND9は any)
}
```

### zone

masterゾーンと slaveゾーンのみ。アクセス制限は allow-transfer のみ指定可。
```
zone "example.com" {
  type master;
  file "example.com.zone";
  allow-transfer { none; };  # optionsの allow-transferより優先
}

zone "example2.com" {
  type slave;
  masters { 10.0.0.1; 192.0.2.1; };
  allow-transfer { mynetwork2; 127.0.0.1; }; # optionsの allow-transferより優先
}
```

