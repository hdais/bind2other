# bind2other

named.conf から、それとなるべく同等の動きをする NSD, Unbound, dnsdist のコンフィグを作る

## 使い方

```./bind2other.py named.conf
```

同じディレクトリに nsd.conf, unbound.conf, dnsdist.conf ができるので、

```sudo nsd -c nsd.conf
sudo unbound -c unbound.conf
sudo dnsdist -C dnsdist.conf -d
```
