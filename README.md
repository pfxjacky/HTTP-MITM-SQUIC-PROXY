

一键安装部署脚本 

```
bash
wget https://raw.githubusercontent.com/pfxjacky/HTTP-MITM-SQUIC-PROXY/refs/heads/main/dingliu_multios_script.sh && chmod +x dingliu_multios_script.sh && ./dingliu_multios_script.sh

```


```
bash
wget https://raw.githubusercontent.com/pfxjacky/HTTP-MITM-SQUIC-PROXY/refs/heads/main/https-zth.sh && chmod +x https-zth.sh && ./https-zth.sh
```

1、拷贝脚本和服务端到VPS上，执行脚本安装。

2、拷贝VPS上的证书mitmproxy-ca-cert.cer到本地目录。

3、打开GUI客户端的界面，填加信息导入mitmproxy-ca-cert.cer证书。

4、点击开始。
