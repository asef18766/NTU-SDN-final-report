# NTU SDN final report
## SSL vul
### ref
* https://www.freebuf.com/vuls/349195.html
* https://github.com/colmmacc/CVE-2022-3602
* https://superhero.ninja/2015/07/22/create-a-simple-https-server-with-openssl-s_server/
* https://shengyu7697.github.io/ubuntu-openssl/
* https://ithelp.ithome.com.tw/articles/10310143
## file explaination
```
.
├── readme.md
└── SSL_vuln # vulnerable ssl server playground
    ├── build_image.sh
    ├── Dockerfile
    └── start_up.sh
```

## poc of cve-2022-3786 (one way)

```
# cmd 1
./run_server.sh vuln

# cmd 2
./run_client.sh ca debug

```
