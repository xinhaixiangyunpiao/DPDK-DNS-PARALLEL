# 运行方式
``` bash
    make
    sudo ./build/server-main -c f -n 4
```
> lcore mask: 0x1111：使用0号，1号，2号，3号核。

# 注意事项
- 本实例经过实测可以实现10000个包的完全收发，在此基础上增加发包数继续优化。
