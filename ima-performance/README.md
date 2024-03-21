# IMA 性能测试

本测试用例，对 ima 的性能进行测试。其基于 unixbench 测试了系统的综合跑分，基于 systemd-analyze 测试了系统的启动时间。

测试条件主要为一下几种：

1. ima with no policy 
2. ima measurement
3. ima appraisal
4. ima + evm
5. ima + evm + sign


# 测试方法
对应以上几种测试条件分别执行如下命令：

``` bash
# 修改 ima 策略会自动重启
make ima-nopolicy
make ima-measurement
make ima-appraisal
make ima-evm
make ima-evm-sign
```

# 测试结果

经过测试，在使能 tpm pcr 扩展时，度量模式（ima measurement）有明显性能下降。性能损耗达 14% 以上，开机启动时间延长一倍。

如果编译时使能 ima，但策略为空，性能损耗小于 1%，处于误差范围内。

在评估模式（ima appraisal 或者 ima+evm appraisal ）以及对其签名时，其性能损耗在 1%~4% 之间，开机启动时间延长一半左右。