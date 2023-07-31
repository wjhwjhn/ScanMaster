# ScanMaster 测绘工具

## 项目思路
main.go

AlivePorts := Plugins.PortScan

进行扫描 

PortConnect

端口测活 + 协议识别 + web服务探测 + 蜜罐探测

WebTitle(&hostinfo, conn)       

//对端口进行 http 协议检测 => web服务检测 + web蜜罐检测


common.HPCheck(&hostinfo, conn) //蜜罐检测


AlivePorts 返ip:port为单位的信息 在main.go中添加进最终格式


## 源码文件夹说明

```
.
├── docker      # ScanMaster docker 部署源码
│   ├── build.sh    # 生成 ScanMaster docker 镜像命令
│   ├── Dockerfile    # Dockerfile 文件
│   ├── iplist.txt
│   ├── ports.txt
│   └── run.sh    # 生成 ScanMaster docker 容器命令
├── README.md
└── source    # ScanMaster 程序源码文件
    ├── iplist.txt    # 待扫描地址文件
    ...
    ...
    ...
    ...
    ├── ports.txt   # 待扫描端口文件
    ├── main.go
    ├── Plugins
    │   ├── postscan.go
    │   └── webtitle.go
    └── WebScan

```

## Docker 部署说明

通过将用户添加至docker组实现不使用sudo运行docker相关命令
```bash
usermod -a -G docker $USER
```

### 拉取本项目

```bash
git clone https://github.com/wjhwjhn/ScanMaster.git
```

### 使用 Docker 进行部署

进入项目文件夹中的 `docker` 目录，并使用脚本构建镜像

```bash
cd docker
./build.sh
```

构建镜像后将会生成一个名为`scanmaster`的容器镜像，执行以下即可运行

```bash
docker run -it --rm -v ./iplist.txt:/scanMaster/iplist.txt -v ./ports.txt:/scanMaster/ports.txt -v ./release:/scanMaster/release --name scanmaster scanmaster
```

此举会让容器内程序根据当前文件夹下的 `iplist.txt` 文件确定扫描的网络地址、通过当前文件夹下的 `ports.txt` 确定所要扫描的端口，并将结果输出到 `release` 文件夹内的 `log.txt` 文件中

## 源码编译使用说明

请确保执行编译的设备已安装配置go，可参阅[官方文档](https://go.dev/doc/install)进行安装


### 拉取本项目

```bash
git clone https://github.com/wjhwjhn/ScanMaster.git
```

### 编译

进入源码文件夹并编译

```bash
cd source
go build -o scanmaster .
```
上述操作将会生成一个名为 `scanmaster` 的可执行文件

### 使用

在编译完成后，可调整当前文件夹中的 `iplist.txt` 和 `ports.txt` 文件，用于自定义扫描的对象

通过以下命令运行本工具

```bash
./scanmaster
```

程序会将输出内容写入到当前文件夹下的`release/log.txt`文件中


## 免责声明

ScanMaster 测绘工具（以下简称“工具”）旨在帮助用户识别和收集计算机信息，以增强网络安全意识和管理。使用本工具需要用户了解并同意以下免责声明。在使用本工具之前，请仔细阅读并理解以下内容：

1. 本工具仅用于合法授权的安全测试和教育目的。用户需获得所有涉及扫描或收集信息的目标系统的明确授权。未经授权地使用本工具可能会涉及非法活动，对他人造成损害，导致法律责任。

2. 使用本工具进行网络安全测试可能会产生网络流量和请求，目标系统管理员或网络服务提供商可能察觉到这些活动。用户需对任何因使用本工具导致的网络干扰或问题负责。

3. 本工具提供的信息仅供参考和指导，不对信息的准确性、完整性或及时性作任何保证。用户需自行对收集到的信息进行分析和解释，并承担使用该信息所带来的一切风险。

4. 使用本工具可能会暴露目标系统的漏洞或安全问题。用户需在获得合法授权后，遵循相关法律和政策，妥善处理和报告发现的漏洞，不得利用这些漏洞进行未授权的访问或攻击。

5. 本工具不对用户在使用过程中产生的任何直接或间接损失负责，包括但不限于数据丢失、系统崩溃、业务中断、利润损失等。

6. 用户应遵守国际和地区相关的法律法规，并在使用本工具时遵循适用的道德和道德规范。

7. 用户应谨慎使用本工具，以免对目标系统造成不必要的负担或干扰。在对外部系统进行测试时，应遵守目标系统的网络使用政策，并尽可能减少对目标系统的影响。

8. 开发者不对用户使用本工具导致的任何违法行为或违反条款的行为负责。用户独立承担因违法或滥用本工具所导致的所有法律责任。

9. 用户对使用本工具及其功能的风险和后果负全部责任。如对免责声明有任何异议或不同意条款，请不要使用本工具。


通过下载、安装或使用本工具，即**表示您已阅读、理解并同意接受以上免责声明的所有条款和条件**。如您不同意此免责声明的任何部分，请立即停止使用本工具，并删除相关文件。

最后，请记住，**在进行任何网络安全测试或信息收集活动时，严格遵守法律法规和道德规范，确保您获得合法授权，并以负责任的态度行事。任何未经授权的活动可能会对您和他人带来不良后果！**