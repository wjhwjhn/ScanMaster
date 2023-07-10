# ScanMaster

### 项目思路
main.go

AlivePorts := Plugins.PortScan

进行扫描 

PortConnect

端口测活 + 协议识别 + web服务探测 + 蜜罐探测

WebTitle(&hostinfo, conn)       

//对端口进行 http 协议检测 => web服务检测 + web蜜罐检测


common.HPCheck(&hostinfo, conn) //蜜罐检测


AlivePorts 返ip:port为单位的信息 在main.go中添加进最终格式

