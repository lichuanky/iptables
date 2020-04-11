#!/bin/bash

#########################################################
# 此脚本的功能
#
# 基本上放弃传入/传递, 并指定白名单中允许的内容。
# 基本上允许发送。但是, 服务器可能会充当跳板并惹恼外部服务器。
# 如果您担心, 最好重写一下, 以便基本上放弃发送和接收, 并允许白名单和接收。
#########################################################

#########################################################
# 术语统一
# 为了清楚起见, 请统一以下规则和注释中的术语
# ACCEPT : 允许
# DROP   : 丢弃
# REJECT : 拒绝
#########################################################

#########################################################
#备忘清单
#
# -A, --append          将一个或多个新规则添加到指定链
# -D, --delete          从指定链中删除一个或多个规则
# -P, --policy          将指定链的策略设置为指定目标
# -N, --new-chain       创建一个新的用户定义链
# -X, --delete-chain    删除指定的用户定义链
# -F                    表初始化
#
# -p, --protocol        指定协议协议（tcp, udp, icmp, 所有）
# -s, --source          IP地址[/mask]源地址。输入IP地址或主机名
# -d, --destination     IP地址[/mask]目标地址。输入IP地址或主机名
# -i, --in-interface    指定设备数据包进入的接口
# -o, --out-interface指 定设备数据包发送出去的接口
# -j, --jump            指定满足目标条件时的操作
# -t, --table           表指定表
# -m state --state      state将数据包状态指定为条件
#                       state可以是新的, 已建立的, 相关的, 无效的
# !                     反转条件（〜除外）
#########################################################

# 路径
PATH=/sbin:/usr/sbin:/bin:/usr/bin

#########################################################
# IP定义
# 必要时定义。即使您没有定义它, 它也可以工作。
#########################################################

# 允许范围作为内部网络
# LOCAL_NET="xxx.xxx.xxx.xxx/xx"

# 允许范围, 但有一些限制作为内部网络
# LIMITED_LOCAL_NET="xxx.xxx.xxx.xxx/xx"

# Zabbix服务器IP
# ZABBIX_IP ="xxx.xxx.xxx.xxx"

# 定义代表所有IP的设置
# ANY ="0.0.0.0/0"

# 可信主机（数组）
# ALLOW_HOSTS =（
#   "xxx.xxx.xxx.xxx"
#   "xxx.xxx.xxx.xxx"
#   "xxx.xxx.xxx.xxx"
# ）

# 无条件拒绝列表（数组）
# DENY_HOSTS =（
#   "xxx.xxx.xxx.xxx"
#   "xxx.xxx.xxx.xxx"
#   "xxx.xxx.xxx.xxx"
# ）

#########################################################
# 端口定义
#########################################################

SSH=22
FTP=20,21
DNS=53
SMTP=25,465,587
POP3=110,995
IMAP=143,993
HTTP=80,443
IDENT=113
NTP=123
MYSQL=3306
NET_BIOS=135,137,138,139,445
DHCP=67,68

#########################################################
# 功能
#########################################################

# iptables初始化, 所有规则均已删除
initialize()
{
    iptables -F # 表初始化
    iptables -X # 删除链
    iptables -Z # 清除数据包计数器/字节计数器
    iptables -P INPUT   ACCEPT
    iptables -P OUTPUT  ACCEPT
    iptables -P FORWARD ACCEPT
}

# 应用规则后处理
finailize()
{
    /etc/init.d/iptables save &&    # 保存设置
    /etc/init.d/iptables restart && # 尝试使用保存的重新启动
    return 0
    return 1
}

#为了发展
if [ "$1" == "dev" ]
then
    iptables() { echo "iptables $@"; }
    finailize() { echo "finailize"; }
fi

#########################################################
# iptables初始化
#########################################################
initialize

#########################################################
# 政策决定
#########################################################
iptables -P INPUT   DROP # 所有删除。最好在打开必要的端口之前堵塞所有孔。
iptables -P OUTPUT  ACCEPT
iptables -P FORWARD DROP

#########################################################
# 允许信任的主机
#########################################################

# Localhost
# lo表示指向其自身主机的本地环回
iptables -A INPUT -i lo -j ACCEPT # SELF-> SELF

# 局域网
# 如果设置了 $LOCAL_NET, 则允许与LAN上的其他服务器进行交互
if [ "$LOCAL_NET" ]
then
    iptables -A INPUT -p tcp -s $LOCAL_NET -j ACCEPT # LOCAL_NET -> SELF
fi

# 可信主机
# 如果设置了 $ALLOW_HOSTS, 则允许与主机交互
if [ "${ALLOW_HOSTS}" ]
then
    for allow_host in ${ALLOW_HOSTS[@]}
    do
        iptables -A INPUT -p tcp -s $allow_host -j ACCEPT # allow_host-> SELF
    done
fi

#########################################################
# 从 $DENY_HOSTS 拒绝访问
#########################################################
if [ "${DENY_HOSTS}" ]
then
    for deny_host in ${DENY_HOSTS[@]}
    do
        iptables -A INPUT -s $deny_host -m limit --limit 1/s -j LOG --log-prefix "deny_host: "
        iptables -A INPUT -s $deny_host -j DROP
    done
fi

#########################################################
# 建立会话后允许数据包通信
#########################################################
iptables -A INPUT  -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT

#########################################################
# 攻击对策: Stealth Scan
#########################################################
iptables -N STEALTH_SCAN # 创建一个名称为 "STEALTH_SCAN" 的链
iptables -A STEALTH_SCAN -j LOG --log-prefix "stealth_scan_attack: "
iptables -A STEALTH_SCAN -j DROP

# 类似于隐形扫描的数据包跳到"STEALTH_SCAN"链
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j STEALTH_SCAN

iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN         -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST         -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j STEALTH_SCAN

iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN     -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH     -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG     -j STEALTH_SCAN

#########################################################
# 攻击对策: 片段数据包端口扫描, DOS攻击
# namap -v -sF等措施
#########################################################
iptables -A INPUT -f -j LOG --log-prefix 'fragment_packet: '
iptables -A INPUT -f -j DROP
 
#########################################################
# 攻击对策: Ping of Death
#########################################################
# 每秒10次以上ping后丢弃
iptables -N PING_OF_DEATH # 创建一个名为 "PING_OF_DEATH" 的链
iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request \
         -m hashlimit \
         --hashlimit 1/s \
         --hashlimit-burst 10 \
         --hashlimit-htable-expire 300000 \
         --hashlimit-mode srcip \
         --hashlimit-name t_PING_OF_DEATH \
         -j RETURN

# 丢弃ICMP超出限制
iptables -A PING_OF_DEATH -j LOG --log-prefix "ping_of_death_attack: "
iptables -A PING_OF_DEATH -j DROP

# ICMP跳至 "PING_OF_DEATH" 链
iptables -A INPUT -p icmp --icmp-type echo-r​​equest -j PING_OF_DEATH

#########################################################
# 攻击对策: SYN Flood攻击
# 除了此解决方案之外, 还应该启用 Syn cookie。
#########################################################
iptables -N SYN_FLOOD # 创建一个名称为"SYN_FLOOD"的链
iptables -A SYN_FLOOD -p tcp --syn \
         -m hashlimit \
         --hashlimit 200/s \
         --hashlimit-burst 3 \
         --hashlimit-htable-expire 300000 \
         --hashlimit-mode srcip \
         --hashlimit-name t_SYN_FLOOD \
         -j RETURN

# 评论
# -m hashlimit                     使用hashlimit而不是limit来限制每个主机
# --hashlimit 200/s                限制200个连接
# --hashlimit-burst 3              如果超过上述限制的连接数连续3次, 则将受到限制
# --hashlimit-htable-expire 300000 管理表中记录的有效期限（单位: 毫秒）
# --hashlimit-mode srcip           按源地址管理请求计数
# --hashlimit- t_SYN_FLOOD         存储在/proc/net/ipt_hashlimit中的哈希表名称
# -j RETURN                        如果在限制范围内, 返回父链

# 丢弃超过限制的SYN报文
iptables -A SYN_FLOOD -j LOG --log-prefix "syn_flood_attack: "
iptables -A SYN_FLOOD -j DROP

# SYN数据包跳至"SYN_FLOOD"链
iptables -A INPUT -p tcp --syn -j SYN_FLOOD

#########################################################
# 攻击对策: HTTP DoS/DDoS攻击
#########################################################
iptables -N HTTP_DOS # 创建一个名称为"HTTP_DOS"的链
iptables -A HTTP_DOS -p tcp -m multiport --dports $HTTP \
         -m hashlimit \
         --hashlimit 1/s \
         --hashlimit-burst 100 \
         --hashlimit-htable-expire 300000 \
         --hashlimit-mode srcip \
         --hashlimit-name t_HTTP_DOS \
         -j RETURN

# 评论
# -m hashlimit                     使用hashlimit而不是limit来限制每个主机
# --hashlimit 1/s                  每秒限制1个连接
# --hashlimit-burst 100            限制将在连续超过100次以上时应用
# --hashlimit-htable-expire 300000 管理表中记录的有效期限（单位: 毫秒）
# --hashlimit-mode srcip           按源地址管理请求计数
# --hashlimit-name t_HTTP_DOS      /proc/net/ipt_hashlimit存储在其中的哈希表的名称
# -j RETURN                        如果在限制范围内, 返回父链

# 丢弃超出限制的连接
iptables -A HTTP_DOS -j LOG --log-prefix "http_dos_attack: "
iptables -A HTTP_DOS -j DROP

# HTTP的数据包跳转到"HTTP_DOS"链
iptables -A INPUT -p tcp -m multiport --dports $HTTP -j HTTP_DOS

#########################################################
# 攻击对策: IDENT端口探针
# 使用 ident 帮助攻击者为将来的攻击做准备, 或者
# 进行端口调查以查看系统是否容易受到攻击
# 在DROP中, 邮件服务器等的响应将减少, 因此拒绝
#########################################################
iptables -A INPUT -p tcp -m multiport --dports $IDENT -j REJECT --reject-with tcp-reset

#########################################################
# 攻击对策: SSH Brute Force
# 如果服务器使用密码身份验证, 则SSH将为密码暴力破解做准备。
# 每分钟仅允许5次连接尝试。
# 使用 REJECT 代替 DROP, 以防止SSH客户端反复重新连接。
# 如果 SSH 服务器的密码验证为 ON, 请取消以下注释
#########################################################
# iptables -A INPUT -p tcp --syn -m multiport --dports $ SSH -m recent --name ssh_attack --set
# iptables -A INPUT -p tcp --syn -m multiport --dports $ SSH -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 5 -j LOG --log-prefix "ssh_brute_force: "
# iptables -A INPUT -p tcp --syn -m multiport --dports $ SSH -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 5 -j REJECT --reject-with tcp-reset

#########################################################
# 攻击对策: FTP Brute Force
# FTP使用密码认证, 因此请做好密码暴力攻击的准备。
# 每分钟仅允许5次连接尝试。
# 使用REJECT代替DROP, 以防止FTP客户端反复重新连接。
# 如果已设置FTP服务器, 请取消注释以下内容
#########################################################
# iptables -A INPUT -p tcp --syn -m multiport --dports $ FTP -m recent --name ftp_attack --set
# iptables -A INPUT -p tcp --syn -m multiport --dports $ FTP -m recent --name ftp_attack --rcheck --seconds 60 --hitcount 5 -j LOG --log-prefix "ftp_brute_force: "
# iptables -A INPUT -p tcp --syn -m multiport --dports $ FTP -m recent --name ftp_attack --rcheck --seconds 60 --hitcount 5 -j REJECT --reject-with tcp-reset

#########################################################
# 丢弃发往所有主机的报文（广播地址, 组播地址）
#########################################################
iptables -A INPUT -d 192.168.1.255   -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 192.168.1.255   -j DROP
iptables -A INPUT -d 255.255.255.255 -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 255.255.255.255 -j DROP
iptables -A INPUT -d 224.0.0.1       -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 224.0.0.1       -j DROP

#########################################################
# 允许来自所有主机的输入（任意）
#########################################################

# ICMP: 设置以响应ping
iptables -A INPUT -p icmp -j ACCEPT # ANY->SELF

# HTTP, HTTPS
iptables -A INPUT -p tcp -m multiport --dports $HTTP -j ACCEPT # ANY -> SELF

# SSH: 如果要限制主机, 请在TRUST_HOSTS中写入受信任的主机, 并注释掉以下内容
iptables -A INPUT -p tcp -m multiport --dports $SSH -j ACCEPT # ANY -> SELF

# FTP
# iptables -A INPUT -p tcp -m multiport --dports $FTP -j ACCEPT # ANY -> SELF

# DNS
# iptables -A INPUT -p tcp -m multiport --sports $DNS -j ACCEPT # ANY -> SELF
# iptables -A INPUT -p udp -m multiport --sports $DNS -j ACCEPT # ANY -> SELF

# SMTP
# iptables -A INPUT -p tcp -m multiport --sports $SMTP -j ACCEPT # ANY -> SELF

# POP3
# iptables -A INPUT -p tcp -m multiport --sports $POP3 -j ACCEPT # ANY -> Self

# IMAP
# iptables -A INPUT -p tcp -m multiport --sports $IMAP -j ACCEPT # ANY -> Self

#########################################################
# 允许来自本地网络的输入（受限）
#########################################################

if [ "$LIMITED_LOCAL_NET" ]
then
    # SSH
    iptables -A INPUT -p tcp -s $LIMITED_LOCAL_NET -m multiport --dports $SSH -j ACCEPT # LIMITED_LOCAL_NET -> SELF

    # FTP
    iptables -A INPUT -p tcp -s $LIMITED_LOCAL_NET -m multiport --dports $FTP -j ACCEPT # LIMITED_LOCAL_NET -> SELF

    # MySQL
    iptables -A INPUT -p tcp -s $LIMITED_LOCAL_NET -m multiport --dports $MYSQL -j ACCEPT # LIMITED_LOCAL_NET -> SELF
fi

#########################################################
# 来自特定主机的输入权限
#########################################################

if [ "$ZABBIX_IP" ]
then
    # 允许Zabbix相关
    iptables -A INPUT -p tcp -s $ZABBIX_IP --dport 10050 -j ACCEPT # Zabbix -> SELF
fi

#########################################################
# 除此之外
# 记录并丢弃不符合上述规则的任何内容
#########################################################
iptables -A INPUT  -j LOG --log-prefix "drop: "
iptables -A INPUT  -j DROP

#########################################################
# SSH规避方法
# 睡眠30秒钟, 然后重置iptables。
# 如果未锁定SSH, 则应该可以按Ctrl-C。
#########################################################
trap'finailize && exit 0' 2 # 终止 Ctrl-C
echo "In 30 seconds iptables will be automatically reset."
echo "Don't forget to test new SSH connection!"
echo "If there is no problem then press Ctrl-C to finish."
sleep 30
echo "rollback..."
initialize