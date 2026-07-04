# JD 3x-ui 可视化组网面板

JD 是一个面向 3x-ui 的可视化组网管理面板，适合多台服务器之间快速编排链路、创建单节点入口、管理防火墙策略、安装 3x-ui 面板，并通过任务中心查看后台执行进度。

无论你已经安装了 3x-ui 面板，还是手里只有一台新服务器，JD 都可以帮助你快速接入资源、编排链路、创建入口节点，并统一管理防火墙策略和后台任务。

## 主要功能

- 多服务器链路编排
- 单节点入口创建
- VLESS Reality 入口
- SOCKS5 单节点入口
- 二维码入口展示
- 防火墙策略管理
- 3x-ui 面板安装任务
- 任务中心后台执行
- 资源中心统一管理
- 审计日志查看
- 解压即用

## 项目优点

- 可视化操作，不需要手写复杂配置。
- 支持多台服务器快速组网。
- 支持已有 3x-ui 面板直接接入。
- 支持新服务器自动安装 3x-ui。
- 支持单节点入口和多跳链路两种使用方式。
- 支持二维码入口，方便客户端导入。
- 支持防火墙策略，便于限制端口访问来源。
- 支持后台任务，耗时操作不会卡住页面。
- 内置依赖，上传即可运行。
- 默认初始密码为 123456，部署后可立即登录。

## 默认登录信息

默认初始密码：

```text
123456
```

首次登录后，请进入后台设置修改管理密码。

## 部署方法

将本项目上传到网站目录，例如：

```text
/www/wwwroot/你的域名/xui-switcher
```

然后访问：

```text
https://你的域名/xui-switcher/
```

使用默认密码登录：

```text
123456
```

## 后台任务必须配置

只上传文件后，面板可以打开，也可以登录，但是任务中心里的后台任务不一定会自动执行。

如果你需要正常使用这些功能：

- 单节点开通
- 链路创建和重配
- 面板安装
- 防火墙策略应用
- 预约任务
- 后台检测

就必须让服务器定时执行 `cron.php`。

推荐在项目目录中执行一次：

```bash
cd /www/wwwroot/你的域名/xui-switcher
bash install_cron.sh
```

`install_cron.sh` 会自动识别当前目录，并把当前目录下的 `cron.php` 加入 crontab，让服务器每分钟执行一次后台任务。

执行成功后可以检查：

```bash
crontab -l
```

正常会看到类似：

```bash
* * * * * /usr/bin/php /www/wwwroot/你的域名/xui-switcher/cron.php >/dev/null 2>&1 # XUI_SWITCHER
```

如果你的 PHP 路径不是 `/usr/bin/php`，请改成服务器上的实际 PHP 路径。

## allow_subpath.sh 的作用

`allow_subpath.sh` 是一个 Nginx 子路径放行辅助脚本。

正常部署时通常不需要使用它。

只有在以下情况才可能需要：

- `/xui-switcher/` 打不开
- 访问面板出现 403
- 宝塔、Nginx 或站点防护规则拦截了子路径
- 网站根路径可以打开，但 `/xui-switcher/` 被安全规则拦住

使用示例：

```bash
bash allow_subpath.sh /www/server/panel/vhost/nginx/你的域名.conf block_client
```

第一个参数是 Nginx 站点配置文件路径。

第二个参数是站点配置里用于拦截访问的变量名，不同服务器可能不一样。常见示例是 `block_client`。

如果你的 `/xui-switcher/` 可以正常打开，就不需要管 `allow_subpath.sh`。

## 运行要求

- PHP 8.0 或以上
- Nginx 或 Apache
- 服务器需要允许 PHP 读写 `data` 目录
- 如果使用面板安装、防火墙管理等功能，需要服务器支持 SSH 命令执行

## 目录说明

```text
index.php                 主面板页面
lib.php                   核心逻辑
qr.php                    二维码生成
cron.php                  后台任务入口
data/                     状态和配置目录
vendor/                   PHP 依赖
composer.json             依赖配置
composer.lock             依赖锁定文件
install_cron.sh           定时任务安装脚本
nginx_xui_switcher.conf   Nginx 子路径配置示例
allow_subpath.sh          子路径辅助脚本
```

## 安全提醒

本项目默认初始密码为 `123456`，请部署后第一时间修改。

如果你公开部署面板，建议限制访问 IP，避免管理入口暴露给所有人。

## 适合人群

- 使用 3x-ui 的用户
- 需要多服务器组网的用户
- 需要管理多跳 VPN 链路的用户
- 需要快速创建单节点入口的用户
- 需要统一管理防火墙规则的用户
