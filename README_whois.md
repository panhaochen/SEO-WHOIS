# Whois 域名信息异步爬虫

## 简介
本项目用于异步批量抓取域名的 Whois 信息，支持高并发、代理池、Redis 任务队列、MongoDB 存储。适合大规模域名信息采集与分析。

## 主要功能
- 从 CSV 文件读取待采集域名
- 使用 Redis 管理任务队列
- aiohttp 异步请求，支持代理和身份认证
- 自动解析 Whois 页面内容
- MongoDB 分库分表存储结果
- 支持批量写入和高并发抓取

## 使用方法

1. 安装依赖
   ```bash
   pip install aiohttp motor redis beautifulsoup4 numpy pymongo
   ```

2. 配置参数
   - 修改 `CSV_FILE` 路径为你的域名列表
   - 设置代理账号、密码、地址
   - 配置 MongoDB、Redis 地址

3. 运行脚本
   ```bash
   python host_whois_crawler-test.py
   ```

## 代理池检测
如需检测代理池可用性，可参考如下方法：
- 用 aiohttp 异步请求 httpbin.org/ip，筛选出可用代理
- 定期检测并剔除失效代理

## 注意事项
- 高并发抓取易被目标网站封禁，建议合理设置并发和延迟
- 代理质量影响采集成功率
- MongoDB 存储量大时建议分库分表

## 适用场景
- 域名资产分析
- Whois信息采集
- 网络安全、品牌保护
