#!/usr/bin/env python3
import asyncio
import csv
import time
import random
from urllib.parse import urlparse
from collections import defaultdict

import numpy as np
import aiohttp
import redis.asyncio as aioredis
import motor.motor_asyncio
import pymongo.errors
from bs4 import BeautifulSoup
from aiohttp import BasicAuth
import requests
import aiohttp_socks

asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ================= CONFIG =================
CSV_FILE = 'my_crawler/google_url.csv'
REDIS_URL = 'redis://localhost:6379/0'
TASK_LIST = 'crawler:tasks'

CONCURRENCY = 100
ROUNDS = 5
TIMEOUT = 20
BATCH_SIZE = 200
MONGO_URI = 'mongodb://localhost:27017'
MONGO_DB_PREFIX = 'results_'
MONGO_SPLIT_THRESHOLD = 500_000

# ★ 测试条数限制
TEST_LIMIT = 10
# http://t18217199987874:5aetv7dd@s858.kdltps.com:15818/
PROXY = 's858.kdltps.com:15818'
USERNAME = 't18217199987874'
PASSWORD = '5aetv7dd'

proxy = f"http://{USERNAME}:{PASSWORD}@{PROXY}"


HEADERS = {
    "Accept-Encoding":"Gzip", # 使用gzip压缩传输数据让访问更快
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36"
}



mongo = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
initial_task_count = 0
failure_count = 0
lock = asyncio.Lock()

def get_db(task_id):
    db_index = task_id // MONGO_SPLIT_THRESHOLD
    return mongo[f"{MONGO_DB_PREFIX}{db_index}"]

async def html_parser(session, idx, host):
    global failure_count

    url = f'https://whois.aizhan.com/{host}/'
    
    try:
        # # 添加随机延迟避免被封
        await asyncio.sleep(random.uniform(5, 10))
        
        async with session.get(url, proxy = proxy, headers = HEADERS) as response:
            if response.status != 200:
                print(f"HTTP错误 {response.status}: {host}")
                failure_count += 1
                return None
                
            html = await response.text()
            return parse_whois_data(html, idx, host)
            
    except asyncio.TimeoutError:
        print(f"请求超时: {host}")
        failure_count += 1
        return None
    except aiohttp.ClientError as e:
        print(f"网络错误 {host}: {e}")
        failure_count += 1
        return None
    except Exception as e:
        print(f"解析错误 {host}: {e}")
        failure_count += 1
        return None
    
def parse_whois_data(html, idx, host):
    bs = BeautifulSoup(html, 'html.parser')
    rows = bs.select('div.whois-infos.box > div.table > table >tr')

    yuming = zhuceshang = canzhaoye = jigoumingchen = jigouyouxiang = chuangjian = gengxin = guoqi = ""
    yumingfuwuqi = []
    DNSfuwuqi = []
    yumingzhuangtai = []
    for row in rows:
        tds = row.find_all('td')
        if len(tds) < 2:
            continue
            
        key = tds[0].get_text(strip=True)
        value = tds[1].get_text(strip=True)
        
        if key == '域名':
            index = value.find('委')
            if index != -1:
                yuming = value[:index]
            else:
                yuming = value
        elif key == '注册商':
            zhuceshang = value
        elif key == '参照页':
            canzhaoye = value
        elif key == '域名持有人/机构名称':
            index = value.find('反')
            if index != -1:
                jigoumingchen = value[:index]
            else:
                jigoumingchen = value
        elif key == '域名持有人/机构邮箱':
            index = value.find('反')
            if index != -1:
                jigouyouxiang = value[:index]
            else:
                jigouyouxiang = value
        elif key == '创建时间':
            chuangjian = value
        elif key == '更新时间':
            gengxin = value
        elif key == '过期时间':
            guoqi = value
        elif key == '域名服务器':
            yumingfuwuqi.append(value)
        elif key == 'DNS服务器':
            DNSfuwuqi.append(value)
        elif key == '域名状态':
            yumingzhuangtai.append(value)
    try:
        contents = bs.select('div.whois-content.box > div.content')[0].text
        index = contents.find('展')
        if index != -1:
            contents = contents[:index]
        else:
            contents = contents
    except:
        contents = ''
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    record = {
            '_id': idx,
            'host': host,
            '域名': yuming,
            '注册商': zhuceshang,
            '参照页': canzhaoye,
            '域名持有人/机构名称': jigoumingchen,
            '域名持有人/机构邮箱': jigouyouxiang,
            '创建时间': chuangjian,
            '更新时间': gengxin,
            '过期时间': guoqi,
            '域名服务器': yumingfuwuqi,
            'DNS服务器': DNSfuwuqi,
            '域名状态': yumingzhuangtai,
            '详细信息': contents,
            'crawl_timestamp': ts
        }
    return record

# ------ Mongo 批量写入 ------
async def db_writer(queue: asyncio.Queue):
    whois = []
    while True:
        item = await queue.get()
        if item is None:
            break

        whois.append(item['record'])
        if len(whois) >= BATCH_SIZE:
            db = get_db(whois[0]['_id'])
            try:
                await db.whois.insert_many(whois, ordered=False)
            except Exception:
                pass
            whois.clear()

        queue.task_done()

    if whois:
        db = get_db(whois[0]['_id'])
        try:
            await db.whois.insert_many(whois, ordered=False)
        except Exception:
            pass


# ------ Worker：从 Redis 取任务并抓取 ------
async def worker(name, redis_conn, session, queue: asyncio.Queue):
    while True:
        entry = await redis_conn.rpop(TASK_LIST)
        if not entry:
            break

        idx_str, host = entry.decode().split(' ',1)
        idx = int(idx_str)
        record = await html_parser(session, idx, host)

        await queue.put({'success': True, 'record': record})


# ------ host 推送 ------
async def push_hosts(host_list, redis_conn):
    pipe = redis_conn.pipeline()
    for idx, host in host_list:
        entry = f'{idx} {host}'
        pipe.lpush(TASK_LIST,entry)
    await pipe.execute()


# ------ 主流程 ------
async def main():
    global initial_task_count

    redis_conn = aioredis.Redis.from_url(REDIS_URL, decode_responses=False)

    db0 = mongo[f"{MONGO_DB_PREFIX}0"]
    if await db0.whois.count_documents({}) > 0:
        await db0.whois.delete_many({})
        print("Cleared existing data in whois collection before test")

    # 读取 CSV 并按 host 分桶（限制 TEST_LIMIT 条）
    host_list = []
    with open(CSV_FILE, newline='', encoding='utf-8') as f:  # 编码更稳
        reader = csv.reader(f)
        next(reader, None)
        for idx, (url,) in enumerate(reader):
            if TEST_LIMIT and idx >= TEST_LIMIT:
                break
            host = urlparse(url).netloc
            if not host in host_list:
                host_list.append((initial_task_count,host))
                initial_task_count += 1

    # 推入 Redis
    await push_hosts(host_list, redis_conn)
    print(f"Initialized with {initial_task_count} tasks (test limit={TEST_LIMIT}).")

    # 启动写库消费者 + 抓取 worker
    write_queue = asyncio.Queue()
    db_task = asyncio.create_task(db_writer(write_queue))

    connector = aiohttp.TCPConnector(ssl=False,keepalive_timeout=0)
    timeout = aiohttp.ClientTimeout(total=None)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        workers = [
            asyncio.create_task(worker(f"w{i}", redis_conn, session, write_queue))
            for i in range(CONCURRENCY)
        ]
        start = time.monotonic()
        await asyncio.gather(*workers)
        await write_queue.put(None)
        await db_task
        elapsed = time.monotonic() - start

    # 统计与“运行成功”标志
    db0 = mongo[f"{MONGO_DB_PREFIX}0"]
    succ = await db0.whois.count_documents({})
    remaining = await redis_conn.llen(TASK_LIST)
    rps = (initial_task_count / elapsed) if elapsed > 0 else 0.0

    print(f"\nTest Complete: {initial_task_count} hosts "
          f"({succ} success) in {elapsed:.2f}s, avg {rps:.2f} req/s")

    # ★ 运行状态标志
    print(f"tasks={initial_task_count}, ok={succ}, remaining={remaining}\n")


if __name__ == '__main__':
    asyncio.run(main())






