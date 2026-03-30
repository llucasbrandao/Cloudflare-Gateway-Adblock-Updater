# Cloudflare Gateway Global Adblock Updater
import requests
import aiohttp
import asyncio
import os
import sys
import time
import logging
import re
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

api_token = os.environ.get('CLOUDFLARE_API_TOKEN')
account_id = os.environ.get('CLOUDFLARE_ACCOUNT_ID')

if not api_token or not account_id:
    logger.error("🚫 Missing API token or account ID.")
    sys.exit(1)

REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', '30'))
MAX_RETRIES = 3
BACKOFF_FACTOR = 5
CHUNK_SIZE = 1000
API_DELAY = 0.1
MAX_CONCURRENT_REQUESTS = int(os.environ.get('MAX_CONCURRENT_REQUESTS', '25'))
Fresh_Start = os.environ.get('FRESH_START', 'false').lower() == 'true'

base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
headers = {
    "Authorization": f"Bearer {api_token}",
    "Content-Type": "application/json"
}

session = requests.Session()
session.headers.update(headers)

# Add or remove lists here
blocklists = [
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/pro.plus-onlydomains.txt",
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/tif-onlydomains.txt"
]

def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253: return False
    return bool(re.match(r'(?i)^([a-z0-9]+(-+[a-z0-9]+)*\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', domain.lower()))

def chunker(seq: List[str], size: int):
    for i in range(0, len(seq), size): yield seq[i:i + size]

def api_request(method: str, url: str, data: Optional[Dict] = None) -> requests.Response:
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            kwargs = {"timeout": REQUEST_TIMEOUT}
            if data: kwargs["json"] = data
            response = getattr(session, method.lower())(url, **kwargs)
            if response.status_code == 429:
                time.sleep(int(response.headers.get('Retry-After', BACKOFF_FACTOR)))
                continue
            if response.status_code >= 500 and attempt < MAX_RETRIES:
                time.sleep(BACKOFF_FACTOR)
                continue
            return response
        except Exception as e:
            if attempt == MAX_RETRIES: raise e
            time.sleep(BACKOFF_FACTOR)

def get_all_paginated(endpoint: str) -> List[Dict]:
    all_items, page, per_page = [], 1, 100
    while True:
        resp = api_request('GET', f"{endpoint}?per_page={per_page}&page={page}").json()
        items = resp.get('result') or []
        all_items.extend(items)
        if page * per_page >= resp.get('result_info', {}).get('total_count', 0) or not items: break
        page += 1
        time.sleep(API_DELAY)
    return all_items

async def async_api_request(session: aiohttp.ClientSession, method: str, url: str, data: Optional[Dict] = None) -> Dict:
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            kwargs = {"timeout": aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)}
            if data: kwargs["json"] = data
            async with getattr(session, method.lower())(url, **kwargs) as response:
                if response.status == 429:
                    await asyncio.sleep(int(response.headers.get('Retry-After', BACKOFF_FACTOR)))
                    continue
                if response.status >= 500 and attempt < MAX_RETRIES:
                    await asyncio.sleep(BACKOFF_FACTOR)
                    continue
                if response.status == 400 and method.upper() in ('PATCH', 'POST', 'PUT'):
                    result = await response.json()
                    if any('not found in list' in e.get('message', '') for e in result.get('errors', [])):
                        return {'status': response.status, 'data': result}
                return {'status': response.status, 'data': await response.json()}
        except Exception as e:
            if attempt == MAX_RETRIES: raise e
            await asyncio.sleep(BACKOFF_FACTOR)

async def async_delete_lists_batch(lists: List[Dict]):
    sem = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    async with aiohttp.ClientSession(headers=headers) as s:
        async def delete(lst):
            async with sem:
                res = await async_api_request(s, 'DELETE', f"{base_url}/lists/{lst['id']}")
                if res['status'] == 200: logger.info(f"🧹 Deleted: {lst['name']}")
                await asyncio.sleep(API_DELAY)
        await asyncio.gather(*(delete(l) for l in lists))

async def async_create_list(session, sem, name, desc, items):
    async with sem:
        data = {"name": name, "type": "DOMAIN", "description": desc, "items": [{"value": d} for d in items]}
        res = await async_api_request(session, 'POST', f"{base_url}/lists", data)
        await asyncio.sleep(API_DELAY)
        if res['status'] == 200 and res['data'].get('success'):
            logger.info(f"🛠️ Created: {name}")
            return res['data']['result']['id']
        return None

async def async_get_list_items(session, list_id):
    all_items, page = [], 1
    while True:
        res = await async_api_request(session, 'GET', f"{base_url}/lists/{list_id}/items?per_page=1000&page={page}")
        if res['status'] != 200: break
        items = res['data'].get('result') or []
        all_items.extend(i['value'] for i in items)
        if page * 1000 >= res['data'].get('result_info', {}).get('total_count', 0) or not items: break
        page += 1
        await asyncio.sleep(API_DELAY)
    return all_items

async def async_patch_list(session, sem, list_id, name, remove, append):
    if not remove and not append: return True
    async with sem:
        payload = {}
        if remove: payload['remove'] = remove
        if append: payload['append'] = [{'value': d} for d in append]
        res = await async_api_request(session, 'PATCH', f"{base_url}/lists/{list_id}", payload)
        await asyncio.sleep(API_DELAY)
        if res['status'] == 200:
            logger.info(f"♻️ Patched {name}: -{len(remove)} / +{len(append)}")
            return True
        return False

def update_policy(list_ids, total_domains, cached_rules):
    name = "Unified Blocklist"
    expr = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in list_ids])
    payload = {
        "name": name, "description": f"Global Unified Blocklist ({total_domains} domains)",
        "action": "block", "enabled": True, "filters": ["dns"], "precedence": 10000, "traffic": expr
    }
    existing = next((r for r in cached_rules if r['name'] == name), None)
    if existing:
        logger.info("✍️ Updating policy...")
        api_request('PUT', f"{base_url}/rules/{existing['id']}", payload)
    else:
        logger.info("✍️ Creating policy...")
        api_request('POST', f"{base_url}/rules", payload)

def run():
    logger.info("🎬 Starting Global Download & Deduplication...")
    global_domains = set()
    
    for url in blocklists:
        try:
            logger.info(f"⬇️ Downloading: {url}")
            resp = requests.get(url, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#') and is_valid_domain(line):
                        global_domains.add(line)
        except Exception as e:
            logger.error(f"⚠️ Failed to download {url}: {e}")

    total_target = len(global_domains)
    logger.info(f"🎯 Total UNIQUE domains globally: {total_target:,}")

    if not global_domains:
        logger.error("🚫 No domains fetched. Exiting.")
        return

    logger.info("📥 Caching Cloudflare state...")
    cached_rules = get_all_paginated(f"{base_url}/rules")
    cached_lists = get_all_paginated(f"{base_url}/lists")
    prefix = "Unified_List_"
    existing_lists = sorted([l for l in cached_lists if l['name'].startswith(prefix)], key=lambda x: int(x['name'].split('_')[-1]) if x['name'].split('_')[-1].isdigit() else 999)

    # FRESH START LOGIC HERE
    if Fresh_Start:
        logger.info("‼ FRESH START ENABLED: Removing old policy and lists...")
        existing_policy = next((r for r in cached_rules if r['name'] == "Unified Blocklist"), None)
        
        if existing_policy:
            logger.info("🗑️ Deleting old policy to release lists...")
            api_request('DELETE', f"{base_url}/rules/{existing_policy['id']}")
            cached_rules = [r for r in cached_rules if r['id'] != existing_policy['id']]
        
        if existing_lists:
            logger.info("🗑️ Deleting all old unified lists...")
            asyncio.run(async_delete_lists_batch(existing_lists))
            existing_lists = [] # Clears the list to force clean recreation

    remote_map, list_caps = {}, {}
    if existing_lists:
        logger.info("📡 Fetching current list contents...")
        async def fetch_all():
            async with aiohttp.ClientSession(headers=headers) as s:
                tasks = [async_get_list_items(s, l['id']) for l in existing_lists]
                results = await asyncio.gather(*tasks)
                for i, doms in enumerate(results):
                    list_caps[existing_lists[i]['id']] = len(doms)
                    for d in doms: remote_map[d] = existing_lists[i]['id']
        asyncio.run(fetch_all())

    current_remote = set(remote_map.keys())
    to_remove = current_remote - global_domains
    to_add = list(global_domains - current_remote)

    logger.info(f"⚖️ Diff: ➖ Remove: {len(to_remove)} | ➕ Add: {len(to_add)}")

    removals_by_list = {}
    for d in to_remove:
        lid = remote_map[d]
        removals_by_list.setdefault(lid, []).append(d)

    patches = {}
    for lid, doms in removals_by_list.items():
        patches[lid] = {'remove': doms, 'append': []}
        list_caps[lid] -= len(doms)

    for lst in existing_lists:
        lid = lst['id']
        space = CHUNK_SIZE - list_caps.get(lid, 0)
        if space > 0 and to_add:
            chunk = to_add[:space]
            to_add = to_add[space:]
            patches.setdefault(lid, {'remove': [], 'append': []})['append'] = chunk
            list_caps[lid] += len(chunk)

    if patches:
        logger.info(f"⚡ Executing {len(patches)} patches...")
        async def exec_patches():
            sem = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
            async with aiohttp.ClientSession(headers=headers) as s:
                tasks = [async_patch_list(s, sem, lid, lid, p['remove'], p['append']) for lid, p in patches.items()]
                await asyncio.gather(*tasks)
        asyncio.run(exec_patches())

    new_list_ids = []
    if to_add:
        logger.info(f"🏗️ Creating new lists for {len(to_add)} domains...")
        chunks = list(chunker(to_add, CHUNK_SIZE))
        start_idx = max([int(l['name'].split('_')[-1]) for l in existing_lists] + [0])
        
        async def create_new():
            sem = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
            async with aiohttp.ClientSession(headers=headers) as s:
                tasks = []
                for i, chunk in enumerate(chunks):
                    idx = start_idx + 1 + i
                    tasks.append(async_create_list(s, sem, f"{prefix}{idx}", f"Unified chunk {idx}", chunk))
                return await asyncio.gather(*tasks)
        new_list_ids = [lid for lid in asyncio.run(create_new()) if lid]

    final_ids = [l['id'] for l in existing_lists if list_caps.get(l['id'], 0) > 0] + new_list_ids
    empty_lists = [l for l in existing_lists if list_caps.get(l['id'], 0) == 0]

    update_policy(final_ids, total_target, cached_rules)

    if empty_lists:
        logger.info(f"🧹 Deleting {len(empty_lists)} empty lists...")
        asyncio.run(async_delete_lists_batch(empty_lists))

    logger.info("✅ Update complete!")

if __name__ == "__main__":
    run()
