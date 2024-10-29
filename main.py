import pandas as pd
import re
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress
import logging

# 配置日志记录
log_file = 'log.txt'
if os.path.exists(log_file):
    open(log_file, 'w').close()  # 清空旧的日志内容

logging.basicConfig(filename=log_file, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

special_file_keyword = "little-snitch-blocklist"
MAP_DICT = {
    'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 'IP-CIDR': 'ip_cidr',
    'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'IP6-CIDR': 'ip_cidr', 'SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip', 
    'DST-PORT': 'port', 'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex", "DOMAIN-REGEX": "domain_regex"
}

def read_yaml_from_url(url):
    response = requests.get(url)
    response.raise_for_status()
    yaml_data = yaml.safe_load(response.text)
    logging.info(f"成功读取 YAML 数据 {url}")
    return yaml_data

def read_list_from_url(url):
    try:
        df = pd.read_csv(url, header=None, names=['pattern', 'address', 'other', 'other2', 'other3'])
        logging.info(f"成功读取列表数据 {url}")
    except Exception as e:
        logging.error(f"读取 {url} 时出错：{e}")
        return pd.DataFrame(), []

    filtered_rows = []
    rules = []

    if 'AND' in df['pattern'].values:
        and_rows = df[df['pattern'].str.contains('AND', na=False)]
        for _, row in and_rows.iterrows():
            rule = {"type": "logical", "mode": "and", "rules": []}
            pattern = ",".join(row.values.astype(str))
            components = re.findall(r'\((.*?)\)', pattern)
            for component in components:
                for keyword in MAP_DICT.keys():
                    if keyword in component:
                        match = re.search(f'{keyword},(.*)', component)
                        if match:
                            value = match.group(1)
                            rule["rules"].append({MAP_DICT[keyword]: value})
            rules.append(rule)
    for index, row in df.iterrows():
        if 'AND' not in row['pattern']:
            filtered_rows.append(row)
    df_filtered = pd.DataFrame(filtered_rows, columns=['pattern', 'address', 'other', 'other2', 'other3'])
    return df_filtered, rules

def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None

def parse_and_convert_to_dataframe(link):
    rules = []
    try:
        if link.endswith('.yaml') or link.endswith('.txt'):
            yaml_data = read_yaml_from_url(link)
            rows = []
            if not isinstance(yaml_data, str):
                items = yaml_data.get('payload', [])
            else:
                lines = yaml_data.splitlines()
                line_content = lines[0]
                items = line_content.split()
            for item in items:
                address = item.strip("'")
                if ',' not in item:
                    if is_ipv4_or_ipv6(item):
                        pattern = 'IP-CIDR'
                    else:
                        if address.startswith('+') or address.startswith('.'):
                            pattern = 'DOMAIN-SUFFIX'
                            address = address[1:]
                            if address.startswith('.'):
                                address = address[1:]
                        else:
                            pattern = 'DOMAIN'
                else:
                    pattern, address = item.split(',', 1)
                if pattern == "IP-CIDR" and "no-resolve" in address:
                    address = address.split(',', 1)[0]
                rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
            df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
        else:
            df, rules = read_list_from_url(link)
    except Exception as e:
        logging.error(f"解析 {link} 时出错：{e}")
        return pd.DataFrame(), []

    logging.info(f"成功解析链接 {link}")
    return df, rules


def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

def parse_special_file(link, output_directory):
    """
    从指定链接解析特殊文件，提取 denied-remote-domains 数据，并将其写入 JSON 文件。

    参数:
        link (str): 要解析的文件链接。
        output_directory (str): JSON 文件的输出目录。
    
    返回:
        None
    """
    try:
        response = requests.get(link)
        response.raise_for_status()  # 确保请求成功
        
        # 假设返回的数据是 JSON 格式
        data = response.json()
        
        # 提取 denied-remote-domains
        denied_domains = data.get("denied-remote-domains", [])
        
        if not denied_domains:
            logging.warning(f"从 {link} 未找到 'denied-remote-domains' 数据")
            return None
        
        # 创建输出目录（如果不存在）
        os.makedirs(output_directory, exist_ok=True)
        
        # 将 denied_domains 写入 JSON 文件
        json_output_path = os.path.join(output_directory, 'fabston-privacylist.json')
        
        # 使用 sort_dict 函数对数据进行排序
        sorted_data = sort_dict({"denied-remote-domains": denied_domains})
        
        with open(json_output_path, 'w') as json_file:
            json.dump(sorted_data, json_file, indent=4)
            logging.info(f"成功处理链接 {link} 并生成 JSON 文件 {json_output_path}")

        # 生成 SRS 文件
        srs_path = json_output_path.replace(".json", ".srs")
        os.system(f"sing-box rule-set compile --output {srs_path} {json_output_path}")
        logging.info(f"成功生成 SRS 文件 {srs_path}")

    except requests.exceptions.RequestException as e:
        logging.error(f'处理特定链接 {link} 时出错：{e}')
    except json.JSONDecodeError:
        logging.error(f"解析 JSON 时出错，从链接 {link} 读取的内容可能不是有效的 JSON。")
    except Exception as e:
        logging.error(f"处理链接 {link} 时发生未知错误：{e}")
        

def parse_list_file(link, output_directory):
    try:
        if "special_file_keyword" in link
            logging.info("检测到关键字特定链接！")
            return parse_special_file(link, output_directory)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = list(executor.map(parse_and_convert_to_dataframe, [link]))
            dfs = [df for df, rules in results]
            rules_list = [rules for df, rules in results]
            df = pd.concat(dfs, ignore_index=True)

        df = df[~df['pattern'].str.contains('IP-CIDR6')].reset_index(drop=True)
        df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)
        df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)
        df = df.drop_duplicates().reset_index(drop=True)
        df['pattern'] = df['pattern'].replace(MAP_DICT)
        os.makedirs(output_directory, exist_ok=True)

        result_rules = {"version": 1, "rules": []}
        domain_entries = []
        for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
            if pattern == 'domain_suffix':
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)
            elif pattern == 'domain':
                domain_entries.extend([address.strip() for address in addresses])
            else:
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)

        domain_entries = list(set(domain_entries))
        if domain_entries:
            result_rules["rules"].insert(0, {'domain': domain_entries})

        file_name = os.path.join(output_directory, f"{os.path.basename(link).split('.')[0]}.json")
        with open(file_name, 'w', encoding='utf-8') as output_file:
            result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
            result_rules_str = result_rules_str.replace('\\\\', '\\')
            output_file.write(result_rules_str)

        srs_path = file_name.replace(".json", ".srs")
        os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")
        logging.info(f"成功处理链接 {link} 并生成 JSON 文件 {file_name}")
        return file_name
    except Exception as e:
        logging.error(f'获取链接 {link} 出错：{e}')
        return None

with open("../links.txt", 'r') as links_file:
    links = links_file.read().splitlines()

links = [l for l in links if l.strip() and not l.strip().startswith("#")]

output_dir = "./"
result_file_names = []

for link in links:
    result_file_name = parse_list_file(link, output_directory=output_dir)
    result_file_names.append(result_file_name)
