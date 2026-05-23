#!/usr/bin/env python3
"""
0day/1day RCE vulnerability intelligence aggregator.

Sources (17):
    Vendor PSIRT (Fortinet/PaloAlto/Cisco/MSRC) + Sploitus exploit feeds
    + research teams (watchTowr/ZDI/Horizon3/Rapid7) + CISA KEV
    + vuln databases (Chaitin/ThreatBook) + GitHub PoC search

Flow:
    fetch → dedup (SQLite, CVE/hash key) → RCE keyword score → Telegram push

CLI:
    python vuln_monitor.py              # fetch (default)
    python vuln_monitor.py query ...    # search DB
    python vuln_monitor.py brief ...    # notification-friendly output
    python vuln_monitor.py stats        # database overview
    python vuln_monitor.py rebuild      # backfill incomplete records
"""
import os
import re
import sys
import json
import time
import html
import hashlib
import logging
import sqlite3
import argparse
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import requests

try:
    from config_utils import CONFIG_FILE, config_exists, data_dir_from_config, ensure_config_file, load_config
except ModuleNotFoundError:
    from .config_utils import CONFIG_FILE, config_exists, data_dir_from_config, ensure_config_file, load_config


# ================== CONFIG ==================
CFG = load_config()
DATA_DIR = data_dir_from_config(CFG)
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_FILE        = DATA_DIR / "vuln_cache.db"
_JSON_LEGACY   = DATA_DIR / "vuln_cache.json"   # migration source
LOCK_FILE      = DATA_DIR / "vuln_monitor.lock"
ALERT_STATE    = DATA_DIR / "vuln_alert_state.json"
LOG_FILE       = DATA_DIR / "vuln_monitor.log"
CACHE_TTL_DAYS = 60
ITEM_PER_FEED  = 50
PUSH_SLEEP_SEC = 1.5
REQUEST_TIMEOUT = int(CFG["network"]["request_timeout"])
LOG_MAX_BYTES  = 5 * 1024 * 1024
LOG_BACKUPS    = 5
ALERT_COOLDOWN_SEC = 3600
PROXY = CFG["network"]["https_proxy"]
TG_BOT_TOKEN = CFG["notify_telegram"]["bot_token"]
TG_CHAT_IDS = CFG["notify_telegram"]["chat_ids"]
GH_TOKENS = list(CFG["github"]["tokens"])
NVD_API_KEY = CFG["nvd"]["api_key"]
LLM_CFG = CFG["llm"]
LLM_PROVIDER = LLM_CFG["provider"]
LLM_API_KEY = LLM_CFG["api_key"]
LLM_MODEL = LLM_CFG["model"]
LLM_BASE_URL = LLM_CFG["base_url"]
LLM_TEMPERATURE = float(LLM_CFG["temperature"])
LLM_MAX_TOKENS = int(LLM_CFG["max_tokens"])
LLM_TIMEOUT = int(LLM_CFG["timeout"])
LLM_MAX_CONTEXT = int(LLM_CFG["max_context"])
LLM_REASONING = LLM_CFG["reasoning_effort"]
LLM_TOP_P = float(LLM_CFG["top_p"])
GHSA_MAX_ITEMS = 300
FETCH_PROGRESS_EVERY = 200
MAX_RELATED_POC_URLS = 2
_RUNTIME_ITEM_PER_FEED = ITEM_PER_FEED
_RUNTIME_GHSA_MAX_ITEMS = GHSA_MAX_ITEMS


def _feed_cap():
    return _RUNTIME_ITEM_PER_FEED


def _ghsa_cap():
    return _RUNTIME_GHSA_MAX_ITEMS


def _set_fetch_runtime(test_mode=False):
    global _RUNTIME_ITEM_PER_FEED, _RUNTIME_GHSA_MAX_ITEMS
    if test_mode:
        _RUNTIME_ITEM_PER_FEED = min(3, ITEM_PER_FEED)
        _RUNTIME_GHSA_MAX_ITEMS = min(20, GHSA_MAX_ITEMS)
    else:
        _RUNTIME_ITEM_PER_FEED = ITEM_PER_FEED
        _RUNTIME_GHSA_MAX_ITEMS = GHSA_MAX_ITEMS

RSS_FEEDS = [
    # ---- vendor PSIRT ----
    # Citrix, F5, Assetnote intentionally omitted: no working RSS as of 2026.
    #   Citrix — Salesforce SPA (covered by watchTowr + KEV JSON + Sploitus below).
    #   F5     — my.f5.com SPA (covered by Sploitus below).
    #   Assetnote — dropped RSS after Searchlight acquisition.
    ("Fortinet",    "https://www.fortiguard.com/rss/ir.xml"),
    ("PaloAlto",    "https://security.paloaltonetworks.com/rss.xml"),
    ("Cisco",       "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"),
    ("MSRC",        "https://api.msrc.microsoft.com/update-guide/rss"),
    # ---- Sploitus keyword feeds (fill PSIRT gaps with exploit/PoC signal) ----
    ("Sploitus_Citrix",   "https://sploitus.com/rss?query=citrix"),
    ("Sploitus_Ivanti",   "https://sploitus.com/rss?query=ivanti"),
    ("Sploitus_F5",       "https://sploitus.com/rss?query=f5+big-ip"),
    # ---- research teams (vuln-focused, not blogs/marketing) ----
    ("watchTowr",   "https://labs.watchtowr.com/rss/"),
    ("ZDI",         "https://www.zerodayinitiative.com/rss/published/"),
    ("Horizon3",    "https://www.horizon3.ai/feed/"),
    ("Rapid7",      "https://www.rapid7.com/blog/rss/"),
    ("DailyCVE",    "https://dailycve.com/feed"),
    # VMware (blog/marketing, 0% CVE) — removed
    # ProjectDisc (product marketing, 0% CVE) — removed
    # GreyNoise (trend analysis, 10% CVE) — removed
    # SentinelLabs (research blog, 0% CVE) — removed
    # XuanwuLab (academic/research, low CVE density) — removed
]

TEST_RSS_FEEDS = [
    ("Fortinet",    "https://www.fortiguard.com/rss/ir.xml"),
    ("PaloAlto",    "https://security.paloaltonetworks.com/rss.xml"),
    ("Cisco",       "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"),
    ("MSRC",        "https://api.msrc.microsoft.com/update-guide/rss"),
    ("watchTowr",   "https://labs.watchtowr.com/rss/"),
    ("ZDI",         "https://www.zerodayinitiative.com/rss/published/"),
]

# CISA KEV uses a JSON endpoint (1500+ entries with structured fields, not RSS).
KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Chaitin Stack vuldb — hidden JSON API behind SafeLine WAF.
# Requires Referer/Origin headers; rate-limited (one call per fetch cycle is fine).
CHAITIN_API_URL = "https://stack.chaitin.com/api/v2/vuln/list/"

# ThreatBook (微步在线) — public homePage endpoint, returns premium + highrisk vulns.
THREATBOOK_API_URL = "https://x.threatbook.com/v5/node/vul_module/homePage"


# ================== RCE PATTERNS ==================
RCE_PATTERNS = [
    # naming
    r"\bRCE\b", r"remote code execution", r"arbitrary (code|command) execution",
    r"execute arbitrary (code|command)", r"execution of arbitrary (code|command)",
    r"code injection", r"command injection", r"OS command injection",
    # Chinese
    r"远程代码执行", r"远程命令执行", r"代码执行漏洞", r"命令执行漏洞", r"任意代码执行", r"反序列化漏洞",
    # auth prerequisite
    r"unauthenticated", r"pre[- ]?auth(entication)?", r"\bunauth\b",
    r"no authentication (required|needed)", r"anonymous\s+(access|rce|exec)",
    # deserialization / injection
    r"deserializ(ation|ing)", r"insecure deserialization", r"unsafe deserialization",
    r"\bSSTI\b", r"server[- ]side template injection",
    r"\bSSRF\b.*(RCE|code exec|chain|gadget)",
    r"\bXXE\b.*(RCE|exec|chain)",
    r"SQL injection.*(RCE|xp_cmdshell|OS cmd|command|exec)",
    r"prototype pollution.*(RCE|exec|gadget|chain)",
    r"\bJNDI\b", r"\bOGNL\b",
    # memory corruption
    r"memory corruption", r"stack[- ]?(based )?(buffer )?overflow", r"heap[- ]?(based )?(buffer )?overflow",
    r"use[- ]after[- ]free\b", r"\bUAF\b", r"double free",
    r"type confusion", r"out[- ]of[- ]bounds? (read|write)", r"\bOOB\b",
    r"integer overflow.*(exec|RCE|oob)",
    r"race condition.*(exec|RCE|kernel)",
    # file upload / traversal escalating to exec
    r"(unrestricted|arbitrary) file upload",
    r"任意文件上传", r"文件上传漏洞",
    r"(path|directory) traversal.*(write|overwrite|exec|upload|RCE)",
    r"webshell", r"arbitrary file write.*(exec|RCE|service)",
    # in-the-wild / value tags
    r"exploited in the wild", r"active(ly)? exploited", r"in[- ]the[- ]wild exploit",
    r"zero[- ]?day\b", r"\b0[- ]?day\b",
    r"exploit chain", r"full chain", r"pre[- ]auth.*(chain|code exec|RCE)",
    # famous exploit nicknames
    r"log4shell", r"spring4shell", r"proxyshell", r"proxylogon", r"proxynotshell",
    r"bluekeep", r"eternalblue", r"shellshock", r"heartbleed",
    r"zerologon", r"printnightmare", r"hivenightmare", r"follina",
    r"citrix\s?bleed", r"ghostcat", r"dirtycow", r"dirty pipe", r"looney tunables",
    r"regresshion", r"text4shell",
]


# ================== ASSET KEYWORDS ==================
ASSET_KEYWORDS = [
    # ----- boundary / VPN / firewall / remote access -----
    "citrix","netscaler","adc","citrix gateway","xenapp","xenmobile",
    "fortinet","fortigate","fortios","fortimanager","fortiproxy","fortiweb","fortiadc","fortinac","fortiswitch","fortianalyzer","fortiportal","fortisiem","fortisoar",
    "ivanti","pulse secure","pulse connect","connect secure","ivanti epm","endpoint manager","avalanche","neurons","moveit","goanywhere","ivanti csa",
    "palo alto","globalprotect","pan-os","prisma","expedition","cortex",
    "cisco asa","cisco ftd","firepower","anyconnect","cisco ios","ios-xe","ios-xr","nx-os","ise","ucs","dna center","webex","sd-wan","cisco meraki","cucm","callmanager",
    "f5","big-ip","big-iq","nginx plus",
    "checkpoint","check point","gaia","harmony",
    "sonicwall","sma","sma 100","sma 200","tz","nsa",
    "zyxel","juniper","junos","junos space","nsm",
    "barracuda","esg","barracuda waf","barracuda backup",
    "sophos","sfos","xg firewall","sophos utm",
    "watchguard","firebox","stormshield","kemp loadmaster","a10","array networks",
    "mikrotik","routeros","pfsense","opnsense",
    "aruba","clearpass","aruba controller","arubaos","arubaos-switch",
    "hp procurve","aruba cx","d-link","tp-link","tp link","totolink","netgear","asus router","draytek","vigor","tenda","linksys","ubiquiti","unifi","edgerouter",
    "rdp","remote desktop","terminal server","rds","rdweb","rdgateway","rdp client",
    "smb","smbv1","smbv2","smbv3","cifs","netbios",
    "openssh","ssh","vnc","telnet","winrm","rpc","dcom","rras",
    "teamviewer","anydesk","rustdesk","splashtop","logmein","connectwise","screenconnect","kaseya","vsa","n-able","n-central","atera","ninjarmm","dameware","dwservice",

    # ----- Microsoft -----
    "windows","windows server","windows 10","windows 11",
    "active directory","domain controller","ad cs","ad fs","adfs","ntlm","kerberos","ldap","dns server","dhcp","spn","gmsa",
    "exchange","exchange online","outlook","owa","ecp",
    "microsoft 365","office 365","office","word","excel","powerpoint","onenote","visio","access",
    "sharepoint","teams","skype","lync","onedrive","dynamics 365","dynamics crm","dynamics ax","dynamics nav",
    "iis","asp.net","aspnet",".net","dotnet","kestrel","msmq",
    "hyper-v","hyperv","wsl","wsa",
    "azure","azure ad","entra","entra id","intune","defender","defender for endpoint","defender for office","defender for identity",
    "wsus","sccm","mecm","configuration manager","system center","scom","scvmm",
    "print spooler","spoolsv","msdtc","mshtml","jscript","vbscript",
    "visual studio","vscode","msbuild","powershell","wmi","wmic",
    "mssql","sql server","ssrs","ssis","ssas",
    "edge","internet explorer","chakra","media foundation","windows codecs","directx","directshow",
    "smartscreen","applocker","mpengine","mpclient","windows defender",

    # ----- databases -----
    "mysql","mariadb","percona",
    "postgresql","postgres","timescaledb","redshift","greenplum",
    "oracle database","oracle db","oracle weblogic","oracle ebs","e-business suite","peoplesoft","jd edwards","oracle middleware","oracle fusion","opatch","oracle tuxedo",
    "mssql","sql server","sybase","sap ase",
    "mongodb","mongo","cosmosdb",
    "redis","keydb","dragonflydb","valkey",
    "elasticsearch","opensearch","elastic","kibana","logstash","beats","fleet",
    "clickhouse","cassandra","scylladb","hbase","accumulo",
    "influxdb","questdb","victoriametrics",
    "couchdb","couchbase","ravendb","firebird","foxpro",
    "memcached","etcd","consul",
    "neo4j","arangodb","janusgraph",
    "db2","informix","teradata","vertica","snowflake","databricks",
    "splunk","splunk enterprise","splunk universal forwarder","splunk phantom",
    "h2 database","h2 console","hsqldb","derby",
    "dm8","达梦","kingbase","人大金仓","tidb","oceanbase",

    # ----- virt / container / k8s / cloud-native -----
    "vmware","vcenter","esxi","vsphere","workstation","fusion","horizon","airwatch","workspace one","nsx","vrealize","aria","tanzu",
    "proxmox","xenserver","citrix hypervisor","xcp-ng","kvm","qemu","libvirt","virtualbox","parallels",
    "docker","docker engine","docker desktop","containerd","runc","cri-o","podman","buildah","skopeo","lxc","lxd","openvz",
    "kubernetes","k8s","kube-apiserver","kubelet","kube-proxy","kubeadm","helm","rancher","openshift","ocp","eks","aks","gke","kops",
    "istio","linkerd","envoy","cilium","calico","flannel","weave",
    "argo","argocd","flux","tekton","spinnaker","crossplane","knative",
    "nomad","consul","vault","terraform","terragrunt","packer","ansible","awx","ansible tower","chef","puppet","saltstack","salt master","rundeck",
    "openstack","nova","neutron","swift","keystone","cinder",
    "harbor","quay","nexus","artifactory","jfrog",

    # ----- CI/CD / devtools / package managers -----
    "jenkins","gitlab","gitea","gogs","github enterprise","github actions","bitbucket","bitbucket server","subversion","svn","mercurial","perforce","cvs",
    "teamcity","bamboo","circleci","buildkite","drone","woodpecker","concourse","travis","azure devops","vsts","tfs","azure pipelines",
    "docker registry","distribution",
    "sonarqube","sonar","snyk","fortify","checkmarx","veracode",
    "maven","gradle","npm","yarn","pnpm","pip","pypi","composer","packagist","rubygems","bundler","nuget","cargo","go modules","stack","mix",
    "phabricator","gerrit",

    # ----- web servers / middleware / app servers / MQ -----
    "apache","apache httpd","httpd","nginx","caddy","lighttpd","h2o","openresty","tengine",
    "tomcat","jetty","undertow","resin",
    "weblogic","websphere","jboss","wildfly","glassfish","payara","jeus",
    "kestrel",
    "haproxy","traefik","kong","apisix","tyk","apigee","wso2","zuul",
    "varnish","squid",
    "rabbitmq","activemq","kafka","pulsar","nats","mosquitto","emqx","nsq","zeromq",
    "zookeeper","bookkeeper",
    "apache shiro","shiro","apache dubbo","dubbo","dubbo admin","apache superset","apache airflow","airflow","apache nifi","nifi","apache druid","druid","apache kylin","kylin","apache ofbiz","ofbiz","apache solr","solr","apache flink","flink","apache spark","spark","apache storm","apache cxf","cxf","apache camel","camel","apache poi","poi","apache fineract","apache unomi","unomi","apache skywalking","apache seatunnel","seatunnel","apache linkis","linkis","apache streampipes","apache inlong","inlong","apache rocketmq","rocketmq","apache iotdb","apache atlas",

    # ----- frameworks / runtimes -----
    "log4j","log4j2","log4net","logback","slf4j",
    "spring","spring framework","spring boot","spring cloud","spring security","spring cloud gateway","spring cloud function","spring data","spring webflow",
    "struts","apache struts","struts2",
    "fastjson","jackson","xstream","snakeyaml","dom4j","xmlbeans",
    "laravel","symfony","codeigniter","yii","cakephp","zend","thinkphp","phalcon","slim",
    "django","flask","fastapi","tornado","pyramid","aiohttp","werkzeug","jinja","bottle",
    "rails","ruby on rails","sinatra","padrino",
    "express","koa","hapi","nestjs","next.js","nuxt","gatsby","sveltekit","remix","astro","fastify",
    "asp.net core","blazor","razor",
    "gin","echo","fiber","beego",
    "actix","axum","rocket","warp",
    "node.js","nodejs","deno","bun",
    "php","php-fpm","cgi","fastcgi",

    # ----- CMS / e-commerce / forum / wiki -----
    "wordpress","wp plugin","elementor","woocommerce",
    "drupal","joomla","magento","prestashop","opencart","shopify","bigcommerce","oscommerce",
    "phpmyadmin","phpbb","vbulletin","xenforo","mybb","discuz","dedecms","ecshop","eyoucms","phpcms","seacms","jeecms","siteserver","dotnetnuke","dnn","umbraco","kentico","sitecore","episerver","optimizely","adobe experience manager","aem",
    "typo3","concrete5","silverstripe","craft cms","ghost","strapi","directus","keystone","contentful","sanity",
    "mediawiki","dokuwiki","bookstack","xwiki","confluence","notion",
    "liferay","alfresco","nuxeo","documentum","sharepoint","owncloud","nextcloud","seafile","pydio",

    # ----- mail servers / collaboration -----
    "exim","postfix","sendmail","qmail","opensmtpd","dovecot","courier","cyrus",
    "zimbra","lotus domino","ibm domino","notes",
    "roundcube","horde","squirrelmail","afterlogic","icewarp","mdaemon","hmailserver","mailenable","open-xchange",
    "slack","mattermost","rocket.chat","discord","zulip","lark","feishu","dingtalk","wecom",
    "zoom","gotomeeting","bluejeans",
    "asterisk","freeswitch","kamailio","opensips","3cx","avaya","mitel","grandstream","yealink",

    # ----- backup / storage / file transfer -----
    "veeam","commvault","veritas","netbackup","backup exec","rubrik","cohesity","arcserve","unitrends","acronis","datto",
    "truenas","freenas","synology","dsm","qnap","qts","netapp","ontap","dell emc","isilon","data domain","powerprotect","nas","san",
    "accellion","fta","kiteworks","filecloud","crushftp","serv-u","wsftp","wing ftp","filezilla server","pureftpd","vsftpd","proftpd",

    # ----- monitoring / ITSM / RMM / inventory -----
    "zabbix","nagios","nagios xi","icinga","prtg","librenms","cacti","observium","op5","whatsup gold","checkmk","pandora fms",
    "prometheus","grafana","alertmanager","thanos","cortex","loki","tempo","jaeger","zipkin",
    "elk","graylog","logrhythm","qradar","arcsight","sumologic","datadog","new relic","appdynamics","dynatrace","instana","sentry",
    "manageengine","adselfservice","adaudit","desktop central","endpoint central","servicedesk plus","servicenow","bmc remedy","helix","jira service management","opmanager","applications manager","password manager pro","exchange reporter plus","mobile device manager plus","patch manager plus","access manager plus","pam360",
    "lansweeper","solarwinds","orion","sam","wpm","dameware",
    "snipe-it","osticket","glpi","otrs","zammad","spiceworks","freshservice",

    # ----- security products -----
    "crowdstrike","sentinelone","carbon black","cylance","defender atp","mde",
    "kaspersky","symantec","norton","mcafee","trend micro","bitdefender","eset","avast","avg","comodo","sophos central","fortiedr","cortex xdr","cortex xsoar","demisto","phantom","swimlane","tines",
    "360安全","奇安信","天擎","qax edr","深信服","sangfor","绿盟","venustech","安恒",
    "nessus","qualys","rapid7","insightvm","nexpose","tenable","acunetix","appscan","burp","burp suite","netsparker","invicti","nikto","wpscan",

    # ----- PKI / identity / secrets -----
    "keycloak","okta","auth0","ping identity","pingfederate","pingaccess","onelogin","duo","centrify","beyondtrust","cyberark","thycotic","delinea","hashicorp vault","conjur",
    "freeipa","openldap","389-ds","apache directory","samba","winbind","sssd",
    "certbot","acme","step-ca","ejbca","dogtag","venafi",
    "password manager","lastpass","1password","bitwarden","vaultwarden","keepass","passbolt","psono","enpass",

    # ----- archivers / parsers / media -----
    "winrar","7-zip","7zip","peazip","unrar","unzip","tar","zstd","bzip2","xz",
    "adobe reader","acrobat","foxit","pdfium","mupdf","poppler","sumatrapdf","nitro pdf",
    "imagemagick","graphicsmagick","libjpeg","libpng","libwebp","libtiff","libheif","libvips","exiftool","exiv2","libraw",
    "ffmpeg","libav","x264","x265","gstreamer","vlc","stagefright",
    "libxml","libxml2","libxslt","expat",
    "openssl","libssl","wolfssl","mbedtls","gnutls","nss","boringssl","libssh","libssh2",
    "curl","libcurl","wget","stunnel",

    # ----- browsers / engines -----
    "chrome","chromium","v8","blink","firefox","spidermonkey","safari","webkit","gecko","edge","brave","opera","vivaldi",
    "electron","cef","webview","webview2","wasmtime",

    # ----- BMC / firmware -----
    "ipmi","idrac","ilo","xclarity","ami megarac","megarac","bmc","redfish","cimc","imm",
    "bios","uefi","tpm","intel amt","intel me","amd psp",

    # ----- ICS / OT (optional) -----
    "siemens","simatic","wincc","step 7","rockwell","studio 5000","factorytalk","schneider","modicon","ecostruxure","mitsubishi","beckhoff","twincat","codesys","moxa","opc ua","ignition",

    # ----- cloud consoles / IAM -----
    "aws","amazon web services","ec2","s3","rds","lambda","iam","cloudfront","cloudformation","ecs","fargate",
    "azure","app service","aks","arc",
    "gcp","google cloud","gke","cloud run","cloud functions","anthos",
    "aliyun","alibaba cloud","tencent cloud","huawei cloud","qcloud","cloudflare","fastly","akamai","guardicore","incapsula","imperva",

    # ----- control panels / hosting -----
    "cpanel","plesk","webmin","usermin","virtualmin","ispconfig","directadmin","vestacp","hestiacp","cyberpanel","centos web panel","cwp","宝塔","baota","bt panel","aapanel","1panel","x-ui",
    "cockpit","unraid","homeassistant","home assistant",

    # ----- Chinese vendors / high-frequency pentest targets -----
    "用友","yonyou","金蝶","kingdee","seeyon","致远","泛微","weaver","e-office","e-cology","tongda","通达","landray","蓝凌","fastadmin",
    "h3c","华三","华为","huawei","ruijie","锐捷",

    # ----- misc media/home -----
    "jellyfin","plex","emby","sonarr","radarr","qbittorrent","transmission","deluge","sabnzbd","nzbget",
]


# ================== EXCLUDE ==================
EXCLUDE_PATTERNS = [
    r"\bXSS\b", r"cross[- ]site[- ]scripting",
    r"\bCSRF\b", r"cross[- ]site request forgery",
    r"clickjacking", r"open redirect", r"host header injection",
    r"information disclosure(?!.*(pre-?auth|unauth|RCE|chain|exploit|credential))",
    r"authenticated admin(?!.*(chain|bypass|RCE|0[- ]?day))",
    r"local privilege escalation(?!.*(chain|RCE|kernel 0[- ]?day))",
    r"\bDoS\b(?!.*(unauth|pre-?auth|chain|kernel))",
    r"denial of service(?!.*(unauth|pre-?auth|chain|kernel))",
    r"\bSSRF\b(?!.*(RCE|code exec|chain|bypass))",
    # Linux kernel subsystem patches (not enterprise-exploitable)
    r"\b(?:staging|ocfs2|fbdev|ALSA|media|usb: gadget|i2c:|s390/|rtnetlink|bcache|tracing):",
    # Apache library-level crashes/bugs (not enterprise-exploitable RCE)
    r"Apache Thrift:",
]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# Vendor advisory ID patterns (fallback when no CVE found)
ADVISORY_RE = re.compile(
    r"FG-IR-\d+-\d+"           # Fortinet
    r"|cisco-sa-[\w-]+"        # Cisco
    r"|PAN-SA-\d+-\d+"         # Palo Alto
    r"|ZDI-\d+-\d+"            # ZDI
    r"|VMSA-\d+-\d+",          # VMware
    re.I,
)

# Sources whose advisories are high-value even when DB fields are incomplete.
HIGH_PRIORITY_SOURCES = frozenset({
    "Fortinet", "PaloAlto", "Cisco", "CISA_KEV", "ZDI",
    "watchTowr", "MSRC", "Horizon3", "Chaitin", "ThreatBook",
})
# Reasons that indicate a genuinely interesting finding.
STRONG_VULN_TYPES = frozenset({"RCE", "other"})

# ── Freshness (1day vs nday) ──
# 1day = 漏洞本体新近公开且处于可利用窗口期，值得立刻关注和防御的新鲜攻击面。
# 不是"任意新内容"：老洞新 PoC / 聚合站重新收录 / 老洞重炒 都不算 1day。
# Sources where publication inherently means the vulnerability is fresh.
FRESH_SOURCES = frozenset({
    "Fortinet", "PaloAlto", "Cisco", "MSRC",        # Vendor PSIRT
    "CISA_KEV",                                       # In-the-wild confirmation
    "ZDI", "watchTowr", "Horizon3", "Rapid7",        # Research teams
    "Chaitin",                                            # Curated vuln database
    # ThreatBook: NOT in FRESH_SOURCES — premium section lacks vuln_publish_time,
    # mixes old vulns (XVE-2025 with 2025-04 pub date) into current listings.
    "DailyCVE",                                        # Aggregator, but entries are day-of CVEs (not old rehash)
    "GHSA",                                            # GitHub Advisory Database (reviewed by GitHub security team)
})
# Sources that aggregate/republish old vulns — need CVE year validation.
# Sploitus_*, GitHub, PoC-GitHub are implicitly NOT in FRESH_SOURCES.

# Fallback advisory page per vendor (used when we know the source but have no
# item-level URL).
VENDOR_URL_FALLBACK = {
    "Fortinet":     "https://www.fortiguard.com/psirt",
    "PaloAlto":     "https://security.paloaltonetworks.com",
    "Cisco":        "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
    "CISA_KEV":     "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "MSRC":         "https://msrc.microsoft.com/update-guide",
    "ZDI":          "https://www.zerodayinitiative.com/advisories/published/",
    "watchTowr":    "https://labs.watchtowr.com",
    "Horizon3":     "https://www.horizon3.ai/attack-research/",
    "Rapid7":       "https://www.rapid7.com/blog/",
    "Chaitin":      "https://stack.chaitin.com/vuldb/index",
    "ThreatBook":   "https://x.threatbook.com/v5/vul",
    "GitHub":       "https://github.com",
}


# ================== LOG / HTTP ==================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("vuln")

SESS = requests.Session()
SESS.headers["User-Agent"] = "vuln-intel/1.0"
if PROXY:
    SESS.proxies = {"http": PROXY, "https": PROXY}

_gh_token_idx = 0

_RETRY_ATTEMPTS = 3
_RETRY_DELAY = 3

def _get_with_retry(session, url, **kwargs):
    """GET with retry on transient failures."""
    for attempt in range(1, _RETRY_ATTEMPTS + 1):
        try:
            r = session.get(url, **kwargs)
            return r
        except (requests.ConnectionError, requests.Timeout) as ex:
            if attempt == _RETRY_ATTEMPTS:
                raise
            log.debug(f"retry {attempt}/{_RETRY_ATTEMPTS} for {url}: {ex}")
            time.sleep(_RETRY_DELAY)
    return None  # unreachable


def _github_rate_limited(resp):
    body = ""
    try:
        body = resp.text.lower()
    except Exception:
        pass
    return resp.status_code in (403, 429) or "secondary rate limit" in body


def _next_github_token():
    global _gh_token_idx
    if not GH_TOKENS:
        return None
    token = GH_TOKENS[_gh_token_idx % len(GH_TOKENS)]
    _gh_token_idx += 1
    return token


def _github_headers(token=None):
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_request(url, *, params=None, timeout=REQUEST_TIMEOUT, raw=False):
    wait_sec = max(0, CFG["github"]["request_interval_sec"])
    attempts = max(1, len(GH_TOKENS) or 1)
    last_resp = None
    tokens = GH_TOKENS[:] or [None]
    for idx in range(attempts):
        token = tokens[idx % len(tokens)]
        try:
            last_resp = _get_with_retry(
                SESS,
                url,
                params=params,
                headers=_github_headers(token),
                timeout=timeout,
            )
        except Exception as ex:
            log.warning(f"GitHub request err for {url}: {ex}")
            last_resp = None
        if last_resp is not None and not _github_rate_limited(last_resp):
            if wait_sec:
                time.sleep(wait_sec)
            return last_resp
        if wait_sec:
            time.sleep(wait_sec)
    return last_resp


# ================== LOCK ==================
class SingletonLock:
    """Prevent overlapping runs. fcntl on POSIX, msvcrt on Windows."""

    def __init__(self, path):
        self.path = path
        self.fh = None

    def __enter__(self):
        self.fh = open(self.path, "a+b")
        self.fh.seek(0, 2)
        if self.fh.tell() == 0:
            self.fh.write(b"0")
            self.fh.flush()
        self.fh.seek(0)
        try:
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as ex:
            self.fh.close()
            self.fh = None
            raise RuntimeError(f"another instance is running ({self.path}): {ex}")
        return self

    def __exit__(self, *a):
        if self.fh:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    self.fh.seek(0)
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                self.fh.close()
            except Exception:
                pass


# ================== DATABASE ==================
def _get_conn():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

import contextlib

@contextlib.contextmanager
def _db():
    """Context manager for DB connections — guarantees close on exception."""
    conn = _get_conn()
    try:
        yield conn
    finally:
        conn.close()

def _ensure_table_and_columns(conn):
    """Ensure table shape exists. Safe for read paths against an existing DB."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vulns (
            key        TEXT PRIMARY KEY,
            cve_id     TEXT,
            source     TEXT,
            title      TEXT NOT NULL,
            link       TEXT,
            summary    TEXT,
            reason     TEXT,
            vuln_type  TEXT,
            freshness  TEXT,
            freshness_reason TEXT,
            pushed     INTEGER DEFAULT 0,
            created_at REAL NOT NULL,
            cve_published TEXT,
            severity      TEXT,
            cvss          REAL,
            llm_verified  INTEGER DEFAULT 0,
            llm_verdict   TEXT,
            llm_notes     TEXT,
            tg_sent       INTEGER DEFAULT 0,
            github_repo_url TEXT,
            github_repo_name TEXT,
            github_repo_desc TEXT,
            github_repo_stars INTEGER,
            github_primary_poc_url TEXT,
            github_poc_index_url TEXT,
            github_related_poc_urls TEXT,
            github_poc_summary TEXT,
            github_poc_readme_excerpt TEXT,
            github_poc_found INTEGER DEFAULT 0,
            github_poc_count INTEGER DEFAULT 0
        )
    """)
    _new_cols = []
    for col, typedef in [
        ("cve_published", "TEXT"),
        ("severity",      "TEXT"),
        ("cvss",          "REAL"),
        ("llm_verified",  "INTEGER DEFAULT 0"),
        ("llm_verdict",   "TEXT"),
        ("llm_notes",     "TEXT"),
        ("tg_sent",       "INTEGER DEFAULT 0"),
        ("freshness",     "TEXT"),
        ("freshness_reason", "TEXT"),
        ("vuln_type",     "TEXT"),
        ("github_repo_url", "TEXT"),
        ("github_repo_name", "TEXT"),
        ("github_repo_desc", "TEXT"),
        ("github_repo_stars", "INTEGER"),
        ("github_primary_poc_url", "TEXT"),
        ("github_poc_index_url", "TEXT"),
        ("github_related_poc_urls", "TEXT"),
        ("github_poc_summary", "TEXT"),
        ("github_poc_readme_excerpt", "TEXT"),
        ("github_poc_found", "INTEGER DEFAULT 0"),
        ("github_poc_count", "INTEGER DEFAULT 0"),
    ]:
        try:
            conn.execute(f"ALTER TABLE vulns ADD COLUMN {col} {typedef}")
            _new_cols.append(col)
        except sqlite3.OperationalError:
            pass
    return _new_cols


def _ensure_indexes(conn):
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_id     ON vulns(cve_id)     WHERE cve_id IS NOT NULL")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_source     ON vulns(source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON vulns(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pushed     ON vulns(pushed)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_verified ON vulns(llm_verified) WHERE llm_verified=0")


def init_db(conn):
    _new_cols = _ensure_table_and_columns(conn)
    # backfill tg_sent: mark already-pushed records as sent (only on first migration)
    if "tg_sent" in _new_cols:
        conn.execute("UPDATE vulns SET tg_sent = 1 WHERE pushed = 1")
    # backfill freshness + vuln_type + migrate legacy values (only on first migration)
    if "freshness" in _new_cols:
        conn.execute("UPDATE vulns SET freshness='nday', reason=SUBSTR(reason,6) WHERE reason LIKE 'nday:%'")
        conn.execute("UPDATE vulns SET freshness='1day' WHERE freshness IS NULL AND reason NOT IN ('excluded','no hit')")
        # migrate legacy llm_verdict values
        conn.execute("UPDATE vulns SET llm_verdict='confirmed' WHERE llm_verdict IN ('1day_rce','1day_high','fallback_regex')")
        conn.execute("UPDATE vulns SET llm_verdict='not_relevant' WHERE llm_verdict='1day_low'")
        conn.execute("UPDATE vulns SET llm_verdict='not_relevant' WHERE llm_verdict='nday'")
    # backfill vuln_type from reason (only on first migration)
    if "vuln_type" in _new_cols:
        conn.execute("UPDATE vulns SET vuln_type='RCE' WHERE reason LIKE '%RCE%'")
        conn.execute("UPDATE vulns SET vuln_type='other' WHERE vuln_type IS NULL AND reason NOT IN ('excluded','no hit')")
    # enforce hard locks on existing data: GitHub/nday must not remain pushed
    conn.execute("UPDATE vulns SET pushed=0 WHERE source IN ('GitHub','PoC-GitHub') AND pushed=1")
    conn.execute("UPDATE vulns SET pushed=0 WHERE freshness='nday' AND pushed=1")
    _ensure_indexes(conn)
    conn.commit()


def init_db_readonly(conn):
    """Best-effort schema compatibility for read-only commands.

    Do not run data-fixing UPDATEs here, otherwise stats/query can block behind
    a writer that is currently ingesting data.
    """
    _ensure_table_and_columns(conn)
    _ensure_indexes(conn)

def migrate_json_cache(conn):
    """One-time migration from vuln_cache.json → SQLite."""
    if not _JSON_LEGACY.exists():
        return
    if conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0] > 0:
        return
    try:
        old = json.loads(_JSON_LEGACY.read_text(encoding="utf-8"))
    except Exception:
        return
    for key, val in old.items():
        cve_id = key.split(":", 1)[1] if key.startswith("cve:") else None
        conn.execute(
            "INSERT OR IGNORE INTO vulns (key,cve_id,title,reason,pushed,created_at) "
            "VALUES (?,?,?,?,?,?)",
            (key, cve_id, val.get("title", "")[:300], val.get("reason", ""),
             1 if val.get("pushed") else 0, val.get("ts", 0)),
        )
    conn.commit()
    _JSON_LEGACY.rename(_JSON_LEGACY.with_suffix(".json.migrated"))
    log.info(f"migrated {len(old)} entries from JSON to SQLite")

def db_cleanup(conn):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=CACHE_TTL_DAYS)).timestamp()
    conn.execute("DELETE FROM vulns WHERE created_at < ?", (cutoff,))
    conn.commit()

def _backfill_row(conn, key, it):
    """UPDATE a record's NULL fields with fresh data from a source item."""
    tag = _extract_id(it["text"], it["link"])
    github = _github_context_from_item(it)
    conn.execute(
        "UPDATE vulns SET cve_id=COALESCE(cve_id,?), source=COALESCE(source,?), "
        "title=COALESCE(title,?), link=COALESCE(link,?), summary=COALESCE(summary,?), "
        "github_repo_url=COALESCE(github_repo_url,?), github_repo_name=COALESCE(github_repo_name,?), "
        "github_repo_desc=COALESCE(github_repo_desc,?), github_repo_stars=COALESCE(github_repo_stars,?), "
        "github_primary_poc_url=COALESCE(github_primary_poc_url,?), github_poc_index_url=COALESCE(github_poc_index_url,?), "
        "github_related_poc_urls=COALESCE(github_related_poc_urls,?), "
        "github_poc_summary=COALESCE(github_poc_summary,?), github_poc_readme_excerpt=COALESCE(github_poc_readme_excerpt,?), "
        "github_poc_found=CASE WHEN github_poc_found IS NULL OR github_poc_found=0 THEN ? ELSE github_poc_found END, "
        "github_poc_count=CASE WHEN github_poc_count IS NULL OR github_poc_count=0 THEN ? ELSE github_poc_count END "
        "WHERE key=?",
        (tag if tag != "N/A" else None, it["source"],
         it["title"][:300], it["link"], it["summary"][:500],
         github["github_repo_url"] or None, github["github_repo_name"] or None,
         github["github_repo_desc"] or None, github["github_repo_stars"] or None,
         github["github_primary_poc_url"] or None, github["github_poc_index_url"] or None,
         github["github_related_poc_urls"] or None,
         github["github_poc_summary"] or None, github["github_poc_readme_excerpt"] or None,
         github["github_poc_found"], github["github_poc_count"], key),
    )

def _infer_source_from_title(title):
    """Best-effort vendor inference from title keywords."""
    low = (title or "").lower()
    for kw, src in (
        ("[kev]", "CISA_KEV"),
        ("zdi-", "ZDI"),
        ("fortiweb", "Fortinet"), ("fortigate", "Fortinet"), ("fortios", "Fortinet"),
        ("fortimanager", "Fortinet"), ("fortianalyzer", "Fortinet"), ("forticlient", "Fortinet"),
        ("fortiproxy", "Fortinet"), ("fortisandbox", "Fortinet"), ("fortisiem", "Fortinet"),
        ("fortisoar", "Fortinet"), ("fortiswitch", "Fortinet"), ("fortiadc", "Fortinet"),
        ("fortinac", "Fortinet"), ("fortiportal", "Fortinet"),
        ("pan-os", "PaloAlto"), ("globalprotect", "PaloAlto"), ("cortex xdr", "PaloAlto"),
        ("palo alto", "PaloAlto"), ("prisma access", "PaloAlto"),
        ("cisco", "Cisco"), ("ios-xe", "Cisco"), ("ios-xr", "Cisco"),
        ("webex", "Cisco"), ("anyconnect", "Cisco"), ("firepower", "Cisco"),
        ("vmware", "VMware"), ("vcenter", "VMware"), ("esxi", "VMware"),
    ):
        if kw in low:
            return src
    return None

def _enrich_record(cve_id, source, title, link):
    """Heuristic enrichment for incomplete records.

    Returns (cve_id, source, link) with NULLs filled where possible.
    """
    # --- infer source from advisory ID pattern ---
    if not source and cve_id:
        for pat, src in (
            (r"FG-IR-", "Fortinet"), (r"ZDI-", "ZDI"), (r"cisco-sa-", "Cisco"),
            (r"PAN-SA-", "PaloAlto"), (r"VMSA-", "VMware"),
        ):
            if re.match(pat, cve_id, re.I):
                source = src
                break
    # --- infer source from title keywords ---
    if not source:
        source = _infer_source_from_title(title)
    # --- construct link from advisory ID ---
    if not link and cve_id:
        if re.match(r"CVE-\d{4}-\d+", cve_id, re.I):
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        elif re.match(r"FG-IR-\d+-\d+", cve_id, re.I):
            link = f"https://fortiguard.fortinet.com/psirt/{cve_id}"
        elif re.match(r"ZDI-\d+-\d+", cve_id, re.I):
            link = f"https://www.zerodayinitiative.com/advisories/{cve_id}/"
        elif re.match(r"cisco-sa-", cve_id, re.I):
            link = f"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{cve_id}"
        elif re.match(r"PAN-SA-", cve_id, re.I):
            link = f"https://security.paloaltonetworks.com/{cve_id}"
    # --- fallback: vendor advisory listing page ---
    if not link and source and source in VENDOR_URL_FALLBACK:
        link = VENDOR_URL_FALLBACK[source]
    return cve_id, source, link

def _auto_enrich():
    """Find incomplete strong-reason records and persist heuristic enrichment.

    Returns number of records updated.
    """
    with _db() as conn:
        init_db(conn)
        # Match strong vuln types
        type_clauses = []
        type_params = []
        for t in STRONG_VULN_TYPES:
            type_clauses.append("vuln_type = ?")
            type_params.append(t)
        candidates = conn.execute(
            f"SELECT key, cve_id, source, title, link FROM vulns "
            f"WHERE (link IS NULL OR link = '') AND ({' OR '.join(type_clauses)})",
            type_params,
        ).fetchall()
        updated = 0
        for key, cve_id, source, title, link in candidates:
            new_cve, new_src, new_link = _enrich_record(cve_id, source, title, link)
            if new_link != link or new_src != source or new_cve != cve_id:
                conn.execute(
                    "UPDATE vulns SET cve_id=COALESCE(cve_id,?), source=COALESCE(source,?), "
                    "link=COALESCE(link,?) WHERE key=?",
                    (new_cve, new_src, new_link, key),
                )
                updated += 1
        conn.commit()
    return updated

_ADVISORY_ID_RE = re.compile(
    r"(XVE-\d{4}-\d+|FG-IR-\d+-\d+|ZDI-\d+-\d+|GHSA-[\w-]+|PAN-SA-\d+-\d+|CT-\d+)", re.I
)

def item_key(title, link, text):
    cves = sorted(set(c.upper() for c in CVE_RE.findall(text)))
    if cves:
        return "cve:" + cves[0]
    # advisory IDs (XVE/FG-IR/ZDI/GHSA/CT) — stable across link/title changes
    adv_ids = sorted(set(m.upper() for m in _ADVISORY_ID_RE.findall(text)))
    if adv_ids:
        return "adv:" + adv_ids[0]
    # fallback: link-only hash
    if link:
        return "u:" + hashlib.sha1(link.encode("utf-8")).hexdigest()[:16]
    return "h:" + hashlib.sha1((title + "|" + (link or "")).encode("utf-8")).hexdigest()[:16]


_github_ctx_cache = {}


def _json_urls(urls):
    clean = []
    seen = set()
    for url in urls or []:
        if not url or url in seen:
            continue
        seen.add(url)
        clean.append(url)
    return json.dumps(clean, ensure_ascii=False)


def _decode_urls(payload):
    if not payload:
        return []
    if isinstance(payload, list):
        return [u for u in payload if isinstance(u, str) and u]
    try:
        data = json.loads(payload)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    return [u for u in data if isinstance(u, str) and u]


def _best_poc_repo(repos, cve_id):
    if not repos:
        return None
    cve_low = (cve_id or "").lower()
    def _score(repo):
        name = (repo.get("full_name") or "").lower()
        desc = (repo.get("description") or "").lower()
        stars = int(repo.get("stargazers_count") or 0)
        score = stars
        if "nomi-sec/poc-in-github" in name:
            score -= 1000
        if cve_low and cve_low in name:
            score += 200
        if cve_low and cve_low in desc:
            score += 50
        if any(word in f"{name} {desc}" for word in ("poc", "exp", "exploit", "proof-of-concept", "proof of concept")):
            score += 20
        return score
    return sorted(repos, key=_score, reverse=True)[0]


def _github_context_from_item(item):
    return {
        "github_repo_url": item.get("github_repo_url") or item.get("link") or "",
        "github_repo_name": item.get("github_repo_name") or item.get("title") or "",
        "github_repo_desc": item.get("github_repo_desc") or item.get("summary") or "",
        "github_repo_stars": int(item.get("github_repo_stars") or 0),
        "github_primary_poc_url": item.get("github_primary_poc_url") or item.get("github_repo_url") or item.get("link") or "",
        "github_poc_index_url": item.get("github_poc_index_url") or "",
        "github_related_poc_urls": item.get("github_related_poc_urls") or _json_urls([]),
        "github_poc_summary": item.get("github_poc_summary") or "",
        "github_poc_readme_excerpt": item.get("github_poc_readme_excerpt") or "",
        "github_poc_found": 1 if item.get("github_poc_found") else 0,
        "github_poc_count": int(item.get("github_poc_count") or 0),
    }


def _empty_github_context():
    return {
        "github_repo_url": "",
        "github_repo_name": "",
        "github_repo_desc": "",
        "github_repo_stars": 0,
        "github_primary_poc_url": "",
        "github_poc_index_url": "",
        "github_related_poc_urls": _json_urls([]),
        "github_poc_summary": "",
        "github_poc_readme_excerpt": "",
        "github_poc_found": 0,
        "github_poc_count": 0,
    }


def _github_repo_readme(full_name):
    if not CFG["github"]["fetch_readme_excerpt"] or not full_name:
        return ""
    resp = _github_request(f"https://api.github.com/repos/{full_name}/readme", timeout=15)
    if not resp or resp.status_code != 200:
        return ""
    try:
        payload = resp.json()
    except Exception:
        return ""
    content = payload.get("content", "")
    if not content:
        return ""
    try:
        import base64

        decoded = base64.b64decode(content).decode("utf-8", "ignore")
    except Exception:
        return ""
    return re.sub(r"\s+", " ", decoded).strip()[:400]


def _poc_summary(repo_name, desc, readme):
    text = " ".join(part for part in [repo_name, desc, readme] if part)
    if not text:
        return "", 0
    low = text.lower()
    found = any(word in low for word in ("poc", "exp", "exploit", "proof of concept"))
    snippets = []
    if desc:
        snippets.append(desc.strip())
    if readme:
        snippets.append(readme.strip())
    summary = re.sub(r"\s+", " ", " ".join(snippets)).strip()[:220]
    return summary, int(found)


def _best_github_repo(items, cve_id):
    if not items:
        return None
    cve_low = (cve_id or "").lower()
    def score_repo(repo):
        name = (repo.get("full_name") or "").lower()
        desc = (repo.get("description") or "").lower()
        stars = int(repo.get("stargazers_count") or 0)
        hit = 50 if cve_low and cve_low in name else 0
        hit += 20 if cve_low and cve_low in desc else 0
        return (hit + stars, stars)
    return sorted(items, key=score_repo, reverse=True)[0]


def _github_nomi_context_for_cve(cve_id):
    cve_upper = (cve_id or "").upper()
    current_year = datetime.now(timezone.utc).year
    for year in (current_year, current_year - 1):
        raw_url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_upper}.json"
        index_url = f"https://github.com/nomi-sec/PoC-in-GitHub/blob/master/{year}/{cve_upper}.json"
        resp = _github_request(raw_url, timeout=15)
        if not resp or resp.status_code != 200:
            continue
        try:
            repos = resp.json()
        except Exception:
            repos = []
        if not isinstance(repos, list) or not repos:
            continue
        best = _best_poc_repo(repos, cve_upper)
        if not best:
            continue
        readme = _github_repo_readme(best.get("full_name", "")) if CFG["github"]["fetch_poc_metadata"] else ""
        summary, found = _poc_summary(best.get("full_name", ""), best.get("description", ""), readme)
        return {
            "github_repo_url": best.get("html_url", ""),
            "github_repo_name": best.get("full_name", ""),
            "github_repo_desc": (best.get("description") or "")[:300],
            "github_repo_stars": int(best.get("stargazers_count") or 0),
            "github_primary_poc_url": best.get("html_url", ""),
            "github_poc_index_url": index_url,
            "github_related_poc_urls": _json_urls([repo.get("html_url", "") for repo in repos[:MAX_RELATED_POC_URLS]]),
            "github_poc_summary": summary,
            "github_poc_readme_excerpt": readme,
            "github_poc_found": int(found or bool(best.get("html_url"))),
            "github_poc_count": len(repos),
        }
    return None


def _github_context_for_cve(cve_id):
    cve_upper = (cve_id or "").upper()
    if not cve_upper.startswith("CVE-"):
        return None
    if cve_upper in _github_ctx_cache:
        return _github_ctx_cache[cve_upper]
    nomi_ctx = _github_nomi_context_for_cve(cve_upper)
    if nomi_ctx:
        _github_ctx_cache[cve_upper] = nomi_ctx
        return nomi_ctx
    resp = _github_request(
        "https://api.github.com/search/repositories",
        params={
            "q": f"{cve_upper} in:name,description,readme",
            "sort": "stars",
            "order": "desc",
            "per_page": CFG["github"]["max_repo_results"],
        },
        timeout=15,
    )
    if not resp or resp.status_code != 200:
        _github_ctx_cache[cve_upper] = None
        return None
    try:
        items = resp.json().get("items", [])
    except Exception:
        items = []
    best = _best_github_repo(items, cve_upper)
    if not best:
        _github_ctx_cache[cve_upper] = None
        return None
    related_urls = [repo.get("html_url", "") for repo in items[: min(len(items), MAX_RELATED_POC_URLS)]]
    readme = _github_repo_readme(best.get("full_name", "")) if CFG["github"]["fetch_poc_metadata"] else ""
    summary, found = _poc_summary(best.get("full_name", ""), best.get("description", ""), readme)
    ctx = {
        "github_repo_url": best.get("html_url", ""),
        "github_repo_name": best.get("full_name", ""),
        "github_repo_desc": (best.get("description") or "")[:300],
        "github_repo_stars": int(best.get("stargazers_count") or 0),
        "github_primary_poc_url": best.get("html_url", ""),
        "github_poc_index_url": "",
        "github_related_poc_urls": _json_urls(related_urls),
        "github_poc_summary": summary,
        "github_poc_readme_excerpt": readme,
        "github_poc_found": found,
        "github_poc_count": len(items),
    }
    _github_ctx_cache[cve_upper] = ctx
    return ctx


def _test_candidate_score(item):
    text = item.get("text", "")
    source = item.get("source", "")
    has_cve = bool(CVE_RE.search(text))
    low = text.lower()
    priority = 0
    try:
        hit, reason, vuln_type = score(text)
    except Exception:
        hit, reason, vuln_type = False, "", ""
    if hit:
        priority += 200
    if reason == "excluded":
        priority -= 200
    if vuln_type == "RCE":
        priority += 40
    if source in HIGH_PRIORITY_SOURCES and has_cve:
        priority += 100
    if source in FRESH_SOURCES and has_cve:
        priority += 50
    if any(word in low for word in ("poc", "exp", "exploit", "proof of concept")):
        priority += 25
    if source in _GITHUB_SOURCES:
        priority += 10
    if source == "GHSA":
        priority += 5
    return priority


# ================== FILTER ==================
# Pre-compile patterns into single combined regexes for performance.
_RCE_RE = re.compile("|".join(f"(?:{p})" for p in RCE_PATTERNS), re.I)
_EXCLUDE_RE = re.compile("|".join(f"(?:{p})" for p in EXCLUDE_PATTERNS), re.I)
_ASSET_KW_SET = frozenset(ASSET_KEYWORDS)

def score(text):
    """Score text for exploitability. Returns (hit, reason, vuln_type).

    reason: detailed match info (RCE+asset/CVE, asset+CVE, etc.)
    vuln_type: simplified classification (RCE / other / None)
    """
    if _EXCLUDE_RE.search(text):
        return False, "excluded", None
    low = text.lower()
    rce   = bool(_RCE_RE.search(text))
    asset = any(k in low for k in _ASSET_KW_SET)
    cve   = bool(CVE_RE.search(text))
    if rce and asset and cve:
        return True, "RCE+asset+CVE", "RCE"
    if rce and asset:
        return True, "RCE+asset", "RCE"
    if rce and cve:
        return True, "RCE+CVE", "RCE"
    if rce:
        return True, "RCE", "RCE"
    if asset and cve:
        return True, "asset+CVE", "other"
    return False, "no hit", None


_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_FRESHNESS_DAYS = 60
_nvd_cache = {}       # cve_id → {"published":"YYYY-MM-DD","cvss":float,"severity":str} or "" or None
_nvd_detail_cache = {}  # full detail cache for LLM tools

def _nvd_detail(cve_id):
    """Query NVD for CVE detail. Returns dict or None.

    Returns: {"published": "YYYY-MM-DD", "cvss": float, "severity": str, "description": str}
    Cache: in-memory dict → NVD API. DB cache handled by caller.
    """
    cve_upper = cve_id.upper()
    # check full detail cache
    if cve_upper in _nvd_detail_cache:
        return _nvd_detail_cache[cve_upper] or None
    # check date-only cache (from _warm_nvd_cache)
    if cve_upper in _nvd_cache:
        cached = _nvd_cache[cve_upper]
        if cached == "":
            return None  # confirmed not in NVD/GitHub, no point retrying
        if cached is None:
            pass  # rate-limited — fall through to query
        elif isinstance(cached, str) and cached:
            # have date in cache but no full detail yet — build partial detail, don't re-query NVD
            _nvd_detail_cache[cve_upper] = {"published": cached, "cvss": None, "severity": None, "description": ""}
            return _nvd_detail_cache[cve_upper]
    # query NVD (rate limit: 50 req/30s with key, 5 req/30s without)
    _nvd_sleep = 0.7 if NVD_API_KEY else 6.5
    time.sleep(_nvd_sleep)
    try:
        hdrs = {"User-Agent": "vuln-monitor/1.0 (security research)"}
        if NVD_API_KEY:
            hdrs["apiKey"] = NVD_API_KEY
        r = SESS.get(_NVD_API, params={"cveId": cve_upper}, timeout=10, headers=hdrs)  # Fix #6: use SESS for proxy
        if r.status_code in (403, 429):
            # rate limited — DON'T cache, allow retry next cycle
            log.debug(f"NVD rate limited for {cve_upper}")
            return None
        if r.status_code != 200:
            _nvd_cache[cve_upper] = ""
            return None
        vulns = r.json().get("vulnerabilities", [])
        if vulns:
            cve_data = vulns[0]["cve"]
            pub = cve_data.get("published", "")
            pub_str = None
            if pub:
                dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                pub_str = dt.strftime("%Y-%m-%d")
            cvss = None
            severity = None
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve_data.get("metrics", {}).get(metric_key, [])
                if metrics:
                    cvss_data = metrics[0].get("cvssData", {})
                    cvss = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "").lower()
                    break
            if cvss and not severity:
                severity = "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium" if cvss >= 4.0 else "low"
            descs = cve_data.get("descriptions", [])
            desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            detail = {"published": pub_str, "cvss": cvss, "severity": severity, "description": desc_en}
            _nvd_cache[cve_upper] = pub_str or ""
            _nvd_detail_cache[cve_upper] = detail
            return detail
        # NVD has no data — fall through to GitHub Advisory fallback
    except Exception:
        pass
    # fallback: GitHub Advisory Database (often has data before NVD, especially for OSS)
    time.sleep(1)  # Fix #11: rate limit coordination
    try:
        r = _github_request("https://api.github.com/advisories", params={"cve_id": cve_upper}, timeout=10)
        if not r:
            return None
        if r.status_code == 200 and r.json():
            adv = r.json()[0]
            pub_raw = adv.get("published_at", "")
            pub_str = pub_raw[:10] if pub_raw else None
            cvss = None
            severity = None
            if adv.get("cvss", {}).get("score"):
                cvss = float(adv["cvss"]["score"])
            sev_raw = adv.get("severity", "")
            if sev_raw in ("critical", "high", "medium", "low"):
                severity = sev_raw
            if cvss and not severity:
                severity = "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium" if cvss >= 4.0 else "low"
            desc = adv.get("summary", "")
            detail = {"published": pub_str, "cvss": cvss, "severity": severity, "description": desc}
            _nvd_cache[cve_upper] = pub_str or ""
            _nvd_detail_cache[cve_upper] = detail
            return detail
    except Exception:
        pass
    # both NVD and GitHub failed — mark as empty to stop retrying (Fix #3)
    _nvd_cache[cve_upper] = ""
    _nvd_detail_cache[cve_upper] = None
    return None

def _nvd_published_date(cve_id):
    """Thin wrapper: returns (datetime, "YYYY-MM-DD") or (None, None)."""
    detail = _nvd_detail(cve_id)
    if detail and detail.get("published"):
        pub_str = detail["published"]
        dt = datetime.fromisoformat(pub_str).replace(tzinfo=timezone.utc)
        return dt, pub_str
    return None, None

def _cvss_to_severity(score):
    """Convert CVSS float to severity string."""
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    return "low"


def _backfill_fortinet(conn):
    """Extract CVSS from Fortinet advisory summary (contains 'CVSSv3 Score: x.x')."""
    rows = conn.execute(
        "SELECT key, summary FROM vulns "
        "WHERE source='Fortinet' AND cvss IS NULL AND summary IS NOT NULL"
    ).fetchall()
    updated = 0
    for key, summary in rows:
        m = re.search(r"CVSSv3\s*Score:\s*(\d+(?:\.\d+)?)", summary)
        if not m:
            continue
        score = float(m.group(1))
        if 0 <= score <= 10:
            conn.execute(
                "UPDATE vulns SET cvss=?, severity=? WHERE key=?",
                (score, _cvss_to_severity(score), key))
            updated += 1
    if updated:
        conn.commit()
        log.info(f"backfill_fortinet: extracted CVSS for {updated} records")


def _backfill_zdi(conn):
    """Fetch CVSS from ZDI advisory page (HTML contains 'CVSS SCORE ... x.x')."""
    rows = conn.execute(
        "SELECT key, link FROM vulns "
        "WHERE source='ZDI' AND cvss IS NULL AND link IS NOT NULL "
        "LIMIT 20"
    ).fetchall()
    updated = 0
    for key, link in rows:
        try:
            r = SESS.get(link, timeout=10, headers={"User-Agent": "vuln-monitor/1.0"})
            if r.status_code != 200:
                continue
            m = re.search(r"CVSS SCORE.*?(\d+\.\d+)", r.text, re.S)
            if not m:
                continue
            score = float(m.group(1))
            if 0 <= score <= 10:
                conn.execute(
                    "UPDATE vulns SET cvss=?, severity=? WHERE key=?",
                    (score, _cvss_to_severity(score), key))
                updated += 1
        except Exception:
            continue
        time.sleep(1)
    if updated:
        conn.commit()
        log.info(f"backfill_zdi: fetched CVSS for {updated} records")


def _backfill_published_fallback(conn):
    """Use created_at as cve_published fallback — only for records older than 7 days.

    Gives NVD/GitHub 7 days to populate real data before falling back.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).timestamp()
    rows = conn.execute(
        "SELECT key, created_at FROM vulns "
        "WHERE cve_published IS NULL AND created_at IS NOT NULL AND created_at < ?",
        (cutoff,)
    ).fetchall()
    if not rows:
        return
    for key, created_at in rows:
        pub = datetime.fromtimestamp(created_at, tz=timezone.utc).strftime("%Y-%m-%d")
        conn.execute("UPDATE vulns SET cve_published=? WHERE key=?", (pub, key))
    conn.commit()
    log.info(f"backfill_published: set created_at fallback for {len(rows)} records")


def _backfill_nvd_severity(conn):
    """Backfill severity, CVSS, and cve_published from NVD + GitHub Advisory."""
    batch = 100 if NVD_API_KEY else 20
    rows = conn.execute(
        "SELECT key, cve_id FROM vulns "
        "WHERE cve_id IS NOT NULL AND cve_id LIKE 'CVE-%' "
        "AND (severity IS NULL OR cve_published IS NULL OR (vuln_type != 'RCE' AND vuln_type IS NOT NULL)) "
        f"LIMIT {batch}"
    ).fetchall()
    updated = 0
    for key, cve_id in rows:
        cves = CVE_RE.findall(cve_id)
        detail = None
        for c in (cves or [cve_id]):
            detail = _nvd_detail(c.upper())
            if detail and (detail.get("cvss") or detail.get("published")):
                break
        if detail:
            # re-score with NVD description to upgrade vuln_type (e.g. other → RCE)
            desc = detail.get("description", "")
            vtype_upgrade = None
            if desc:
                hit, _, vt = score(desc)
                if hit and vt == "RCE":
                    vtype_upgrade = "RCE"
            sql = ("UPDATE vulns SET severity=COALESCE(severity,?), cvss=COALESCE(cvss,?), "
                   "cve_published=COALESCE(cve_published,?)")
            params = [detail.get("severity"), detail.get("cvss"), detail.get("published")]
            if vtype_upgrade:
                sql += ", vuln_type=?"
                params.append(vtype_upgrade)
            sql += " WHERE key=?"
            params.append(key)
            conn.execute(sql, params)
            updated += 1
    if updated:
        conn.commit()
        log.info(f"backfill_nvd_severity: updated {updated} records")
    # source-specific backfills
    _backfill_fortinet(conn)
    _backfill_zdi(conn)
    _backfill_published_fallback(conn)


# ================== LLM ENRICHMENT ==================
# System prompt: load from DATA_DIR/llm_prompt.txt if exists, else use default.
_LLM_PROMPT_FILE = DATA_DIR / "llm_prompt.txt"
_LLM_SYSTEM_PROMPT_DEFAULT = """你是一名漏洞情报分析师。请判断该漏洞是否真实、是否值得在企业内部告警。

## Verdict 取值:
- confirmed: 真实漏洞，且值得推送告警
- not_relevant: 真实漏洞，但实际影响较低，不值得推送
- noise: 噪声或无实际威胁，不值得关注

## 研判规则:
1. Fortinet/Cisco/PaloAlto/MSRC 等官方 PSIRT 基本可确认漏洞真实，但“真实”不等于“值得推送”，仍需判断影响面。
2. 满足以下情况通常应判为 confirmed：可远程利用、影响广泛部署产品、RCE、命令注入、SQL 注入、认证绕过、未授权高权限访问。
3. 以下情况通常判为 not_relevant：仅 DoS/崩溃、仅信息泄露且无提权路径、必须认证后本地利用、非常小众产品、仅代码库级别缺陷但缺乏生产环境直接利用路径。
4. CVSS 仅作参考，高 CVSS 的 DoS 仍可能不值得推送；低 CVSS 的预认证 RCE 仍可能值得推送。
5. GitHub 仓库需要判断是否真有 PoC/Exp；空仓库、占位仓库、无代码的低质量 fork 更接近 noise。
6. 如果标题或摘要不清晰，可以调用工具核实。
7. 如果发现公开 PoC/Exp，请在 notes 中用中文简短说明。

严格只输出 JSON，不要输出 markdown，不要输出额外解释。
notes 必须使用简体中文，控制在一句话内。
输出格式:
{"verdict": "confirmed|not_relevant|noise", "notes": "中文一句话说明"}
"""

def _get_llm_prompt():
    """Load system prompt from file (if exists) or use default."""
    if _LLM_PROMPT_FILE.exists():
        try:
            custom = _LLM_PROMPT_FILE.read_text(encoding="utf-8").strip()
            if custom:
                return custom
        except Exception:
            pass
    return _LLM_SYSTEM_PROMPT_DEFAULT

_ENRICH_TOOLS = [
    {"type": "function", "function": {
        "name": "fetch_nvd_detail",
        "description": "Get NVD detail for a CVE: CVSS score, severity, full description, published date.",
        "parameters": {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]},
    }},
    {"type": "function", "function": {
        "name": "fetch_source_page",
        "description": "Fetch text content of a URL (advisory page, blog post). Returns first 2000 chars.",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    }},
    {"type": "function", "function": {
        "name": "search_github",
        "description": "Search GitHub for PoC/exploit repositories related to a CVE.",
        "parameters": {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]},
    }},
    {"type": "function", "function": {
        "name": "search_chaitin",
        "description": "Search Chaitin Stack vuldb (Chinese vulnerability database) for details.",
        "parameters": {"type": "object", "properties": {"keyword": {"type": "string"}}, "required": ["keyword"]},
    }},
]

_VERDICT_PUSH = {"confirmed": 1, "not_relevant": 0, "noise": 0}

_GITHUB_SOURCES = frozenset({"GitHub", "PoC-GitHub"})

def _resolve_pushed(verdict, freshness, source):
    """Determine pushed value from LLM verdict, respecting hard constraints.

    Rules:
      - freshness must be '1day' to push — nday/None/unknown all locked 0
      - GitHub/PoC-GitHub → locked 0, candidate only
      - LLM can downgrade any record, but cannot override freshness or source trust
    """
    llm_wants_push = _VERDICT_PUSH.get(verdict, 0)
    # only 1day is pushable — nday, None (no CVE / unverified) all blocked
    if freshness != "1day":
        return 0
    if source in _GITHUB_SOURCES:
        return 0
    return llm_wants_push
_MAX_TOOL_ROUNDS = 5


def _get_llm_client():
    """Create OpenAI-compatible client. Returns (client, model) or (None, None)."""
    try:
        from openai import OpenAI
    except ImportError:
        log.error("openai package not installed. Run: pip install openai")
        return None, None
    api_key = LLM_API_KEY
    if not api_key:
        return None, None
    if (LLM_PROVIDER or "").lower() == "deepseek":
        base_url = LLM_BASE_URL or "https://api.deepseek.com"
        model = LLM_MODEL or "deepseek-chat"
    else:
        base_url = LLM_BASE_URL or "https://api.openai.com"
        model = LLM_MODEL or "gpt-4o-mini"
    # avoid double /v1 if user already included it in base_url
    base = base_url.rstrip("/")
    if not base.endswith("/v1"):
        base += "/v1"
    client = OpenAI(api_key=api_key, base_url=base, timeout=LLM_TIMEOUT)
    log.info(f"LLM client: model={model} base_url={base}")
    return client, model

_llm_client = None
_llm_model = None


_TOOL_MAX_OUTPUT = 3000  # truncate tool output to avoid blowing context

def _tool_fetch_nvd_detail(cve_id):
    detail = _nvd_detail(cve_id)
    if not detail:
        return '{"error": "not found in NVD"}'
    # truncate description to avoid huge output
    if detail.get("description"):
        detail["description"] = detail["description"][:1000]
    return json.dumps(detail, ensure_ascii=False)[:_TOOL_MAX_OUTPUT]

def _tool_fetch_source_page(url):
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return json.dumps({"error": "only http/https allowed"})
        # block internal/private IPs (SSRF protection)
        import socket, ipaddress
        try:
            for info in socket.getaddrinfo(parsed.hostname or "", None):
                addr = ipaddress.ip_address(info[4][0])
                if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                    return json.dumps({"error": "internal addresses not allowed"})
        except (socket.gaierror, ValueError):
            return json.dumps({"error": "DNS resolution failed"})
        r = SESS.get(url, timeout=15, headers={"User-Agent": "vuln-monitor/1.0"})
        text = re.sub(r"<[^>]+>", " ", r.text)
        return re.sub(r"\s+", " ", text).strip()[:2000]
    except Exception as ex:
        return json.dumps({"error": str(ex)})

def _tool_search_github(cve_id):
    try:
        r = _github_request(
            "https://api.github.com/search/repositories",
            params={"q": f"{cve_id} in:name,description", "sort": "stars", "per_page": 5},
            timeout=15,
        )
        if not r:
            return json.dumps({"error": "request failed"})
        if r.status_code != 200:
            return json.dumps({"error": f"HTTP {r.status_code}"})
        repos = [{"name": rr["full_name"], "desc": (rr.get("description") or "")[:200],
                  "stars": rr["stargazers_count"], "url": rr["html_url"]}
                 for rr in r.json().get("items", [])]
        return json.dumps(repos, ensure_ascii=False)[:_TOOL_MAX_OUTPUT]
    except Exception as ex:
        return json.dumps({"error": str(ex)})

def _tool_search_chaitin(keyword):
    s = requests.Session()
    if PROXY:
        s.proxies = {"http": PROXY, "https": PROXY}
    try:
        s.headers.update({"User-Agent": "Mozilla/5.0", "Referer": "https://stack.chaitin.com/vuldb/index",
                          "Origin": "https://stack.chaitin.com", "Accept": "application/json"})
        r = s.get(CHAITIN_API_URL, params={"limit": 5, "offset": 0, "search": keyword}, timeout=15)
        if r.status_code != 200:
            return json.dumps({"error": f"HTTP {r.status_code}"})
        items = r.json().get("data", {}).get("list", [])
        return json.dumps([{"cve": v.get("cve_id", ""), "title": v.get("title", ""),
                            "severity": v.get("severity", ""), "summary": (v.get("summary") or "")[:300]}
                           for v in items], ensure_ascii=False)[:_TOOL_MAX_OUTPUT]
    except Exception as ex:
        return json.dumps({"error": str(ex)})
    finally:
        s.close()

_TOOL_DISPATCH = {
    "fetch_nvd_detail": _tool_fetch_nvd_detail,
    "fetch_source_page": _tool_fetch_source_page,
    "search_github": _tool_search_github,
    "search_chaitin": _tool_search_chaitin,
}


def _enrich_one(record):
    """Run LLM agent loop on one vulnerability. Returns (verdict, notes) or (None, None)."""
    global _llm_client, _llm_model
    if _llm_client is None:
        _llm_client, _llm_model = _get_llm_client()
    if _llm_client is None:
        return None, None

    key, cve_id, source, title, link, summary, reason, severity, cvss, *_ = record
    user_msg = (
        f"Assess this vulnerability:\n"
        f"CVE: {cve_id or 'N/A'}\nSource: {source}\nTitle: {title}\n"
        f"URL: {link or 'N/A'}\nSummary: {summary or 'N/A'}\n"
        f"Regex match: {reason}\nCVSS: {cvss or 'unknown'}\nSeverity: {severity or 'unknown'}"
    )
    # skip tools for high-trust sources with sufficient data — direct judgment is faster
    has_enough_context = (source in FRESH_SOURCES and (severity or cvss))
    if has_enough_context:
        user_msg += "\n\nYou have enough context from this PSIRT advisory. Do NOT call tools — respond with JSON verdict directly."
    messages = [{"role": "system", "content": _get_llm_prompt()},
                {"role": "user", "content": user_msg}]
    # rough token estimate: 1 token ≈ 4 chars. Reserve max_tokens for output.
    _ctx_budget = (LLM_MAX_CONTEXT - LLM_MAX_TOKENS) * 4
    use_tools = not has_enough_context
    max_rounds = _MAX_TOOL_ROUNDS if use_tools else 1
    try:
        for round_i in range(max_rounds):
            kwargs = {
                "model": _llm_model, "messages": messages,
                "max_tokens": LLM_MAX_TOKENS,
                "temperature": LLM_TEMPERATURE,
                "top_p": LLM_TOP_P,
            }
            if use_tools:
                kwargs["tools"] = _ENRICH_TOOLS
            if LLM_REASONING:
                kwargs["reasoning_effort"] = LLM_REASONING
            try:
                resp = _llm_client.chat.completions.create(**kwargs)
            except Exception as first_err:
                err_msg = str(first_err).lower()
                # some models don't support certain params — retry without
                for param in ("temperature", "top_p", "reasoning_effort", "tools"):
                    if param in err_msg:
                        kwargs.pop(param, None)
                        break
                else:
                    raise
                resp = _llm_client.chat.completions.create(**kwargs)
            choice = resp.choices[0]
            if choice.message.tool_calls and round_i < max_rounds - 1:
                messages.append(choice.message)
                for tc in choice.message.tool_calls:
                    fn = _TOOL_DISPATCH.get(tc.function.name)
                    try:
                        args = json.loads(tc.function.arguments)
                    except (json.JSONDecodeError, TypeError):
                        args = {}
                    result = fn(**args) if fn else json.dumps({"error": "unknown tool"})
                    # truncate tool result to fit context budget
                    total_chars = sum(len(str(m.get("content", "") if isinstance(m, dict) else getattr(m, "content", ""))) for m in messages)
                    remaining = max(500, _ctx_budget - total_chars)
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": result[:remaining]})
                continue
            # last round with pending tool_calls: force a verdict
            if choice.message.tool_calls:
                messages.append(choice.message)
                for tc in choice.message.tool_calls:
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": '{"note":"round limit, give verdict now"}'})
                resp = _llm_client.chat.completions.create(
                    model=_llm_model, messages=messages,
                    max_tokens=LLM_MAX_TOKENS, temperature=LLM_TEMPERATURE)
                choice = resp.choices[0]
            # final response
            content = (choice.message.content or "").strip()
            # strip markdown fences and prose prefix before JSON
            content = re.sub(r"^```json\s*", "", content)
            content = re.sub(r"```\s*$", "", content)
            # extract first JSON object if LLM added prose around it
            m = re.search(r'\{[^{}]*"verdict"[^{}]*\}', content)
            if m:
                content = m.group(0)
            try:
                data = json.loads(content)
                return data.get("verdict"), data.get("notes", "")
            except (json.JSONDecodeError, AttributeError):
                log.warning(f"LLM unparseable for {cve_id}: {content[:200]}")
                return None, None
        log.warning(f"LLM exceeded {max_rounds} rounds for {cve_id}")
    except Exception as ex:
        log.warning(f"LLM err for {cve_id}: {ex}")
    return None, None


def _warm_nvd_cache(conn):
    """Pre-load DB cve_published values into in-memory cache at startup."""
    _nvd_cache.clear()
    _nvd_detail_cache.clear()  # Fix #9: prevent unbounded memory growth
    try:
        rows = conn.execute("SELECT cve_id, cve_published FROM vulns WHERE cve_published IS NOT NULL").fetchall()
        for cve_id, pub in rows:
            if cve_id and pub:
                _nvd_cache[cve_id] = pub
    except Exception:
        pass

def _is_fresh(source, text):
    """Is this a fresh vulnerability disclosure (1day), not an nday rehash?

    Returns (fresh: bool, pub_date_str: str or None, reason: str).
    reason explains WHY: old_cve / nvd_60d / high_trust_source / no_cve_low_trust.
    """
    cves = CVE_RE.findall(text)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=_FRESHNESS_DAYS)
    year = now.year
    latest_pub_str = None
    has_nvd_confirmed_recent = False
    has_recent_year = False
    for c in cves:
        pub_dt, pub_str = _nvd_published_date(c.upper())
        if pub_str:
            if latest_pub_str is None or pub_str > latest_pub_str:
                latest_pub_str = pub_str
            if pub_dt and pub_dt >= cutoff:
                has_nvd_confirmed_recent = True
        else:
            # NVD unavailable — track year for high-trust fallback only
            try:
                cve_year = int(c.split("-")[1])
                if cve_year >= year - 1:
                    has_recent_year = True
            except (IndexError, ValueError):
                pass
    # hard cutoff: if ALL CVEs are > 1 year old → nday
    if cves:
        all_old = True
        for c in cves:
            try:
                cve_year = int(c.split("-")[1])
                if cve_year >= year - 1:
                    all_old = False
                    break
            except (IndexError, ValueError):
                all_old = False
                break
        if all_old:
            return False, latest_pub_str, "old_cve"
    # high-trust sources: trust timeliness (NVD confirmed OR recent CVE year)
    if source in FRESH_SOURCES:
        return True, latest_pub_str, "high_trust_source"
    # low-trust sources: no CVE = can't verify
    if not cves:
        return False, None, "no_cve_low_trust"
    # low-trust with CVE: require actual NVD confirmation, year fallback not trusted
    if has_nvd_confirmed_recent:
        return True, latest_pub_str, "nvd_60d"
    return False, latest_pub_str, "nvd_60d"


# ================== SOURCES ==================
def fetch_rss(name, url):
    """Fetch with our own timeout (feedparser.parse(url) has no timeout control)."""
    out = []
    try:
        r = _get_with_retry(SESS, url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        if r.status_code != 200:
            log.warning(f"RSS {name} HTTP {r.status_code}")
            return out
        d = feedparser.parse(r.content)
        if getattr(d, "bozo", False) and not d.entries:
            log.warning(f"RSS {name} parse error: {getattr(d, 'bozo_exception', '')}")
            return out
        for e in d.entries[:_feed_cap()]:
            title   = (e.get("title") or "").strip()
            link    = (e.get("link") or "").strip()
            summary = re.sub(r"<[^>]+>", " ", e.get("summary", "") or "").strip()
            out.append({
                "source": name,
                "title": title,
                "link": link,
                "summary": summary[:500],
                "text": f"{title}\n{summary}",
            })
    except Exception as ex:
        log.warning(f"RSS {name} err: {ex}")
    return out

def fetch_kev_json():
    """CISA KEV: gold-standard in-the-wild exploited list. JSON with 1500+ entries."""
    out = []
    try:
        r = _get_with_retry(SESS, KEV_JSON_URL, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning(f"KEV HTTP {r.status_code}")
            return out
        data = r.json()
        kev_cutoff = (datetime.now(timezone.utc) - timedelta(days=CACHE_TTL_DAYS)).strftime("%Y-%m-%d")
        for v in data.get("vulnerabilities", []):
            if v.get("dateAdded", "") < kev_cutoff:
                continue
            cve = v.get("cveID", "")
            vendor = v.get("vendorProject", "")
            product = v.get("product", "")
            name = v.get("vulnerabilityName", "")
            short = v.get("shortDescription", "")
            ransomware = v.get("knownRansomwareCampaignUse", "")
            due = v.get("dueDate", "")
            title = f"[KEV] {cve} {vendor} {product}: {name}"
            summary = f"{short} (due {due}, ransomware={ransomware})"
            out.append({
                "source": "CISA_KEV",
                "title": title[:300],
                "link": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "summary": summary[:500],
                "text": f"{title}\n{summary}",
            })
    except Exception as ex:
        log.warning(f"KEV err: {ex}")
    return out


def fetch_chaitin():
    """Chaitin Stack vuldb — Chinese vuln database (350k+ total, ~184 curated).

    Uses a hidden JSON API; fresh session + Referer header to pass SafeLine WAF.
    Default list returns curated high-risk items (~184), not the full database.
    API limited to ~15 results per call; used as supplementary source.
    """
    out = []
    s = requests.Session()
    if PROXY:
        s.proxies = {"http": PROXY, "https": PROXY}
    try:
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://stack.chaitin.com/vuldb/index",
            "Origin": "https://stack.chaitin.com",
            "Accept": "application/json",
        })
        r = _get_with_retry(s, CHAITIN_API_URL,
                  params={"limit": _feed_cap(), "offset": 0},
                  timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning(f"Chaitin HTTP {r.status_code}")
            return out
        data = r.json()
        for v in data.get("data", {}).get("list", []):
            ct_id = v.get("ct_id", "")
            cve = v.get("cve_id", "")
            title = v.get("title", "")
            severity = v.get("severity", "")
            summary = v.get("summary", "")
            refs = v.get("references", "")
            link = f"https://stack.chaitin.com/vuldb/detail/{v['id']}" if v.get("id") else ""
            full_title = f"[{severity.upper()}] {cve or ct_id} {title}"
            out.append({
                "source": "Chaitin",
                "title": full_title[:300],
                "link": link,
                "summary": summary[:500],
                "text": f"{full_title}\n{summary}\n{refs}",
            })
    except Exception as ex:
        log.warning(f"Chaitin err: {ex}")
    finally:
        s.close()
    return out


def fetch_threatbook():
    """微步在线 ThreatBook — premium + highrisk vuln listings."""
    out = []
    s = requests.Session()
    if PROXY:
        s.proxies = {"http": PROXY, "https": PROXY}
    try:
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://x.threatbook.com/v5/vul",
            "Origin": "https://x.threatbook.com",
            "Accept": "application/json",
        })
        r = _get_with_retry(s, THREATBOOK_API_URL, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning(f"ThreatBook HTTP {r.status_code}")
            return out
        data = r.json().get("data", {})
        for section in ("premium", "highrisk"):
            for v in data.get(section, []):
                xve = v.get("id", "")
                name = v.get("vuln_name_zh", "")
                risk = v.get("riskLevel", "")
                poc = v.get("pocExist", False)
                affects = ", ".join(v.get("affects", []))
                pub_date = v.get("vuln_publish_time", "")
                link = f"https://x.threatbook.com/v5/vul/{xve}" if xve else ""
                title = f"[{risk}] {xve} {name}"
                summary = f"affects: {affects}" if affects else ""
                if poc:
                    summary = f"PoC available. {summary}"
                if pub_date:
                    summary = f"published: {pub_date}. {summary}"
                out.append({
                    "source": "ThreatBook",
                    "title": title[:300],
                    "link": link,
                    "summary": summary[:500],
                    "text": f"{title}\n{summary}\n{affects}",
                    "_pub_date": pub_date,  # used by _run() to set cve_published
                })
    except Exception as ex:
        log.warning(f"ThreatBook err: {ex}")
    finally:
        s.close()
    return out


# NVD API is used only for cve_published date lookup (_nvd_published_date),
# NOT as an intelligence source. Raw NVD data is too noisy (kernel patches,
# personal project CVEs, etc.) and has no editorial curation.


def fetch_github_cve():
    out = []
    year = datetime.now().year
    for q in (f"CVE-{year}-", f"CVE-{year - 1}-"):
        try:
            r = _github_request(
                "https://api.github.com/search/repositories",
                params={"q": f"{q} in:name", "sort": "updated", "order": "desc", "per_page": 30},
                timeout=REQUEST_TIMEOUT,
            )
            if not r:
                continue
            if r.status_code != 200:
                log.warning(f"GitHub {q} status {r.status_code}: {r.text[:150]}")
                continue
            for repo in r.json().get("items", []):
                stars = repo.get("stargazers_count", 0)
                if stars < 3:
                    continue
                name = repo["full_name"]
                desc = repo.get("description") or ""
                poc_summary, poc_found = _poc_summary(name, desc, "")
                out.append({
                    "source": "GitHub",
                    "title": name,
                    "link": repo["html_url"],
                    "summary": desc[:500],
                    "text": f"{name}\n{desc}",
                    "github_repo_url": repo["html_url"],
                    "github_repo_name": name,
                    "github_repo_desc": desc[:300],
                    "github_repo_stars": stars,
                    "github_primary_poc_url": repo["html_url"],
                    "github_poc_index_url": "",
                    "github_related_poc_urls": _json_urls([repo["html_url"]]),
                    "github_poc_summary": poc_summary,
                    "github_poc_readme_excerpt": "",
                    "github_poc_found": poc_found,
                    "github_poc_count": 1,
                })
        except Exception as ex:
            log.warning(f"GitHub {q} err: {ex}")
    return out


def fetch_poc_in_github():
    """nomi-sec/PoC-in-GitHub: latest commit diff → new PoC repos for recent CVEs."""
    out = []
    year = datetime.now().year
    try:
        r = _github_request(
            "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/commits/master",
            timeout=REQUEST_TIMEOUT)
        if not r:
            return out
        if r.status_code != 200:
            log.warning(f"PoC-in-GitHub HTTP {r.status_code}")
            return out
        files = r.json().get("files", [])
        for f in files:
            fname = f.get("filename", "")
            # only current/previous year CVEs (path: "2026/CVE-2026-xxxx.json")
            if not (fname.startswith(f"{year}/") or fname.startswith(f"{year-1}/")):
                continue
            cves = CVE_RE.findall(fname)
            if not cves:
                continue
            cve = cves[0].upper()
            raw_url = f.get("raw_url", "")
            blob_url = f.get("blob_url", "") or f"https://github.com/nomi-sec/PoC-in-GitHub/blob/master/{fname}"
            # fetch the JSON to get PoC repo URLs
            if raw_url:
                try:
                    jr = _github_request(raw_url, timeout=10)
                    if jr.status_code == 200:
                        repos = jr.json() if isinstance(jr.json(), list) else []
                        best_repo = _best_poc_repo(repos, cve)
                        related_urls = [repo.get("html_url", "") for repo in repos[:MAX_RELATED_POC_URLS]]
                        primary_url = best_repo.get("html_url", "") if best_repo else ""
                        primary_name = best_repo.get("full_name", "") if best_repo else ""
                        primary_desc = best_repo.get("description") or "" if best_repo else ""
                        for repo in repos[:3]:
                            name = repo.get("full_name", "")
                            desc = repo.get("description") or ""
                            html_url = repo.get("html_url", "")
                            poc_summary, poc_found = _poc_summary(name, desc, "")
                            out.append({
                                "source": "PoC-GitHub",
                                "title": f"{cve} PoC: {name}",
                                "link": html_url,
                                "summary": desc[:500],
                                "text": f"{cve} {name}\n{desc}",
                                "github_repo_url": html_url,
                                "github_repo_name": name,
                                "github_repo_desc": desc[:300],
                                "github_repo_stars": int(repo.get("stargazers_count") or 0),
                                "github_primary_poc_url": primary_url or html_url,
                                "github_poc_index_url": blob_url,
                                "github_related_poc_urls": _json_urls(related_urls),
                                "github_poc_summary": poc_summary,
                                "github_poc_readme_excerpt": "",
                                "github_poc_found": 1,
                                "github_poc_count": len(repos),
                            })
                except Exception:
                    pass
    except Exception as ex:
        log.warning(f"PoC-in-GitHub err: {ex}")
    return out


def fetch_github_advisories():
    """Fetch recent advisories from GitHub Advisory Database.

    Uses date-range windowing to cover the last 30 days, avoiding pagination limits.
    Pulls critical + high severity in weekly windows.
    """
    out = []
    now = datetime.now(timezone.utc)
    total_added = 0
    for severity in ("critical", "high"):
        # slide 7-day windows over last 30 days
        for weeks_ago in range(5):
            if total_added >= _ghsa_cap():
                return out
            end = now - timedelta(days=weeks_ago * 7)
            start = end - timedelta(days=7)
            date_range = f"{start.strftime('%Y-%m-%d')}..{end.strftime('%Y-%m-%d')}"
            for page in (1, 2):
                if total_added >= _ghsa_cap():
                    return out
                try:
                    r = _github_request(
                        "https://api.github.com/advisories",
                        params={"severity": severity, "published": date_range,
                                "sort": "published", "direction": "desc",
                                "per_page": 100, "page": page},
                        timeout=15,
                    )
                    if not r:
                        break
                    if r.status_code != 200:
                        break
                    advs = r.json()
                    if not isinstance(advs, list) or not advs:
                        break
                    for adv in advs:
                        if total_added >= _ghsa_cap():
                            return out
                        cve = adv.get("cve_id") or adv.get("ghsa_id", "")
                        summary = adv.get("summary", "")
                        cvss = adv.get("cvss", {}).get("score")
                        sev = adv.get("severity", "")
                        cvss_str = f" (CVSS {cvss})" if cvss else ""
                        sev_str = f" [{sev.upper()}]" if sev else ""
                        out.append({
                            "source": "GHSA",
                            "title": f"{sev_str} {cve} {summary[:200]}".strip(),
                            "link": adv.get("html_url", ""),
                            "summary": f"{summary}{cvss_str}",
                            "text": f"{cve} {summary}",
                        })
                        total_added += 1
                    if len(advs) < 100:
                        break  # no more pages for this window
                except Exception as ex:
                    log.warning(f"GHSA {severity} {date_range} p{page}: {ex}")
                    break
                time.sleep(0.5)
            time.sleep(0.5)
    return out


def _fetch_all_sources(test_mode=False, target_items=None):
    """Collect items from all configured sources. Used by _run() and cmd_rebuild()."""
    items = []
    counts = {}
    rss_feeds = TEST_RSS_FEEDS if test_mode else RSS_FEEDS
    extra_sources = (
        [("CISA_KEV", fetch_kev_json), ("GHSA", fetch_github_advisories)]
        if test_mode else
        [("CISA_KEV", fetch_kev_json), ("Chaitin", fetch_chaitin),
         ("ThreatBook", fetch_threatbook),
         ("GitHub", fetch_github_cve), ("PoC-GitHub", fetch_poc_in_github),
         ("GHSA", fetch_github_advisories)]
    )
    seed_target = max(6, (target_items or 0) * 4) if test_mode else None
    for name, url in rss_feeds:
        batch = fetch_rss(name, url)
        counts[name] = len(batch)
        items.extend(batch)
        if test_mode and seed_target and len(items) >= seed_target:
            log.info(f"test mode: seeded {len(items)} items from RSS, stopping source expansion early")
            log.info("source counts: " + "  ".join(f"{k}={v}" for k, v in counts.items()))
            return items
    for name, func in extra_sources:
        batch = func()
        counts[name] = len(batch)
        items.extend(batch)
        if test_mode and seed_target and len(items) >= seed_target:
            log.info(f"test mode: seeded {len(items)} items after {name}, stopping source expansion early")
            log.info("source counts: " + "  ".join(f"{k}={v}" for k, v in counts.items()))
            return items
    log.info("source counts: " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    return items


# ================== PUSH ==================
def tg_escape(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _extract_id(text, link):
    """Extract CVE or vendor advisory ID from text+link."""
    cves = sorted(set(c.upper() for c in CVE_RE.findall(text)))
    if cves:
        return " ".join(cves)
    # fallback: vendor advisory ID from text or link
    for src in (text, link or ""):
        m = ADVISORY_RE.search(src)
        if m:
            return m.group()
    return "N/A"


def _display_id(it):
    cve_id = (it.get("cve_id") or "").strip().upper()
    if cve_id.startswith("CVE-"):
        return cve_id
    return _extract_id(it.get("text", ""), it.get("link", ""))


def _clean_text(value, limit=None):
    text = html.unescape((value or "").strip())
    text = re.sub(r"\s+", " ", text).strip()
    if limit:
        return text[:limit]
    return text


def _github_context_lines(it):
    if not CFG["notify"]["include_github_context"]:
        return []
    repo = it.get("github_repo_name") or ""
    url = it.get("github_repo_url") or ""
    primary_url = it.get("github_primary_poc_url") or url
    index_url = it.get("github_poc_index_url") or ""
    related_urls = _decode_urls(it.get("github_related_poc_urls"))
    desc = (it.get("github_poc_summary") or it.get("github_repo_desc") or "").strip()
    found = "yes" if it.get("github_poc_found") else "no"
    if not any([repo, url, primary_url, index_url, desc, related_urls]):
        return []
    lines = [f"GitHub: {repo or 'N/A'}", f"PoC: {found}"]
    if primary_url:
        lines.append(f"Primary PoC: {primary_url}")
    if index_url:
        lines.append(f"PoC Index: {index_url}")
    if url and url != primary_url:
        lines.append(f"Repo: {url}")
    if related_urls:
        lines.append(f"Related: {' | '.join(related_urls[:MAX_RELATED_POC_URLS])}")
    if desc:
        lines.append(f"Desc: {desc[:220]}")
    return lines


def format_msg(it, reason):
    tag = _display_id(it)
    msg = (
        f"<b>[{tg_escape(it['source'])}]</b> <code>{tg_escape(tag)}</code>\n"
        f"<b>{tg_escape(it['title'][:220])}</b>\n"
        f"{tg_escape(it['link'])}\n"
        f"{tg_escape(it['summary'][:400])}\n"
        f"<i>match: {tg_escape(reason)}</i>"
    )
    extra = _github_context_lines(it)
    if extra:
        msg += "\n" + "\n".join(tg_escape(line) for line in extra)
    return msg[:4000]


def _severity_meta(it, reason=None):
    severity = (it.get("severity") or "").strip().lower()
    cvss = it.get("cvss")
    if severity in ("critical", "high", "medium", "low"):
        label_map = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}
        color_map = {"critical": "warning", "high": "warning", "medium": "info", "low": "comment"}
        label = label_map[severity]
        if cvss:
            label = f"{label} (CVSS {cvss})"
        return label, color_map[severity]
    if "RCE" in (reason or ""):
        return "高危", "warning"
    return "待研判", "comment"


def _reason_cn(reason):
    mapping = {
        "RCE+asset+CVE": "疑似可被远程未授权利用，且命中重点资产/厂商并存在 CVE 编号",
        "RCE+CVE": "疑似可被远程利用，且存在 CVE 编号",
        "RCE+asset": "疑似可被远程利用，且命中重点资产/厂商",
        "excluded": "已命中过滤规则，不建议推送",
        "no hit": "未命中有效漏洞规则",
    }
    return mapping.get(reason or "", reason or "待研判")


def _vuln_type_cn(it, reason):
    vuln_type = (it.get("vuln_type") or "").strip().lower()
    if vuln_type == "rce":
        return "远程代码执行"
    if vuln_type == "other":
        if "unauthorized" in ((it.get("title") or "") + " " + (it.get("summary") or "")).lower():
            return "未授权访问 / 权限绕过"
        return "高危漏洞"
    if "unauthorized" in ((it.get("title") or "") + " " + (it.get("summary") or "")).lower():
        return "未授权访问 / 权限绕过"
    if "RCE" in (reason or ""):
        return "远程代码执行"
    return "待研判"


def _llm_cn(it):
    verdict = (it.get("llm_verdict") or "").strip()
    notes = (it.get("llm_notes") or "").strip()
    verdict_map = {
        "confirmed": "确认值得关注",
        "not_relevant": "相关性较低",
        "noise": "噪声/不建议关注",
    }
    verdict_cn = verdict_map.get(verdict, "")
    notes_clean = _clean_text(notes, 180)
    if notes_clean and not re.search(r"[\u4e00-\u9fff]", notes_clean):
        if verdict == "confirmed":
            notes_clean = "官方通告及现有情报显示该漏洞真实存在，具备较高关注价值，建议优先排查和修复。"
        elif verdict == "not_relevant":
            notes_clean = "该漏洞真实存在，但结合现有情报判断实际利用价值较低，可降低优先级处理。"
        elif verdict == "noise":
            notes_clean = "当前公开情报不足以支持高价值告警，建议暂不作为重点漏洞处理。"
    if verdict_cn and notes_clean:
        return f"{verdict_cn}：{notes_clean}"
    if verdict_cn:
        return verdict_cn
    if notes_clean:
        return notes_clean
    return ""


def format_wecom_msg(it, reason):
    tag = _display_id(it)
    severity_label, severity_color = _severity_meta(it, reason)
    primary_poc = it.get("github_primary_poc_url") or ""
    poc_index = it.get("github_poc_index_url") or ""
    related_urls = _decode_urls(it.get("github_related_poc_urls"))[:MAX_RELATED_POC_URLS]
    llm_text = _llm_cn(it)
    title = _clean_text(it.get("title"), 180)
    summary = _clean_text(it.get("summary"), 220) or "暂无公开摘要"
    source_name = _clean_text(it.get("source")) or "N/A"
    reason_cn = _reason_cn(reason)
    reference_lines = [f"- [官方公告]({it['link']})" if it.get("link") else "- 官方公告：无"]
    if primary_poc:
        reference_lines.append(f"- [主 PoC 链接]({primary_poc})")
    if poc_index:
        reference_lines.append(f"- [PoC 索引]({poc_index})")
    for idx, url in enumerate(related_urls, 1):
        reference_lines.append(f"- [其他参考PoC{idx}]({url})")
    lines = [
        "# <font color=\"warning\">漏洞安全告警</font>",
        "",
        "## 漏洞基本信息",
        f"> **漏洞编号：** `{tag}`",
        f"> **危险等级：** <font color=\"{severity_color}\">{severity_label}</font>",
        f"> **漏洞类型：** {_vuln_type_cn(it, reason)}",
        f"> **来源厂商：** {source_name}",
    ]
    if primary_poc:
        lines.append(f"> **PoC/Exp：** [主 PoC 链接]({primary_poc})")
    else:
        lines.append("> **PoC/Exp：** 无")
    if poc_index:
        lines.append(f"> **PoC 索引：** [PoC-in-GitHub 索引]({poc_index})")
    if related_urls:
        links = " | ".join(f"[其他参考PoC{i+1}]({url})" for i, url in enumerate(related_urls))
        lines.append(f"> **其他参考PoC：** {links}")
    lines.extend([
        "",
        "## 漏洞概述",
        f"**标题：** {title}",
        "",
        "## 风险说明",
        f"**漏洞原理：** {summary}",
        f"**影响范围：** 建议优先排查 `{source_name}` 对应产品及对外暴露的管理/API 面。",
        f"**漏洞危害：** {reason_cn}",
    ])
    if llm_text:
        lines.append(f"**LLM研判：** {llm_text}")
    lines.extend([
        "",
        "## 修复及缓解方案",
        "尽快核查受影响版本并参考官方公告完成升级或补丁修复；修复前建议限制管理面/API 暴露范围，并排查异常访问日志。",
        "",
        "## 参考链接",
    ])
    lines.extend(reference_lines)
    return "\n".join(line for line in lines if line is not None)[:3900]

def send_telegram(msg):
    if not (TG_BOT_TOKEN and TG_CHAT_IDS):
        log.info(f"[TG-DRY] {msg[:500]}")
        return True
    ok = True
    for chat_id in TG_CHAT_IDS:
        try:
            r = SESS.post(
                f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": msg,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": False,
                },
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200:
                log.warning(f"TG push {chat_id} {r.status_code}: {r.text[:200]}")
                ok = False
        except Exception as ex:
            log.warning(f"TG err {chat_id}: {ex}")
            ok = False
    return ok


def send_wecom(msg):
    webhook = CFG["notify_wecom"]["webhook_url"]
    if not webhook:
        log.info(f"[WECOM-DRY] {msg[:500]}")
        return True
    try:
        r = SESS.post(
            webhook,
            json={"msgtype": "markdown", "markdown": {"content": msg[:3900]}},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code != 200:
            log.warning(f"WeCom push HTTP {r.status_code}: {r.text[:200]}")
            return False
        data = r.json()
        if data.get("errcode") != 0:
            log.warning(f"WeCom push err: {data}")
            return False
        return True
    except Exception as ex:
        log.warning(f"WeCom err: {ex}")
        return False


def send_notifications(it, reason):
    channels = CFG["notify"]["enabled"] or [CFG["notify"]["default_channel"]]
    ok = True
    for channel in channels:
        if channel == "telegram":
            ok = send_telegram(format_msg(it, reason)) and ok
        elif channel == "wecom":
            ok = send_wecom(format_wecom_msg(it, reason)) and ok
    return ok


def send_failure_alert(msg):
    """Rate-limited error notification so silent cron breakage is noticed."""
    now = time.time()
    state = {}
    if ALERT_STATE.exists():
        try:
            state = json.loads(ALERT_STATE.read_text(encoding="utf-8"))
        except Exception:
            pass
    if now - state.get("last_alert_ts", 0) < ALERT_COOLDOWN_SEC:
        log.warning(f"alert suppressed (cooldown): {msg[:150]}")
        return
    if not (CFG["notify_wecom"]["webhook_url"] or (TG_BOT_TOKEN and TG_CHAT_IDS)):
        log.error(f"[ALERT-DRY] {msg[:500]}")
    else:
        if CFG["notify_wecom"]["webhook_url"]:
            try:
                send_wecom(f"**vuln-monitor error**\n\n{msg[:3600]}")
            except Exception as ex:
                log.error(f"alert push wecom failed: {ex}")
        if TG_BOT_TOKEN and TG_CHAT_IDS:
            for chat_id in TG_CHAT_IDS:
                try:
                    SESS.post(
                        f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
                        json={
                            "chat_id": chat_id,
                            "text": f"vuln-monitor error\n\n{msg[:3800]}",
                            "disable_web_page_preview": True,
                        },
                        timeout=REQUEST_TIMEOUT,
                    )
                except Exception as ex:
                    log.error(f"alert push {chat_id} failed: {ex}")
    state["last_alert_ts"] = now
    try:
        tmp = ALERT_STATE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, ALERT_STATE)
    except Exception as ex:
        log.warning(f"alert state save failed: {ex}")


# ================== MAIN ==================
def _run(no_push=False, max_items=None, test_mode=False):
    _set_fetch_runtime(test_mode=test_mode)
    try:
        with _db() as conn:
            init_db(conn)
            migrate_json_cache(conn)
            _warm_nvd_cache(conn)
            now = datetime.now(timezone.utc).timestamp()

            # detect cold start: if DB is empty, this is initial seeding — suppress push
            _cold_start = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0] == 0

            items = _fetch_all_sources(test_mode=test_mode, target_items=max_items)
            if test_mode:
                log.info("test mode active: using reduced source set and prioritizing pushable CVE items")
                items = sorted(items, key=_test_candidate_score, reverse=True)
            if max_items:
                items = items[:max_items]
                log.info(f"test cap: limiting fetch processing to {len(items)} items")
            log.info(f"collected {len(items)} items")

            seen_this_run = set()
            pushed = 0
            skipped_seen = 0
            skipped_filter = 0
            backfilled = 0
            processed = 0

            for it in items:
                processed += 1
                if processed % FETCH_PROGRESS_EVERY == 0:
                    log.info(
                        f"processing progress: {processed}/{len(items)} "
                        f"pushed={pushed} filtered={skipped_filter} seen={skipped_seen}"
                    )
                key = item_key(it["title"], it["link"], it["text"])
                if key in seen_this_run:
                    skipped_seen += 1
                    continue

                row = conn.execute("SELECT source, link FROM vulns WHERE key=?", (key,)).fetchone()
                if row:
                    if row[0] is None or row[1] is None:
                        _backfill_row(conn, key, it)
                        backfilled += 1
                    skipped_seen += 1
                    seen_this_run.add(key)
                    continue
                seen_this_run.add(key)

                # ── Exploitability (severity) ──
                hit, reason, vuln_type = score(it["text"])

                # ── Freshness — ALL records with CVE get cve_published + freshness ──
                cve_pub = None
                freshness = None
                fresh_reason = None
                if CVE_RE.search(it["text"]):
                    fresh, cve_pub, fresh_reason = _is_fresh(it["source"], it["text"])
                    freshness = "1day" if fresh else "nday"
                    if hit and not fresh:
                        hit = False
                elif it["source"] in FRESH_SOURCES:
                    # check source-provided publish date first (e.g. ThreatBook vuln_publish_time)
                    src_pub = it.get("_pub_date", "")
                    if src_pub:
                        cve_pub = src_pub[:10]
                        try:
                            pub_dt = datetime.fromisoformat(src_pub[:10]).replace(tzinfo=timezone.utc)
                            cutoff = datetime.now(timezone.utc) - timedelta(days=_FRESHNESS_DAYS)
                            if pub_dt >= cutoff:
                                freshness = "1day"
                                fresh_reason = "source_pub_date"
                            else:
                                freshness = "nday"
                                fresh_reason = "source_pub_date"
                                hit = False
                        except ValueError:
                            freshness = "1day"
                            fresh_reason = "high_trust_source"
                    else:
                        # fallback: check advisory ID year (XVE-2023, FG-IR-24, etc.)
                        year = datetime.now(timezone.utc).year
                        id_year_m = re.search(r'(?:XVE|FG-IR|ZDI|PAN-SA)-(\d{4})', it["text"])
                        if id_year_m and int(id_year_m.group(1)) < year - 1:
                            freshness = "nday"
                            fresh_reason = "old_advisory_id"
                            hit = False
                        else:
                            freshness = "1day"
                            fresh_reason = "high_trust_source"
                elif hit:
                    # low-trust source, no CVE → can't verify freshness
                    freshness = "nday"
                    fresh_reason = "no_cve_low_trust"
                    hit = False

                tag = _extract_id(it["text"], it["link"])
                cve_id = tag if tag != "N/A" else None
                nvd = _nvd_detail_cache.get(cve_id.upper()) if cve_id and cve_id.startswith("CVE-") else None
                nvd_severity = nvd["severity"] if nvd else None
                nvd_cvss = nvd["cvss"] if nvd else None
                should_push = hit and freshness == "1day" and it["source"] not in _GITHUB_SOURCES
                github_ctx = _github_context_from_item(it) if it["source"] in _GITHUB_SOURCES else None
                github_ctx = github_ctx or _empty_github_context()
                conn.execute(
                    "INSERT OR IGNORE INTO vulns "
                    "(key,cve_id,source,title,link,summary,reason,vuln_type,freshness,freshness_reason,pushed,created_at,cve_published,severity,cvss,"
                    "github_repo_url,github_repo_name,github_repo_desc,github_repo_stars,github_primary_poc_url,github_poc_index_url,github_related_poc_urls,github_poc_summary,github_poc_readme_excerpt,github_poc_found,github_poc_count) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (key, cve_id, it["source"], it["title"][:300], it["link"],
                     it["summary"][:500], reason, vuln_type, freshness, fresh_reason,
                     1 if should_push else 0, now, cve_pub, nvd_severity, nvd_cvss,
                     github_ctx["github_repo_url"], github_ctx["github_repo_name"], github_ctx["github_repo_desc"],
                     github_ctx["github_repo_stars"], github_ctx["github_primary_poc_url"], github_ctx["github_poc_index_url"], github_ctx["github_related_poc_urls"], github_ctx["github_poc_summary"], github_ctx["github_poc_readme_excerpt"],
                     github_ctx["github_poc_found"], github_ctx["github_poc_count"]),
                )
                if should_push:
                    pushed += 1
                else:
                    skipped_filter += 1

            conn.commit()

            # cold start: mark all records as already sent to prevent initial flood
            if _cold_start and not test_mode:
                suppressed = conn.execute("UPDATE vulns SET tg_sent=1 WHERE pushed=1 AND tg_sent=0").rowcount
                conn.commit()
                if suppressed:
                    log.info(f"cold start: suppressed {suppressed} initial notifications (seeding run)")

            db_cleanup(conn)
            total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
            log.info(
                f"done: pushed={pushed}  filtered={skipped_filter}  already_seen={skipped_seen}  "
                f"backfilled={backfilled}  db_size={total}"
            )

            # Send pending Telegram notifications (unless --no-push)
            if not no_push:
                _push_pending(conn)
    finally:
        _set_fetch_runtime(test_mode=False)


def _push_pending(conn):
    """Send notifications for all pushed=1, tg_sent=0 records."""
    pending = conn.execute(
        "SELECT key, cve_id, source, title, link, summary, reason, severity, cvss, vuln_type, llm_verdict, llm_notes, "
        "github_repo_url, github_repo_name, github_repo_desc, github_repo_stars, github_primary_poc_url, github_poc_index_url, github_related_poc_urls, github_poc_summary, github_poc_readme_excerpt, github_poc_found, github_poc_count "
        "FROM vulns WHERE pushed=1 AND tg_sent=0"
    ).fetchall()
    if not pending:
        return
    sent = 0
    for key, cve_id, source, title, link, summary, reason, severity, cvss, vuln_type, verdict, notes, github_repo_url, github_repo_name, github_repo_desc, github_repo_stars, github_primary_poc_url, github_poc_index_url, github_related_poc_urls, github_poc_summary, github_poc_readme_excerpt, github_poc_found, github_poc_count in pending:
        it = {"source": source or "", "title": title or "", "link": link or "",
              "summary": summary or "", "text": f"{title or ''}\n{summary or ''}",
              "cve_id": cve_id or "", "severity": severity or "", "cvss": cvss, "vuln_type": vuln_type or "",
              "reason": reason or "", "llm_verdict": verdict or "", "llm_notes": notes or "",
              "github_repo_url": github_repo_url or "", "github_repo_name": github_repo_name or "",
              "github_repo_desc": github_repo_desc or "", "github_repo_stars": github_repo_stars or 0,
              "github_primary_poc_url": github_primary_poc_url or "", "github_poc_index_url": github_poc_index_url or "", "github_related_poc_urls": github_related_poc_urls or _json_urls([]),
              "github_poc_summary": github_poc_summary or "", "github_poc_readme_excerpt": github_poc_readme_excerpt or "",
              "github_poc_found": github_poc_found or 0, "github_poc_count": github_poc_count or 0}
        ok = send_notifications(it, reason)
        if ok:
            conn.execute("UPDATE vulns SET tg_sent=1 WHERE key=?", (key,))
            sent += 1
        time.sleep(PUSH_SLEEP_SEC)
    conn.commit()
    if sent:
        log.info(f"push: sent {sent} notifications")


def cmd_notify(args):
    """Resend or send pending notifications."""
    with SingletonLock(LOCK_FILE):
        with _db() as conn:
            init_db(conn)
            updated = 0
            if getattr(args, "cve", None):
                updated = conn.execute(
                    "UPDATE vulns SET tg_sent=0 WHERE cve_id=? AND pushed=1",
                    (args.cve.strip().upper(),),
                ).rowcount
            elif getattr(args, "latest", 0):
                rows = conn.execute(
                    "SELECT key FROM vulns WHERE pushed=1 ORDER BY created_at DESC LIMIT ?",
                    (max(1, int(args.latest)),),
                ).fetchall()
                for (key,) in rows:
                    updated += conn.execute("UPDATE vulns SET tg_sent=0 WHERE key=?", (key,)).rowcount
            if updated:
                conn.commit()
                log.info(f"notify: reset {updated} records to pending")
            if getattr(args, "dry", False):
                print(f"pending reset: {updated}")
                return
            _push_pending(conn)


# ================== TABLE FORMATTER ==================
def fmt_table(headers, rows):
    if not rows:
        print("(no results)")
        return
    all_rows = [headers] + rows
    widths = [max(len(str(c)) for c in col) for col in zip(*all_rows)]
    def fmt_row(r):
        return "  ".join(str(c).ljust(w) for c, w in zip(r, widths))
    print(fmt_row(headers))
    print("  ".join("─" * w for w in widths))
    for r in rows:
        print(fmt_row(r))


# ================== CLI: query ==================
def _query_rows(args, quality_filter=False):
    """Shared query logic — returns rows with all fields.

    quality_filter=True adds SQL-level gates for notification views:
      link IS NOT NULL, source IS NOT NULL, reason not in (no hit, excluded).
    """
    with _db() as conn:
        init_db_readonly(conn)
        where, params = [], []
        if args.cve:
            where.append("cve_id LIKE ?"); params.append(f"%{args.cve}%")
        if args.source:
            where.append("source LIKE ?"); params.append(f"%{args.source}%")
        if args.keyword:
            where.append("(title LIKE ? OR summary LIKE ?)")
            params.extend([f"%{args.keyword}%"] * 2)
        if args.days:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=args.days)).timestamp()
            where.append("created_at > ?"); params.append(cutoff)
        if args.pushed:
            where.append("pushed = 1")
        if args.reason:
            where.append("reason LIKE ?"); params.append(f"%{args.reason}%")
        if quality_filter:
            where.append("link IS NOT NULL AND link != ''")
            where.append("source IS NOT NULL AND source != ''")
            if not args.reason:
                where.append("reason NOT IN ('no hit','excluded') AND freshness != 'nday'")

        sql = "SELECT cve_id,source,title,link,summary,reason,pushed,created_at FROM vulns"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(args.limit)

        rows = conn.execute(sql, params).fetchall()
    return rows

def cmd_query(args):
    rows = _query_rows(args)

    if args.json:
        out = []
        for cve, src, title, link, summary, reason, pushed, ts in rows:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None
            out.append({"id": cve, "source": src, "title": title, "url": link,
                        "summary": summary, "reason": reason, "pushed": bool(pushed), "date": dt})
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return

    if args.full:
        # one-record-per-block, human readable, all fields
        for i, (cve, src, title, link, summary, reason, pushed, ts) in enumerate(rows):
            dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if ts else "-"
            if i > 0:
                print()
            print(f"[{src or '-'}] {cve or 'N/A'}  ({reason or '-'})  {dt}")
            print(f"  {title or '-'}")
            print(f"  {link or '(no url)'}")
            if summary:
                print(f"  {summary[:200]}")
        print(f"\n({len(rows)} rows)")
        return

    # default: compact table WITH url
    headers = ["ID", "Source", "Title", "URL", "Reason", "Date"]
    table = []
    for cve, src, title, link, summary, reason, pushed, ts in rows:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d") if ts else "-"
        table.append([
            cve or "-", src or "-", (title or "")[:45],
            (link or "-")[:55], reason or "-", dt,
        ])
    fmt_table(headers, table)
    print(f"\n({len(rows)} rows)")


# ================== CLI: brief ==================
def cmd_brief(args):
    """Notification-friendly output: one block per vuln, copy-paste ready.

    Pipeline: _auto_enrich() → SQL quality filter → output.
    """
    enriched = _auto_enrich()
    explain = getattr(args, "explain", False)
    if explain:
        with _db() as conn:
            init_db_readonly(conn)
            total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
            no_link = conn.execute("SELECT COUNT(*) FROM vulns WHERE link IS NULL OR link=''").fetchone()[0]
            placeholders = ",".join("?" for _ in STRONG_VULN_TYPES)
            strong_no_link = conn.execute(
                f"SELECT COUNT(*) FROM vulns WHERE (link IS NULL OR link='') AND vuln_type IN ({placeholders})",
                tuple(STRONG_VULN_TYPES),
            ).fetchone()[0]
        print(f"[explain] enriched {enriched} records this pass")
        print(f"[explain] db total={total}  still_no_link={no_link}  strong_without_link={strong_no_link}")
        if strong_no_link:
            print(f"[explain] {strong_no_link} strong records could not be enriched (run 'rebuild' to fix from feeds)")
        print(f"[explain] quality filter: link NOT NULL, source NOT NULL, reason NOT IN (no hit, excluded), freshness != nday")
        print()
    rows = _query_rows(args, quality_filter=True)
    if not rows:
        print("(no results matching quality threshold)")
        return
    for i, (cve, src, title, link, summary, reason, pushed, ts) in enumerate(rows):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d") if ts else "-"
        tag = cve or "N/A"
        if i > 0:
            print(f"{'─' * 60}")
        print(f"{tag}  [{src}]  {dt}")
        print(f"{title or '-'}")
        print(f"{link}")
        print(f"match: {reason or '-'}")
    print(f"\n({len(rows)} results)")


# ================== CLI: stats ==================
def cmd_stats(args):
    with _db() as conn:
        init_db_readonly(conn)
        total   = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
        pushed  = conn.execute("SELECT COUNT(*) FROM vulns WHERE pushed=1").fetchone()[0]
        day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).timestamp()
        recent  = conn.execute("SELECT COUNT(*) FROM vulns WHERE created_at>?", (day_ago,)).fetchone()[0]
        last_ts = conn.execute("SELECT MAX(created_at) FROM vulns").fetchone()[0]
        last_dt = datetime.fromtimestamp(last_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if last_ts else "-"
        print(f"Total: {total}  |  Pushed: {pushed}  |  Last 24h: {recent}  |  Last update: {last_dt}\n")

        sources = conn.execute("SELECT source,COUNT(*) FROM vulns GROUP BY source ORDER BY COUNT(*) DESC").fetchall()
        print("── By Source ──")
        fmt_table(["Source", "Count"], [[s or "(migrated)", str(n)] for s, n in sources])

        print()
        reasons = conn.execute(
            "SELECT reason,COUNT(*) FROM vulns WHERE pushed=1 GROUP BY reason ORDER BY COUNT(*) DESC"
        ).fetchall()
        print("── By Reason (pushed only) ──")
        fmt_table(["Reason", "Count"], [[r, str(n)] for r, n in reasons])


# ================== CLI: rebuild ==================
def cmd_rescore(args):
    """Re-evaluate all records with current score() + _is_fresh() rules."""
    with SingletonLock(LOCK_FILE):
        _cmd_rescore_inner()

def _cmd_rescore_inner():
    with _db() as conn:
        init_db(conn)
        _warm_nvd_cache(conn)
        # only rescore records NOT yet verified by LLM — don't override LLM verdicts
        rows = conn.execute("SELECT key, cve_id, source, title, link, summary, reason, pushed, cve_published FROM vulns WHERE llm_verified=0").fetchall()
        upgraded = downgraded = unchanged = 0
        for key, cve_id, source, title, link, summary, old_reason, old_pushed, existing_pub in rows:
            text = f"{title or ''}\n{summary or ''}"

            hit, reason, vuln_type = score(text)
            cve_pub = None
            freshness = None
            fresh_reason = None
            if CVE_RE.search(text):
                fresh, cve_pub, fresh_reason = _is_fresh(source or "", text)
                freshness = "1day" if fresh else "nday"
                if hit and not fresh:
                    hit = False
            elif source in FRESH_SOURCES:
                # use existing cve_published from DB if available (same as _run's _pub_date)
                if existing_pub:
                    try:
                        pub_dt = datetime.fromisoformat(existing_pub[:10]).replace(tzinfo=timezone.utc)
                        cutoff = datetime.now(timezone.utc) - timedelta(days=_FRESHNESS_DAYS)
                        if pub_dt >= cutoff:
                            freshness = "1day"
                            fresh_reason = "source_pub_date"
                        else:
                            freshness = "nday"
                            fresh_reason = "source_pub_date"
                            hit = False
                    except ValueError:
                        freshness = "1day"
                        fresh_reason = "high_trust_source"
                else:
                    year = datetime.now(timezone.utc).year
                    id_year_m = re.search(r'(?:XVE|FG-IR|ZDI|PAN-SA)-(\d{4})', text)
                    if id_year_m and int(id_year_m.group(1)) < year - 1:
                        freshness = "nday"
                        fresh_reason = "old_advisory_id"
                        hit = False
                    else:
                        freshness = "1day"
                        fresh_reason = "high_trust_source"
            elif hit:
                freshness = "nday"
                fresh_reason = "no_cve_low_trust"
                hit = False

            new_pushed = 1 if (hit and freshness == "1day" and source not in _GITHUB_SOURCES) else 0
            if reason != old_reason or new_pushed != old_pushed or cve_pub:
                conn.execute("UPDATE vulns SET reason=?, vuln_type=?, freshness=?, freshness_reason=?, pushed=?, cve_published=COALESCE(?,cve_published) WHERE key=?",
                            (reason, vuln_type, freshness, fresh_reason, new_pushed, cve_pub, key))
                if new_pushed > old_pushed:
                    upgraded += 1
                elif new_pushed < old_pushed:
                    downgraded += 1
                else:
                    unchanged += 1  # reason changed but pushed same

        conn.commit()
        total = len(rows)
        same = total - upgraded - downgraded - unchanged
    print(f"rescored {total} records: {upgraded} upgraded, {downgraded} downgraded, {unchanged} reason-changed, {same} unchanged")


def cmd_enrich(args):
    """LLM-based vulnerability enrichment: NVD severity + LLM agent + push."""
    with SingletonLock(LOCK_FILE):
        _cmd_enrich_inner(
            getattr(args, 'dry', False),
            limit=getattr(args, 'limit', 500),
            prefer_github_context=getattr(args, 'prefer_github_context', False),
            force_llm=getattr(args, 'force_llm', False),
        )

def _cmd_enrich_inner(dry=False, limit=500, prefer_github_context=False, force_llm=False):
    with _db() as conn:
        init_db(conn)
        _warm_nvd_cache(conn)

        # Phase 1: NVD severity/CVSS backfill
        _backfill_nvd_severity(conn)

        # Phase 2: LLM enrichment
        api_key = LLM_API_KEY
        if not api_key:
            log.info("enrich: no LLM API key, skipping LLM enrichment")
        else:
            candidates = conn.execute(
                "SELECT key, cve_id, source, title, link, summary, reason, severity, cvss, freshness "
                "FROM vulns WHERE llm_verified = 0 "
                "AND reason NOT IN ('excluded', 'no hit') "
                "ORDER BY created_at DESC LIMIT ?",
                (max(1, limit),)
            ).fetchall()

            if candidates:
                if prefer_github_context:
                    candidates = sorted(
                        candidates,
                        key=lambda rec: (
                            1 if (rec[1] and rec[1].startswith("CVE-")) else 0,
                            1 if rec[2] in HIGH_PRIORITY_SOURCES else 0,
                            1 if any(word in ((rec[3] or "") + " " + (rec[5] or "")).lower() for word in ("poc", "exp", "exploit")) else 0,
                        ),
                        reverse=True,
                    )
                # group by CVE to avoid duplicate LLM calls
                by_cve = {}
                no_cve = []
                for rec in candidates:
                    cve_id = rec[1]
                    if cve_id and cve_id.startswith("CVE-"):
                        by_cve.setdefault(cve_id, []).append(rec)
                    else:
                        no_cve.append(rec)

                auto_approved = llm_processed = llm_errors = 0

                # auto-approve: any record from high-trust source + critical CVSS
                for cve_id, records in by_cve.items():
                    rep = records[0]
                    any_high_trust = any(r[2] in HIGH_PRIORITY_SOURCES for r in records)
                    best_cvss = max((r[8] for r in records if r[8]), default=None)
                    if (not force_llm) and any_high_trust and best_cvss and best_cvss >= 9.0:
                        for rec in records:
                            pushed_val = _resolve_pushed("confirmed", rec[9], rec[2])
                            conn.execute(
                                "UPDATE vulns SET llm_verified=1, llm_verdict='confirmed', "
                                "llm_notes='自动确认：高可信来源且 CVSS>=9.0', pushed=? WHERE key=?",
                                (pushed_val, rec[0]))
                        auto_approved += len(records)
                        continue

                    # LLM enrichment
                    verdict, notes = _enrich_one(rep)
                    if verdict is None:
                        llm_errors += 1
                        continue
                    for rec in records:
                        pushed_val = _resolve_pushed(verdict, rec[9], rec[2])
                        conn.execute(
                            "UPDATE vulns SET llm_verified=1, llm_verdict=?, llm_notes=?, pushed=? WHERE key=?",
                            (verdict, (notes or "")[:500], pushed_val, rec[0]))
                    llm_processed += 1
                    time.sleep(0.5)

                # non-CVE records
                for rec in no_cve:
                    verdict, notes = _enrich_one(rec)
                    if verdict is None:
                        llm_errors += 1
                        continue
                    pushed_val = _resolve_pushed(verdict, rec[9], rec[2])
                    conn.execute(
                        "UPDATE vulns SET llm_verified=1, llm_verdict=?, llm_notes=?, pushed=? WHERE key=?",
                        (verdict, (notes or "")[:500], pushed_val, rec[0]))
                    llm_processed += 1
                    time.sleep(0.5)

                conn.commit()
                log.info(f"enrich: auto={auto_approved} llm={llm_processed} errors={llm_errors} force_llm={1 if force_llm else 0}")

                # fallback: too many LLM errors → push regex-scored items
                if llm_errors > 3:
                    fallback = conn.execute(
                        "UPDATE vulns SET llm_verified=1, llm_verdict='confirmed', llm_notes='兜底确认：LLM 多次失败，回退到规则命中结果', pushed=1 "
                        "WHERE llm_verified=0 AND vuln_type IN ('RCE','other') "
                        "AND freshness='1day' AND source NOT IN ('GitHub','PoC-GitHub')"
                    ).rowcount
                    conn.commit()
                    if fallback:
                        log.warning(f"enrich: LLM errors, fell back to regex for {fallback} records")
            else:
                log.info("enrich: no unverified candidates")

        # Phase 2.5: GitHub PoC/readme enrichment for recent interesting CVEs.
        gh_candidates = conn.execute(
            "SELECT key, cve_id, github_repo_name, github_repo_url, github_primary_poc_url, github_poc_index_url, github_related_poc_urls, github_poc_summary, github_poc_readme_excerpt "
            "FROM vulns WHERE cve_id LIKE 'CVE-%' "
            "AND freshness='1day' "
            "AND (github_repo_url IS NULL OR github_repo_url='' OR github_primary_poc_url IS NULL OR github_primary_poc_url='' OR github_poc_readme_excerpt IS NULL OR github_poc_readme_excerpt='') "
            "ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
        gh_updated = 0
        for key, cve_id, repo_name, repo_url, primary_poc_url, poc_index_url, related_poc_urls, poc_summary, readme_excerpt in gh_candidates:
            ctx = _github_context_for_cve(cve_id)
            if not ctx:
                continue
            conn.execute(
                "UPDATE vulns SET "
                "github_repo_url=COALESCE(NULLIF(github_repo_url,''),?), "
                "github_repo_name=COALESCE(NULLIF(github_repo_name,''),?), "
                "github_repo_desc=COALESCE(NULLIF(github_repo_desc,''),?), "
                "github_repo_stars=CASE WHEN github_repo_stars IS NULL OR github_repo_stars=0 THEN ? ELSE github_repo_stars END, "
                "github_primary_poc_url=COALESCE(NULLIF(github_primary_poc_url,''),?), "
                "github_poc_index_url=COALESCE(NULLIF(github_poc_index_url,''),?), "
                "github_related_poc_urls=COALESCE(NULLIF(github_related_poc_urls,''),?), "
                "github_poc_summary=COALESCE(NULLIF(github_poc_summary,''),?), "
                "github_poc_readme_excerpt=COALESCE(NULLIF(github_poc_readme_excerpt,''),?), "
                "github_poc_found=CASE WHEN github_poc_found IS NULL OR github_poc_found=0 THEN ? ELSE github_poc_found END, "
                "github_poc_count=CASE WHEN github_poc_count IS NULL OR github_poc_count=0 THEN ? ELSE github_poc_count END "
                "WHERE key=?",
                (
                    ctx["github_repo_url"], ctx["github_repo_name"], ctx["github_repo_desc"],
                    ctx["github_repo_stars"], ctx["github_primary_poc_url"], ctx["github_poc_index_url"], ctx["github_related_poc_urls"], ctx["github_poc_summary"], ctx["github_poc_readme_excerpt"],
                    ctx["github_poc_found"], ctx["github_poc_count"], key,
                ),
            )
            gh_updated += 1
        if gh_updated:
            conn.commit()
            log.info(f"enrich: github-context updated {gh_updated} records")

        # Phase 3: push pending
        if not dry:
            _push_pending(conn)


def cmd_rebuild(args):
    """Re-fetch all sources and backfill NULL fields in existing records."""
    with SingletonLock(LOCK_FILE):
        _cmd_rebuild_inner()

def _cmd_rebuild_inner():
    with _db() as conn:
        init_db(conn)

        items = _fetch_all_sources()
        print(f"fetched {len(items)} items from sources")

        updated = 0
        for it in items:
            key = item_key(it["title"], it["link"], it["text"])
            row = conn.execute("SELECT source, link FROM vulns WHERE key=?", (key,)).fetchone()
            if row and (row[0] is None or row[1] is None):
                _backfill_row(conn, key, it)
                updated += 1

        conn.commit()
        # report remaining incomplete records
        incomplete = conn.execute(
            "SELECT COUNT(*) FROM vulns WHERE source IS NULL OR link IS NULL"
        ).fetchone()[0]
    print(f"backfilled {updated} records")
    if incomplete:
        print(f"note: {incomplete} records still have NULL fields (source no longer in feeds)")


# ================== MAIN ==================
def cmd_daemon(args):
    """Long-running daemon: fetch → enrich → sleep → repeat."""
    interval = int(CFG["app"]["fetch_interval"])
    log.info(f"daemon started: interval={interval}s")
    while True:
        try:
            with SingletonLock(LOCK_FILE):
                _run(no_push=True)
                _cmd_enrich_inner()
        except RuntimeError as ex:
            log.warning(f"daemon skip (lock held): {ex}")
        except Exception:
            import traceback
            tb = traceback.format_exc()
            log.exception("daemon error")
            send_failure_alert(f"daemon error:\n{tb[-3500:]}")
        time.sleep(interval)


def main():
    if not config_exists():
        ensure_config_file()
        print(f"NOTICE: created default config at {CONFIG_FILE}")
    parser = argparse.ArgumentParser(description="vuln-monitor: 0day/1day RCE intelligence")
    sub = parser.add_subparsers(dest="cmd")

    fp = sub.add_parser("fetch", help="Fetch all sources, dedup, store, push")
    fp.add_argument("--no-push", action="store_true", help="Do not send Telegram (for chained use with enrich)")
    fp.add_argument("--test", action="store_true", help="Lightweight test mode: lower per-source volume and prioritize likely pushable CVE items")
    fp.add_argument("--max-items", type=int, default=None, help="Only process the top N collected items this run")

    # shared filter args for query and brief
    def _add_filter_args(p):
        p.add_argument("--cve",     help="Filter by CVE ID (substring match)")
        p.add_argument("--source",  help="Filter by source name")
        p.add_argument("--keyword", "-k", help="Search title and summary")
        p.add_argument("--days",    type=int, help="Only last N days")
        p.add_argument("--pushed",  action="store_true", help="Only pushed items")
        p.add_argument("--reason",  help="Filter by match reason")
        p.add_argument("--limit",   type=int, default=50, help="Max rows (default 50)")

    qp = sub.add_parser("query", help="Query stored vulnerabilities")
    _add_filter_args(qp)
    qp.add_argument("--full",   action="store_true", help="Detailed multi-line output")
    qp.add_argument("--json",   action="store_true", help="JSON output")

    bp = sub.add_parser("brief", help="Notification-friendly output (human readable, with URL)")
    _add_filter_args(bp)
    bp.add_argument("--explain", action="store_true", help="Show enrichment/filter diagnostics")

    sub.add_parser("stats", help="Database statistics")
    sub.add_parser("rebuild", help="Re-fetch sources and backfill NULL fields in existing records")
    sub.add_parser("rescore", help="Re-evaluate all records with current scoring rules")
    np = sub.add_parser("notify", help="Send pending notifications or resend selected pushed records")
    np.add_argument("--cve", help="Resend a specific pushed CVE, e.g. CVE-2026-20223")
    np.add_argument("--latest", type=int, default=0, help="Resend the latest N pushed records")
    np.add_argument("--dry", action="store_true", help="Only reset to pending; do not send")

    ep = sub.add_parser("enrich", help="LLM-based enrichment: NVD severity + AI verdict + push")
    ep.add_argument("--dry", action="store_true", help="Enrich but do not push notifications")
    ep.add_argument("--limit", type=int, default=500, help="Max candidate records to analyze this run")
    ep.add_argument("--prefer-github-context", action="store_true", help="Prioritize CVE items more likely to have GitHub PoC context")
    ep.add_argument("--force-llm", action="store_true", help="Bypass auto-approve and force LLM analysis for test validation")

    sub.add_parser("daemon", help="Long-running: fetch+enrich loop (env FETCH_INTERVAL=300)")

    args = parser.parse_args()

    if args.cmd == "daemon":
        cmd_daemon(args)
    elif args.cmd == "query":
        cmd_query(args)
    elif args.cmd == "brief":
        cmd_brief(args)
    elif args.cmd == "stats":
        cmd_stats(args)
    elif args.cmd == "rebuild":
        cmd_rebuild(args)
    elif args.cmd == "rescore":
        cmd_rescore(args)
    elif args.cmd == "notify":
        try:
            cmd_notify(args)
        except RuntimeError as ex:
            log.warning(str(ex))
            sys.exit(0)
        except Exception:
            import traceback
            tb = traceback.format_exc()
            log.exception("notify error")
            send_failure_alert(f"notify failed:\n{tb[-3500:]}")
            sys.exit(1)
    elif args.cmd == "enrich":
        try:
            cmd_enrich(args)
        except RuntimeError as ex:
            log.warning(str(ex))
            sys.exit(0)
        except Exception:
            import traceback
            tb = traceback.format_exc()
            log.exception("enrich error")
            send_failure_alert(f"enrich failed:\n{tb[-3500:]}")
            sys.exit(1)
    else:
        # default / "fetch": original behavior
        try:
            with SingletonLock(LOCK_FILE):
                _run(
                    no_push=getattr(args, 'no_push', False),
                    max_items=getattr(args, 'max_items', None),
                    test_mode=getattr(args, 'test', False),
                )
        except RuntimeError as ex:
            log.warning(str(ex))
            sys.exit(0)
        except Exception:
            import traceback
            tb = traceback.format_exc()
            log.exception("unhandled error")
            send_failure_alert(tb[-3500:])
            sys.exit(1)


if __name__ == "__main__":
    main()
