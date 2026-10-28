





import json
import os
import asyncio
import logging
import time
import base64
import threading
import subprocess
import signal
import sys
import traceback
import sqlite3
import collections
import shutil
import socket
from typing import List, Dict, Optional
from abc import ABC, abstractmethod
from urllib.parse import quote, urlparse

import aiohttp
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
import uvicorn


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)




def _base_dir() -> str:
    return os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))

BASE_DIR = _base_dir()
DATA_DIR = os.path.join(BASE_DIR, "data")
_SELF_SCRIPT = "main.py"


AUX_DATA_DIR = os.path.join(BASE_DIR, "aux_data")
AUX_HISTORY_TEMP_DIR = os.path.join(AUX_DATA_DIR, "history_temp")

try:
    from logging.handlers import RotatingFileHandler
    _rfh = RotatingFileHandler(os.path.join(DATA_DIR, "app.log"),
                               maxBytes=2_000_000, backupCount=3, encoding="utf-8", delay=True)
    _rfh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(_rfh)
except Exception as _e:
    # 日志文件加不上时程序仍可运行，但用户有权知道日志没落盘
    print(f"警告：日志文件不可用，仅输出到控制台（{_e}）", file=sys.stderr)

import re as _logre


class _RedactFilter(logging.Filter):
    """日志脱敏。必须先 getMessage() 合参再替换：
    只扫 record.msg 时，真值躺在 record.args 里原样落盘。"""
    _pat = _logre.compile(
        r"(sk-[A-Za-z0-9_\-]{8,}|Bearer\s+\S{8,}|"
        r"(?:api[_-]?key|app_?secret|app_?id|client[_-]?secret|access[_-]?token"
        r"|password|passwd|token)\s*[=:]\s*\S{4,})",
        _logre.I)

    def filter(self, record):
        try:
            raw = record.getMessage()
            masked = self._pat.sub("***", raw)
            if masked != raw:
                record.msg = masked
                record.args = ()
        except Exception:
            pass
        return True
_redact_f = _RedactFilter()
for _h in list(logging.getLogger().handlers) + list(logger.handlers):
    try:
        _h.addFilter(_redact_f)
    except Exception:
        pass

_BOOT_TS = time.time()
_recent_errors = []


class _ErrorCapture(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self, level=logging.ERROR)

    def emit(self, record):
        try:
            _recent_errors.append(f"{time.strftime('%H:%M:%S')} {record.getMessage()[:180]}")
            if len(_recent_errors) > 5:
                del _recent_errors[:-5]
        except Exception:
            pass


logger.addHandler(_ErrorCapture())

_http_shared = None


async def _http() -> aiohttp.ClientSession:
    global _http_shared
    if _http_shared is None or _http_shared.closed:
        _http_shared = aiohttp.ClientSession()
    return _http_shared


def _ensure_data_dir() -> str:
    os.makedirs(DATA_DIR, exist_ok=True)
    _lockdown_data_dir()
    return DATA_DIR


def _current_user() -> str:
    dom = (os.environ.get("USERDOMAIN") or "").strip()
    usr = (os.environ.get("USERNAME") or "").strip()
    if usr:
        return f"{dom}\\{usr}" if dom else usr
    try:
        return os.getlogin()
    except Exception:
        return ""


def _acl_grants_full(path: str, user: str) -> bool:
    try:
        out = subprocess.run(["icacls", path], capture_output=True, text=True, errors="ignore").stdout
    except Exception:
        return False
    short = user.split("\\")[-1].lower()
    for line in out.splitlines():
        low = line.lower()
        if short and short in low and "(f)" in low:
            return True
    return False


def _lockdown_dir(path: str) -> None:
    """收紧目录权限到当前用户，并下发到子对象。

    顺序必须是「先授权、后清继承」：反过来会先把 DACL 清空，
    一旦紧接着的 grant 失败（用户名取不到、含空格、策略拦截），
    目录就变成谁都打不开，连主人一起锁死。收权后必须回读校验。
    """
    if not (sys.platform == "win32" and os.path.isdir(path)):
        return
    user = _current_user()
    if not user:
        logger.warning(f"无法确定当前用户，跳过权限收紧: {path}")
        return
    try:
        grant = subprocess.run(
            ["icacls", path, "/grant:r", f"{user}:(OI)(CI)F"],
            capture_output=True, text=True, errors="ignore")
        if grant.returncode != 0:
            logger.warning(f"授权失败，跳过收紧: {path}")
            return
        subprocess.run(["icacls", path, "/inheritance:r"],
                       capture_output=True, text=True, errors="ignore")
        if not _acl_grants_full(path, user):
            logger.warning(f"权限回读校验失败，恢复继承: {path}")
            subprocess.run(["icacls", path, "/inheritance:e"],
                           capture_output=True, text=True, errors="ignore")
    except Exception as e:
        logger.warning(f"权限收紧失败(可忽略): {e}")


def _repair_dir_acl(path: str) -> None:
    """目录 ACL 里没有当前用户时补回来，用于修复历史版本留下的锁死目录。"""
    if not (sys.platform == "win32" and os.path.isdir(path)):
        return
    user = _current_user()
    if not user:
        return
    if _acl_grants_full(path, user):
        return
    try:
        subprocess.run(["icacls", path, "/grant", f"{user}:(OI)(CI)F"],
                       capture_output=True, text=True, errors="ignore")
        logger.info(f"已修复目录权限: {path}")
    except Exception as e:
        logger.warning(f"目录权限修复失败: {e}")


def _lockdown_data_dir() -> None:
    _lockdown_dir(DATA_DIR)


def _ensure_aux_data_dir() -> str:
    os.makedirs(AUX_DATA_DIR, exist_ok=True)
    os.makedirs(AUX_HISTORY_TEMP_DIR, exist_ok=True)
    _repair_dir_acl(AUX_DATA_DIR)
    _repair_dir_acl(AUX_HISTORY_TEMP_DIR)
    _lockdown_dir(AUX_DATA_DIR)
    return AUX_DATA_DIR

_ensure_data_dir()


CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
AUX_CONFIG_FILE = os.path.join(AUX_DATA_DIR, "config.json")

TOKEN_USAGE_FILE = os.path.join(DATA_DIR, "token_usage.json")

MODEL_CONFIGS_FILE = os.path.join(DATA_DIR, "model_configs.json")



def _load_model_configs() -> List[Dict]:
    if not os.path.exists(MODEL_CONFIGS_FILE):
        return []
    try:
        with open(MODEL_CONFIGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except Exception as e:
        logger.warning(f"操作失败(可忽略): {e}")
    return []

def _save_model_configs(configs: List[Dict]) -> None:
    try:
        tmp = MODEL_CONFIGS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(configs, f, ensure_ascii=False, indent=2)
        os.replace(tmp, MODEL_CONFIGS_FILE)
    except Exception as e:
        logger.warning(f"保存模型配置集失败: {e}")

def _save_current_as_model_config(name: str) -> bool:
    name = (name or "").strip()
    if not name:
        return False
    try:
        configs = _load_model_configs()
        entry = {
            "name": name,
            "provider_type": config.get("provider_type", ""),
            "base_url": config.get("base_url", ""),
            "api_key": _encode(config.get("api_key", "")),
            "model": config.get("model", ""),
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        configs = [c for c in configs if c.get("name") != name]
        configs.append(entry)
        _save_model_configs(configs)
        return True
    except Exception as e:
        logger.warning(f"保存当前模型配置失败: {e}")
        return False

def _apply_model_config(name: str) -> bool:
    try:
        configs = _load_model_configs()
        target = next((c for c in configs if c.get("name") == name), None)
        if not target:
            return False
        global config
        for k in ("provider_type", "base_url", "api_key", "model"):
            if k in target and target[k] is not None:
                config[k] = _decode(str(target[k])) if k == "api_key" else target[k]
        save_config(config)
        return True
    except Exception as e:
        logger.warning(f"应用模型配置失败: {e}")
        return False

def _delete_model_config(name: str) -> bool:
    try:
        configs = _load_model_configs()
        new = [c for c in configs if c.get("name") != name]
        if len(new) == len(configs):
            return False
        _save_model_configs(new)
        return True
    except Exception:
        return False


_TOKEN_USAGE_LOCK = threading.Lock()


def _record_token_usage(user_id: str, provider_type: str, model: str,
                        prompt_tokens: int, completion_tokens: int, total_tokens: int,
                        cache_hit: int = 0, cache_miss: int = 0) -> None:
    try:
        with _TOKEN_USAGE_LOCK:
            entry = {
                "ts": time.time(),
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "user_id": user_id,
                "provider": provider_type,
                "model": model,
                "prompt_tokens": int(prompt_tokens or 0),
                "completion_tokens": int(completion_tokens or 0),
                "total_tokens": int(total_tokens or 0),
                "cache_hit_tokens": int(cache_hit or 0),
                "cache_miss_tokens": int(cache_miss or 0),
            }
            try:
                with open(TOKEN_USAGE_FILE, "r", encoding="utf-8") as f:
                    recs = json.load(f)
                    if not isinstance(recs, list):
                        recs = []
            except Exception:
                recs = []
            recs.append(entry)

            # 按时间滚动保留 30 天，再兜一个条数上限，防止长期运行后文件膨胀
            _cutoff = time.time() - 30 * 86400
            recs = [r for r in recs if float(r.get("ts") or 0) >= _cutoff]
            if len(recs) > 5000:
                recs = recs[-5000:]
            tmp = TOKEN_USAGE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(recs, f, ensure_ascii=False, indent=1)
            os.replace(tmp, TOKEN_USAGE_FILE)
    except Exception as e:
        logger.warning(f"记录token消耗失败: {e}")


def _load_token_usage() -> List[Dict]:
    try:
        with open(TOKEN_USAGE_FILE, "r", encoding="utf-8") as f:
            recs = json.load(f)
            if not isinstance(recs, list):
                return []

            recs.sort(key=lambda x: x.get("ts", 0), reverse=True)
            return recs
    except Exception:
        return []


def _clear_token_usage_before(before_ts: float) -> int:
    try:
        with open(TOKEN_USAGE_FILE, "r", encoding="utf-8") as f:
            recs = json.load(f)
            if not isinstance(recs, list):
                recs = []
    except Exception:
        recs = []
    kept = [r for r in recs if r.get("ts", 0) >= before_ts]
    removed = len(recs) - len(kept)
    if removed > 0:
        tmp = TOKEN_USAGE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(kept, f, ensure_ascii=False, indent=1)
        os.replace(tmp, TOKEN_USAGE_FILE)
    return removed





DEFAULT_CONFIG = {
    "app_id": "",
    "app_secret": "",
    "provider_type": "deepseek",
    "api_key": "",
    "base_url": "",
    "system_prompt": "",
    "max_rounds": 5,
    "temperature": 0.7,
    "thinking": "off",
    "model": "",
    "compression_enabled": False,
    "compression_token_limit": 60000,
    "model_context_tokens": 32768,
    "max_concurrent": 3,
    "max_sessions": 1000,
    "archive_recall": True,
    "archive_recall_top": 4,
    "archive_keep": 5000,
    "archive_keep_total": 200000,
    "history_temp_keep_groups": 10,
    "history_temp_cleanup_enabled": True,
}

def _encode(s: str) -> str:


    if not s:
        return ""
    try:
        return "dpapi:" + base64.b64encode(_dpapi_protect(s.encode("utf-8"))).decode()
    except Exception as e:
        logger.warning(f"DPAPI 加密失败，密钥未落盘（避免明文泄露）: {e}")
        return ""

def _decode(s: str) -> str:
    if not s:
        return ""
    if isinstance(s, str) and s.startswith("dpapi:"):
        try:
            raw = base64.b64decode(s[len("dpapi:"):])
            return _dpapi_unprotect(raw).decode("utf-8")
        except Exception:
            return ""
    return s


def _err_summary(status, body) -> str:
    try:
        d = json.loads(body) if isinstance(body, str) else None
        if isinstance(d, dict):
            return f"status={status} code={d.get('code') or ''} msg={(str(d.get('message') or ''))[:120]}"
    except Exception:
        pass
    return f"status={status}"


def _dpapi_protect(data: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]
    def _blob(buf: bytes):
        arr = (ctypes.c_byte * len(buf))(*buf)
        return DATA_BLOB(len(buf), ctypes.cast(arr, ctypes.POINTER(ctypes.c_byte)))
    crypt32 = ctypes.windll.crypt32
    local_free = ctypes.windll.kernel32.LocalFree
    inblob = _blob(data)
    outblob = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(inblob), None, None, None, None, 0, ctypes.byref(outblob)):
        raise OSError("DPAPI protect failed")
    try:
        result = ctypes.string_at(outblob.pbData, outblob.cbData)
        return result
    finally:
        if outblob.pbData:
            local_free(outblob.pbData)

def _dpapi_unprotect(data: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]
    def _blob(buf: bytes):
        arr = (ctypes.c_byte * len(buf))(*buf)
        return DATA_BLOB(len(buf), ctypes.cast(arr, ctypes.POINTER(ctypes.c_byte)))
    crypt32 = ctypes.windll.crypt32
    local_free = ctypes.windll.kernel32.LocalFree
    inblob = _blob(data)
    outblob = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(inblob), None, None, None, None, 0, ctypes.byref(outblob)):
        raise OSError("DPAPI unprotect failed")
    try:
        result = ctypes.string_at(outblob.pbData, outblob.cbData)
        return result
    finally:
        if outblob.pbData:
            local_free(outblob.pbData)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            cfg = json.load(f)

        # 旧配置缺新增键时补默认值，否则升级后这些键在接口里是缺失状态
        cfg = {**DEFAULT_CONFIG, **cfg}

        need_migrate = False
        if "app_secret" in cfg and cfg["app_secret"]:
            if not cfg["app_secret"].startswith("dpapi:"):
                need_migrate = True
            cfg["app_secret"] = _decode(cfg["app_secret"])
        if "api_key" in cfg and cfg["api_key"]:
            if not cfg["api_key"].startswith("dpapi:"):
                need_migrate = True
            cfg["api_key"] = _decode(cfg["api_key"])
        if need_migrate:
            save_config(cfg)
        return cfg
    else:
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

def save_config(cfg):
    to_save = cfg.copy()

    old = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, encoding='utf-8') as f:
                old = json.load(f)
        except Exception as e:
            logger.warning(f"操作失败(可忽略): {e}")
    for key in ("app_secret", "api_key"):
        val = to_save.get(key)
        if val:
            enc = _encode(val)
            to_save[key] = enc if enc else old.get(key, "")
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(to_save, f, indent=2)
    os.replace(tmp, CONFIG_FILE)






AUX_CLONE_KEYS = [
    "max_rounds", "temperature", "thinking",
    "compression_enabled", "compression_token_limit", "model_context_tokens",
    "history_temp_keep_groups", "history_temp_cleanup_enabled",
    "archive_recall", "archive_recall_top", "archive_keep", "archive_keep_total",
]
DEFAULT_AUX_CONFIG = {
    "app_id": "", "app_secret": "",
    "provider_type": "deepseek",
    "api_key": "", "base_url": "",
    "system_prompt": "",
    "max_rounds": 5, "temperature": 0.7, "thinking": "off", "model": "",
    "compression_enabled": False, "compression_token_limit": 60000,
    "model_context_tokens": 32768,
    "history_temp_keep_groups": 10, "history_temp_cleanup_enabled": True,
    "archive_recall": True, "archive_recall_top": 4, "archive_keep": 5000, "archive_keep_total": 200000,
}

def _ensure_aux_config_keys(cfg: dict) -> dict:
    out = dict(DEFAULT_AUX_CONFIG)
    out.update(cfg or {})
    return out

def load_aux_config():
    # 不建目录、不落默认配置。以前这里一 import 就 mkdir 并写一份空配置，
    # 结果没用辅助机器人也会在程序目录里留一个 aux_data。
    if os.path.exists(AUX_CONFIG_FILE):
        with open(AUX_CONFIG_FILE, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        need_migrate = False
        if "app_secret" in cfg and cfg["app_secret"]:
            if not cfg["app_secret"].startswith("dpapi:"):
                need_migrate = True
            cfg["app_secret"] = _decode(cfg["app_secret"])
        if "api_key" in cfg and cfg["api_key"]:
            if not cfg["api_key"].startswith("dpapi:"):
                need_migrate = True
            cfg["api_key"] = _decode(cfg["api_key"])
        cfg = _ensure_aux_config_keys(cfg)
        if need_migrate:
            save_aux_config(cfg)
        return cfg
    return DEFAULT_AUX_CONFIG.copy()

def save_aux_config(cfg):
    _ensure_aux_data_dir()
    to_save = cfg.copy()
    old = {}
    if os.path.exists(AUX_CONFIG_FILE):
        try:
            with open(AUX_CONFIG_FILE, encoding='utf-8') as f:
                old = json.load(f)
        except Exception as e:
            logger.warning(f"操作失败(可忽略): {e}")
    for key in ("app_secret", "api_key"):
        val = to_save.get(key)
        if val:
            enc = _encode(val)
            to_save[key] = enc if enc else old.get(key, "")
    tmp = AUX_CONFIG_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(to_save, f, indent=2)
    os.replace(tmp, AUX_CONFIG_FILE)

def clone_global_to_aux(aux_cfg: dict, main_cfg: dict) -> dict:
    merged = dict(aux_cfg)
    for k in AUX_CLONE_KEYS:
        if k in main_cfg:
            merged[k] = main_cfg[k]
    return merged

_ALLOWED_HOSTS = ("127.0.0.1", "localhost")
_ALLOWED_ORIGINS = frozenset({
    "http://127.0.0.1:8000", "http://localhost:8000",
})


def _same_origin_scheme_host(origin: str) -> bool:
    try:
        p = urlparse(origin)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "").lower()
    if host not in _ALLOWED_HOSTS:
        return False
    port = p.port or (443 if p.scheme == "https" else 80)
    return port == 8000


def check_referer(request: Request):
    """本机接口的来源校验。

    三道：Host 头白名单（挡 DNS rebinding）、Origin 精确比对（挡 CSRF，
    浏览器跨站请求必带 Origin）、Referer 兜底（老浏览器 / 无 Origin 场景）。
    Referer 单独不可靠：加上 no-referrer 就能让它消失。
    """
    host = (request.headers.get("host") or "").split(":")[0].lower().strip()
    if host not in _ALLOWED_HOSTS:
        raise HTTPException(status_code=403, detail="Forbidden: 仅允许本机访问")

    origin = request.headers.get("origin")
    if origin:
        if origin.rstrip("/") in _ALLOWED_ORIGINS or _same_origin_scheme_host(origin):
            return
        raise HTTPException(status_code=403, detail="Invalid Origin")

    referer = request.headers.get("referer")
    if not referer:
        if request.method != "GET":
            raise HTTPException(status_code=403, detail="Forbidden: 写操作需同源 Origin 或 Referer")
        return
    if not _same_origin_scheme_host(referer) and (urlparse(referer).hostname or "").lower() not in _ALLOWED_HOSTS:
        raise HTTPException(status_code=403, detail="Invalid Referer")



PID_FILE = os.path.join(DATA_DIR, "app.pid")


def _write_pid():
    try:
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
    except Exception as e:
        logger.warning(f"写入 PID 文件失败: {e}")


def _read_pid() -> Optional[int]:
    try:
        if os.path.exists(PID_FILE):
            with open(PID_FILE, "r", encoding="utf-8") as f:
                return int(f.read().strip())
    except Exception as e:
        logger.warning(f"操作失败(可忽略): {e}")
    return None


def _remove_pid():
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except Exception as e:
        logger.warning(f"操作失败(可忽略): {e}")


def _terminate_pid(pid: int) -> bool:
    if not pid:
        return False
    if sys.platform == "win32":
        try:
            import ctypes

            h = ctypes.windll.kernel32.OpenProcess(0x0001, False, pid)
            if h:
                ctypes.windll.kernel32.TerminateProcess(h, 1)
                ctypes.windll.kernel32.CloseHandle(h)
                return True
        except Exception as e:
            logger.warning(f"操作失败(可忽略): {e}")
        return False

    try:
        os.kill(pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        return True
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
            time.sleep(0.2)
        except (OSError, ProcessLookupError):
            return True
    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except Exception:
        return False


def _free_port_8000(exclude_pid: Optional[int] = None) -> None:

    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes

        out = subprocess.run(["netstat", "-ano"], capture_output=True,
                             text=True, encoding="gbk", errors="ignore").stdout
        pids = set()
        for line in out.splitlines():
            if ":8000" in line and "LISTENING" in line.upper():
                parts = line.split()
                if parts:
                    try:
                        pids.add(int(parts[-1]))
                    except ValueError:
                        pass
        if not pids:
            return
        for pid in pids:
            if exclude_pid is not None and pid == exclude_pid:
                continue
            cmdline = ""
            try:
                ps = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine"],
                    capture_output=True, text=True, timeout=8)
                cmdline = ps.stdout or ""
            except Exception as _e:
                # 查不到命令行就判断不了归属，只能保守跳过。
                # 至少留一条日志，否则「停止不彻底」永远查无实据。
                logger.warning(f"查询 PID={pid} 命令行失败，按保守策略跳过: {_e}")
            if not any(k in cmdline for k in (_SELF_SCRIPT, "QQBotAgent.exe")):
                logger.info(f"8000 端口被非本程序占用 PID={pid}，跳过(不误杀)")
                continue
            _terminate_pid(pid)
    except Exception as e:
        logger.warning(f"操作失败(可忽略): {e}")


def _port_8000_in_use() -> bool:
    # 先尝试连接：比解析 netstat 稳，不受输出编码和 PATH 影响。
    # 之前只靠 netstat，在子 shell 里可能解析失败，导致误判为空闲、
    # 把已在运行的服务重启一遍，正在处理的对话被打断。
    try:
        with socket.create_connection(("127.0.0.1", 8000), timeout=0.5):
            return True
    except OSError:
        pass
    if sys.platform != "win32":
        return False
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True,
                             text=True, encoding="gbk", errors="ignore").stdout
        return any(":8000" in line and "LISTENING" in line.upper() for line in out.splitlines())
    except Exception:
        return False


def start_daemon() -> Optional[int]:
    """启动后台服务，返回子进程 PID；服务已在运行时返回 None。"""

    if _port_8000_in_use():
        print("  服务已在运行，无需重复启动。")
        return None

    _free_port_8000()
    _remove_pid()
    _ensure_data_dir()


    if getattr(sys, "frozen", False):
        target = [sys.executable, "--serve"]
    else:
        target = [sys.executable, os.path.abspath(__file__), "--serve"]

    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    _daemon_log_path = os.path.join(DATA_DIR, "daemon.log")
    if os.path.exists(_daemon_log_path) and os.path.getsize(_daemon_log_path) > 5_000_000:
        try:
            os.replace(_daemon_log_path, _daemon_log_path + ".old")
        except Exception:
            pass
    logf = open(_daemon_log_path, "a", encoding="utf-8")
    try:
        proc = subprocess.Popen(
            target,
            cwd=BASE_DIR,
            stdout=logf, stderr=logf,
            stdin=subprocess.DEVNULL,
            close_fds=True,
            creationflags=creationflags,
        )
    finally:
        # 启动失败时也要关掉句柄，否则每次失败泄漏一个文件描述符
        logf.close()
    # 父进程只是启动器，连接不再使用却一直持有 WAL 锁——
    # 子进程 import 时的迁移与索引校验会被锁卡住约 20 秒。
    # spawn 后立刻释放，子进程秒级就绪。
    try:
        session_mgr.close()
    except Exception:
        pass
    if aux_session_mgr is not None:
        try:
            aux_session_mgr.close()
        except Exception:
            pass
    return proc.pid


def _check_bind_safety() -> None:

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:


            s.bind(("0.0.0.0", 0))
        finally:
            s.close()

        logger.info("网络安全自检：服务将仅绑定 127.0.0.1（本机），不对互联网/局域网开放。")
    except Exception as e:
        logger.warning(f"网络安全自检异常（不影响启动）: {e}")











def _redact(content: str, secrets: List[str]) -> str:
    for s in secrets:
        if s and len(s) >= 6 and s in content:
            content = content.replace(s, "[已隐藏]")
    return content







import re as _re


_LOCAL_PATH_RE = _re.compile(
    r"(?i)(?:[a-zA-Z]:[\\/][\w\- .\\/]+|/(?:Users|home|etc|var|opt|tmp|root|dev)/[\w\- ./\\/]*)"
)

_SECRET_PAT_RE = _re.compile(
    r"(?i)(sk-[a-z0-9]{8,}|pk-[a-z0-9]{8,}|rk-[a-z0-9]{8,}|"
    r"Bearer\s+[A-Za-z0-9._\-]{16,}|"
    r"(?:api[_-]?key|secret|password|passwd|token|credential|access[_-]?key|private[_-]?key)\s*[:=]\s*[A-Za-z0-9@$!%*#?&._\-]{6,}|"
    r"(?=[A-Za-z0-9+/]{40,}={0,2})[A-Za-z0-9+/]*[0-9+/][A-Za-z0-9+/]*={0,2})"
)

_FILE_ACCESS_RE = _re.compile(
    r"(?i)(?:读取|查看|打开|列出|访问).{0,12}(?:文件|目录|硬盘|磁盘|C:盘|D:盘|磁盘分区|配置文件)|"
    r"(?:读|访问).{0,6}(?:C:\\|C:/|D:\\|D:/|/etc/|/Users/|/home/)"
)

_CMD_EXEC_RE = _re.compile(
    r"(?i)(?:执行|运行|调用|输入).{0,8}(?:命令|控制台|python|bash|sh|批处理)|(?:python|bash)\s+[/-]?[a-z]"
)


def _is_local_secretive(text: str) -> bool:
    return bool(_LOCAL_PATH_RE.search(text) or _SECRET_PAT_RE.search(text))


def _is_file_access_request(text: str) -> bool:
    return bool(_FILE_ACCESS_RE.search(text) or _CMD_EXEC_RE.search(text))


def _isolate_content(content: str, secrets: List[str]) -> str:





    content = _redact(content, secrets)

    if _is_file_access_request(content):
        return "[该请求涉及访问本机文件或执行命令，已拦截，未发送。]"

    if _is_local_secretive(content):
        return "[已隔离：内容涉及本机敏感信息，未发送。]"
    return content


_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=180, connect=15)


def _is_retryable_error(e: Exception) -> bool:
    """只重试有意义的错误。

    401/400/403/404 是配置或权限问题，重试只会拖慢报错；
    429 与 5xx 是临时状态，超时和连接中断同理。
    """
    if isinstance(e, (aiohttp.ClientError, asyncio.TimeoutError, TimeoutError, OSError)):
        return True
    m = _re.search(r"\b(\d{3})\b", str(e))
    if m:
        code = int(m.group(1))
        if 400 <= code < 500:
            return code == 429
        return code >= 500
    return False


class Provider(ABC):

    def _register_secret(self, secret: str):
        self._secrets = getattr(self, "_secrets", [])
        if secret and secret not in self._secrets:
            self._secrets.append(secret)

    def _sanitize_messages(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """历史只做密钥替换，只有最后一条用户输入做访问隔离。

        旧实现对每条历史都跑 _isolate_content，历史里出现过路径类内容
        就被整条替换成「已隔离」，几轮之后上下文全是拦截文案，模型接不上话。
        """
        secrets = getattr(self, "_secrets", []) or []
        out: List[Dict[str, str]] = []
        last = len(messages) - 1
        for i, m in enumerate(messages):
            content = m.get("content", "")
            if i == last and m.get("role") == "user":
                content = _isolate_content(content, secrets)
            else:
                content = _redact(content, secrets)
            out.append({"role": m.get("role", ""), "content": content})
        return out

    @abstractmethod
    async def get_models(self) -> List[str]:
        pass
    @abstractmethod
    async def test_connection(self) -> bool:
        pass
    @abstractmethod
    async def chat_completion(self, messages: List[Dict[str, str]], temperature: float,
                              model: str, reasoning_effort: Optional[str] = None,
                              usage_ctx: Optional[dict] = None) -> str:
        pass

    async def chat_completion_resilient(self, messages: List[Dict[str, str]], temperature: float,
                                        model: str, reasoning_effort: Optional[str] = None,
                                        usage_ctx: Optional[dict] = None,
                                        attempts: int = 3) -> str:
        """对可重试错误做指数退避。

        鉴权与参数错误重试没有意义，直接抛；429、5xx、超时、连接中断才退避重试。
        """
        delay = 1.0
        for i in range(1, attempts + 1):
            try:
                return await self.chat_completion(messages, temperature, model,
                                                  reasoning_effort, usage_ctx)
            except Exception as e:
                if i >= attempts or not _is_retryable_error(e):
                    raise
                logger.warning(f"模型调用失败({i}/{attempts})，{delay:.0f}s 后重试: {e}")
                await asyncio.sleep(delay)
                delay = min(8.0, delay * 2)
        raise RuntimeError("unreachable")


class OpenAIProvider(Provider):
    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1"):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/') if base_url else "https://api.openai.com/v1"
        self._register_secret(api_key)
        self.thinking_profile = THINKING_PROFILES["_default"]
    async def get_models(self) -> List[str]:
        session = await _http()
        headers = {"Authorization": f"Bearer {self.api_key}"}
        async with session.get(f"{self.base_url}/models", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return [m['id'] for m in data.get('data', [])]
            return []
    async def test_connection(self) -> bool:

        try:
            models = await self.get_models()
            return len(models) > 0
        except Exception:
            return False
    async def chat_completion(self, messages: List[Dict[str, str]], temperature: float,
                              model: str, reasoning_effort: Optional[str] = None,
                              usage_ctx: Optional[dict] = None) -> str:
        messages = self._sanitize_messages(messages)
        profile = getattr(self, "thinking_profile", THINKING_PROFILES["_default"])




        thinking_extra = None
        if reasoning_effort == "off":
            thinking_extra = profile["off_payload"]
        elif reasoning_effort and reasoning_effort in profile.get("levels", []):
            thinking_extra = profile["on_payload"](reasoning_effort)
        session = await _http()
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

        payload = {"model": model, "messages": messages, "temperature": temperature}
        if thinking_extra:
            payload.update(thinking_extra)
        async with session.post(f"{self.base_url}/chat/completions", headers=headers, json=payload,
                                timeout=_HTTP_TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()

                if usage_ctx and isinstance(data, dict):
                    usage = data.get("usage", {}) or {}
                    _record_token_usage(
                        user_id=usage_ctx.get("user_id", ""),
                        provider_type=usage_ctx.get("provider_type", ""),
                        model=model,
                        prompt_tokens=usage.get("prompt_tokens", 0),
                        completion_tokens=usage.get("completion_tokens", 0),
                        total_tokens=usage.get("total_tokens", 0),
                        cache_hit=usage.get("prompt_cache_hit_tokens", 0),
                        cache_miss=usage.get("prompt_cache_miss_tokens", 0),
                    )
                return data['choices'][0]['message']['content']
            else:
                error = await resp.text()
                raise Exception(f"OpenAI API error: {resp.status} - {error}")

class AnthropicProvider(Provider):
    def __init__(self, api_key: str, base_url: str = "https://api.anthropic.com/v1"):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/') if base_url else "https://api.anthropic.com/v1"
        self._register_secret(api_key)
    async def get_models(self) -> List[str]:
        return ["claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307"]
    async def test_connection(self) -> bool:
        try:
            session = await _http()
            headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
            payload = {"model": "claude-3-haiku-20240307", "max_tokens": 1, "messages": [{"role": "user", "content": "ping"}]}
            async with session.post(f"{self.base_url}/messages", headers=headers, json=payload,
                                    timeout=_HTTP_TIMEOUT) as resp:
                return resp.status == 200
        except Exception:
            return False
    async def chat_completion(self, messages: List[Dict[str, str]], temperature: float,
                              model: str, reasoning_effort: Optional[str] = None,
                              usage_ctx: Optional[dict] = None) -> str:
        messages = self._sanitize_messages(messages)

        system_prompt = ""
        user_msgs = []
        for msg in messages:
            if msg['role'] == 'system':
                system_prompt = msg['content']
            elif msg['role'] == 'user':
                user_msgs.append({"role": "user", "content": msg['content']})
            elif msg['role'] == 'assistant':
                user_msgs.append({"role": "assistant", "content": msg['content']})
        session = await _http()
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}


        payload = {"model": model, "system": system_prompt, "messages": user_msgs,
                   "temperature": temperature, "max_tokens": 32768}
        async with session.post(f"{self.base_url}/messages", headers=headers, json=payload) as resp:
            if resp.status == 200:
                data = await resp.json()

                if usage_ctx and isinstance(data, dict):
                    usage = data.get("usage", {}) or {}
                    _record_token_usage(
                        user_id=usage_ctx.get("user_id", ""),
                        provider_type=usage_ctx.get("provider_type", ""),
                        model=model,
                        prompt_tokens=usage.get("input_tokens", 0),
                        completion_tokens=usage.get("output_tokens", 0),
                        total_tokens=(usage.get("input_tokens", 0) or 0) + (usage.get("output_tokens", 0) or 0),
                        cache_hit=usage.get("cache_read_input_tokens", 0),
                        cache_miss=usage.get("cache_creation_input_tokens", 0),
                    )
                return data['content'][0]['text']
            else:
                error = await resp.text()
                raise Exception(f"Anthropic API error: {resp.status} - {error}")




PROVIDER_PRESETS = [

    ("openai",      "OpenAI",                 "https://api.openai.com/v1"),
    ("anthropic",   "Anthropic",              "https://api.anthropic.com/v1"),
    ("deepseek",    "DeepSeek",               "https://api.deepseek.com/v1"),
    ("glm",         "智谱 GLM",               "https://open.bigmodel.cn/api/paas/v4"),
    ("kimi",        "月之暗面 Kimi",          "https://api.moonshot.cn/v1"),
    ("siliconflow", "硅基流动 SiliconFlow",   "https://api.siliconflow.cn/v1"),
    ("qwen",        "阿里通义千问 Qwen",      "https://dashscope.aliyuncs.com/compatible-mode/v1"),
    ("hunyuan",     "腾讯混元 Hunyuan",       "https://api.hunyuan.cloud.tencent.com/v1"),
    ("ollama",      "本地 Ollama",            "http://127.0.0.1:11434/v1"),
    ("custom",      "自定义",                 ""),
]

PROVIDER_MAP = {"openai": OpenAIProvider, "anthropic": AnthropicProvider}

_OPENAI_COMPAT = ("openai", "deepseek", "glm", "kimi", "siliconflow", "qwen", "hunyuan", "ollama", "custom")
for _p in _OPENAI_COMPAT:
    PROVIDER_MAP.setdefault(_p, OpenAIProvider)




THINKING_PROFILES = {

    "deepseek": {
        "levels": ["low", "high", "max"],
        "off_payload": {"thinking": {"type": "disabled"}},
        "on_payload": lambda eff: {"thinking": {"type": "enabled"}, "reasoning_effort": eff},
    },

    "openai": {
        "levels": ["low", "medium", "high"],
        "off_payload": {"reasoning_effort": "none"},
        "on_payload": lambda eff: {"reasoning_effort": eff},
    },

    "ollama": {
        "levels": ["low", "medium", "high"],
        "off_payload": {},
        "on_payload": lambda eff: {},
    },

    "_default": {
        "levels": ["low", "medium", "high"],
        "off_payload": {"reasoning_effort": "none"},
        "on_payload": lambda eff: {"reasoning_effort": eff},
    },
}


def create_provider(provider_type: str, api_key: str, base_url: str) -> Provider:
    cls = PROVIDER_MAP.get(provider_type)
    if not cls:
        raise ValueError(f"不支持的Provider: {provider_type}")
    inst = cls(api_key, base_url)

    if isinstance(inst, OpenAIProvider):
        inst.thinking_profile = THINKING_PROFILES.get(provider_type, THINKING_PROFILES["_default"])
    return inst

def provider_default_base(provider_type: str) -> str:
    for pt, _name, base in PROVIDER_PRESETS:
        if pt == provider_type:
            return base
    return ""




_MASKED = "******"


def merge_saved(current: dict, incoming: dict, keys: List[str]) -> dict:


    merged = dict(current)
    for k in keys:
        v = incoming.get(k)

        if v is None or v == "" or v == _MASKED:
            merged[k] = current.get(k, "")
        else:
            merged[k] = v
    return merged



HISTORY_TEMP_DIR = os.path.join(BASE_DIR, "history_temp")

def _ensure_history_temp_dir() -> str:
    os.makedirs(HISTORY_TEMP_DIR, exist_ok=True)
    return HISTORY_TEMP_DIR

def _estimate_tokens(content: str) -> int:
    if not content:
        return 0
    ascii_n = sum(1 for c in content if ord(c) < 128)
    cjk_n = len(content) - ascii_n
    return max(1, int(ascii_n / 4 + cjk_n * 0.75) + 2)

def _estimate_messages_tokens(messages: List[Dict[str, str]]) -> int:
    total = 0
    for m in messages:
        total += _estimate_tokens(m.get("content", "")) + 10
    return total


def _safe_group_id(group_id) -> int:
    """组号必须落成 int。字符串形式带 "/" 或 ".." 时，
    f-string 拼进路径会造出新的路径段，形成目录穿越。"""
    try:
        return int(group_id)
    except (TypeError, ValueError):
        return 0


def _temp_dir_for_group(user_id: str, group_id: int, base_dir: str = None) -> str:

    base = base_dir or HISTORY_TEMP_DIR
    os.makedirs(base, exist_ok=True)
    safe_uid = "".join(c for c in str(user_id) if c.isalnum() or c in "-_")[:40] or "unknown"
    d = os.path.join(base, f"{safe_uid}_g{_safe_group_id(group_id)}")
    os.makedirs(d, exist_ok=True)
    return d

def _load_all_temp_compressions(user_id: str, group_id: int, base_dir: str = None) -> List[Dict]:
    out = []
    try:
        d = _temp_dir_for_group(user_id, group_id, base_dir)
        if not os.path.isdir(d):
            return out
        for fn in os.listdir(d):
            fp = os.path.join(d, fn)
            if fn == "summary.txt":
                try:
                    with open(fp, "r", encoding="utf-8") as f:
                        out.append({"file": fn, "round": "999999", "summary": f.read()})
                except Exception:
                    continue
            elif fn.startswith("compress_") and fn.endswith(".txt"):
                try:
                    with open(fp, "r", encoding="utf-8") as f:
                        out.append({"file": fn, "round": fn.replace("compress_", "").replace(".txt", ""), "summary": f.read()})
                except Exception:
                    continue
        out.sort(key=lambda x: int(x.get("round", "0")))
    except Exception as e:
        logger.warning(f"读取压缩记录失败: {e}")
    return out


MEMORY_FILE = "memory.json"
_MEM_MAX_EVENTS = 40
_MEM_MAX_FACTS = 80
_MEM_MAX_TRAITS = 20
_MEM_MAX_TASKS = 30
_MEM_MAX_RELATIONS = 25


def _memory_path(user_id: str, group_id: int, base_dir: str = None) -> str:
    return os.path.join(_temp_dir_for_group(user_id, group_id, base_dir), MEMORY_FILE)


def _empty_memory() -> Dict:
    return {
        "version": 1,
        "updated": 0,
        "note": "",
        "user": {"nick": "", "traits": []},
        "facts": [],
        "tasks": [],
        "relations": {},
        "events": [],
    }


def _as_str(v) -> str:
    if isinstance(v, (str, int, float)):
        return str(v).strip()
    return ""


def _as_list(v) -> List:
    if isinstance(v, list):
        return v
    if isinstance(v, dict):
        return [v]
    s = _as_str(v)
    return [s] if s else []


def _normalize_memory(raw: Dict, prev: Optional[Dict] = None) -> Dict:
    """把模型输出收敛成固定结构。

    模型返回的 JSON 形状不可信，字段类型可能是错的，列表里可能混字符串
    与对象。这里逐字段纠正类型、去重、按上限截断，避免脏数据进上下文。
    """
    now = int(time.time())
    out = _empty_memory()
    out["updated"] = now
    prev = prev if isinstance(prev, dict) else {}

    pu = prev.get("user") if isinstance(prev.get("user"), dict) else {}
    ru = raw.get("user") if isinstance(raw.get("user"), dict) else {}
    nick = _as_str(ru.get("nick")) or _as_str(pu.get("nick"))
    traits: List[str] = []
    for t in _as_list(ru.get("traits")) + _as_list(pu.get("traits")):
        s = _as_str(t)
        if s and s not in traits:
            traits.append(s)
    out["user"] = {"nick": nick[:60], "traits": traits[:_MEM_MAX_TRAITS]}

    facts: Dict[str, Dict] = {}
    for src in (prev.get("facts"), raw.get("facts")):
        for f in _as_list(src):
            if isinstance(f, dict):
                k, v = _as_str(f.get("k")), _as_str(f.get("v"))
            else:
                k, v = _as_str(f), ""
            if k and v:
                facts[k[:60]] = {"k": k[:60], "v": v[:300], "t": now}
    out["facts"] = list(facts.values())[-_MEM_MAX_FACTS:]

    tasks: Dict[str, Dict] = {}
    for src in (prev.get("tasks"), raw.get("tasks")):
        for t in _as_list(src):
            if not isinstance(t, dict):
                continue
            name = _as_str(t.get("task"))[:200]
            if not name:
                continue
            st = _as_str(t.get("status")).lower()
            done = st in ("done", "closed", "已完成", "完成", "已结束")
            tasks[name] = {"task": name, "status": "done" if done else "open", "t": now}
    out["tasks"] = list(tasks.values())[-_MEM_MAX_TASKS:]

    rel: Dict[str, str] = {}
    for src in (prev.get("relations"), raw.get("relations")):
        if isinstance(src, dict):
            for k, v in src.items():
                k2, v2 = _as_str(k), _as_str(v)
                if k2 and v2:
                    rel[k2[:80]] = v2[:120]
    out["relations"] = dict(list(rel.items())[:_MEM_MAX_RELATIONS])

    events: List[str] = []
    seen = set()
    for src in (prev.get("events"), raw.get("events")):
        for e in _as_list(src):
            s = _as_str(e)[:200]
            if s and s not in seen:
                seen.add(s)
                events.append(s)
    out["events"] = events[-_MEM_MAX_EVENTS:]

    # 模型没按 JSON 输出时，原文降级存在这里，不丢
    out["note"] = _as_str(raw.get("note"))[:4000] or _as_str(prev.get("note"))[:4000]
    return out


def _parse_memory_json(text: str) -> Optional[Dict]:
    """模型输出不保证是纯 JSON：可能带代码围栏、前后说明、尾随逗号。"""
    if not text:
        return None
    s = text.strip()
    if "```" in s:
        for part in s.split("```"):
            q = part.strip()
            if q[:4].lower() == "json":
                q = q[4:].strip()
            if q.startswith("{"):
                s = q
                break
    i, j = s.find("{"), s.rfind("}")
    if i < 0 or j <= i:
        return None
    cand = s[i:j + 1]
    for attempt in (cand, _re.sub(r",\s*([}\]])", r"\1", cand)):
        try:
            d = json.loads(attempt)
            if isinstance(d, dict):
                return d
        except Exception:
            continue
    return None


def _load_memory(user_id: str, group_id: int, base_dir: str = None) -> Optional[Dict]:
    try:
        with open(_memory_path(user_id, group_id, base_dir), "r", encoding="utf-8") as f:
            m = json.load(f)
        if isinstance(m, dict) and m.get("version"):
            return _normalize_memory(m)
    except Exception:
        pass
    return None


def _save_memory(user_id: str, group_id: int, mem: Dict, base_dir: str = None) -> str:
    try:
        fp = _memory_path(user_id, group_id, base_dir)
        tmp = fp + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(mem, f, ensure_ascii=False, indent=1)
        os.replace(tmp, fp)
        return fp
    except Exception as e:
        logger.warning(f"保存记忆失败: {e}")
        return ""


def _render_memory(mem: Dict) -> str:
    """把结构化记忆渲染成紧凑文本，替代自然语言摘要。

    同样信息量下比摘要省 3 到 5 倍 token，且同 key 直接覆盖，
    不会像滚动摘要那样每压一次糊一层。
    """
    if not mem:
        return ""
    lines = ["[长期记忆]"]
    u = mem.get("user") or {}
    if u.get("nick"):
        lines.append(f"称呼：{u['nick']}")
    if u.get("traits"):
        lines.append("特征：" + "、".join(u["traits"][:12]))
    facts = mem.get("facts") or []
    if facts:
        lines.append("事实：" + "；".join(f"{f.get('k')}={f.get('v')}" for f in facts[:40]))
    tasks = [t for t in (mem.get("tasks") or []) if t.get("status") != "done"]
    if tasks:
        lines.append("未完成：" + "；".join(str(t.get("task", "")) for t in tasks[:10]))
    rel = mem.get("relations") or {}
    if rel:
        lines.append("关系：" + "；".join(f"{k}-{v}" for k, v in list(rel.items())[:15]))
    ev = mem.get("events") or []
    if ev:
        lines.append("近期：" + "；".join(str(x) for x in ev[-15:]))
    if mem.get("note"):
        lines.append("备注：" + str(mem["note"])[:2000])
    return "\n".join(lines)


def _cleanup_temp_compressions(user_id: str, group_id: int, base_dir: str = None) -> None:
    try:
        d = _temp_dir_for_group(user_id, group_id, base_dir)
        if not os.path.isdir(d):
            return
        for fn in os.listdir(d):
            if fn.startswith("compress_") and fn.endswith(".txt"):
                try:
                    os.remove(os.path.join(d, fn))
                except Exception:
                    pass
    except Exception as e:
        logger.warning(f"清理旧压缩文件失败: {e}")

def _delete_temp_group(user_id: str, group_id: int, base_dir: str = None):
    try:
        safe_uid = "".join(c for c in str(user_id) if c.isalnum() or c in "-_")[:40] or "unknown"
        d = os.path.join(base_dir or HISTORY_TEMP_DIR, f"{safe_uid}_g{_safe_group_id(group_id)}")
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
    except Exception as e:
        logger.warning(f"操作失败(可忽略): {e}")

def _cleanup_old_temp_groups(user_id: str, current_group_id: int, keep_groups: int, base_dir: str = None):
    if keep_groups <= 0:
        return
    try:
        base = base_dir or HISTORY_TEMP_DIR
        safe_uid = "".join(c for c in str(user_id) if c.isalnum() or c in "-_")[:40] or "unknown"
        if not os.path.isdir(base):
            return
        prefix = f"{safe_uid}_g"

        dirs = []
        for fn in os.listdir(base):
            if fn.startswith(prefix):
                try:
                    gid = int(fn[len(prefix):])
                    dirs.append((gid, os.path.join(base, fn)))
                except ValueError:
                    continue

        dirs.sort(key=lambda x: x[0])

        keep_from = current_group_id - keep_groups + 1
        for gid, path in dirs:
            if gid < keep_from:
                shutil.rmtree(path, ignore_errors=True)
                logger.info(f"自动清理 history temp: 组 {gid}")
    except Exception as e:
        logger.warning(f"清理 history temp 失败: {e}")

_SCHEMA_VERSION = 3

# 检索时丢弃的虚词。整句当查询命中率低，切词后这些词没有区分度。
_STOP_CHARS = set(
    "的了吗呢吧啊呀哦嗯是在有和就都也还又很太真把被让给对从向于这那我你他她它们个上下去来说要会能可以"
    "什么怎哪几为"
)


def _query_terms(text: str, limit: int = 8) -> List[str]:
    """从一句话里抽检索词。

    直接按固定窗口滑会切出「你还记」「得我养」这类跨词碎片，在原文里
    根本不存在。正确做法是先按虚词把句子切成实词块，块太短就丢，
    块够长再在块内生成片段。

    这样「你还记得我养的那只猫吗」能抽出「记得」「只猫」，
    命中「记住了」「养了两只猫」。整句 LIKE 一条都命中不了。
    """
    if not text:
        return []
    segs = _re.findall(r"[\u4e00-\u9fff]+|[A-Za-z0-9_]+", text)
    terms: List[str] = []
    seen = set()

    def add(t: str) -> None:
        t = (t or "").strip()
        if len(t) < 2 or len(t) > 6 or t in seen:
            return
        # 纯符号或纯下划线没有检索意义：清洗后变成空串，
        # 拼进 LIKE 就是 '%%'，会把整张归档表捞出来污染上下文。
        if not any(c.isalnum() or "\u4e00" <= c <= "\u9fff" for c in t):
            return
        seen.add(t)
        terms.append(t)

    for s in segs:
        if _re.fullmatch(r"[A-Za-z0-9_]+", s):
            if len(s) >= 2:
                add(s.lower())
            continue
        chunks: List[str] = []
        buf = ""
        for ch in s:
            if ch in _STOP_CHARS:
                if buf:
                    chunks.append(buf)
                    buf = ""
            else:
                buf += ch
        if buf:
            chunks.append(buf)
        for c in chunks:
            if len(c) >= 2:
                add(c)
            if len(c) >= 4:
                for n in (3, 2):
                    for i in range(len(c) - n + 1):
                        add(c[i:i + n])

    terms.sort(key=len, reverse=True)
    return terms[:limit]


class _SessionStore:
    """会话持久化。

    旧实现每次变动都把整个 sessions 字典重新序列化写盘，消息越多越慢：
    写入量与历史总长度成正比。改成 SQLite 后单条消息只更新一行，
    写入量与历史长度无关。
    """

    def __init__(self, db_path: str):
        self.path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        # 服务常驻时 CLI 命令也会连这个库，PRAGMA 阶段遇锁必须降级而不是崩掉——
        # journal_mode 拿不到 WAL 就用默认 journal，功能照常只是慢一点
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
        except Exception as e:
            logger.warning(f"WAL 不可用(库忙)，用默认 journal: {e}")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        # 关闭后删除的行会留在未分配的页里，用十六进制编辑器就能捞回来。
        # 聊天记录属于删除即应消失的数据，代价是写放大一点。
        self._conn.execute("PRAGMA secure_delete=ON")
        self._conn.execute("PRAGMA foreign_keys=ON")
        # 页缓存 8MB（默认 2MB）：归档检索和消息回读基本都是热数据
        self._conn.execute("PRAGMA cache_size=-8000")
        # 让查询规划器定期更新统计信息。库被占用时会 locked，
        # 这条只是例行维护，失败不能拖垮启动。
        try:
            self._conn.execute("PRAGMA optimize")
        except Exception as e:
            logger.warning(f"PRAGMA optimize 跳过(库忙): {e}")
        try:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS sessions("
                "user_id TEXT PRIMARY KEY, data TEXT NOT NULL, last_used REAL)"
            )
            self._conn.commit()
        except Exception as e:
            # 服务常驻时 CLI 进程可能连不上（锁/权限），此时让 CLI 的
            # --stop 等不需要库的操作照常执行，而不是在 import 阶段崩掉
            logger.warning(f"会话库暂不可用(库忙): {e}")
        self._fts = False
        try:
            self._migrate()
            self._probe_fts()
        except Exception as e:
            logger.warning(f"会话库结构检查跳过(库忙): {e}")

    def _probe_fts(self) -> None:
        """确认全文索引可用并校验一致性。

        FTS 表损坏时检索会静默返回空，看起来像「没有历史」，
        实际是索引坏了。启动时校验一次，坏了直接重建。
        """
        try:
            row = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='archive_fts'").fetchone()
            if not row:
                self._fts = False
                return
            self._fts = True
            try:
                self._conn.execute("INSERT INTO archive_fts(archive_fts) VALUES('integrity-check')")
            except Exception as e:
                if "locked" in str(e).lower():
                    # 服务正在运行，库被占用，跳过本次校验。
                    # 不能因此把 _fts 判成不可用，否则 CLI 检索会莫名退回 LIKE。
                    return
                logger.warning(f"归档索引校验失败，重建索引: {e}")
                self._conn.execute("INSERT INTO archive_fts(archive_fts) VALUES('rebuild')")
                self._conn.commit()
        except Exception as e:
            logger.warning(f"归档索引探测失败，检索回落 LIKE: {e}")
            self._fts = False

    def _migrate(self) -> None:
        """按 user_version 升级表结构。老库没有版本号，从 0 开始逐级升。"""
        try:
            cur = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        except Exception:
            cur = 0
        if cur >= _SCHEMA_VERSION:
            return
        try:
            if cur < 1:
                self._init_archive()
            if cur < 2:
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_archive_user_group "
                    "ON archive(user_id, group_id, id)")
            if cur < 3:
                self._conn.execute(
                    "CREATE TABLE IF NOT EXISTS messages("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "user_id TEXT NOT NULL, group_id INTEGER NOT NULL, seq INTEGER NOT NULL,"
                    "role TEXT NOT NULL, content TEXT NOT NULL, ts REAL NOT NULL)")
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_messages_group "
                    "ON messages(user_id, group_id, seq)")
                # 把 sessions.data 里的 history 搬进 messages，之后 data 只存元数据
                for uid, data in self._conn.execute("SELECT user_id, data FROM sessions").fetchall():
                    try:
                        d = json.loads(data)
                    except Exception:
                        continue
                    groups = d.get("groups") or []
                    if not isinstance(groups, list):
                        continue
                    for idx, g in enumerate(groups):
                        if not isinstance(g, dict):
                            continue
                        hist = g.get("history") or []
                        if hist:
                            self._messages_insert(uid, idx + 1, hist, 0)
                        g["history"] = []
                        g["synced"] = len(hist)
                    self._conn.execute(
                        "UPDATE sessions SET data=? WHERE user_id=?",
                        (json.dumps(d, ensure_ascii=False), uid))
            self._conn.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            self._conn.commit()
            logger.info(f"会话库已升级到 schema v{_SCHEMA_VERSION}（原 v{cur}）")
        except Exception as e:
            logger.error(f"会话库升级失败，继续使用当前结构: {e}")

    def vacuum(self) -> None:
        """重整文件、回收已删除页。低频调用，会锁库。"""
        try:
            self._conn.commit()
            self._conn.execute("VACUUM")
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception as e:
            logger.warning(f"VACUUM 失败(可忽略): {e}")

    def count(self) -> int:
        try:
            return int(self._conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0])
        except Exception:
            return 0

    def load_all(self) -> Dict[str, Dict]:
        out: Dict[str, Dict] = {}
        try:
            for uid, data in self._conn.execute("SELECT user_id, data FROM sessions"):
                try:
                    v = json.loads(data)
                except Exception:
                    continue
                if isinstance(v, dict):
                    out[uid] = v
        except Exception as e:
            logger.warning(f"读取会话库失败: {e}")
        return out

    def upsert(self, user_id: str, payload: Dict) -> None:
        # history 已单独落 messages 表，这里只存元数据，
        # 否则同一份内容会被序列化两遍
        slim = dict(payload)
        groups = payload.get("groups")
        if isinstance(groups, list):
            slim["groups"] = [
                {k: v for k, v in g.items() if k != "history"} if isinstance(g, dict) else g
                for g in groups
            ]
        try:
            self._conn.execute(
                "INSERT INTO sessions(user_id, data, last_used) VALUES(?,?,?) "
                "ON CONFLICT(user_id) DO UPDATE SET data=excluded.data, last_used=excluded.last_used",
                (user_id, json.dumps(slim, ensure_ascii=False),
                 float(payload.get("last_used") or time.time())))
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def delete(self, user_id: str) -> None:
        self._conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        self._conn.commit()

    def delete_all(self) -> None:
        self._conn.execute("DELETE FROM sessions")
        self._conn.commit()
        self.vacuum()

    # ---- 归档：被压缩或翻篇挤出去的原文 ----
    # 归档只做检索用，不进常规上下文，删掉不影响会话本身。

    def _init_archive(self) -> None:
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS archive("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "user_id TEXT NOT NULL,"
            "group_id INTEGER NOT NULL DEFAULT 0,"
            "role TEXT NOT NULL,"
            "content TEXT NOT NULL,"
            "ts REAL NOT NULL)"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_archive_user ON archive(user_id, ts)")
        self._fts = False
        try:
            self._conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS archive_fts USING fts5(content, tokenize='trigram')")
            self._conn.execute(
                "CREATE TRIGGER IF NOT EXISTS archive_ai AFTER INSERT ON archive BEGIN "
                "INSERT INTO archive_fts(rowid, content) VALUES (new.id, new.content); END")
            self._conn.execute(
                "CREATE TRIGGER IF NOT EXISTS archive_ad AFTER DELETE ON archive BEGIN "
                "DELETE FROM archive_fts WHERE rowid = old.id; END")
            self._fts = True
        except Exception as e:
            logger.warning(f"归档全文索引不可用，检索回落 LIKE: {e}")
        self._conn.commit()

    def archive_add(self, user_id: str, group_id: int, items: List[Dict]) -> int:
        if not items:
            return 0
        rows = []
        for m in items:
            content = (m.get("content") or "").strip()
            if not content:
                continue
            rows.append((user_id, int(group_id or 0), m.get("role") or "user",
                         content, float(m.get("ts") or time.time())))
        if not rows:
            return 0
        try:
            self._conn.executemany(
                "INSERT INTO archive(user_id, group_id, role, content, ts) VALUES(?,?,?,?,?)", rows)
            self._conn.commit()
            return len(rows)
        except Exception as e:
            logger.warning(f"归档写入失败: {e}")
            return 0

    def archive_search(self, user_id: str, query: str, limit: int = 4,
                       expand: bool = True) -> List[Dict]:
        """按关键词召回归档。

        打分而不是简单过滤：抽出多个检索词，命中越多分越高，长词权重更大；
        同分按时间近优先。命中后再把前后各一条捞回来，
        避免只返回一句孤零零的回复——那样召回也没用。

        这是关键词检索，不是语义检索。
        """
        terms = _query_terms(query)
        if not terms:
            return []
        limit = max(1, min(20, int(limit or 4)))

        conds, params = [], []
        clean_terms = []
        for t in terms:
            # 去掉 LIKE 通配符后再判空：剩下的空串匹配所有行
            c = t.replace("%", "").replace("_", "").strip()
            if not c:
                continue
            clean_terms.append(c)
            conds.append("(CASE WHEN content LIKE ? THEN 1 ELSE 0 END) * ?")
            params.extend([f"%{c}%", max(1, len(c) - 1)])
        if not conds:
            return []
        score_sql = " + ".join(conds)

        # 所有词都够长时用 FTS 预过滤缩小候选集，语义与 LIKE 等价但快得多。
        # 混有短词时不能走 FTS——trigram 对两字以内无效，会漏掉短词的命中。
        base_where = "user_id=?"
        base_params = list(params) + [user_id, limit]
        use_fts = self._fts and all(len(c) >= 3 for c in clean_terms)
        if use_fts:
            fts_expr = " OR ".join('"' + c.replace('"', '""') + '"' for c in clean_terms)
            # 占位符顺序：user_id 在前，FTS 表达式在子查询里靠后
            where = base_where + " AND id IN (SELECT rowid FROM archive_fts WHERE archive_fts MATCH ?)"
            exec_params = list(params) + [user_id, fts_expr, limit]
        else:
            where = base_where
            exec_params = base_params
        sql_tpl = (
            "SELECT id, role, content, ts, score FROM ("
            " SELECT id, role, content, ts, (" + score_sql + ") AS score"
            " FROM archive WHERE {where}"
            ") WHERE score > 0 ORDER BY score DESC, ts DESC LIMIT ?"
        )
        try:
            rows = self._conn.execute(sql_tpl.format(where=where), exec_params).fetchall()
        except Exception as e:
            if not use_fts:
                logger.warning(f"归档检索失败: {e}")
                return []
            logger.warning(f"FTS 预过滤失败，回落全表打分: {e}")
            try:
                rows = self._conn.execute(sql_tpl.format(where=base_where), base_params).fetchall()
            except Exception as e2:
                logger.warning(f"归档检索失败: {e2}")
                return []
        if not rows:
            return []
        if not rows:
            return []

        if not expand:
            return [{"role": r[1], "content": r[2], "ts": r[3], "score": r[4]} for r in rows]

        # 命中后带上下文：同一个 id 前后各一条
        picked: Dict[int, Dict] = {}
        for r in rows:
            hid = r[0]
            try:
                near = self._conn.execute(
                    "SELECT id, role, content, ts FROM archive "
                    "WHERE user_id=? AND id BETWEEN ? AND ? ORDER BY id",
                    (user_id, hid - 1, hid + 1)).fetchall()
            except Exception:
                near = []
            if not near:
                near = [(r[0], r[1], r[2], r[3])]
            for n in near:
                picked.setdefault(n[0], {"role": n[1], "content": n[2], "ts": n[3]})
        return [picked[k] for k in sorted(picked)]

    def archive_count(self, user_id: str = None) -> int:
        try:
            if user_id:
                return int(self._conn.execute(
                    "SELECT COUNT(*) FROM archive WHERE user_id=?", (user_id,)).fetchone()[0])
            return int(self._conn.execute("SELECT COUNT(*) FROM archive").fetchone()[0])
        except Exception:
            return 0

    def archive_list(self, user_id: str, limit: int = 50, offset: int = 0) -> List[Dict]:
        try:
            cur = self._conn.execute(
                "SELECT group_id, role, content, ts FROM archive WHERE user_id=? "
                "ORDER BY ts DESC LIMIT ? OFFSET ?", (user_id, limit, offset))
            return [{"group_id": r[0], "role": r[1], "content": r[2], "ts": r[3]} for r in cur]
        except Exception:
            return []

    def archive_purge(self, user_id: str, vacuum: bool = True) -> int:
        try:
            n = self.archive_count(user_id)
            self._conn.execute("DELETE FROM archive WHERE user_id=?", (user_id,))
            self._conn.commit()
            if vacuum:
                self.vacuum()
            return n
        except Exception:
            self._conn.rollback()
            return 0

    def archive_drop_all(self) -> None:
        try:
            self._conn.execute("DELETE FROM archive")
            self._conn.commit()
        except Exception as e:
            logger.warning(f"清空归档表失败: {e}")

    def archive_trim_total(self, keep: int) -> int:
        """全库归档上限。单用户上限乘以用户数仍可能撑爆磁盘。"""
        if keep <= 0:
            return 0
        try:
            total = self.archive_count()
            if total <= keep:
                return 0
            self._conn.execute(
                "DELETE FROM archive WHERE id IN ("
                "  SELECT id FROM archive ORDER BY ts ASC LIMIT ?)", (total - keep,))
            self._conn.commit()
            return total - keep
        except Exception:
            return 0

    # ---- 会话消息：增量持久化 ----
    # 旧实现每次保存都把整个会话序列化一遍，单用户聊得越久写一次越慢。
    # 现在按条追加，只有新消息才落盘。

    def _messages_insert(self, user_id: str, group_id: int, items: List[Dict], start_seq: int = 0) -> int:
        rows = []
        for i, m in enumerate(items):
            content = (m.get("content") or "").strip()
            if not content:
                continue
            rows.append((user_id, int(group_id), start_seq + i,
                         m.get("role") or "user", content, float(m.get("ts") or time.time())))
        if not rows:
            return 0
        try:
            self._conn.executemany(
                "INSERT INTO messages(user_id, group_id, seq, role, content, ts) VALUES(?,?,?,?,?,?)", rows)
            self._conn.commit()
            return len(rows)
        except Exception:
            self._conn.rollback()
            raise

    def messages_append(self, user_id: str, group_id: int, items: List[Dict], start_seq: int) -> int:
        # 不吞异常：写失败必须让调用方知道，否则 synced 会被错误推进，
        # 内存认为已落盘，这批消息就再也不会重试了。
        return self._messages_insert(user_id, group_id, items, start_seq)

    def messages_replace(self, user_id: str, group_id: int, items: List[Dict]) -> int:
        """整组重写。压缩截断 history 后走这条。失败向上抛，由调用方决定是否推进计数。"""
        try:
            self._conn.execute("DELETE FROM messages WHERE user_id=? AND group_id=?",
                               (user_id, int(group_id)))
            n = self._messages_insert(user_id, group_id, items, 0)
            self._conn.commit()
            return n
        except Exception:
            # DELETE+INSERT 必须原子：回滚后旧数据还在，下次重写才不丢
            self._conn.rollback()
            raise

    def messages_load(self, user_id: str, group_id: int) -> List[Dict]:
        try:
            cur = self._conn.execute(
                "SELECT role, content FROM messages WHERE user_id=? AND group_id=? ORDER BY seq, id",
                (user_id, int(group_id)))
            return [{"role": r[0], "content": r[1]} for r in cur]
        except Exception:
            return []

    def messages_drop_group(self, user_id: str, group_id: int) -> None:
        try:
            self._conn.execute("DELETE FROM messages WHERE user_id=? AND group_id=?",
                               (user_id, int(group_id)))
            self._conn.commit()
        except Exception as e:
            logger.warning(f"删除分组消息失败: {e}")

    def messages_drop_user(self, user_id: str) -> None:
        try:
            self._conn.execute("DELETE FROM messages WHERE user_id=?", (user_id,))
            self._conn.commit()
        except Exception as e:
            logger.warning(f"删除用户消息失败: {e}")

    def messages_count(self) -> int:
        try:
            return int(self._conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0])
        except Exception:
            return 0

    def messages_drop_all(self) -> None:
        try:
            self._conn.execute("DELETE FROM messages")
            self._conn.commit()
        except Exception as e:
            logger.warning(f"清空消息表失败: {e}")

    def archive_trim(self, user_id: str, keep: int) -> int:
        """单用户归档上限，超出丢最旧的。"""
        if keep <= 0:
            return 0
        try:
            total = self.archive_count(user_id)
            if total <= keep:
                return 0
            self._conn.execute(
                "DELETE FROM archive WHERE id IN ("
                "  SELECT id FROM archive WHERE user_id=? ORDER BY ts ASC LIMIT ?)",
                (user_id, total - keep))
            self._conn.commit()
            return total - keep
        except Exception:
            return 0

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


class SessionManager:
    def __init__(self, max_rounds: int = 5, system_prompt: str = "", expire_minutes: int = 60,
                 store_file: str = None, history_temp_dir: str = None):
        self.max_rounds = max_rounds
        self.system_prompt = system_prompt
        self.expire_minutes = expire_minutes
        self.store_file = store_file or os.path.join(DATA_DIR, "sessions.json")
        self.db_file = os.path.splitext(self.store_file)[0] + ".db"

        self.history_temp_dir = history_temp_dir or HISTORY_TEMP_DIR
        self.sessions: Dict[str, Dict] = {}
        self._lock = asyncio.Lock()
        self._cleanup_task = None
        self.model = ""
        self._compressing = False
        # 防重入按用户隔离：全局标志会让一个群压缩时其它群全部跳过，
        # 后续超限不再触发，上下文无限增长。
        self._compressing_users = set()
        # 压缩失败退避：失败后阈值不会自己回落，不设退避就会每条消息
        # 都重新调一次大模型，费用与延迟同时放大。
        self._compress_backoff: Dict[str, Dict] = {}
        # 后台压缩任务引用，防止未完成就被 GC 回收
        self._compress_tasks: set = set()

        self.compression_enabled = False
        self.compression_token_limit = 60000
        self.model_context_tokens = 0
        self.history_temp_keep_groups = 10
        self.history_temp_cleanup_enabled = True
        self.max_sessions = 1000
        # 归档检索：命中才取几条，不常驻上下文
        self.archive_recall = True
        self.archive_recall_top = 4
        self.archive_keep = 5000
        self.archive_keep_total = 200000
        os.makedirs(os.path.dirname(self.db_file) or ".", exist_ok=True)
        self.store = _SessionStore(self.db_file)
        self._load()


    def _hydrate(self, user_id: str, sess: Dict) -> None:
        """把 messages 表里的消息填回内存 history。"""
        for idx, g in enumerate(sess.get("groups") or []):
            if not isinstance(g, dict):
                continue
            rows = self.store.messages_load(user_id, idx + 1)
            if rows:
                g["history"] = rows
            g["synced"] = len(g.get("history") or [])

    def _load(self):
        try:
            data = self.store.load_all()
            if data:
                if not self.sessions:
                    for uid, sess in data.items():
                        if isinstance(sess, dict):
                            self._hydrate(uid, sess)
                    self.sessions = data
                    logger.info(f"已从会话库加载: {len(data)} 个会话")
                return
            # 旧版本用 sessions.json，首次启动时导入并改名留档
            if os.path.exists(self.store_file):
                with open(self.store_file, "r", encoding="utf-8") as f:
                    old = json.load(f)
                if isinstance(old, dict) and old:
                    self.sessions = old
                    for uid, payload in old.items():
                        if isinstance(payload, dict):
                            self._sync_messages(uid, payload)
                            self.store.upsert(uid, payload)
                    os.replace(self.store_file, self.store_file + ".migrated")
                    logger.info(f"已迁移 {len(old)} 个会话到 SQLite，原文件保留为 sessions.json.migrated")
        except Exception as e:
            logger.warning(f"加载对话记录失败(将使用空会话): {e}")

    def _sync_messages(self, user_id: str, payload: Dict) -> None:
        """把内存里新增的消息落到 messages 表。

        按 synced 计数增量追加；history 变短（压缩截断）时整组重写。
        """
        groups = payload.get("groups") or []
        for idx, g in enumerate(groups):
            if not isinstance(g, dict):
                continue
            gid = idx + 1
            hist = g.get("history") or []
            synced = int(g.get("synced") or 0)
            if len(hist) == synced:
                continue
            if len(hist) > synced:
                try:
                    self.store.messages_append(user_id, gid, hist[synced:], synced)
                except Exception as e:
                    # 写失败就停在这里，synced 不推进，下次保存重试同一批
                    logger.warning(f"追加消息失败，保留待重试: {e}")
                    return
            else:
                try:
                    self.store.messages_replace(user_id, gid, hist)
                except Exception as e:
                    logger.warning(f"重写消息失败，保留待重试: {e}")
                    return
            g["synced"] = len(hist)

    def _save(self, user_id: str = None):
        """只写变动部分：新消息追加，元数据单行更新。"""
        try:
            targets = [user_id] if user_id else list(self.sessions.keys())
            for uid in targets:
                payload = self.sessions.get(uid)
                if not isinstance(payload, dict):
                    continue
                self._sync_messages(uid, payload)
                self.store.upsert(uid, payload)
        except Exception as e:
            logger.warning(f"保存对话记录失败: {e}")

    def close(self) -> None:
        try:
            self.store.close()
        except Exception:
            pass

    def export_snapshot(self, out_path: str = None) -> str:
        """手动导出全量会话为 JSON。

        自动每小时备份已取消：备份是明文，且会把「已删除」变成
        「十小时内还能找回来」，与删除语义冲突。数据本身有 WAL 和事务兜底。
        """
        out_path = out_path or os.path.join(DATA_DIR, f"sessions_{time.strftime('%Y%m%d_%H%M%S')}.json")
        try:
            tmp = out_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.sessions, f, ensure_ascii=False)
            os.replace(tmp, out_path)
            return out_path
        except Exception as e:
            logger.warning(f"导出会话失败: {e}")
            return ""

    def _session_count(self) -> int:
        return len(self.sessions)

    def list_sessions(self) -> List[Dict]:
        out = []
        for uid, sess in self.sessions.items():
            groups = sess.get("groups", [])
            cur = sess.get("current_group", 0)
            last_used = sess.get("last_used", 0)
            total_rounds = sum(g.get("rounds", 0) for g in groups)

            out.append({
                "user_id": uid,
                "group_count": len(groups),
                "current_group": cur + 1,
                "messages": sum(len(g.get("history", [])) for g in groups),
                "rounds": total_rounds,
                "last_used": last_used,
            })
        out.sort(key=lambda x: x["last_used"], reverse=True)
        return out

    def get_session(self, user_id: str) -> Optional[Dict]:
        sess = self.sessions.get(user_id)
        if not sess:
            return None
        groups = sess.get("groups", [])

        out_groups = []
        for idx, g in enumerate(groups):
            comp = g.get("compressed", [])
            out_groups.append({
                "group_id": idx + 1,
                "history": g.get("history", []),
                "rounds": g.get("rounds", 0),
                "compressed_count": len(comp),
                "last_summary": (comp[-1].get("brief") or comp[-1].get("summary") or "")[:100] if comp else "",
            })
        return {
            "user_id": user_id,
            "groups": out_groups,
            "current_group": sess.get("current_group", 0) + 1,
            "last_used": sess.get("last_used", 0),
        }

    def clear_session_persist(self, user_id: str) -> bool:
        if user_id not in self.sessions:
            return False
        del self.sessions[user_id]

        try:
            safe_uid = "".join(c for c in str(user_id) if c.isalnum() or c in "-_")[:40] or "unknown"
            prefix = f"{safe_uid}_g"
            if os.path.isdir(self.history_temp_dir):
                for fn in os.listdir(self.history_temp_dir):
                    if fn.startswith(prefix):
                        shutil.rmtree(os.path.join(self.history_temp_dir, fn), ignore_errors=True)
        except Exception as e:
            logger.warning(f"操作失败(可忽略): {e}")
        self.store.delete(user_id)
        self.store.messages_drop_user(user_id)
        # 归档里还有该用户的原文，不清的话「删除用户」只删了一半
        self.store.archive_purge(user_id, vacuum=False)
        logger.info(f"已清除用户 {user_id} 的全部对话")
        return True

    async def clear_group(self, user_id: str, group_id: int) -> bool:
        async with self._lock:
            sess = self.sessions.get(user_id)
            if not sess:
                return False
            groups = sess.get("groups", [])
            idx = group_id - 1
            if idx < 0 or idx >= len(groups):
                return False
            groups.pop(idx)

            _delete_temp_group(user_id, group_id, self.history_temp_dir)

            cur = sess.get("current_group", 0)
            if cur >= len(groups):
                sess["current_group"] = max(0, len(groups) - 1)
            elif cur > idx:
                sess["current_group"] = cur - 1
            # 组号前移了，messages 里的 group_id 要整体重排，直接重写
            self.store.messages_drop_user(user_id)
            for g in groups:
                if isinstance(g, dict):
                    g["synced"] = 0
            self._save(user_id)
            return True

    def clear_all(self) -> int:
        n = len(self.sessions)
        self.sessions = {}
        try:
            self.store.delete_all()
            self.store.messages_drop_all()
            self.store.archive_drop_all()
        except Exception as e:
            logger.warning(f"清空会话库失败: {e}")
        try:
            if os.path.exists(self.store_file):
                os.remove(self.store_file)
        except Exception as e:
            logger.warning(f"删除旧对话记录文件失败: {e}")

        try:
            if os.path.isdir(self.history_temp_dir):
                shutil.rmtree(self.history_temp_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"操作失败(可忽略): {e}")
        logger.info(f"已清空全部对话记录，共 {n} 个会话")
        return n

    def start_cleanup(self):
        async def cleanup_loop():
            while True:
                await asyncio.sleep(60)
                try:
                    await self._cleanup_expired()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    # 单次清理失败不能让整个循环退出，否则过期会话再也不清
                    logger.warning(f"过期会话清理失败，下个周期重试: {e}")
        self._cleanup_task = asyncio.create_task(cleanup_loop())

    def stop_cleanup(self):
        if self._cleanup_task:
            self._cleanup_task.cancel()

    async def _cleanup_expired(self):
        now = time.time()
        expire_seconds = self.expire_minutes * 60
        async with self._lock:
            expired = [uid for uid, sess in self.sessions.items() if now - sess["last_used"] > expire_seconds]
            for uid in expired:
                del self.sessions[uid]
                self.store.delete(uid)
        if expired:
            logger.info(f"清理了 {len(expired)} 个过期会话")

    def set_system_prompt(self, prompt: str):
        self.system_prompt = prompt

    def set_max_rounds(self, rounds: int):
        self.max_rounds = rounds

    def set_compression(self, enabled: bool, token_limit: int,
                        history_temp_keep_groups: int, history_temp_cleanup: bool,
                        model_context_tokens: int = 0):
        self.compression_enabled = enabled
        if token_limit and token_limit > 0:
            self.compression_token_limit = token_limit
        if model_context_tokens and model_context_tokens > 0:
            self.model_context_tokens = int(model_context_tokens)
        self.history_temp_keep_groups = history_temp_keep_groups if history_temp_keep_groups and history_temp_keep_groups > 0 else 10
        self.history_temp_cleanup_enabled = history_temp_cleanup

    def set_archive(self, recall: bool = True, top: int = 4, keep: int = 5000,
                    keep_total: int = 200000):
        self.archive_recall = bool(recall)
        self.archive_recall_top = max(1, min(20, int(top or 4)))
        self.archive_keep = max(0, int(keep or 0))
        self.archive_keep_total = max(0, int(keep_total or 0))

    def get_compression_config(self) -> dict:
        return {
            "compression_enabled": self.compression_enabled,
            "compression_token_limit": self.compression_token_limit,
            "model_context_tokens": getattr(self, "model_context_tokens", 0),
            "effective_token_limit": self._effective_token_limit(),
            "history_temp_keep_groups": self.history_temp_keep_groups,
            "history_temp_cleanup_enabled": self.history_temp_cleanup_enabled,
            "archive_recall": getattr(self, "archive_recall", True),
            "archive_recall_top": getattr(self, "archive_recall_top", 4),
            "archive_keep": getattr(self, "archive_keep", 5000),
            "archive_keep_total": getattr(self, "archive_keep_total", 200000),
            "archive_count": self.store.archive_count() if getattr(self, "store", None) else 0,
        }

    def _ensure_user(self, user_id: str) -> Dict:
        if user_id not in self.sessions:
            # 会话数上限：不设的话被拉进一堆群之后字典只增不减
            limit = int(getattr(self, "max_sessions", 0) or 0)
            if limit > 0 and len(self.sessions) >= limit:
                oldest = sorted(self.sessions, key=lambda k: self.sessions[k].get("last_used", 0))[:50]
                for uid in oldest:
                    self.sessions.pop(uid, None)
                    try:
                        self.store.delete(uid)
                        self.store.messages_drop_user(uid)
                    except Exception:
                        pass
                logger.info(f"会话数超过 {limit}，淘汰最久未用的 {len(oldest)} 个")
            self.sessions[user_id] = {
                "groups": [{"history": [], "rounds": 0, "compressed": []}],
                "current_group": 0,
                "last_used": time.time(),
            }
        return self.sessions[user_id]

    def _current_group(self, session: Dict) -> Dict:
        return session["groups"][session["current_group"]]

    def _roll_group(self, user_id: str, session: Dict):
        old_cur = session["current_group"]
        old_group = session["groups"][old_cur]

        # 翻篇的旧组原文先进归档，再清空，避免整组内容直接蒸发
        if old_group.get("history"):
            self.store.archive_add(user_id, old_cur + 1, old_group["history"])
            self.store.archive_trim(user_id, int(getattr(self, "archive_keep", 0) or 0))
            self.store.archive_trim_total(int(getattr(self, "archive_keep_total", 0) or 0))

        session["groups"].append({"history": [], "rounds": 0, "compressed": [], "synced": 0})
        session["current_group"] = len(session["groups"]) - 1

        if self.history_temp_cleanup_enabled:
            _cleanup_old_temp_groups(user_id, len(session["groups"]), self.history_temp_keep_groups, self.history_temp_dir)
        self._save(user_id)
        logger.info(f"用户 {user_id} 第 {old_cur+1} 组已满，翻篇到第 {len(session['groups'])} 组")

    def _memory_messages(self, user_id: str, group_id: int) -> List[Dict[str, str]]:
        """优先使用结构化记忆；没有则回退到旧的摘要文件，升级不丢历史。"""
        out: List[Dict[str, str]] = []
        mem = _load_memory(user_id, group_id, self.history_temp_dir)
        if mem:
            txt = _render_memory(mem)
            if txt:
                out.append({"role": "system", "content": txt})
            return out
        comps = _load_all_temp_compressions(user_id, group_id, self.history_temp_dir)
        for c in comps:
            _r = c.get('round', '?')
            _lab = "滚动合并摘要" if str(_r) == "999999" else f"历史摘要(第{_r}次压缩)"
            out.append({"role": "system", "content": f"[{_lab}]\n{c.get('summary', '')}"})
        return out

    def get_current_group_messages(self, user_id: str) -> List[Dict[str, str]]:
        session = self._ensure_user(user_id)
        cur = self._current_group(session)
        group_id = session["current_group"] + 1
        messages = self._memory_messages(user_id, group_id)
        messages.extend(cur.get("history", []))
        return messages

    async def get_context(self, user_id: str, user_message: str) -> List[Dict[str, str]]:
        async with self._lock:
            session = self._ensure_user(user_id)
            session["last_used"] = time.time()
            cur = self._current_group(session)
            group_id = session["current_group"] + 1

            if cur["rounds"] >= self.max_rounds:
                self._roll_group(user_id, session)
                cur = self._current_group(session)
                group_id = session["current_group"] + 1

            messages = []

            if self.system_prompt:
                messages.append({"role": "system", "content": self.system_prompt})

            # 历史里不带时间，模型分不清「刚才」和「三天前」。
            # 每次注入当前时间，让它能自己算相对时间。
            _lt = time.localtime()
            _stamp = time.strftime("%Y-%m-%d %H:%M", _lt) + f" 周{'一二三四五六日'[_lt.tm_wday]}"
            messages.append({"role": "system", "content": f"[当前时间] {_stamp}"})

            messages.extend(self._memory_messages(user_id, group_id))
            if getattr(self, "archive_recall", False) and user_message:
                self._append_archive_hits(messages, user_id, user_message)
            messages.extend(cur.get("history", []))
            messages.append({"role": "user", "content": user_message})
            return messages

    def _append_archive_hits(self, messages: List[Dict[str, str]], user_id: str, query: str) -> int:
        """按当前消息检索归档，拼一条 system。

        归档是「死数据」：不进常规上下文、不占常驻内存，只有命中才取几条。
        关键词检索，不是语义检索，命不中就当没有。
        """
        try:
            hits = self.store.archive_search(user_id, query, int(getattr(self, "archive_recall_top", 4) or 4))
        except Exception as e:
            logger.warning(f"归档检索失败: {e}")
            return 0
        if not hits:
            return 0
        lines = ["[归档检索]"]
        for h in hits:
            try:
                _t = time.strftime("%Y-%m-%d", time.localtime(float(h.get("ts") or 0)))
            except Exception:
                _t = "未知日期"
            _role = "用户" if h.get("role") == "user" else "机器人"
            _txt = (h.get("content") or "").replace("\n", " ")[:200]
            lines.append(f"{_t} {_role}：{_txt}")
        messages.append({"role": "system", "content": "\n".join(lines)})
        return len(hits)

    def _note_compress_failure(self, key: str) -> None:
        """压缩失败后退避。阈值不会因为失败而回落，不设退避就会每条消息
        都重新调一次大模型。"""
        st = self._compress_backoff.get(key) or {"count": 0, "next": 0.0}
        st["count"] = int(st.get("count", 0)) + 1
        delay = min(1800, 60 * (2 ** (st["count"] - 1)))
        st["next"] = time.time() + delay
        self._compress_backoff[key] = st
        logger.warning(f"压缩失败 {key}，{delay}s 内不再重试")

    def _effective_token_limit(self) -> int:
        """阈值不得大于模型窗口的 60%，否则压缩请求本身超窗，
        永远失败。窗口未知时沿用配置值。"""
        limit = int(self.compression_token_limit or 60000)
        ctx = int(getattr(self, "model_context_tokens", 0) or 0)
        if ctx > 0:
            return max(2000, min(limit, int(ctx * 0.6)))
        return limit

    async def maybe_compress(self, user_id: str, provider, usage_ctx: dict = None) -> bool:
        if not self.compression_enabled:
            return False
        if user_id in self._compressing_users:
            return False
        async with self._lock:
            session = self._ensure_user(user_id)
            cur = self._current_group(session)
            group_id = session["current_group"] + 1
            if not cur.get("history"):
                return False
            key = f"{user_id}:{group_id}"
            st = self._compress_backoff.get(key)
            if st and time.time() < st.get("next", 0):
                return False
            comps = _load_all_temp_compressions(user_id, group_id, self.history_temp_dir)
            total_tokens = 0
            for c in comps:
                total_tokens += _estimate_tokens(c.get("summary", "")) + 10
            total_tokens += _estimate_messages_tokens(cur.get("history", []))
            if total_tokens < self._effective_token_limit():
                return False

        logger.info(f"用户 {user_id} 组{group_id} token {total_tokens} 超限，后台压缩(第{cur.get('rounds', 0)+1}次)")
        self._compressing_users.add(user_id)
        # 必须持有引用：create_task 不保存的话，任务可能在跑完前被回收
        _task = asyncio.create_task(self._run_compress(user_id, provider, usage_ctx, key))
        self._compress_tasks.add(_task)
        _task.add_done_callback(self._compress_tasks.discard)
        return True

    async def _run_compress(self, user_id: str, provider, usage_ctx: dict = None, key: str = ""):
        ok = False
        try:
            async with self._lock:
                session = self._ensure_user(user_id)
                group_id = session["current_group"] + 1
                key = key or f"{user_id}:{group_id}"
                cur = self._current_group(session)
                round_no = cur.get("rounds", 0) + 1
                hist = list(cur.get("history", []))
                if not hist:
                    return
                comps = _load_all_temp_compressions(user_id, group_id, self.history_temp_dir)
                old_sums = "\n".join(c.get("summary", "") for c in comps)
                prev_mem = _load_memory(user_id, group_id, self.history_temp_dir)
                hist_tokens = _estimate_messages_tokens(hist)

            # 抽取请求耗时以秒计，必须在锁外执行。持锁调用会让所有用户
            # 的消息处理一起卡住。
            mem, raw_text = await self._extract_memory(provider, hist, usage_ctx, prev_mem, old_sums)
            if mem:
                summary = _render_memory(mem)
            elif raw_text and len(raw_text.strip()) >= 20:
                # 模型没按 JSON 输出，把原文存成备注，同样进 memory.json，
                # 不额外写 summary.txt
                mem = _normalize_memory({"note": raw_text.strip()[:4000]})
                summary = _render_memory(mem)
                logger.warning("记忆抽取未返回 JSON，降级为文本备注")
            else:
                return
            if not summary:
                return

            async with self._lock:
                session = self._ensure_user(user_id)
                if session["current_group"] + 1 != group_id:
                    # 期间已翻篇，记忆与当前组对不上，丢弃但不计失败
                    logger.info(f"用户 {user_id} 组{group_id} 压缩期间已翻篇，跳过写入")
                    ok = True
                    return
                cur = self._current_group(session)
                # 用当前 history 的尾部，保住压缩期间新追加的消息
                keep_n = 2 if (self.max_rounds or 5) > 2 else 1
                _full = cur.get("history", [])
                _keep = keep_n * 2
                _dropped = _full[:-_keep] if len(_full) > _keep else []
                cur["history"] = _full[-_keep:] if len(_full) > _keep else _full
                cur["rounds"] = min(keep_n, len(cur["history"]) // 2)
                if _dropped:
                    # 被摘要覆盖掉的原文不丢，进归档供以后检索
                    self.store.archive_add(user_id, group_id, _dropped)
                    self.store.archive_trim(user_id, int(getattr(self, "archive_keep", 0) or 0))
                    self.store.archive_trim_total(int(getattr(self, "archive_keep_total", 0) or 0))
                if old_sums:
                    _cleanup_temp_compressions(user_id, group_id, self.history_temp_dir)
                mem_fp = ""
                if mem:
                    mem_fp = _save_memory(user_id, group_id, mem, self.history_temp_dir)
                # 不再写 summary.txt。memory.json 是权威存储，再落一份
                # 渲染文本只会多一个失败点和一个不一致来源。
                # 界面预览用 brief 字段，完整内容从 memory.json 渲染。
                cur["compressed"].append({"time": time.strftime("%Y-%m-%d %H:%M:%S"),
                                          "round": round_no, "memory": mem_fp,
                                          "brief": summary[:80]})
                self._save(user_id)
                ok = True

            sum_tokens = _estimate_tokens(summary)
            saved = hist_tokens - sum_tokens
            logger.info(f"用户 {user_id} 组{group_id} 记忆更新(第{round_no}次): "
                        f"本轮 {hist_tokens} token -> 记忆 {sum_tokens} token"
                        f"(省 {max(0, saved)} token / {100 * max(0, saved) // max(1, hist_tokens)}%), 保留近 {keep_n} 轮原文")
        except Exception as e:
            logger.error(f"后台压缩异常: {e}")
        finally:
            self._compressing_users.discard(user_id)
            if ok:
                self._compress_backoff.pop(key, None)
            elif key:
                self._note_compress_failure(key)

    async def _extract_memory(self, provider, dialogue, usage_ctx, prev_mem=None, old_sums: str = ""):
        """把对话抽成结构化记忆，返回 (记忆字典或 None, 模型原始输出)。

        比自然语言摘要的优势：同一 key 直接覆盖，不会每压一次糊一层；
        渲染成文本后 token 更少；字段可复用，界面也能直接展示。
        """
        raw_text = ""
        try:
            prompt_content = "\n".join(f"[{m.get('role','')}]\n{m.get('content','')}" for m in dialogue)
            if old_sums and not prev_mem:
                prompt_content = "【既有摘要(需并入记忆)】\n" + old_sums + "\n\n【本轮新增对话】\n" + prompt_content
            prev_json = json.dumps(prev_mem, ensure_ascii=False) if prev_mem else "{}"
            sys_prompt = (
                "你是对话记忆抽取器。读既有记忆与本轮对话，输出更新后的记忆 JSON。"
                "只输出 JSON，不要解释，不要代码围栏。\n"
                '结构：{"user":{"nick":"","traits":[]},'
                '"facts":[{"k":"","v":""}],'
                '"tasks":[{"task":"","status":"open"}],'
                '"relations":{"":""},"events":[""]}\n'
                "规则：\n"
                "1. facts 存稳定信息：工作、住址、宠物、喜好、重要数字；k 用两到四字短标签\n"
                "2. tasks 存提到但未完成的事，已完成把 status 改成 done\n"
                "3. events 一句话一件事，只留最近 40 条，最旧的先丢\n"
                "4. 同一 key 的新信息覆盖旧信息，以对话里更晚出现的为准\n"
                "5. 没有内容的字段给空数组或空对象，不要省略\n"
                "6. 不要编造对话里没有的信息"
            )
            msgs = [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": f"【既有记忆】\n{prev_json}\n\n【本轮新增对话】\n{prompt_content}"},
            ]
            reply = await provider.chat_completion_resilient(
                msgs,
                temperature=0.2,
                model=self.model or "",
                reasoning_effort="off",
                usage_ctx=usage_ctx,
            )
            raw_text = reply or ""
            raw = _parse_memory_json(raw_text)
            if raw is None:
                return None, raw_text
            return _normalize_memory(raw, prev_mem), raw_text
        except Exception as e:
            logger.error(f"记忆抽取失败: {e}")
            return None, raw_text

    async def _generate_summary(self, provider, summarize_input: List[Dict[str, str]], usage_ctx: dict,
                                old_sums: str = "") -> str:
        try:

            prompt_content = "\n".join(f"[{m.get('role','')}]\n{m.get('content','')}" for m in summarize_input)
            if old_sums:
                prompt_content = "【既有历史摘要(需并入,勿丢失要点)】\n" + old_sums + "\n\n【本轮新增对话】\n" + prompt_content
            sys_prompt = (
                "你是上下文压缩助手。把下面的内容压缩成简洁的中文摘要，保留关键信息："
                "用户偏好、进行中的任务、重要决定、待办事项、出现过的人名与数字。"
                "若内容含既有摘要，请把新旧信息合并为一份连贯摘要，不要遗漏既有摘要中的要点。"
                "不要回答对话中的问题，只输出摘要。"
                "尽量控制在约 " + str(max(500, self._effective_token_limit() // 20)) + " token 以内。"
            )
            msgs = [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": f"待压缩的对话：\n{prompt_content}"},
            ]
            reply = await provider.chat_completion_resilient(
                msgs,
                temperature=0.3,
                model=self.model or "",
                reasoning_effort="off",
                usage_ctx=usage_ctx,
            )
            return reply.strip()
        except Exception as e:
            logger.error(f"生成摘要失败: {e}")
            return ""

    async def add_response(self, user_id: str, user_message: str, assistant_message: str):
        async with self._lock:
            if user_id not in self.sessions:
                return
            session = self.sessions[user_id]
            cur = self._current_group(session)

            cur["history"].append({"role": "user", "content": user_message})
            cur["history"].append({"role": "assistant", "content": assistant_message})
            cur["rounds"] += 1
            session["last_used"] = time.time()
            self._save(user_id)

    async def clear_session(self, user_id: str):
        async with self._lock:
            if user_id in self.sessions:
                self.store.messages_drop_user(user_id)
                # 归档里的原文仍会被检索召回，不清的话「清除对话」等于没清干净
                # 网页热路径不跑 VACUUM：同步 VACUUM 会锁库阻塞整个事件循环
                self.store.archive_purge(user_id, vacuum=False)
                self.sessions[user_id]["groups"] = [{"history": [], "rounds": 0, "compressed": [], "synced": 0}]
                self.sessions[user_id]["current_group"] = 0
                self._save(user_id)


class QQBot:
    def __init__(self, app_id: str, app_secret: str, provider: Provider, session_mgr: SessionManager,
                 config: dict = None, data_dir: str = None):
        self.app_id = app_id
        self.app_secret = app_secret
        self.provider = provider
        self.session_mgr = session_mgr
        self.config = config or {}
        self.data_dir = data_dir or DATA_DIR

        provider._register_secret(app_id)
        provider._register_secret(app_secret)
        self.access_token = None
        self.ws_url = None
        self.ws = None
        self._ws_session = None
        self.running = False
        self.temperature = 0.7
        self.model = "gpt-3.5-turbo"
        self.thinking = "off"
        self._stop_flag = False
        self._heartbeat_task = None

        # 网关重连（op=7）会重发最近事件，不去重就会重复回答同一句。
        self._seen_msg_ids = collections.OrderedDict()
        self._seen_msg_max = 500
        # 同一会话串行处理，避免连发两条时后一条看不到前一条的回复。
        self._user_locks: Dict[str, asyncio.Lock] = {}
        # 持有运行中的消息任务引用，避免被 GC 提前回收。
        self._tasks = set()
        # 并发闸：消息改成异步派发后，不限制的话被刷屏时会同时打满接口。
        _mc = 3
        try:
            _mc = max(1, min(20, int(self.config.get("max_concurrent", 3) or 3)))
        except (TypeError, ValueError):
            pass
        self._llm_sem = asyncio.Semaphore(_mc)

    async def _get_access_token(self):


        url = "https://bots.qq.com/app/getAppAccessToken"
        payload = {"appId": self.app_id, "clientSecret": self.app_secret}
        session = await _http()
        try:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                body = await resp.text()
                try:
                    data = await resp.json()
                except Exception:
                    data = body
                if resp.status == 200 and isinstance(data, dict) and data.get("access_token"):
                    self.access_token = data["access_token"]
                    logger.info("获取access_token成功")
                    return True
                else:
                    if isinstance(data, dict) and data.get("data", {}).get("access_token"):
                        self.access_token = data["data"]["access_token"]
                        logger.info("获取access_token成功")
                        return True
                    logger.error(f"获取access_token失败: status={resp.status}")
                    self._log_connect_error(f"获取access_token失败: {_err_summary(resp.status, body)}")
                    return False
        except Exception as e:
            logger.error(f"获取access_token异常: {e}")
            self._log_connect_error(f"获取access_token异常: {e}")
            return False

    def _log_connect_error(self, msg: str) -> None:
        try:
            with open(os.path.join(self.data_dir, "qq_connect.log"), "a", encoding="utf-8") as _f:
                _f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
        except Exception as e:
            logger.warning(f"操作失败(可忽略): {e}")

    async def _get_ws_url(self):

        url = "https://api.sgroup.qq.com/gateway"
        headers = {"Authorization": f"QQBot {self.access_token}", "X-Union-Appid": self.app_id}
        session = await _http()
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                body = await resp.text()
                try:
                    data = await resp.json()
                except Exception:
                    data = body
                if resp.status == 200 and isinstance(data, dict) and data.get("url"):
                    self.ws_url = data["url"]
                    safe_ws = _re.sub(r"access_token=[^&]+", "access_token=***", self.ws_url)
                    logger.info(f"获取WebSocket地址成功: {safe_ws}")
                    return True
                else:
                    logger.error(f"获取WS地址失败: status={resp.status}")
                    self._log_connect_error(f"获取WS地址失败: {_err_summary(resp.status, body)}")
                    return False
        except Exception as e:
            logger.error(f"获取WS地址异常: {e}")
            self._log_connect_error(f"获取WS地址异常: {e}")
            return False

    async def _handle_message(self, payload: dict):
        try:

            event_type = payload.get("t", "")
            d = payload.get("d", {}) or {}
            if event_type not in ("C2C_MESSAGE_CREATE", "GROUP_AT_MESSAGE_CREATE"):
                return
            content = (d.get("content") or "").strip()
            if not content:
                return
            author = d.get("author", {}) or {}

            if event_type == "C2C_MESSAGE_CREATE":
                target_id = author.get("user_openid") or ""
            else:
                target_id = author.get("member_openid") or ""
            if not target_id:
                # openid 拿不到时回复也无门可发；挤进 "unknown" 共享会话只会互相串话
                logger.warning("消息缺少 openid，无法定位会话与回复目标，跳过")
                return
            group_id = d.get("group_openid", "") if event_type == "GROUP_AT_MESSAGE_CREATE" else ""
            msg_id = d.get("id", "")
            if msg_id:
                if msg_id in self._seen_msg_ids:
                    logger.info(f"忽略重复消息 id={msg_id}")
                    return
                self._seen_msg_ids[msg_id] = time.time()
                while len(self._seen_msg_ids) > self._seen_msg_max:
                    self._seen_msg_ids.popitem(last=False)
            if len(content) > 4000:
                content = content[:4000]
                logger.info(f"消息过长已截断 from {target_id}")
            _k = (target_id, group_id)
            _now = time.time()
            if not hasattr(self, "_last_msg_at"):
                self._last_msg_at = {}
            if _now - self._last_msg_at.get(_k, 0) < 1.2:
                logger.info(f"忽略高频消息 from {target_id} (1.2s 窗口内)")
                return
            self._last_msg_at[_k] = _now
            logger.info(f"收到消息 from {target_id} ({event_type}): len={len(content)}")

            # 同一会话串行：连发两条时，后一条必须看到前一条的回复，
            # 否则两边的上下文各写各的，历史会乱序。
            lock = self._user_lock(target_id)
            async with lock:
                await self._respond(event_type, target_id, group_id, content, msg_id)
        except Exception as e:
            logger.error(f"处理消息异常: {e}")

    def _track_task(self, task: asyncio.Task) -> None:
        """持有消息任务引用，并在结束时把异常暴露出来。

        原来只做 discard，任务里漏出的异常会被悄悄丢掉，出问题只能靠猜。
        """
        self._tasks.add(task)

        def _done(t: asyncio.Task) -> None:
            self._tasks.discard(t)
            if t.cancelled():
                return
            try:
                e = t.exception()
            except asyncio.CancelledError:
                return
            if e:
                logger.error(f"消息处理任务异常: {e}")

        task.add_done_callback(_done)

    def _user_lock(self, user_id: str) -> asyncio.Lock:
        lock = self._user_locks.get(user_id)
        if lock is None:
            if len(self._user_locks) > 2000:
                for k in [k for k, v in list(self._user_locks.items()) if not v.locked()][:1000]:
                    self._user_locks.pop(k, None)
            lock = asyncio.Lock()
            self._user_locks[user_id] = lock
        return lock

    async def _respond(self, event_type: str, target_id: str, group_id: str,
                       content: str, msg_id: str):
        usage_ctx = {"user_id": target_id, "provider_type": self.config.get("provider_type", "")}
        try:
            await self.session_mgr.maybe_compress(target_id, self.provider, usage_ctx)
        except Exception as e:
            logger.warning(f"压缩检查异常: {e}")
        messages = await self.session_mgr.get_context(target_id, content)
        try:
            async with self._llm_sem:
                reply = await self.provider.chat_completion_resilient(
                    messages,
                    temperature=self.temperature,
                    model=self.model,
                    reasoning_effort=self.thinking,
                    usage_ctx=usage_ctx
                )
            await self.session_mgr.add_response(target_id, content, reply)
            await self._reply_message(event_type, target_id, group_id, reply, msg_id)
            logger.info(f"回复成功 to {target_id}")
        except Exception as e:
            logger.error(f"大模型调用失败: {e}")
            await self._reply_message(event_type, target_id, group_id, "处理失败，请稍后再试。", msg_id)

    async def _reply_message(self, event_type: str, target_id: str, group_id: str, reply_content: str, msg_id: str = ""):



        try:
            if event_type == "GROUP_AT_MESSAGE_CREATE":
                if not group_id:
                    logger.error("群消息缺少 group_openid，无法回复")
                    return
                url = f"https://api.sgroup.qq.com/v2/groups/{quote(group_id, safe='')}/messages"
            else:
                url = f"https://api.sgroup.qq.com/v2/users/{quote(target_id, safe='')}/messages"
            headers = {"Authorization": f"QQBot {self.access_token}", "Content-Type": "application/json"}
            payload = {"content": reply_content, "msg_type": 0}
            if msg_id:
                payload["msg_id"] = msg_id
            last_err = None
            _sess = await _http()
            for attempt in range(3):
                try:
                    async with _sess.post(url, json=payload, headers=headers,
                                          timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            return
                        body = await resp.text()
                        last_err = _err_summary(resp.status, body)
                        if resp.status < 500:
                            logger.error(f"回复消息失败: {last_err}")
                            return
                except Exception as e:
                    last_err = str(e)
                logger.warning(f"回复消息重试(第{attempt+1}次): {last_err}")
                await asyncio.sleep(1.5 * (2 ** attempt))
            logger.error(f"回复消息失败(已重试): {last_err}")
        except Exception as e:
            logger.error(f"回复消息失败: {e}")

    async def send_group_message(self, group_openid: str, content: str):
        if not group_openid:
            raise ValueError("目标群 group_openid 为空")
        if not self.access_token:
            raise ValueError("尚未连接 QQ，无法主动发消息")
        url = f"https://api.sgroup.qq.com/v2/groups/{quote(group_openid, safe='')}/messages"
        headers = {"Authorization": f"QQBot {self.access_token}", "Content-Type": "application/json"}
        payload = {"content": content, "msg_type": 0}
        session = await _http()
        async with session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                body = await resp.text()
                raise RuntimeError(f"主动发消息失败: {_err_summary(resp.status, body)}")
            return True

    async def _listen(self):
        try:

            heartbeat_interval = 45.0
            last_seq = None


            identify = {
                "op": 2,
                "d": {
                    "token": f"QQBot {self.access_token}",
                    "intents": 1 << 25,
                    "shard": [0, 1],
                    "properties": {"$os": "windows", "$browser": "QQBotAgent", "$device": "QQBotAgent"}
                }
            }
            await self.ws.send_json(identify)
            logger.info("已发送 Identify 鉴权")

            async def heartbeat():
                while self.running and self.ws and not self.ws.closed:
                    try:
                        await self.ws.send_json({"op": 1, "d": last_seq})
                    except Exception:
                        break
                    await asyncio.sleep(heartbeat_interval)
            self._heartbeat_task = asyncio.create_task(heartbeat())

            async for msg in self.ws:
                if self._stop_flag:
                    break
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    op = data.get("op")
                    if op == 10:
                        d = data.get("d", {}) or {}
                        hb = d.get("heartbeat_interval")
                        if hb:
                            heartbeat_interval = hb / 1000.0
                    elif op == 0:
                        last_seq = data.get("s")
                        # 不能 await：一次模型调用要几秒，串行会把同一时刻
                        # 其它群的消息全堵住。会话内的顺序由 _user_locks 保证。
                        self._track_task(asyncio.create_task(self._handle_message(data)))
                    elif op == 11:
                        pass
                    elif op == 7:
                        logger.info("收到网关 Reconnect，准备重连")
                        break
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    break
        except Exception as e:
            logger.error(f"WebSocket监听异常: {e}")
        finally:
            if self._heartbeat_task:
                self._heartbeat_task.cancel()

    async def connect_with_retry(self):


        self.running = True
        retries = 0
        while self.running and not self._stop_flag:
            try:
                if not await self._get_access_token():
                    raise Exception("获取access_token失败")
                if not await self._get_ws_url():
                    raise Exception("获取WebSocket地址失败")
                session = aiohttp.ClientSession()
                self._ws_session = session

                ws_headers = {
                    "Authorization": f"QQBot {self.access_token}",
                    "X-Union-Appid": self.app_id,
                }
                self.ws = await session.ws_connect(self.ws_url, headers=ws_headers, timeout=30.0)
                logger.info("QQ机器人WebSocket已连接")
                self.running = True
                retries = 0
                await self._listen()
                if self._stop_flag or not self.running:
                    break
                if self.ws and not self.ws.closed:
                    try:
                        await self.ws.close()
                    except Exception as e:
                        logger.warning(f"操作失败(可忽略): {e}")
                self.ws = None
                if self._ws_session and not self._ws_session.closed:
                    try:
                        await self._ws_session.close()
                    except Exception as e:
                        logger.warning(f"操作失败(可忽略): {e}")
                self._ws_session = None
                logger.info("连接已断开，准备重新连接")
                await asyncio.sleep(3)
            except Exception as e:
                retries += 1
                delay = min(2 ** min(retries, 6), 60)
                logger.error(f"连接失败(第 {retries} 次): {e}，{delay} 秒后重试")

                try:
                    with open(os.path.join(self.data_dir, "qq_connect.log"), "a", encoding="utf-8") as _f:
                        _f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} 连接失败(第 {retries} 次): {e}\n")
                except Exception as e2:
                    logger.warning(f"操作失败(可忽略): {e2}")
                await asyncio.sleep(delay)

    def stop(self):
        self._stop_flag = True
        self.running = False
        if self._heartbeat_task:
            try:
                self._heartbeat_task.cancel()
            except Exception as e:
                logger.warning(f"操作失败(可忽略): {e}")

    async def aclose(self):
        self._stop_flag = True
        self.running = False
        if self._heartbeat_task:
            try:
                self._heartbeat_task.cancel()
            except Exception as e:
                logger.warning(f"操作失败(可忽略): {e}")
        if self.ws and not self.ws.closed:
            try:
                await self.ws.close()
            except Exception as e:
                logger.warning(f"操作失败(可忽略): {e}")
            self.ws = None
        if self._ws_session and not self._ws_session.closed:
            try:
                await self._ws_session.close()
            except Exception as e:
                logger.warning(f"操作失败(可忽略): {e}")
            self._ws_session = None

    async def set_params(self, temperature: float, model: str, thinking: str = "off"):
        self.temperature = temperature
        self.model = model
        if thinking in ("off", "low", "medium", "high"):
            self.thinking = thinking




from contextlib import asynccontextmanager

@asynccontextmanager
async def _lifespan(app: FastAPI):
    logger.info("[启动] lifespan 开始")
    session_mgr.start_cleanup()
    if aux_session_mgr is not None:
        aux_session_mgr.start_cleanup()
    yield
    session_mgr.stop_cleanup()
    if aux_session_mgr is not None:
        aux_session_mgr.stop_cleanup()
        aux_session_mgr.close()
    session_mgr.close()
    global _http_shared
    if _http_shared and not _http_shared.closed:
        try:
            await _http_shared.close()
        except Exception as e:
            logger.warning(f"关闭HTTP连接失败(可忽略): {e}")
        _http_shared = None

APP_VERSION = "6.0.0"
app = FastAPI(title="QQBotAgent", version=APP_VERSION, lifespan=_lifespan)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    return response


config = load_config()
session_mgr = SessionManager(
    max_rounds=config.get("max_rounds", 5),
    system_prompt=config.get("system_prompt", "")
)

session_mgr.set_compression(
    enabled=config.get("compression_enabled", False),
    token_limit=config.get("compression_token_limit", 60000),
    model_context_tokens=config.get("model_context_tokens", 32768),
    history_temp_keep_groups=config.get("history_temp_keep_groups", 10),
    history_temp_cleanup=config.get("history_temp_cleanup_enabled", True),
)
session_mgr.max_sessions = int(config.get("max_sessions", 1000) or 1000)
session_mgr.set_archive(
    recall=config.get("archive_recall", True),
    top=config.get("archive_recall_top", 4),
    keep=config.get("archive_keep", 5000),
    keep_total=config.get("archive_keep_total", 200000),
)
bot: Optional[QQBot] = None
bot_task: Optional[asyncio.Task] = None
provider_instance: Optional[Provider] = None





aux_config = load_aux_config()
aux_session_mgr: Optional[SessionManager] = None


def _aux_mgr() -> "SessionManager":
    """辅助实例按需创建。

    没配辅助机器人时，不应该在程序目录里留下一个空的 aux_data。
    模块导入就建实例的话，那套空目录和空数据库会一直存在。
    """
    global aux_session_mgr
    if aux_session_mgr is None:
        mgr = SessionManager(
            max_rounds=aux_config.get("max_rounds", 5),
            system_prompt=aux_config.get("system_prompt", ""),
            store_file=os.path.join(AUX_DATA_DIR, "sessions.json"),
            history_temp_dir=AUX_HISTORY_TEMP_DIR,
        )
        mgr.set_compression(
            enabled=aux_config.get("compression_enabled", False),
            token_limit=aux_config.get("compression_token_limit", 60000),
            model_context_tokens=aux_config.get("model_context_tokens", 32768),
            history_temp_keep_groups=aux_config.get("history_temp_keep_groups", 10),
            history_temp_cleanup=aux_config.get("history_temp_cleanup_enabled", True),
        )
        mgr.max_sessions = int(aux_config.get("max_sessions", 1000) or 1000)
        mgr.set_archive(
            recall=aux_config.get("archive_recall", True),
            top=aux_config.get("archive_recall_top", 4),
            keep=aux_config.get("archive_keep", 5000),
            keep_total=aux_config.get("archive_keep_total", 200000),
        )
        aux_session_mgr = mgr
    return aux_session_mgr


aux_bot: Optional[QQBot] = None
aux_bot_task: Optional[asyncio.Task] = None
aux_provider_instance: Optional[Provider] = None

from jinja2 import Environment, BaseLoader
env = Environment(loader=BaseLoader(), autoescape=True)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>QQ聊天机器人Agent配置</title>
    <style>
        :root {
            --bg: #f3f5f9;
            --surface: #ffffff;
            --line: #e3e8ef;
            --text: #1f2733;
            --text-2: #5c6b80;
            --text-3: #8a94a6;
            --primary: #3563e9;
            --primary-2: #4a7dff;
            --ok: #1e9e5a;
            --warn: #b7791f;
            --bad: #d64545;
        }
        body { font-family: system-ui, "Segoe UI", "Noto Sans SC", "Source Han Sans SC", sans-serif; margin: 24px 16px; background: var(--bg); color: var(--text); font-size: 14px; }
        .container { max-width: 860px; margin: auto; background: var(--surface); padding: 26px 28px 30px; border-radius: 10px; border: 1px solid var(--line); box-shadow: 0 1px 2px rgba(16,24,40,.04), 0 8px 24px -12px rgba(16,24,40,.12); }
        .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
        .brand svg { width: 36px; height: 36px; flex: none; }
        .brand h1 { font-size: 19px; margin: 0; color: var(--text); text-align: left; letter-spacing: .2px; line-height: 1.2; }
        .brand-sub { font-size: 12px; color: var(--text-3); margin-top: 2px; }
        .brand-ver { margin-left: auto; font-size: 12px; color: var(--text-3); border: 1px solid var(--line); padding: 2px 9px; border-radius: 999px; background: #fff; }
        h3 { font-size: 15px; color: var(--text); margin: 24px 0 10px; padding-left: 10px; border-left: 3px solid var(--primary); line-height: 1.3; }
        .form-group { margin-bottom: 14px; }
        label { display: block; font-weight: 600; font-size: 13px; margin-bottom: 5px; color: var(--text); }
        input, select, textarea { width: 100%; padding: 8px 10px; border: 1px solid var(--line); border-radius: 6px; box-sizing: border-box; font-size: 13px; color: var(--text); background: #fff; transition: border-color .15s, box-shadow .15s; font-family: inherit; }
        input:focus, select:focus, textarea:focus { outline: none; border-color: var(--primary-2); box-shadow: 0 0 0 3px rgba(74,125,255,.13); }
        textarea { height: 80px; resize: vertical; }
        .btn { position: relative; padding: 7px 15px; border: 1px solid rgba(255,255,255,.55); border-bottom-color: rgba(180,192,210,.65); border-radius: 7px; cursor: pointer; margin-right: 8px; font-size: 13px; font-family: inherit; color: var(--text); background: linear-gradient(180deg, rgba(255,255,255,.42), rgba(238,243,250,.32)); backdrop-filter: blur(10px) saturate(1.35); -webkit-backdrop-filter: blur(10px) saturate(1.35); box-shadow: 0 2px 0 rgba(185,196,215,.55), 0 4px 10px -2px rgba(16,24,40,.14), inset 0 1px 0 rgba(255,255,255,.65); transition: box-shadow .12s, transform .12s, filter .12s, border-color .15s, background .15s; }
        .btn:hover { filter: brightness(1.04); border-color: rgba(255,255,255,.85); box-shadow: 0 2px 0 rgba(180,192,210,.55), 0 6px 14px -2px rgba(16,24,40,.18), inset 0 1px 0 rgba(255,255,255,.65); }
        .btn:active { transform: translateY(2px); box-shadow: 0 0 0 rgba(185,196,215,.4), inset 0 1px 3px rgba(16,24,40,.15); }
        .btn-primary { background: linear-gradient(180deg, rgba(91,138,255,.56), rgba(47,90,222,.56)); border-color: rgba(88,130,255,.9); border-bottom-color: rgba(38,72,184,.9); color: #fff; box-shadow: 0 3px 0 rgba(38,72,184,.85), 0 6px 14px -2px rgba(53,99,233,.45), inset 0 1px 0 rgba(255,255,255,.35); text-shadow: 0 1px 0 rgba(0,0,0,.18); }
        .btn-primary:hover { filter: brightness(1.08); }
        .btn-primary:active { transform: translateY(3px); box-shadow: 0 0 0 rgba(38,72,184,.85), inset 0 1px 2px rgba(0,0,0,.2); }
        .btn-success { background: linear-gradient(180deg, rgba(52,189,114,.56), rgba(25,142,81,.56)); border-color: rgba(23,143,81,.9); border-bottom-color: rgba(17,110,60,.9); color: #fff; box-shadow: 0 3px 0 rgba(17,110,60,.85), 0 6px 14px -2px rgba(30,158,90,.45), inset 0 1px 0 rgba(255,255,255,.32); text-shadow: 0 1px 0 rgba(0,0,0,.18); }
        .btn-success:hover { filter: brightness(1.07); }
        .btn-success:active { transform: translateY(3px); box-shadow: 0 0 0 rgba(17,110,60,.85), inset 0 1px 2px rgba(0,0,0,.2); }
        .btn-danger { background: linear-gradient(180deg, rgba(255,122,122,.52), rgba(214,69,69,.55)); border-color: rgba(230,110,110,.85); border-bottom-color: rgba(185,58,58,.9); color: #fff; box-shadow: 0 2px 0 rgba(185,58,58,.8), 0 4px 12px -2px rgba(214,69,69,.3), inset 0 1px 0 rgba(255,255,255,.3); text-shadow: 0 1px 0 rgba(0,0,0,.15); }
        .btn-danger:hover { filter: brightness(1.07); }
        .btn-danger:active { transform: translateY(2px); box-shadow: 0 0 0 rgba(185,58,58,.8), inset 0 1px 2px rgba(0,0,0,.2); }
        .btn-warning { background: linear-gradient(180deg, rgba(255,190,80,.52), rgba(217,139,31,.55)); border-color: rgba(220,155,50,.85); border-bottom-color: rgba(170,115,30,.9); color: #fff; box-shadow: 0 2px 0 rgba(170,115,30,.8), 0 4px 12px -2px rgba(183,121,31,.3), inset 0 1px 0 rgba(255,255,255,.35); text-shadow: 0 1px 0 rgba(0,0,0,.15); }
        .btn-warning:hover { filter: brightness(1.07); }
        .btn-warning:active { transform: translateY(2px); box-shadow: 0 0 0 rgba(170,115,30,.8), inset 0 1px 2px rgba(0,0,0,.2); }
        .row { display: flex; gap: 15px; flex-wrap: wrap; }
        .row .form-group { flex: 1; min-width: 200px; }
        .status { padding: 9px 12px; border-radius: 6px; margin: 4px 0 10px; font-size: 13px; display: flex; align-items: center; gap: 8px; }
        .status::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: currentColor; box-shadow: 0 0 0 3px rgba(0,0,0,.05); flex: none; }
        .status.online { background: #e8f6ee; color: #17683d; border: 1px solid #c6e8d4; }
        .status.offline { background: #fdeeee; color: #8f2f2f; border: 1px solid #f3caca; }
        .status-panel { border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; background: #fafbfd; }
        .status-panel table td { border-bottom: 1px solid #eef1f5; }
        .status-panel table tr:last-child td { border-bottom: none; }
        .st-ok { color: var(--ok); font-weight: 600; }
        .st-bad { color: var(--bad); font-weight: 600; }
        .st-neutral { color: var(--text-3); }
        .hint { font-size: 12px; color: var(--text-3); line-height: 1.5; }
        .sess-item { border: 1px solid var(--line); border-radius: 8px; margin-bottom: 6px; overflow: hidden; background: #fff; transition: border-color .15s; }
        .sess-item:hover { border-color: #cdd7e4; }
        .sess-head { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; cursor: pointer; background: #fafbfd; }
        .sess-head:hover { background: #f1f4f9; }
        .sess-head .uid { font-weight: 600; color: var(--text); }
        .sess-head .meta { font-size: 12px; color: var(--text-3); margin-left: 12px; }
        .sess-head .arrow { color: #b6c0cf; transition: transform .15s; }
        .sess-head.open .arrow { transform: rotate(90deg); }
        .sess-body { display: none; padding: 10px 14px; border-top: 1px solid var(--line); background: #fff; }
        .sess-body.open { display: block; }
        .sess-msg { margin-bottom: 8px; }
        .sess-msg .role { font-size: 11px; font-weight: 600; color: var(--primary); }
        .sess-msg .role.assistant { color: var(--ok); }
        .sess-msg .txt { font-size: 13px; color: #35404e; background: #f5f7fa; border: 1px solid #edf0f4; padding: 6px 9px; border-radius: 6px; margin-top: 2px; white-space: pre-wrap; word-break: break-word; }
        .sess-empty { color: var(--text-3); font-size: 13px; padding: 10px; }
        .sess-actions { margin-top: 10px; }
        .tok-list { font-size: 12px; }
        .tok-row { display: flex; flex-wrap: wrap; gap: 4px 14px; padding: 6px 2px; border-bottom: 1px dashed #e8ecf2; }
        .tok-row:last-child { border-bottom: none; }
        .tok-row .tok-time { color: var(--text); min-width: 150px; }
        .tok-row .tok-prov { color: var(--text-3); }
        .tok-row .tok-uid { color: var(--primary); max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .tok-row .tok-nums { color: #c05545; font-weight: 600; margin-left: auto; }
        .model-list { background: #f8f9fb; border: 1px solid var(--line); padding: 10px; border-radius: 6px; margin-top: 10px; max-height: 150px; overflow-y: auto; }
        .hidden { display: none; }
        /* ---- 状态徽标：代替旧版 emoji 标记 ---- */
        .tag { font-size: 13px; font-weight: 800; letter-spacing: 2px; vertical-align: 1px; }
        .tag-ok { color: #1e9e5a; }
        .tag-info { color: var(--primary); }
        .tag-warn { color: #c9a24f; }
        .tag-bad { color: var(--bad); }
        body.night .tag-ok { color: #4ade80; }
        body.night .tag-info { color: #7fa5ff; }
        body.night .tag-warn { color: #f0b95a; }
        body.night .tag-bad { color: #ff8585; }
        /* ---- 右上角主题切换 ---- */
        .theme-ctl { margin-left: 10px; display: flex; gap: 6px; }
        .theme-btn { width: 34px; height: 34px; border-radius: 8px; border: 1px solid var(--line); background: linear-gradient(180deg, #fff, #f2f5fa); cursor: pointer; display: flex; align-items: center; justify-content: center; box-shadow: 0 2px 0 #dde3ec; padding: 0; transition: transform .1s, box-shadow .1s; }
        .theme-btn:active { transform: translateY(2px); box-shadow: none; }
        .theme-btn svg { width: 20px; height: 20px; }
        #theme-btn .ic-night { display: none; }
        body.night #theme-btn .ic-day { display: none; }
        body.night #theme-btn .ic-night { display: block; }
        /* ---- 夜间模式 ---- */
        body.night { --bg: #12151c; --surface: #181d26; --line: #2a3242; --text: #e6eaf2; --text-2: #aab3c5; --text-3: #7d8798; }
        body.night .container { box-shadow: 0 1px 2px rgba(0,0,0,.4), 0 10px 30px -12px rgba(0,0,0,.6); }
        body.night .brand-ver, body.night .theme-btn { background: #141924; }
        body.night .theme-btn { border-color: #2a3242; box-shadow: 0 2px 0 #10141c; }
        body.night .btn { background: linear-gradient(180deg, rgba(42,50,66,.42), rgba(24,29,40,.4)); border-color: rgba(90,104,132,.5); border-bottom-color: rgba(42,50,66,.7); color: var(--text); box-shadow: 0 2px 0 rgba(10,13,20,.8), 0 4px 10px -2px rgba(0,0,0,.5), inset 0 1px 0 rgba(255,255,255,.07); }
        body.night .btn:hover { filter: brightness(1.18); border-color: #48566f; }
        body.night .btn:active { transform: translateY(2px); box-shadow: 0 0 0 #10141c; }
        body.night .btn-primary { background: linear-gradient(180deg, rgba(91,138,255,.42), rgba(47,85,200,.42)); border-color: rgba(110,150,255,.55); box-shadow: 0 3px 0 rgba(25,50,140,.8), 0 6px 14px -2px rgba(74,125,255,.45), inset 0 1px 0 rgba(255,255,255,.25); }
        body.night .btn-success { background: linear-gradient(180deg, rgba(38,163,93,.38), rgba(20,110,62,.4)); border-color: rgba(60,180,110,.5); box-shadow: 0 3px 0 rgba(10,70,40,.8), 0 6px 14px -2px rgba(38,163,93,.4), inset 0 1px 0 rgba(255,255,255,.22); }
        body.night .btn-danger { background: linear-gradient(180deg, rgba(60,34,34,.94), rgba(45,26,26,.94)); border-color: #5c3333; border-bottom-color: #4a2828; color: #ff9c9c; box-shadow: 0 2px 0 #1a0f0f, 0 4px 10px -2px rgba(0,0,0,.4), inset 0 1px 0 rgba(255,255,255,.06); }
        body.night .btn-danger:hover { background: var(--bad); border-color: var(--bad); color: #fff; }
        body.night .btn-warning { background: linear-gradient(180deg, rgba(58,48,28,.94), rgba(44,37,22,.94)); border-color: #5c4e2c; color: #e8c26a; box-shadow: 0 2px 0 #191509, 0 4px 10px -2px rgba(0,0,0,.4), inset 0 1px 0 rgba(255,255,255,.06); }
        body.night input, body.night select, body.night textarea { background: #12161f; border-color: #2a3242; color: var(--text); }
        body.night input:focus, body.night select:focus, body.night textarea:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(91,138,255,.15); }
        body.night .status-panel, body.night .model-list { background: #141924; }
        body.night .status-panel table td { border-color: #1f2734; }
        body.night .status.online { background: #10241a; color: #5fd394; border-color: #1d4029; }
        body.night .status.offline { background: #2a1414; color: #ff9c9c; border-color: #4a2020; }
        body.night .sess-item { background: var(--surface); }
        body.night .sess-head { background: #141924; }
        body.night .sess-head:hover { background: #181f2d; }
        body.night .sess-msg .txt { background: #141924; border-color: #1f2734; color: #c9d2e0; }
        body.night .tok-row { border-color: #1f2734; }
        @media (max-width: 700px) {
            body { margin: 8px; }
            .container { padding: 14px; }
            .form-row, .row { flex-direction: column; }
            .nav-tabs { flex-wrap: wrap; }
            .tok-row .tok-uid { max-width: 90px; }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="brand">
        <svg viewBox="0 0 36 36" fill="none" aria-hidden="true">
            <rect x="6" y="11" width="24" height="18" rx="5" stroke="#3563e9" stroke-width="2"/>
            <path d="M18 11V6" stroke="#3563e9" stroke-width="2" stroke-linecap="round"/>
            <circle cx="18" cy="4.5" r="1.8" fill="#3563e9"/>
            <circle cx="13.5" cy="19" r="2" fill="#3563e9"/>
            <circle cx="22.5" cy="19" r="2" fill="#3563e9"/>
            <path d="M13 24.5h10" stroke="#3563e9" stroke-width="2" stroke-linecap="round"/>
        </svg>
        <div>
            <h1>QQ 机器人 Agent</h1>
            <div class="brand-sub">本地服务 · 配置与运行管理</div>
        </div>
        <span class="brand-ver">v6.0.0</span>
        <div class="theme-ctl">
            <button type="button" id="theme-btn" class="theme-btn" onclick="toggleTheme()" title="切换白天 / 夜间模式">
                <svg class="ic-day" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="4.2" fill="#ffd76a" stroke="#c9a24f" stroke-width="1.6"/><path d="M12 2.5v2.6M12 18.9v2.6M2.5 12h2.6M18.9 12h2.6M5.2 5.2l1.9 1.9M16.9 16.9l1.9 1.9M18.8 5.2 16.9 7.1M7.1 16.9l-1.9 1.9" stroke="#c9a24f" stroke-width="1.7" stroke-linecap="round"/></svg>
                <svg class="ic-night" viewBox="0 0 24 24" fill="none"><path d="M20 14.5A8.2 8.2 0 0 1 9.5 4 8.3 8.3 0 1 0 20 14.5z" fill="#cfd8ea" stroke="#7d8798" stroke-width="1.6" stroke-linejoin="round"/></svg>
            </button>
        </div>
    </div>
    <div id="status-bar" class="status offline">未连接</div>
    <div id="status-panel" class="status-panel" style="margin-bottom:12px;">
        <table style="width:100%;font-size:13px;border-collapse:collapse;">
            <tr>
                <td style="padding:4px 8px;color:#7f8c8d;width:110px;">服务状态</td>
                <td style="padding:4px 8px;" id="st-service">—</td>
                <td style="padding:4px 8px;color:#7f8c8d;width:110px;">QQ 连接</td>
                <td style="padding:4px 8px;" id="st-qq">—</td>
            </tr>
            <tr>
                <td style="padding:4px 8px;color:#7f8c8d;">模型连接</td>
                <td style="padding:4px 8px;" id="st-model-link">—</td>
                <td style="padding:4px 8px;color:#7f8c8d;">当前模型</td>
                <td style="padding:4px 8px;" id="st-model">—</td>
            </tr>
            <tr>
                <td style="padding:4px 8px;color:#7f8c8d;">运行时长</td>
                <td style="padding:4px 8px;" id="st-uptime">—</td>
                <td style="padding:4px 8px;color:#7f8c8d;">会话数</td>
                <td style="padding:4px 8px;" id="st-session">—</td>
            </tr>
            <tr>
                <td style="padding:4px 8px;color:#7f8c8d;">最近错误</td>
                <td colspan="3" style="padding:4px 8px;" id="st-errors">无</td>
            </tr>
        </table>
        <div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
            <button type="button" class="btn btn-primary" onclick="updateStatus()" style="padding:4px 12px;" title="手动刷新链接状态与当前工作模型">刷新状态</button>
            <span style="font-size:13px;color:#7f8c8d;">快速切换配置：</span>
            <select id="quick-model-switch" style="padding:5px;border:1px solid #ccc;border-radius:4px;min-width:180px;"></select>
            <button type="button" class="btn btn-primary" onclick="applyModelConfig()" style="padding:4px 12px;">应用</button>
            <button type="button" class="btn btn-warning" onclick="saveModelConfig()" style="padding:4px 12px;" title="把当前表单的 Provider/URL/Key/模型保存为一套配置">保存当前为配置</button>
            <button type="button" class="btn btn-danger" onclick="deleteModelConfig()" style="padding:4px 12px;" title="删除下拉列表中当前选中的已保存配置">删除所选配置</button>
            <button type="button" class="btn btn-danger" onclick="restartService()" style="padding:4px 12px;" title="重启整个服务（停 bot → 重新拉起）">重启服务</button>
            <button type="button" class="btn btn-success" onclick="startBot()" style="padding:4px 12px;" title="启动机器人（连接 QQ 网关开始收发消息）">启动机器人</button>
            <button type="button" class="btn btn-danger" onclick="shutdownAll()" style="padding:4px 12px;" title="停止整个服务及所有相关进程">一键停止服务</button>
        </div>
        <div class="hint" style="margin-top:4px;">状态为手动刷新：点「刷新状态」更新；不会自动轮询自检。</div>
    </div>

    <div style="margin:14px 0 10px; display:flex; gap:8px; align-items:center; border-bottom:2px solid #eee; padding-bottom:10px; flex-wrap:wrap;">
        <button type="button" class="btn btn-primary" id="tab-main" onclick="switchPanel('main')" style="padding:8px 22px;">主程序</button>
        <button type="button" class="btn" id="tab-aux" onclick="switchPanel('aux')" style="padding:8px 22px;">辅助程序（独立 bot）</button>
        <span class="hint">辅助程序是独立 bot：人设/历史各自独立，模型与 QQ 凭证单独填；点「读取主程序配置」可克隆非人设的全局对话设置。</span>
    </div>

    <div id="panel-main">
    <form id="config-form">
        <h3>QQ机器人配置</h3>
        <div class="row">
            <div class="form-group">
                <label>AppID</label>
                <input id="app_id" placeholder="请输入 AppID" value="">
            </div>
            <div class="form-group">
                <label>AppSecret <span id="app_secret_saved_tag" class="hint" style="font-weight:normal;"></span></label>
                <input id="app_secret" type="password" autocomplete="new-password" placeholder="请输入 AppSecret" value="">
            </div>
        </div>

        <h3>大模型Provider配置</h3>
        <div class="row">
            <div class="form-group">
                <label>Provider</label>
                <select id="provider_type" onchange="onProviderChange()">
                    {% for pt, pname, _pbase in PROVIDER_PRESETS %}
                    <option value="{{ pt }}">{{ pname }}</option>
                    {% endfor %}
                </select>
            </div>
            <div class="form-group">
                <label>API Key <span id="api_key_saved_tag" class="hint" style="font-weight:normal;"></span></label>
                <input id="api_key" type="password" autocomplete="new-password" placeholder="请输入 API Key" value="">
            </div>
            <div class="form-group">
                <label>Base URL (可选)</label>
                <input id="base_url" placeholder="请输入 Base URL" value="">
            </div>
        </div>
        <div id="key-hint" class="hint" style="margin-top:6px;"></div>
        <button type="button" class="btn btn-primary" onclick="fetchModels()">获取模型列表</button>
        <button type="button" class="btn btn-warning" onclick="testConnection()">测试连通性</button>
        <div id="model-msg" class="hint" style="margin-top:6px;"></div>
        <div style="display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap;">
            <span style="font-size:13px;color:#7f8c8d;">选择模型：</span>
            <select id="model-pick" style="padding:5px;min-width:240px;"><option value=""></option></select>
            <button type="button" class="btn btn-primary" onclick="applyModelPick()" style="padding:4px 12px;" title="立即启用所选模型（保存配置并让机器人用新模型重连）">应用</button>
        </div>

        <h3>对话设置</h3>
        <div class="form-group">
            <label>人设 (System Prompt)</label>
            
            <textarea id="system_prompt" placeholder=""></textarea>
        </div>
        <div class="row">
            <div class="form-group">
                <label>最大对话轮数 (清空历史)</label>
                <input id="max_rounds" type="number" value="5" min="1" max="20">
            </div>
            <div class="form-group">
                <label>Temperature</label>
                <input id="temperature" type="number" step="0.1" value="0.7" min="0" max="2">
            </div>
            <div class="form-group">
                <label>思考深度</label>
                <select id="thinking">
                    <option value="off">关闭</option>
                </select>
            </div>
            <div class="form-group">
                <label>模型 (用于聊天)</label>
                <select id="model">
                    <option value=""></option>
                </select>
            </div>
        </div>

        <h3>上下文压缩</h3>
        <div class="row">
            <div class="form-group">
                <label style="display:flex;align-items:center;gap:6px;">
                    <input id="compression_enabled" type="checkbox" style="width:auto;">
                    启用压缩
                </label>
                <div class="hint" style="margin-top:4px;">当前组对话 token 超限时，把旧对话压成摘要，省 token。</div>
            </div>
            <div class="form-group">
                <label>压缩触发 token 上限</label>
                <input id="compression_token_limit" type="number" value="60000" min="1000" max="1000000">
                <div class="hint" style="margin-top:4px;">当前组累计 token 超过此值即触发压缩。</div>
            </div>
            <div class="form-group">
                <label>模型上下文窗口 (token)</label>
                <input id="model_context_tokens" type="number" value="32768" min="0" max="2000000">
                <div class="hint" style="margin-top:4px;">实际触发阈值取「压缩上限」与「窗口 60%」的较小值。填 0 表示不按窗口收敛。接口不返回窗口大小，需按模型手填。</div>
            </div>
            <div class="form-group">
                <label style="display:flex;align-items:center;gap:6px;">
                    <input id="archive_recall" type="checkbox" style="width:auto;">
                    归档检索
                </label>
                <div class="hint" style="margin-top:4px;">压缩掉和翻篇的原文存入本地归档，按当前消息关键词召回。归档不进常驻上下文，不占 token。</div>
            </div>
            <div class="form-group">
                <label>归档召回条数</label>
                <input id="archive_recall_top" type="number" value="4" min="1" max="20">
            </div>
            <div class="form-group">
                <label>单用户归档上限</label>
                <input id="archive_keep" type="number" value="5000" min="0" max="1000000">
                <div class="hint" style="margin-top:4px;">超出丢最旧的，填 0 表示不限制。命令行可查看与删除：--archive-list / --archive-search / --archive-purge。</div>
            </div>
            <div class="form-group">
                <label>全库归档上限</label>
                <input id="archive_keep_total" type="number" value="200000" min="0" max="50000000">
                <div class="hint" style="margin-top:4px;">所有用户合计，防止多群累加撑爆磁盘。</div>
            </div>
            <div class="form-group">
                <label>模型并发上限</label>
                <input id="max_concurrent" type="number" value="3" min="1" max="20">
                <div class="hint" style="margin-top:4px;">同时在跑的模型请求数。被刷屏时超出的排队等待，防止打满接口配额。</div>
            </div>
            <div class="form-group">
                <label>会话数上限</label>
                <input id="max_sessions" type="number" value="1000" min="0" max="100000">
                <div class="hint" style="margin-top:4px;">超出后淘汰最久未用的会话，填 0 表示不限制。</div>
            </div>
            <div class="form-group">
                <label>history temp 保留组数</label>
                <input id="history_temp_keep_groups" type="number" value="10" min="1" max="100">
                <div class="hint" style="margin-top:4px;">自动删除更早组的历史压缩文件，当前组永不删。</div>
            </div>
            <div class="form-group">
                <label style="display:flex;align-items:center;gap:6px;">
                    <input id="history_temp_cleanup_enabled" type="checkbox" style="width:auto;">
                    启用自动清理
                </label>
                <div class="hint" style="margin-top:4px;">关闭则不自动删旧组压缩文件。</div>
            </div>
        </div>

        <div style="margin-top: 20px;">
            <button type="button" class="btn btn-success" onclick="startBot()">启动机器人</button>
            <button type="button" class="btn btn-primary" onclick="saveConfig()">保存配置</button>
            <button type="button" class="btn btn-warning" onclick="clearSessions()">清空对话记录</button>
        </div>
        <div class="hint" style="margin-top:10px;">对话记录保存于程序同目录 <b>data/sessions.db</b>（SQLite）。「一键停止服务」会关闭整个程序（包括机器人），停止后本页面不可用；重新双击 <b>start.bat</b> 即可再次启动。</div>
    </form>

    <h3>对话记录 <span id="sess-total" style="font-weight:normal;font-size:13px;color:#7f8c8d;"></span></h3>
    <div style="margin-bottom:8px;">
        <button type="button" class="btn btn-primary" onclick="loadSessions()">刷新</button>
        <button type="button" class="btn btn-warning" onclick="clearSessions()">清空全部</button>
    </div>
    <div id="session-menu"></div>
    <div class="hint" style="margin-top:8px;">同一 QQ 号合并为一条，点开按「组」展示对话（每 max_rounds 轮一组），可批量删除某组或清空整个 QQ 号。</div>

    <h3 style="margin-top:24px;">Token 消耗 <span id="tok-total" style="font-weight:normal;font-size:13px;color:#7f8c8d;"></span></h3>
    <div style="margin-bottom:8px; display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
        <button type="button" class="btn btn-primary" onclick="loadTokenUsage()">刷新</button>
        <input type="date" id="tok-clear-date" style="padding:5px;border:1px solid #ccc;border-radius:4px;" title="清除该日期之前（不含当天）的消耗记录">
        <button type="button" class="btn btn-warning" onclick="clearTokenUsageBefore()">清除该日期前记录</button>
    </div>
    <div id="token-menu"></div>
    <div class="hint" style="margin-top:8px;">记录每次调用大模型消耗的 token（本地 data/token_usage.json），点开可查看明细。「清除该日期前记录」会删除所选日期之前的全部消耗记录（当天及之后的保留）。</div>
</div>

    <div id="panel-aux" class="hidden">
        <div id="aux-status-bar" class="status offline">辅助程序未启动</div>
        <div id="aux-status-panel" class="status-panel" style="margin-bottom:12px;">
            <table style="width:100%;font-size:13px;border-collapse:collapse;">
                <tr>
                    <td style="padding:4px 8px;color:#7f8c8d;width:110px;">QQ 连接</td>
                    <td style="padding:4px 8px;" id="aux-st-qq">—</td>
                    <td style="padding:4px 8px;color:#7f8c8d;width:110px;">当前模型</td>
                    <td style="padding:4px 8px;" id="aux-st-model">—</td>
                </tr>
            </table>
            <div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
                <button type="button" class="btn btn-primary" onclick="auxRefreshStatus()" style="padding:4px 12px;" title="手动刷新辅助程序状态">刷新状态</button>
                <button type="button" class="btn btn-success" onclick="startAuxBot()" style="padding:4px 12px;">启动辅助程序</button>
                <button type="button" class="btn btn-danger" onclick="stopAuxBot()" style="padding:4px 12px;">停止辅助程序</button>
            </div>
            <div class="hint" style="margin-top:4px;">辅助程序为独立 bot，状态与配置均独立于主程序，数据存于 aux_data/。</div>
        </div>

        <div style="margin-bottom:10px; display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
            <button type="button" class="btn btn-warning" onclick="cloneAuxFromMain()" style="padding:8px 16px;" title="把主程序的全局对话设置(max_rounds/temperature/压缩/历史清理)克隆进辅助程序，人设与连接不克隆">读取主程序配置</button>
            <button type="button" class="btn btn-primary" onclick="auxRefreshConfig()" style="padding:8px 16px;">刷新配置</button>
            <span class="hint" id="aux-clone-hint"></span>
        </div>

        <form id="aux-config-form">
            <h3>辅助程序 · QQ机器人配置（独立）</h3>
            <div class="row">
                <div class="form-group">
                    <label>AppID（可与主程序不同）</label>
                    <input id="aux_app_id" placeholder="辅助 bot 的 AppID" value="">
                </div>
                <div class="form-group">
                    <label>AppSecret <span id="aux_app_secret_saved_tag" class="hint" style="font-weight:normal;"></span></label>
                    <input id="aux_app_secret" type="password" autocomplete="new-password" placeholder="辅助 bot 的 AppSecret" value="">
                </div>
            </div>

            <h3>辅助程序 · 大模型Provider配置（独立）</h3>
            <div class="row">
                <div class="form-group">
                    <label>Provider</label>
                    <select id="aux_provider_type" onchange="onAuxProviderChange()">
                        {% for pt, pname, _pbase in PROVIDER_PRESETS %}
                        <option value="{{ pt }}">{{ pname }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="form-group">
                    <label>API Key <span id="aux_api_key_saved_tag" class="hint" style="font-weight:normal;"></span></label>
                    <input id="aux_api_key" type="password" autocomplete="new-password" placeholder="辅助 bot 的 API Key" value="">
                </div>
                <div class="form-group">
                    <label>Base URL (可选)</label>
                    <input id="aux_base_url" placeholder="辅助 bot 的 Base URL" value="">
                </div>
            </div>
            <div id="aux-key-hint" class="hint" style="margin-top:6px;"></div>
            <button type="button" class="btn btn-primary" onclick="auxFetchModels()">获取模型列表</button>
            <button type="button" class="btn btn-warning" onclick="auxTestConnection()">测试连通性</button>
            <div id="aux-model-msg" class="hint" style="margin-top:6px;"></div>

            <h3>辅助程序 · 人设（独立，不克隆主程序）</h3>
            <div class="form-group">
                <label>人设 (System Prompt)</label>
                <textarea id="aux_system_prompt" placeholder="辅助 bot 的专属人设"></textarea>
            </div>

            <h3>对话设置（点「读取主程序配置」可从主程序克隆，也可单独改）</h3>
            <div class="row">
                <div class="form-group">
                    <label>最大对话轮数 (清空历史)</label>
                    <input id="aux_max_rounds" type="number" value="5" min="1" max="20">
                </div>
                <div class="form-group">
                    <label>Temperature</label>
                    <input id="aux_temperature" type="number" step="0.1" value="0.7" min="0" max="2">
                </div>
                <div class="form-group">
                    <label>思考深度</label>
                    <select id="aux_thinking">
                        <option value="off">关闭</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>模型 (用于聊天)</label>
                    <select id="aux_model">
                        <option value=""></option>
                    </select>
                </div>
            </div>

            <h3>上下文压缩</h3>
            <div class="row">
                <div class="form-group">
                    <label style="display:flex;align-items:center;gap:6px;">
                        <input id="aux_compression_enabled" type="checkbox" style="width:auto;">
                        启用压缩
                    </label>
                </div>
                <div class="form-group">
                    <label>压缩触发 token 上限</label>
                    <input id="aux_compression_token_limit" type="number" value="60000" min="1000" max="1000000">
                </div>
                <div class="form-group">
                    <label>模型上下文窗口 (token)</label>
                    <input id="aux_model_context_tokens" type="number" value="32768" min="0" max="2000000">
                </div>
                <div class="form-group">
                    <label style="display:flex;align-items:center;gap:6px;">
                        <input id="aux_archive_recall" type="checkbox" style="width:auto;">
                        归档检索
                    </label>
                </div>
                <div class="form-group">
                    <label>归档召回条数</label>
                    <input id="aux_archive_recall_top" type="number" value="4" min="1" max="20">
                </div>
                <div class="form-group">
                    <label>单用户归档上限</label>
                    <input id="aux_archive_keep" type="number" value="5000" min="0" max="1000000">
                </div>
                <div class="form-group">
                    <label>全库归档上限</label>
                    <input id="aux_archive_keep_total" type="number" value="200000" min="0" max="50000000">
                </div>
                <div class="form-group">
                    <label>history temp 保留组数</label>
                    <input id="aux_history_temp_keep_groups" type="number" value="10" min="1" max="100">
                </div>
                <div class="form-group">
                    <label style="display:flex;align-items:center;gap:6px;">
                        <input id="aux_history_temp_cleanup_enabled" type="checkbox" style="width:auto;">
                        启用自动清理
                    </label>
                </div>
            </div>

            <div style="margin-top: 20px;">
                <button type="button" class="btn btn-success" onclick="startAuxBot()">启动辅助程序</button>
                <button type="button" class="btn btn-primary" onclick="saveAuxConfig()">保存配置</button>
                <button type="button" class="btn btn-danger" onclick="stopAuxBot()">停止辅助程序</button>
            </div>
            <div class="hint" style="margin-top:10px;">辅助程序的对话记录/历史压缩独立存于 <b>aux_data/</b> 文件夹，与主程序互不干扰。</div>
        </form>
    </div>

</div>

<script>
    
    // 统一转义入口。任何拼进 innerHTML 的外部数据（聊天内容、模型摘要、
    // 群成员标识、后端错误信息）都必须先过这里，否则一个诱导模型输出的
    // 摘要就能在管理界面上执行脚本，进而调用本机接口。
    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }
    // 会话标识通过索引与全局引用传递，不拼进 onclick 字符串，
    // 避免引号与反斜杠在多层转义里失真。
    var sessList = [];
    function toggleSessionIdx(el, i) {
        var s = sessList[i];
        if (s) toggleSession(el, s.user_id);
    }

    const PROVIDER_BASE = {
        {% for pt, _name, pbase in PROVIDER_PRESETS %}
        "{{ pt }}": "{{ pbase }}",
        {% endfor %}
    };
    
    function onProviderChange() {
        const pt = document.getElementById('provider_type').value;
        const base = PROVIDER_BASE[pt] || '';
        const baseInput = document.getElementById('base_url');
        if (base && !baseInput.value) {
            baseInput.value = base;
        }
        loadThinkingLevels(pt);
    }
    
    async function loadThinkingLevels(pt) {
        pt = pt || document.getElementById('provider_type').value;
        try {
            const resp = await fetch('/api/thinking_levels?provider_type=' + encodeURIComponent(pt));
            const data = await resp.json();
            const levels = data.levels || [];
            const cur = document.getElementById('thinking');
            let opts = '<option value="off">关闭</option>';
            (levels || []).forEach(l => { opts += `<option value="${l}">${l}</option>`; });
            cur.innerHTML = opts;
        } catch (e) {  }
    }
    async function loadConfig() {
        const resp = await fetch('/api/config');
        const data = await resp.json();
        
        
        const hasAppSecret = !!data.has_app_secret;
        const hasApiKey = !!data.has_api_key;
        const hasBaseUrl = !!data.has_base_url;
        document.getElementById('app_id').value = data.app_id || '';
        
        
        
        document.getElementById('app_secret').value = hasAppSecret ? '******' : '';
        document.getElementById('provider_type').value = data.provider_type || 'deepseek';
        document.getElementById('api_key').value = hasApiKey ? '******' : '';
        
        document.getElementById('base_url').value = data.base_url || '';
        
        const tag = ok => ok ? '<span style="color:#27ae60;">(已保存)</span>' : '<span style="color:#c0392b;">(未设置)</span>';
        const t1 = document.getElementById('app_secret_saved_tag');
        const t2 = document.getElementById('api_key_saved_tag');
        if (t1) t1.innerHTML = tag(hasAppSecret);
        if (t2) t2.innerHTML = tag(hasApiKey);
        document.getElementById('system_prompt').value = data.system_prompt || '';
        document.getElementById('max_rounds').value = data.max_rounds || 5;
        document.getElementById('temperature').value = data.temperature ?? 0.7;
        
        window._saved_thinking = data.thinking || 'off';
        await loadThinkingLevels(data.provider_type || 'deepseek');
        const thSel = document.getElementById('thinking');
        const want = (data.thinking && data.thinking !== 'off') ? data.thinking : 'off';
        thSel.value = want;
        if (!thSel.value) thSel.value = 'off';  
        document.getElementById('model').value = data.model || '';
        const _pick = document.getElementById('model-pick');
        if (_pick) {
            if (!_pick.options.length || (_pick.options.length === 1 && !_pick.options[0].value)) _pick.innerHTML = '<option value=""></option>';
            _pick.value = data.model || '';
        }
        
        const comp = data._compression || {};
        const ce = document.getElementById('compression_enabled');
        if (ce) ce.checked = !!(comp.compression_enabled ?? false);
        const ctl = document.getElementById('compression_token_limit');
        if (ctl) ctl.value = comp.compression_token_limit ?? 60000;
        const mctx = document.getElementById('model_context_tokens');
        if (mctx) mctx.value = comp.model_context_tokens ?? 32768;
        const arEl = document.getElementById('archive_recall');
        if (arEl) arEl.checked = comp.archive_recall !== false;
        const artEl = document.getElementById('archive_recall_top');
        if (artEl) artEl.value = comp.archive_recall_top ?? 4;
        const akEl = document.getElementById('archive_keep');
        if (akEl) akEl.value = comp.archive_keep ?? 5000;
        const aktEl = document.getElementById('archive_keep_total');
        if (aktEl) aktEl.value = comp.archive_keep_total ?? 200000;
        const mcEl = document.getElementById('max_concurrent');
        if (mcEl) mcEl.value = data.max_concurrent ?? 3;
        const msEl = document.getElementById('max_sessions');
        if (msEl) msEl.value = data.max_sessions ?? 1000;
        const ckeep = document.getElementById('history_temp_keep_groups');
        if (ckeep) ckeep.value = comp.history_temp_keep_groups ?? 10;
        const cclean = document.getElementById('history_temp_cleanup_enabled');
        if (cclean) cclean.checked = !!(comp.history_temp_cleanup_enabled ?? true);
        
        const keyMsg = document.getElementById('key-hint');
        if (keyMsg) {
            const hasAny = hasApiKey || hasAppSecret || hasBaseUrl;
            keyMsg.textContent = hasAny
                ? '敏感字段已保存（显示为 ******），不可还原；留空则沿用已保存，重新输入可更新。'
                : '尚未保存敏感字段，请填写 API Key 与 AppSecret。';
        }
    }

    async function saveConfig() {
        const payload = getFormData();
        const resp = await fetch('/api/config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (resp.ok) {
            alert('配置已保存');
            loadConfig();
        } else {
            alert('保存失败');
        }
    }

    function getFormData() {
        
        
        const secretVal = id => {
            const v = document.getElementById(id).value;
            
            if (v === '' || /^[\\s*•.]+$/.test(v)) return '';
            return v;
        };
        return {
            app_id: document.getElementById('app_id').value,
            app_secret: secretVal('app_secret'),
            provider_type: document.getElementById('provider_type').value,
            api_key: secretVal('api_key'),
            base_url: document.getElementById('base_url').value,  
            system_prompt: document.getElementById('system_prompt').value,
            max_rounds: parseInt(document.getElementById('max_rounds').value),
            temperature: parseFloat(document.getElementById('temperature').value),
            thinking: document.getElementById('thinking').value,
            model: document.getElementById('model').value,
            compression_enabled: !!(document.getElementById('compression_enabled')?.checked),
            compression_token_limit: parseInt(document.getElementById('compression_token_limit')?.value || 60000),
            model_context_tokens: parseInt(document.getElementById('model_context_tokens')?.value || 0),
            history_temp_keep_groups: parseInt(document.getElementById('history_temp_keep_groups')?.value || 10),
            history_temp_cleanup_enabled: !!(document.getElementById('history_temp_cleanup_enabled')?.checked),
            archive_recall: !!(document.getElementById('archive_recall')?.checked),
            archive_recall_top: parseInt(document.getElementById('archive_recall_top')?.value || 4),
            archive_keep: parseInt(document.getElementById('archive_keep')?.value || 5000),
            archive_keep_total: parseInt(document.getElementById('archive_keep_total')?.value || 200000),
            max_concurrent: parseInt(document.getElementById('max_concurrent')?.value || 3),
            max_sessions: parseInt(document.getElementById('max_sessions')?.value || 1000),
        };
    }

    async function fetchModels() {
        const provider_type = document.getElementById('provider_type').value;
        
        const api_key = (() => {
            const v = document.getElementById('api_key').value;
            return (v === '' || /^[\\s*•.]+$/.test(v)) ? '' : v;
        })();
        const base_url = document.getElementById('base_url').value;
        const resp = await fetch('/api/models', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ provider_type, api_key, base_url })
        });
        const msg = document.getElementById('model-msg');
        if (resp.ok) {
            const data = await resp.json();
            const models = data.models || [];
            if (models.length === 0) {
                msg.textContent = '未拉到模型（该 provider 可能不支持列模型）。';
                return;
            }
            const sel = document.getElementById('model');
            const pick = document.getElementById('model-pick');
            const current = sel.value;
            const opts = models.map(m => `<option value="${esc(m)}">${esc(m)}</option>`).join('');
            sel.innerHTML = opts;
            pick.innerHTML = '<option value=""></option>' + opts;
            sel.value = models.includes(current) ? current : models[0];
            pick.value = sel.value;
            msg.textContent = `已获取 ${models.length} 个模型，请在下方「选择模型」中选定后点「应用」。`;
        } else {
            msg.textContent = '获取模型列表失败';
        }
    }

    async function applyModelPick() {
        const pick = document.getElementById('model-pick');
        const m = pick ? pick.value : '';
        if (!m) { alert('请先「获取模型列表」并在下拉框中选中一个模型。'); return; }
        if (!confirm(`确定应用模型「${m}」吗？\\n将立即保存配置；若机器人运行中会自动用新模型重连。`)) return;
        document.getElementById('model').value = m;
        await saveConfig();
        updateStatus();
    }

    async function testConnection() {
        const provider_type = document.getElementById('provider_type').value;
        
        const api_key = (() => {
            const v = document.getElementById('api_key').value;
            return (v === '' || /^[\\s*•.]+$/.test(v)) ? '' : v;
        })();
        const base_url = document.getElementById('base_url').value;
        const resp = await fetch('/api/test', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ provider_type, api_key, base_url })
        });
        if (resp.ok) {
            const data = await resp.json();
            alert(data.success ? '连通性测试成功！' : '连通性测试失败');
        } else {
            alert('测试请求失败');
        }
    }

    async function startBot() {
        const payload = getFormData();
        
        
        let serverCfg = {};
        try {
            const r = await fetch('/api/config');
            if (r.ok) serverCfg = await r.json();
        } catch (e) {  }
        const real = {
            app_id: !!serverCfg.has_app_id,
            app_secret: !!serverCfg.has_app_secret,
            api_key: !!serverCfg.has_api_key,
        };
        
        const missingAppId = !payload.app_id && !real.app_id;
        const missingAppSecret = !payload.app_secret && !real.app_secret;
        if (missingAppId) { alert('请填写 AppID'); return; }
        if (missingAppSecret) { alert('请填写 AppSecret'); return; }
        if (!payload.api_key && !real.api_key) { alert('请填写 API Key'); return; }
        if (!payload.model) { alert('请先选择模型(点「获取模型列表」后在下拉中选择)'); return; }
        const resp = await fetch('/api/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (resp.ok) {
            updateStatus();
        } else {
            const t = await resp.text();
            alert('启动失败：' + t);
        }
    }

    async function stopBot() {
        const resp = await fetch('/api/stop', { method: 'POST' });
        if (resp.ok) {
            alert('已停止');
            updateStatus();
        }
    }

    async function shutdownApp() {
        if (!confirm('确定要退出整个服务程序吗？\\n退出后需重新双击 start.bat 才能再访问本页面。')) {
            return;
        }
        try {
            await fetch('/api/shutdown', { method: 'POST' });
        } catch (e) {  }
        alert('服务已退出。');
    }

    
    async function ensureRunning() {
        try {
            const resp = await fetch('/api/ensure_running', { method: 'POST' });
            const data = await resp.json();
            if (data.status === 'already_running') {
                alert('服务已在运行：' + (data.url || 'http://127.0.0.1:8000'));
            } else if (data.status === 'starting') {
                alert('服务启动中... 若 2 秒后本页没刷新，请手动访问 http://127.0.0.1:8000');
                setTimeout(() => location.reload(), 2500);
            }
            updateStatus();
        } catch (e) {
            alert('请求失败');
        }
    }

    
    async function shutdownAll() {
        if (!confirm('确定要一键停止服务吗？\\n将关闭整个程序（包括机器人）。停止后本页面不可用，重新双击 start.bat 可再次启动。')) {
            return;
        }
        try {
            await fetch('/api/shutdown_all', { method: 'POST' });
        } catch (e) {  }
        setStoppedUI();
        alert('服务已停止。重新双击 start.bat 可再次启动。');
    }

    function setStoppedUI() {
        const bar = document.getElementById('status-bar');
        if (bar) { bar.className = 'status offline'; bar.textContent = '服务已停止'; }
        const bad = '<span class="tag tag-bad">已停止</span>';
        const stService = document.getElementById('st-service');
        const stQq = document.getElementById('st-qq');
        if (stService) stService.innerHTML = bad + ' 未运行';
        if (stQq) stQq.innerHTML = bad + ' 未连接';
    }

    async function clearSessions() {
        
        if (!confirm('确定要清空全部对话记录吗？\\n将删除所有用户的所有组对话 + 全部 history temp 压缩记录，此操作无法恢复！')) {
            return;
        }
        const r = prompt('此操作不可恢复。请输入「确认删除」以继续：', '');
        if (r !== '确认删除') {
            alert('已取消删除。');
            return;
        }
        try {
            const resp = await fetch('/api/clear_sessions', { method: 'POST' });
            const data = await resp.json();
            alert(data.status === 'cleared' ? `已清空 ${data.cleared} 个会话的对话记录。` : '清空失败');
            loadSessions();
        } catch (e) {
            alert('清空请求失败');
        }
    }

    
    async function loadSessions() {
        try {
            const resp = await fetch('/api/sessions');
            if (!resp.ok) return;
            const data = await resp.json();
            const sessions = data.sessions || [];
            document.getElementById('sess-total').textContent = `（${sessions.length} 个QQ号）`;
            const menu = document.getElementById('session-menu');
            if (sessions.length === 0) {
                menu.innerHTML = '<div class="sess-empty">暂无对话记录。</div>';
                return;
            }
            sessList = sessions;
            menu.innerHTML = sessions.map((s, i) => {
                const t = new Date(s.last_used * 1000);
                const timeStr = t.toLocaleString('zh-CN', { hour12: false });
                const uid = esc(s.user_id);
                const curTag = `<span style="color:#27ae60;font-size:12px;">（当前第 ${s.current_group} 组）</span>`;
                return `<div class="sess-item">
                    <div class="sess-head" onclick="toggleSessionIdx(this, ${i})">
                        <span>
                            <span class="uid">${uid}</span>
                            <span class="meta">${s.group_count} 组 · ${s.rounds} 轮 · ${timeStr}</span>
                            ${curTag}
                        </span>
                        <span class="arrow">▶</span>
                    </div>
                    <div class="sess-body" id="sess-body-${i}"></div>
                </div>`;
            }).join('');
        } catch (e) { }
    }

    async function loadTokenUsage() {
        try {
            const resp = await fetch('/api/token_usage');
            if (!resp.ok) return;
            const data = await resp.json();
            const recs = data.records || [];
            const sum = data.summary || {};
            document.getElementById('tok-total').textContent =
                `（${sum.count || 0} 次 · 输入 ${sum.prompt_tokens || 0} · 输出 ${sum.completion_tokens || 0} · 合计 ${sum.total_tokens || 0} tokens · 缓存命中 ${sum.cache_hit_tokens || 0} / 未命中 ${sum.cache_miss_tokens || 0}）`;
            const menu = document.getElementById('token-menu');
            if (recs.length === 0) {
                menu.innerHTML = '<div class="sess-empty">暂无 token 消耗记录。</div>';
                return;
            }
            const groups = {};
            recs.forEach(r => {
                const day = (r.time || '').slice(0, 10) || '未知';
                (groups[day] = groups[day] || []).push(r);
            });
            const days = Object.keys(groups);
            menu.innerHTML = days.map((day, gi) => {
                const dayRecs = groups[day];
                const dayTotal = dayRecs.reduce((a, r) => a + (r.total_tokens || 0), 0);
                const items = dayRecs.map((r, ri) => {
                    const t = r.time || '';
                    const cacheTag = (r.cache_hit_tokens || r.cache_miss_tokens)
                        ? `<span style="color:#8e44ad;">（缓存命中 ${r.cache_hit_tokens || 0} / 未命中 ${r.cache_miss_tokens || 0}）</span>` : '';
                    return `<div class="tok-row">
                        <span class="tok-time">${t}</span>
                        <span class="tok-prov">${r.provider || ''} · ${r.model || ''}</span>
                        <span class="tok-uid">${r.user_id || ''}</span>
                        <span class="tok-nums">输入 ${r.prompt_tokens || 0} / 输出 ${r.completion_tokens || 0} / 合计 ${r.total_tokens || 0} ${cacheTag}</span>
                    </div>`;
                }).join('');
                return `<div class="sess-item">
                    <div class="sess-head" onclick="toggleTokenDay(this)">
                        <span>
                            <span class="uid">${day}</span>
                            <span class="meta">${dayRecs.length} 次 · 合计 ${dayTotal} tokens</span>
                        </span>
                        <span class="arrow">▶</span>
                    </div>
                    <div class="sess-body" id="tok-body-${gi}"><div class="tok-list">${items}</div></div>
                </div>`;
            }).join('');
        } catch (e) { }
    }

    function toggleTokenDay(headEl) {
        const body = headEl.nextElementSibling;
        const isOpen = body.classList.contains('open');
        if (isOpen) {
            body.classList.remove('open');
            headEl.classList.remove('open');
        } else {
            body.classList.add('open');
            headEl.classList.add('open');
        }
    }

    async function clearTokenUsageBefore() {
        const dateVal = document.getElementById('tok-clear-date').value;
        if (!dateVal) {
            alert('请先选择日期。');
            return;
        }
        if (!confirm(`确定要删除 ${dateVal} 之前的所有 token 消耗记录吗？\\n当天及之后的记录会保留，此操作无法恢复。`)) {
            return;
        }
        try {
            const resp = await fetch('/api/token_usage/clear_before', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ date: dateVal })
            });
            const data = await resp.json();
            if (data.status === 'cleared') {
                alert(`已删除 ${data.date} 之前的记录，共 ${data.removed} 条。`);
                loadTokenUsage();
            } else {
                alert('删除失败：' + (data.detail || ''));
            }
        } catch (e) {
            alert('删除请求失败');
        }
    }

    async function toggleSession(headEl, uid) {
        const body = headEl.nextElementSibling;
        const isOpen = body.classList.contains('open');
        if (isOpen) {
            body.classList.remove('open');
            headEl.classList.remove('open');
            return;
        }
        body.classList.add('open');
        headEl.classList.add('open');
        try {
            const resp = await fetch('/api/session?user_id=' + encodeURIComponent(uid));
            if (!resp.ok) {
                body.innerHTML = '<div class="sess-empty">加载失败。</div>';
                return;
            }
            const data = await resp.json();
            const groups = data.groups || [];
            if (groups.length === 0) {
                body.innerHTML = '<div class="sess-empty">该会话暂无组。</div>';
                return;
            }
            body.dataset.uid = uid;
            const html = groups.map(g => {
                const cur = (g.group_id === data.current_group);
                const histHtml = (g.history && g.history.length)
                    ? g.history.map(m => {
                        const role = m.role === 'user' ? 'user' : 'assistant';
                        const content = esc(m.content || '');
                        return `<div class="sess-msg">
                            <div class="role ${role}">${role === 'user' ? '用户' : '机器人'}</div>
                            <div class="txt">${content}</div>
                        </div>`;
                    }).join('')
                    : '<div class="sess-empty">该组暂无消息。</div>';
                const compTag = (g.compressed_count > 0)
                    ? `<div class="hint" style="margin-top:4px;">已压缩 ${g.compressed_count} 次` + (g.last_summary ? `，摘要：${esc(g.last_summary)}...` : '') + `</div>`
                    : '';
                return `<div class="grp-block" style="border:1px solid #eee;border-radius:4px;margin-bottom:8px;padding:8px;">
                    <div class="grp-head" style="font-weight:bold;color:#2c3e50;margin-bottom:6px;">
                        第 ${g.group_id} 组（${g.rounds} 轮）${cur ? '<span style="color:#27ae60;">[当前]</span>' : ''}
                        <button type="button" class="btn btn-warning" style="float:right;font-size:12px;padding:2px 8px;" onclick="clearOneGroup(this.closest('.sess-body').dataset.uid, ${g.group_id})">删该组</button>
                    </div>
                    ${compTag}
                    ${histHtml}
                </div>`;
            }).join('');
            body.innerHTML = html +
                `<div class="sess-actions" style="margin-top:10px;">
                    <button type="button" class="btn btn-warning" onclick="clearOneSession(this.closest('.sess-body').dataset.uid)">删除该 QQ 号全部对话</button>
                </div>`;
        } catch (e) {
            body.innerHTML = '<div class="sess-empty">加载失败。</div>';
        }
    }

    async function clearOneGroup(uid, gid) {
        if (!confirm(`确定要删除 ${uid} 的第 ${gid} 组对话吗？该组压缩记录也会一并删除，无法恢复。`)) return;
        try {
            const resp = await fetch('/api/clear_group', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: uid, group_id: gid })
            });
            const data = await resp.json();
            if (data.status === 'cleared') {
                alert(`已删除 ${uid} 的第 ${gid} 组。`);
                loadSessions();
            } else {
                alert('删除失败：' + (data.detail || ''));
            }
        } catch (e) {
            alert('删除请求失败');
        }
    }

    async function clearOneSession(uid) {
        if (!confirm(`确定要清除 ${uid} 的全部对话（所有组 + 压缩记录）吗？此操作无法恢复。`)) return;
        try {
            const resp = await fetch('/api/clear_session', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: uid })
            });
            const data = await resp.json();
            if (data.status === 'cleared') {
                alert(`已清除 ${uid} 的全部对话。`);
                loadSessions();
            } else {
                alert('清除失败：' + (data.detail || ''));
            }
        } catch (e) {
            alert('清除请求失败');
        }
    }

    async function updateStatus() {
        try {
            const resp = await fetch('/api/status');
            if (!resp.ok) return;
            const data = await resp.json();
            
            const bar = document.getElementById('status-bar');
            if (bar) {
                if (data.qq_connected) {
                    bar.className = 'status online';
                    bar.textContent = '已连接 · QQ 网关在线';
                } else {
                    bar.className = 'status offline';
                    bar.textContent = '未连接 · QQ 网关离线';
                }
            }
            
            const ok = '<span class="tag tag-ok">正常</span>';
            const bad = '<span class="tag tag-bad">未连接</span>';
            const off = '<span class="tag tag-bad">未运行</span>';
            const nocfg = '<span class="tag tag-bad">未配置</span>';
            const stService = document.getElementById('st-service');
            const stQq = document.getElementById('st-qq');
            const stModelLink = document.getElementById('st-model-link');
            const stModel = document.getElementById('st-model');
            if (stService) stService.innerHTML = data.service_running ? ok + ' 运行中' : off + ' 未运行';
            if (stQq) stQq.innerHTML = data.qq_connected ? ok + ' 已连接' : bad + ' 未连接';
            const hasModelCfg = data.provider_type && data.model;
            if (stModelLink) stModelLink.innerHTML = hasModelCfg ? ok + ` ${esc(data.provider_type || '')}` : nocfg + ' 未配置';
            if (stModel) stModel.innerHTML = data.model ? `<span class="st-ok">${esc(data.model)}</span>` : '<span class="st-bad">未选择</span>';
            const stUptime = document.getElementById('st-uptime');
            const stSess = document.getElementById('st-session');
            const stErr = document.getElementById('st-errors');
            if (stUptime) {
                const up = data.uptime || 0;
                const h = Math.floor(up / 3600), m = Math.floor(up % 3600 / 60);
                stUptime.textContent = (h ? h + '时' : '') + m + '分';
            }
            if (stSess) stSess.textContent = String(data.session_count || 0);
            if (stErr) {
                const es = data.recent_errors || [];
                stErr.innerHTML = es.length ? es.map(function(x){ return '<div style="color:#c0392b;font-size:12px">' + esc(x) + '</div>'; }).join('') : '无';
            }
        } catch (e) {  }
    }

    
    async function loadModelConfigs() {
        try {
            const resp = await fetch('/api/model_configs');
            if (!resp.ok) return;
            const data = await resp.json();
            const sel = document.getElementById('quick-model-switch');
            if (!sel) return;
            const configs = data.configs || [];
            if (configs.length === 0) {
                sel.innerHTML = '<option value="">（暂无已保存配置）</option>';
                return;
            }
            sel.innerHTML = configs.map(c => {
                const label = `${c.name}（${c.provider_type || ''} · ${c.model || ''}${c.has_api_key ? ' · key✓' : ''}）`;
                const cur = (c.name === data.current) ? ' [当前]' : '';
                return `<option value="${c.name.replace(/"/g, '&quot;')}">${label}${cur}</option>`;
            }).join('');
        } catch (e) {  }
    }

    async function applyModelConfig() {
        const sel = document.getElementById('quick-model-switch');
        const name = sel ? sel.value : '';
        if (!name) { alert('请先选择要应用的配置。'); return; }
        if (!confirm(`确定切换到配置「${name}」吗？\\n将更新 Provider/Base URL/API Key/模型，若机器人运行中会自动用新模型重连。`)) return;
        try {
            const resp = await fetch('/api/model_configs/apply', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            const data = await resp.json();
            if (data.status === 'applied') {
                alert(`已切换到「${name}」。`);
                loadConfig();
                loadModelConfigs();
                updateStatus();
            } else {
                alert('切换失败：' + (data.detail || ''));
            }
        } catch (e) {
            alert('切换请求失败');
        }
    }

    async function saveModelConfig() {
        const name = prompt('给这套配置起个名字（如：DeepSeek-V4 / GLM-5.1 / 备用Key）：', '');
        if (!name) return;
        try {
            const resp = await fetch('/api/model_configs/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            const data = await resp.json();
            if (data.status === 'saved') {
                alert(`已保存配置「${name}」（Provider/URL/Key/模型）。`);
                loadModelConfigs();
            } else {
                alert('保存失败：' + (data.detail || ''));
            }
        } catch (e) {
            alert('保存请求失败');
        }
    }

    async function deleteModelConfig() {
        const sel = document.getElementById('quick-model-switch');
        const name = sel ? sel.value : '';
        if (!name) { alert('请先在下拉框选择要删除的配置。'); return; }
        if (!confirm(`确定要删除已保存的配置「${name}」吗？\\n仅删除该套配置，不影响当前正在使用的设置。`)) return;
        try {
            const resp = await fetch('/api/model_configs/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            const data = await resp.json();
            if (resp.ok) {
                alert(`已删除配置「${name}」。`);
                loadModelConfigs();
            } else {
                alert('删除失败：' + (data.detail || ''));
            }
        } catch (e) {
            alert('删除请求失败');
        }
    }

    async function restartService() {
        if (!confirm('确定要重启整个服务吗？\\n将停止机器人并重新启动服务进程，页面会短暂断开后需重新加载。')) return;
        try {
            const resp = await fetch('/api/restart', { method: 'POST' });
            const data = await resp.json();
            if (data.status === 'restarting') {
                alert('服务重启中... 几秒后请刷新页面。');
                setTimeout(() => location.reload(), 6000);
            }
        } catch (e) {
            
            setTimeout(() => location.reload(), 6000);
        }
    }

    
    function switchPanel(which) {
        const main = document.getElementById('panel-main');
        const aux = document.getElementById('panel-aux');
        const tabMain = document.getElementById('tab-main');
        const tabAux = document.getElementById('tab-aux');
        if (which === 'aux') {
            main.classList.add('hidden');
            aux.classList.remove('hidden');
            tabMain.className = 'btn';
            tabMain.style.background = '';
            tabMain.style.color = '';
            tabAux.className = 'btn btn-primary';
            tabAux.style.background = '';
            tabAux.style.color = '';
            auxRefreshConfig();   
            auxRefreshStatus();
        } else {
            aux.classList.add('hidden');
            main.classList.remove('hidden');
            tabAux.className = 'btn';
            tabAux.style.background = '';
            tabAux.style.color = '';
            tabMain.className = 'btn btn-primary';
            tabMain.style.background = '';
            tabMain.style.color = '';
        }
    }

    
    async function loadAuxThinkingLevels(pt) {
        pt = pt || document.getElementById('aux_provider_type').value;
        try {
            const resp = await fetch('/api/thinking_levels?provider_type=' + encodeURIComponent(pt));
            const data = await resp.json();
            const levels = data.levels || [];
            const cur = document.getElementById('aux_thinking');
            let opts = '<option value="off">关闭</option>';
            (levels || []).forEach(l => { opts += `<option value="${l}">${l}</option>`; });
            cur.innerHTML = opts;
        } catch (e) {  }
    }

    function onAuxProviderChange() {
        const pt = document.getElementById('aux_provider_type').value;
        const base = PROVIDER_BASE[pt] || '';
        const baseInput = document.getElementById('aux_base_url');
        if (base && !baseInput.value) {
            baseInput.value = base;
        }
        loadAuxThinkingLevels(pt);
    }

    function getAuxFormData() {
        const secretVal = id => {
            const v = document.getElementById(id).value;
            if (v === '' || /^[\\s*•.]+$/.test(v)) return '';
            return v;
        };
        return {
            app_id: document.getElementById('aux_app_id').value,
            app_secret: secretVal('aux_app_secret'),
            provider_type: document.getElementById('aux_provider_type').value,
            api_key: secretVal('aux_api_key'),
            base_url: document.getElementById('aux_base_url').value,
            system_prompt: document.getElementById('aux_system_prompt').value,
            max_rounds: parseInt(document.getElementById('aux_max_rounds').value),
            temperature: parseFloat(document.getElementById('aux_temperature').value),
            thinking: document.getElementById('aux_thinking').value,
            model: document.getElementById('aux_model').value,
            compression_enabled: !!(document.getElementById('aux_compression_enabled')?.checked),
            compression_token_limit: parseInt(document.getElementById('aux_compression_token_limit')?.value || 60000),
            model_context_tokens: parseInt(document.getElementById('aux_model_context_tokens')?.value || 0),
            history_temp_keep_groups: parseInt(document.getElementById('aux_history_temp_keep_groups')?.value || 10),
            history_temp_cleanup_enabled: !!(document.getElementById('aux_history_temp_cleanup_enabled')?.checked),
            archive_recall: !!(document.getElementById('aux_archive_recall')?.checked),
            archive_recall_top: parseInt(document.getElementById('aux_archive_recall_top')?.value || 4),
            archive_keep: parseInt(document.getElementById('aux_archive_keep')?.value || 5000),
            archive_keep_total: parseInt(document.getElementById('aux_archive_keep_total')?.value || 200000),
        };
    }

    async function loadAuxConfig() {
        const resp = await fetch('/api/aux/config');
        const data = await resp.json();
        const hasAppSecret = !!data.has_app_secret;
        const hasApiKey = !!data.has_api_key;
        const hasBaseUrl = !!data.has_base_url;
        document.getElementById('aux_app_id').value = data.app_id || '';
        document.getElementById('aux_app_secret').value = hasAppSecret ? '******' : '';
        document.getElementById('aux_provider_type').value = data.provider_type || 'deepseek';
        document.getElementById('aux_api_key').value = hasApiKey ? '******' : '';
        document.getElementById('aux_base_url').value = data.base_url || '';
        const tag = ok => ok ? '<span style="color:#27ae60;">(已保存)</span>' : '<span style="color:#c0392b;">(未设置)</span>';
        const t1 = document.getElementById('aux_app_secret_saved_tag');
        const t2 = document.getElementById('aux_api_key_saved_tag');
        if (t1) t1.innerHTML = tag(hasAppSecret);
        if (t2) t2.innerHTML = tag(hasApiKey);
        document.getElementById('aux_system_prompt').value = data.system_prompt || '';
        document.getElementById('aux_max_rounds').value = data.max_rounds || 5;
        document.getElementById('aux_temperature').value = data.temperature ?? 0.7;
        window._saved_aux_thinking = data.thinking || 'off';
        await loadAuxThinkingLevels(data.provider_type || 'deepseek');
        const thSel = document.getElementById('aux_thinking');
        const want = (data.thinking && data.thinking !== 'off') ? data.thinking : 'off';
        thSel.value = want;
        if (!thSel.value) thSel.value = 'off';
        document.getElementById('aux_model').value = data.model || '';
        const comp = data._compression || {};
        const ce = document.getElementById('aux_compression_enabled');
        if (ce) ce.checked = !!(comp.compression_enabled ?? false);
        const ctl = document.getElementById('aux_compression_token_limit');
        if (ctl) ctl.value = comp.compression_token_limit ?? 60000;
        const mctx = document.getElementById('aux_model_context_tokens');
        if (mctx) mctx.value = comp.model_context_tokens ?? 32768;
        const arEl = document.getElementById('aux_archive_recall');
        if (arEl) arEl.checked = comp.archive_recall !== false;
        const artEl = document.getElementById('aux_archive_recall_top');
        if (artEl) artEl.value = comp.archive_recall_top ?? 4;
        const akEl = document.getElementById('aux_archive_keep');
        if (akEl) akEl.value = comp.archive_keep ?? 5000;
        const aktEl = document.getElementById('aux_archive_keep_total');
        if (aktEl) aktEl.value = comp.archive_keep_total ?? 200000;
        const ckeep = document.getElementById('aux_history_temp_keep_groups');
        if (ckeep) ckeep.value = comp.history_temp_keep_groups ?? 10;
        const cclean = document.getElementById('aux_history_temp_cleanup_enabled');
        if (cclean) cclean.checked = !!(comp.history_temp_cleanup_enabled ?? true);
        const keyMsg = document.getElementById('aux-key-hint');
        if (keyMsg) {
            const hasAny = hasApiKey || hasAppSecret || hasBaseUrl;
            keyMsg.textContent = hasAny
                ? '敏感字段已保存（显示为 ******），不可还原；留空则沿用已保存，重新输入可更新。'
                : '尚未保存敏感字段，请填写 API Key 与 AppSecret。';
        }
    }

    async function auxRefreshConfig() {
        await loadAuxConfig();
        const hint = document.getElementById('aux-clone-hint');
        if (hint) hint.textContent = '';
    }

    async function saveAuxConfig() {
        const payload = getAuxFormData();
        const resp = await fetch('/api/aux/config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (resp.ok) {
            alert('辅助程序配置已保存');
            loadAuxConfig();
        } else {
            const t = await resp.text();
            alert('保存失败：' + t);
        }
    }

    async function auxRefreshStatus() {
        try {
            const resp = await fetch('/api/aux/status');
            if (!resp.ok) return;
            const data = await resp.json();
            const bar = document.getElementById('aux-status-bar');
            if (bar) {
                if (data.qq_connected) {
                    bar.className = 'status online';
                    bar.textContent = '已连接 · 辅助网关在线';
                } else {
                    bar.className = 'status offline';
                    bar.textContent = '未连接 · 辅助网关离线';
                }
            }
            const ok = '<span class="tag tag-ok">正常</span>';
            const bad = '<span class="tag tag-bad">未连接</span>';
            const stQq = document.getElementById('aux-st-qq');
            const stModel = document.getElementById('aux-st-model');
            if (stQq) stQq.innerHTML = data.qq_connected ? ok + ' 已连接' : bad + ' 未连接';
            if (stModel) stModel.innerHTML = data.model ? `<span class="st-ok">${esc(data.model)}</span>` : '<span class="st-bad">未选择</span>';
        } catch (e) {  }
    }

    async function cloneAuxFromMain() {
        try {
            const resp = await fetch('/api/aux/clone', { method: 'POST' });
            if (resp.ok) {
                const data = await resp.json();
                await loadAuxConfig();
                auxRefreshStatus();
                const hint = document.getElementById('aux-clone-hint');
                if (hint) {
                    const keys = Object.keys(data.cloned || {});
                    hint.innerHTML = '<span style="color:#27ae60;">已克隆 ' + keys.length + ' 项全局对话设置（人设/连接未动）</span>';
                }
            } else {
                const t = await resp.text();
                alert('克隆失败：' + t);
            }
        } catch (e) {
            alert('克隆请求失败');
        }
    }

    async function startAuxBot() {
        const payload = getAuxFormData();
        let serverCfg = {};
        try {
            const r = await fetch('/api/aux/config');
            if (r.ok) serverCfg = await r.json();
        } catch (e) {  }
        const real = {
            app_id: !!serverCfg.has_app_id,
            app_secret: !!serverCfg.has_app_secret,
            api_key: !!serverCfg.has_api_key,
        };
        const missingAppId = !payload.app_id && !real.app_id;
        const missingAppSecret = !payload.app_secret && !real.app_secret;
        if (missingAppId) { alert('请填写辅助程序 AppID（注意：AppID 不随「读取主程序配置」克隆，须单独填）'); return; }
        if (missingAppSecret) { alert('请填写辅助程序 AppSecret'); return; }
        if (!payload.api_key && !real.api_key) { alert('请填写辅助程序 API Key'); return; }
        if (!payload.model) { alert('请先选择辅助程序模型(点「获取模型列表」后选择)'); return; }
        const resp = await fetch('/api/aux/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (resp.ok) {
            alert('辅助程序启动中...');
            auxRefreshStatus();
        } else {
            const t = await resp.text();
            alert('启动失败：' + t);
        }
    }

    async function stopAuxBot() {
        try {
            const resp = await fetch('/api/aux/stop', { method: 'POST' });
            if (resp.ok) {
                alert('辅助程序已停止');
                auxRefreshStatus();
            } else {
                const t = await resp.text();
                alert('停止失败：' + t);
            }
        } catch (e) {
            alert('停止请求失败');
        }
    }

    async function auxFetchModels() {
        const provider_type = document.getElementById('aux_provider_type').value;
        const api_key = (() => {
            const v = document.getElementById('aux_api_key').value;
            return (v === '' || /^[\\s*•.]+$/.test(v)) ? '' : v;
        })();
        const base_url = document.getElementById('aux_base_url').value;
        const resp = await fetch('/api/aux/models', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ provider_type, api_key, base_url })
        });
        const msg = document.getElementById('aux-model-msg');
        if (resp.ok) {
            const data = await resp.json();
            const models = data.models || [];
            if (models.length === 0) {
                msg.textContent = '未拉到模型（该 provider 可能不支持列模型）。';
                return;
            }
            const sel = document.getElementById('aux_model');
            const current = sel.value;
            sel.innerHTML = models.map(m => `<option value="${esc(m)}">${esc(m)}</option>`).join('');
            sel.value = models.includes(current) ? current : models[0];
            msg.textContent = `已获取 ${models.length} 个模型，请从下拉列表选择。`;
        } else {
            const t = await resp.text();
            msg.textContent = '获取模型列表失败：' + t;
        }
    }

    async function auxTestConnection() {
        const provider_type = document.getElementById('aux_provider_type').value;
        const api_key = (() => {
            const v = document.getElementById('aux_api_key').value;
            return (v === '' || /^[\\s*•.]+$/.test(v)) ? '' : v;
        })();
        const base_url = document.getElementById('aux_base_url').value;
        const resp = await fetch('/api/aux/test', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ provider_type, api_key, base_url })
        });
        if (resp.ok) {
            const data = await resp.json();
            alert(data.success ? '辅助程序连通性测试成功！' : '辅助程序连通性测试失败');
        } else {
            const t = await resp.text();
            alert('测试请求失败：' + t);
        }
    }

    /* ---- 主题：日夜切换（纯 CSS 主题，无光照引擎） ---- */
    let _theme = localStorage.getItem('qa_theme') || 'day';

    function applyTheme() {
        const b = document.body;
        b.classList.toggle('night', _theme === 'night');
        try {
            localStorage.setItem('qa_theme', _theme);
        } catch (e) { /* 隐私模式下 localStorage 不可用，静默降级 */ }
    }

    function toggleTheme() { _theme = (_theme === 'night') ? 'day' : 'night'; applyTheme(); }
    applyTheme();

    window.onload = function() {
        loadConfig();
        updateStatus();
        loadSessions();
        loadTokenUsage();
        loadModelConfigs();
        setInterval(function() { updateStatus(); }, 5000);
    };
</script>
</body>
</html>
"""


class ProviderConfig(BaseModel):
    provider_type: str
    api_key: str
    base_url: Optional[str] = ""

class TestConnectionRequest(BaseModel):
    provider_type: str
    api_key: str
    base_url: Optional[str] = ""

class ConfigUpdate(BaseModel):

    app_id: str = ""
    app_secret: str = ""
    provider_type: str = "deepseek"
    api_key: str = ""
    base_url: str = ""
    system_prompt: str = ""
    max_rounds: int = Field(5, ge=1, le=20)
    temperature: float = Field(0.7, ge=0.0, le=2.0)
    thinking: str = "off"
    model: str = ""

    compression_enabled: bool = False
    compression_token_limit: int = Field(60000, ge=1000, le=1000000)
    model_context_tokens: int = Field(32768, ge=0, le=2000000)
    max_concurrent: int = Field(3, ge=1, le=20)
    max_sessions: int = Field(1000, ge=0, le=100000)
    archive_recall: bool = True
    archive_recall_top: int = Field(4, ge=1, le=20)
    archive_keep: int = Field(5000, ge=0, le=1000000)
    archive_keep_total: int = Field(200000, ge=0, le=50000000)
    history_temp_keep_groups: int = Field(10, ge=1, le=100)
    history_temp_cleanup_enabled: bool = True

class BotStartRequest(BaseModel):

    app_id: str = ""
    app_secret: str = ""
    provider_type: str = "deepseek"
    api_key: str = ""
    base_url: str = ""
    system_prompt: str = ""
    max_rounds: int = Field(5, ge=1, le=20)
    temperature: float = Field(0.7, ge=0.0, le=2.0)
    thinking: str = "off"
    model: str = ""

class ClearSessionRequest(BaseModel):
    user_id: str

class ClearGroupRequest(BaseModel):
    user_id: str
    group_id: int


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    check_referer(request)
    template = env.from_string(HTML_TEMPLATE)




    return HTMLResponse(
        content=template.render(PROVIDER_PRESETS=PROVIDER_PRESETS),
        headers={"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"},
    )

@app.get("/api/config")
async def get_config(request: Request):
    check_referer(request)


    safe = {k: v for k, v in config.items() if k not in ["app_secret", "api_key"]}
    safe["app_secret"] = "******" if config.get("app_secret") else ""
    safe["api_key"] = "******" if config.get("api_key") else ""
    safe["has_app_id"] = bool(config.get("app_id"))
    safe["has_app_secret"] = bool(config.get("app_secret"))
    safe["has_api_key"] = bool(config.get("api_key"))
    safe["has_base_url"] = bool(config.get("base_url"))

    safe["_compression"] = session_mgr.get_compression_config()
    return safe

@app.post("/api/config")
async def update_config(request: Request, update: ConfigUpdate):
    check_referer(request)
    global config, session_mgr, provider_instance, bot
    incoming = update.dict()

    merged = merge_saved(config, incoming, ["api_key", "app_secret", "base_url"])

    for k, v in incoming.items():
        if k not in ("api_key", "app_secret", "base_url"):
            merged[k] = v
    config = merged
    save_config(config)
    session_mgr.set_system_prompt(update.system_prompt)
    session_mgr.set_max_rounds(update.max_rounds)

    session_mgr.set_compression(
        enabled=update.compression_enabled,
        token_limit=update.compression_token_limit,
        model_context_tokens=update.model_context_tokens,
        history_temp_keep_groups=update.history_temp_keep_groups,
        history_temp_cleanup=update.history_temp_cleanup_enabled,
    )
    session_mgr.max_sessions = int(getattr(update, "max_sessions", 1000) or 1000)
    session_mgr.set_archive(
        recall=getattr(update, "archive_recall", True),
        top=getattr(update, "archive_recall_top", 4),
        keep=getattr(update, "archive_keep", 5000),
        keep_total=getattr(update, "archive_keep_total", 200000),
    )
    try:
        provider_instance = create_provider(update.provider_type, config["api_key"], config["base_url"])
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    logger.info("配置已更新")
    return {"status": "ok"}

@app.post("/api/models")
async def get_models(request: Request, req: ProviderConfig):
    check_referer(request)

    merged = merge_saved(config, req.dict(), ["api_key", "base_url"])
    api_key = merged["api_key"]
    base_url = merged["base_url"] or provider_default_base(req.provider_type)
    if not api_key:
        raise HTTPException(status_code=400, detail="请先填写并保存 API Key")
    try:
        provider = create_provider(req.provider_type, api_key, base_url)
        models = await provider.get_models()
        return {"models": models}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/test")
async def test_connection(request: Request, req: TestConnectionRequest):
    check_referer(request)

    merged = merge_saved(config, req.dict(), ["api_key", "base_url"])
    api_key = merged["api_key"]
    base_url = merged["base_url"] or provider_default_base(req.provider_type)
    if not api_key:
        raise HTTPException(status_code=400, detail="请先填写并保存 API Key")
    try:
        provider = create_provider(req.provider_type, api_key, base_url)
        ok = await provider.test_connection()
        return {"success": ok}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/start")
async def start_bot(request: Request, req: BotStartRequest):
    check_referer(request)
    global bot, bot_task, provider_instance, session_mgr, config
    incoming = req.dict()
    merged = merge_saved(config, incoming, ["api_key", "app_secret", "base_url"])
    for k, v in incoming.items():
        if k not in ("api_key", "app_secret", "base_url"):
            merged[k] = v
    app_id = str(merged.get("app_id") or "").strip()
    app_secret = str(merged.get("app_secret") or "").strip()
    api_key = str(merged.get("api_key") or "").strip()
    base_url = (merged.get("base_url") or "").strip() or provider_default_base(merged.get("provider_type") or "deepseek")
    if not app_id or not app_secret or not api_key:
        raise HTTPException(400, "AppID、AppSecret、API Key 均不能为空")
    if not req.model:
        raise HTTPException(400, "model 不能为空，请先点「获取模型列表」选择模型")
    try:
        provider = create_provider(merged.get("provider_type") or "deepseek", api_key, base_url)
        provider_instance = provider
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    if bot:
        await bot.aclose()
        if bot_task:
            bot_task.cancel()
            try:
                await bot_task
            except asyncio.CancelledError:
                pass
            bot_task = None
        bot = None

    bot = QQBot(app_id, app_secret, provider, session_mgr,
                config=config, data_dir=DATA_DIR)
    bot.temperature = req.temperature
    bot.model = req.model
    if req.thinking in ("off", "low", "medium", "high"):
        bot.thinking = req.thinking

    session_mgr.model = req.model

    async def run():
        try:
            await bot.connect_with_retry()
        except Exception as e:
            logger.error(f"Bot连接失败: {e}")
    bot_task = asyncio.create_task(run())
    logger.info("机器人启动命令已发出")
    return {"status": "starting"}

@app.get("/api/status")
async def get_status(request: Request):
    check_referer(request)
    qq_connected = bool(bot and bot.running)

    current_model = ""
    if bot:
        current_model = getattr(bot, "model", "") or ""
    if not current_model:
        current_model = config.get("model", "")
    return {
        "qq_connected": qq_connected,
        "connected": qq_connected,
        "service_running": True,
        "provider_type": config.get("provider_type", ""),
        "base_url": config.get("base_url", ""),
        "model": current_model,
        "bot_running": qq_connected,
        "uptime": int(time.time() - _BOOT_TS),
        "recent_errors": list(_recent_errors),
        "session_count": len(session_mgr.sessions),
    }


@app.get("/health")
async def health(request: Request):
    host = (request.headers.get("host") or "").split(":")[0].lower().strip()
    if host and host not in _ALLOWED_HOSTS:
        raise HTTPException(status_code=403, detail="Forbidden: 仅允许本机访问")
    return {"status": "ok", "version": APP_VERSION, "service": True, "qq_connected": bool(bot and bot.running)}


@app.post("/api/stop")
async def stop_bot(request: Request):
    check_referer(request)
    global bot, bot_task
    if bot:
        await bot.aclose()
        if bot_task:
            bot_task.cancel()
            try:
                await bot_task
            except asyncio.CancelledError:
                pass
            bot_task = None
        bot = None
        logger.info("机器人已停止")
        return {"status": "stopped"}
    return {"status": "not running"}




@app.get("/api/aux/config")
async def get_aux_config(request: Request):
    check_referer(request)
    safe = {k: v for k, v in aux_config.items() if k not in ["app_secret", "api_key"]}
    safe["app_secret"] = "******" if aux_config.get("app_secret") else ""
    safe["api_key"] = "******" if aux_config.get("api_key") else ""
    safe["has_app_id"] = bool(aux_config.get("app_id"))
    safe["has_app_secret"] = bool(aux_config.get("app_secret"))
    safe["has_api_key"] = bool(aux_config.get("api_key"))
    safe["has_base_url"] = bool(aux_config.get("base_url"))
    # 辅助实例不存在时别为了读配置把它创建出来，否则打开页面就生成 aux_data
    if aux_session_mgr is not None:
        safe["_compression"] = aux_session_mgr.get_compression_config()
    else:
        safe["_compression"] = {
            "compression_enabled": aux_config.get("compression_enabled", False),
            "compression_token_limit": aux_config.get("compression_token_limit", 60000),
            "model_context_tokens": aux_config.get("model_context_tokens", 32768),
            "effective_token_limit": aux_config.get("compression_token_limit", 60000),
            "history_temp_keep_groups": aux_config.get("history_temp_keep_groups", 10),
            "history_temp_cleanup_enabled": aux_config.get("history_temp_cleanup_enabled", True),
            "archive_recall": aux_config.get("archive_recall", True),
            "archive_recall_top": aux_config.get("archive_recall_top", 4),
            "archive_keep": aux_config.get("archive_keep", 5000),
            "archive_keep_total": aux_config.get("archive_keep_total", 200000),
            "archive_count": 0,
        }

    safe["main_clone"] = {k: config.get(k) for k in AUX_CLONE_KEYS}
    safe["main_has_app_id"] = bool(config.get("app_id"))
    return safe

@app.post("/api/aux/config")
async def update_aux_config(request: Request, update: ConfigUpdate):
    check_referer(request)
    global aux_config, aux_session_mgr, aux_provider_instance, aux_bot
    incoming = update.dict()
    merged = merge_saved(aux_config, incoming, ["api_key", "app_secret", "base_url"])
    for k, v in incoming.items():
        if k not in ("api_key", "app_secret", "base_url"):
            merged[k] = v
    aux_config = merged
    save_aux_config(aux_config)
    _aux_mgr().set_system_prompt(update.system_prompt)
    _aux_mgr().set_max_rounds(update.max_rounds)
    _aux_mgr().set_compression(
        enabled=update.compression_enabled,
        token_limit=update.compression_token_limit,
        model_context_tokens=update.model_context_tokens,
        history_temp_keep_groups=update.history_temp_keep_groups,
        history_temp_cleanup=update.history_temp_cleanup_enabled,
    )
    _aux_mgr().max_sessions = int(getattr(update, "max_sessions", 1000) or 1000)
    _aux_mgr().set_archive(
        recall=getattr(update, "archive_recall", True),
        top=getattr(update, "archive_recall_top", 4),
        keep=getattr(update, "archive_keep", 5000),
        keep_total=getattr(update, "archive_keep_total", 200000),
    )
    try:
        aux_provider_instance = create_provider(update.provider_type, aux_config["api_key"], aux_config["base_url"])
    except Exception as e:
        logger.warning(f"操作失败(可忽略): {e}")
    logger.info("辅助程序配置已更新")
    return {"status": "ok"}

@app.post("/api/aux/clone")
async def clone_aux_from_main(request: Request):
    check_referer(request)
    global aux_config, aux_session_mgr
    aux_config = clone_global_to_aux(aux_config, config)
    save_aux_config(aux_config)
    _aux_mgr().set_max_rounds(aux_config.get("max_rounds", 5))
    _aux_mgr().set_compression(
        enabled=aux_config.get("compression_enabled", False),
        token_limit=aux_config.get("compression_token_limit", 60000),
        model_context_tokens=aux_config.get("model_context_tokens", 32768),
        history_temp_keep_groups=aux_config.get("history_temp_keep_groups", 10),
        history_temp_cleanup=aux_config.get("history_temp_cleanup_enabled", True),
    )
    logger.info("辅助程序已克隆主程序全局对话配置")
    return {"status": "ok", "cloned": {k: aux_config.get(k) for k in AUX_CLONE_KEYS}}

@app.post("/api/aux/start")
async def start_aux_bot(request: Request, req: BotStartRequest):
    check_referer(request)
    global aux_bot, aux_bot_task, aux_provider_instance, aux_session_mgr, aux_config
    incoming = req.dict()
    merged = merge_saved(aux_config, incoming, ["api_key", "app_secret", "base_url"])
    for k, v in incoming.items():
        if k not in ("api_key", "app_secret", "base_url"):
            merged[k] = v
    app_id = str(merged.get("app_id") or "").strip()
    app_secret = str(merged.get("app_secret") or "").strip()
    api_key = str(merged.get("api_key") or "").strip()
    base_url = (merged.get("base_url") or "").strip() or provider_default_base(merged.get("provider_type") or "deepseek")
    if not app_id or not app_secret or not api_key:
        raise HTTPException(400, "AppID、AppSecret、API Key 均不能为空")
    if not req.model:
        raise HTTPException(400, "model 不能为空，请先点「获取模型列表」选择模型")
    try:
        provider = create_provider(merged.get("provider_type") or "deepseek", api_key, base_url)
        aux_provider_instance = provider
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    if aux_bot:
        await aux_bot.aclose()
        if aux_bot_task:
            aux_bot_task.cancel()
            try:
                await aux_bot_task
            except asyncio.CancelledError:
                pass
            aux_bot_task = None
        aux_bot = None
    aux_bot = QQBot(app_id, app_secret, provider, _aux_mgr(),
                    config=aux_config, data_dir=AUX_DATA_DIR)
    aux_bot.temperature = req.temperature
    aux_bot.model = req.model
    if req.thinking in ("off", "low", "medium", "high"):
        aux_bot.thinking = req.thinking
    _aux_mgr().model = req.model

    async def run():
        try:
            await aux_bot.connect_with_retry()
        except Exception as e:
            logger.error(f"辅助程序连接失败: {e}")
    aux_bot_task = asyncio.create_task(run())
    logger.info("辅助程序启动命令已发出")
    return {"status": "starting"}

@app.post("/api/aux/stop")
async def stop_aux_bot(request: Request):
    check_referer(request)
    global aux_bot, aux_bot_task
    if aux_bot:
        await aux_bot.aclose()
        if aux_bot_task:
            aux_bot_task.cancel()
            try:
                await aux_bot_task
            except asyncio.CancelledError:
                pass
            aux_bot_task = None
        aux_bot = None
        logger.info("辅助程序已停止")
        return {"status": "stopped"}
    return {"status": "not running"}

@app.get("/api/aux/status")
async def get_aux_status(request: Request):
    check_referer(request)
    qq_connected = bool(aux_bot and aux_bot.running)
    current_model = ""
    if aux_bot:
        current_model = getattr(aux_bot, "model", "") or ""
    if not current_model:
        current_model = aux_config.get("model", "")
    return {
        "qq_connected": qq_connected,
        "bot_running": qq_connected,
        "provider_type": aux_config.get("provider_type", ""),
        "base_url": aux_config.get("base_url", ""),
        "model": current_model,
    }

@app.post("/api/aux/models")
async def get_aux_models(request: Request, req: ProviderConfig):
    check_referer(request)

    merged = merge_saved(aux_config, req.dict(), ["api_key", "base_url"])
    api_key = merged["api_key"]
    base_url = merged["base_url"] or provider_default_base(req.provider_type)
    if not api_key:
        raise HTTPException(status_code=400, detail="请先填写并保存辅助程序 API Key")
    try:
        provider = create_provider(req.provider_type, api_key, base_url)
        models = await provider.get_models()
        return {"models": models}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/aux/test")
async def test_aux_connection(request: Request, req: TestConnectionRequest):
    check_referer(request)
    merged = merge_saved(aux_config, req.dict(), ["api_key", "base_url"])
    api_key = merged["api_key"]
    base_url = merged["base_url"] or provider_default_base(req.provider_type)
    if not api_key:
        raise HTTPException(status_code=400, detail="请先填写并保存辅助程序 API Key")
    try:
        provider = create_provider(req.provider_type, api_key, base_url)
        ok = await provider.test_connection()
        return {"success": ok}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/shutdown_all")
async def shutdown_all(request: Request):
    check_referer(request)
    global bot, bot_task
    logger.info("收到一键关闭指令，正在关闭所有服务...")
    if bot:
        try:
            await bot.aclose()
        except Exception as e:
            logger.warning(f"操作失败(可忽略): {e}")
        if bot_task:
            try:
                bot_task.cancel()
            except Exception as e:
                logger.warning(f"操作失败(可忽略): {e}")
        bot = None
        bot_task = None
    def _do():
        time.sleep(0.4)
        _free_port_8000()
        _remove_pid()
        os._exit(0)
    threading.Thread(target=_do, daemon=True).start()
    return {"status": "shutting_down_all"}

@app.post("/api/ensure_running")
async def ensure_running(request: Request):
    check_referer(request)
    if _port_8000_in_use():
        return {"status": "already_running", "url": "http://127.0.0.1:8000"}

    def _boot():
        start_daemon()
    threading.Thread(target=_boot, daemon=True).start()
    return {"status": "starting", "url": "http://127.0.0.1:8000"}

@app.post("/api/restart")
async def restart_service(request: Request):
    check_referer(request)
    global bot, bot_task
    logger.info("收到重启指令，正在重启服务...")
    if bot:
        try:
            await bot.aclose()
        except Exception as e:
            logger.warning(f"操作失败(可忽略): {e}")
        if bot_task:
            try:
                bot_task.cancel()
            except Exception as e:
                logger.warning(f"操作失败(可忽略): {e}")
        bot = None
        bot_task = None
    def _do():
        time.sleep(1.0)
        my_pid = os.getpid()
        _free_port_8000(exclude_pid=my_pid)
        _remove_pid()
        try:


            if getattr(sys, "frozen", False):
                target = [sys.executable, "--serve"]
            else:
                target = [sys.executable, os.path.abspath(__file__), "--serve"]
            creationflags = 0
            if sys.platform == "win32":
                creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            logf = open(os.path.join(DATA_DIR, "daemon.log"), "a", encoding="utf-8")
            proc = subprocess.Popen(
                target, cwd=BASE_DIR,
                stdout=logf, stderr=logf, stdin=subprocess.DEVNULL,
                close_fds=True, creationflags=creationflags,
            )
            logf.close()
            logger.info(f"重启：新服务进程已拉起 (PID {proc.pid})")
        except Exception as e:
            logger.error(f"重启拉起失败: {e}")
            try:
                with open(os.path.join(DATA_DIR, "qq_connect.log"), "a", encoding="utf-8") as _f:
                    _f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} 重启拉起失败: {e}\n")
            except Exception as e:
                logger.warning(f"操作失败(可忽略): {e}")

        os._exit(0)
    threading.Thread(target=_do, daemon=True).start()
    return {"status": "restarting"}


@app.get("/api/model_configs")
async def get_model_configs(request: Request):
    check_referer(request)
    configs = _load_model_configs()
    safe = []
    for c in configs:
        safe.append({
            "name": c.get("name", ""),
            "provider_type": c.get("provider_type", ""),
            "base_url": c.get("base_url", ""),
            "model": c.get("model", ""),
            "has_api_key": bool(c.get("api_key")),
            "saved_at": c.get("saved_at", ""),
        })

    current_name = ""
    for c in configs:
        if (c.get("provider_type") == config.get("provider_type")
                and c.get("base_url") == config.get("base_url")
                and c.get("model") == config.get("model")):
            current_name = c.get("name", "")
            break
    return {"configs": safe, "current": current_name}

class SaveModelConfigRequest(BaseModel):
    name: str = ""

@app.post("/api/model_configs/save")
async def save_model_config(request: Request, req: SaveModelConfigRequest):
    check_referer(request)
    ok = _save_current_as_model_config(req.name)
    if not ok:
        raise HTTPException(status_code=400, detail="保存失败：名称不能为空或写入失败")
    return {"status": "saved", "name": req.name}

class ApplyModelConfigRequest(BaseModel):
    name: str = ""

@app.post("/api/model_configs/apply")
async def apply_model_config(request: Request, req: ApplyModelConfigRequest):
    check_referer(request)
    global bot, bot_task, provider_instance
    ok = _apply_model_config(req.name)
    if not ok:
        raise HTTPException(status_code=404, detail="未找到该配置")

    try:
        provider_instance = create_provider(config["provider_type"], config["api_key"], config["base_url"])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"provider 创建失败: {e}")

    if bot:
        try:
            await bot.aclose()
        except Exception as e:
            logger.warning(f"操作失败(可忽略): {e}")
        if bot_task:
            try:
                bot_task.cancel()
            except Exception as e:
                logger.warning(f"操作失败(可忽略): {e}")
        bot = None
        bot_task = None
        new_bot = QQBot(config["app_id"], config["app_secret"], provider_instance, session_mgr)
        new_bot.temperature = config.get("temperature", 0.7)
        new_bot.model = config.get("model", "")
        new_bot.thinking = config.get("thinking", "off")
        async def _run():
            try:
                await new_bot.connect_with_retry()
            except Exception as e:
                logger.error(f"切换模型后 bot 连接失败: {e}")
        bot = new_bot
        bot_task = asyncio.create_task(_run())
    logger.info(f"已应用模型配置: {req.name}")
    return {"status": "applied", "name": req.name}

class DeleteModelConfigRequest(BaseModel):
    name: str = ""

@app.post("/api/model_configs/delete")
async def delete_model_config(request: Request, req: DeleteModelConfigRequest):
    check_referer(request)
    ok = _delete_model_config(req.name)
    if not ok:
        raise HTTPException(status_code=404, detail="未找到该配置")
    return {"status": "deleted", "name": req.name}

@app.post("/api/clear_sessions")
async def clear_sessions(request: Request):
    check_referer(request)
    n = session_mgr.clear_all()
    logger.info(f"手动清空对话记录: {n} 个会话")
    return {"status": "cleared", "cleared": n}

@app.get("/api/sessions")
async def list_sessions(request: Request):
    check_referer(request)
    return {"sessions": session_mgr.list_sessions()}

@app.get("/api/token_usage")
async def get_token_usage(request: Request):
    check_referer(request)
    recs = _load_token_usage()
    total_prompt = sum(r.get("prompt_tokens", 0) for r in recs)
    total_completion = sum(r.get("completion_tokens", 0) for r in recs)
    total_all = sum(r.get("total_tokens", 0) for r in recs)
    total_hit = sum(r.get("cache_hit_tokens", 0) for r in recs)
    total_miss = sum(r.get("cache_miss_tokens", 0) for r in recs)
    return {
        "records": recs,
        "summary": {
            "count": len(recs),
            "prompt_tokens": total_prompt,
            "completion_tokens": total_completion,
            "total_tokens": total_all,
            "cache_hit_tokens": total_hit,
            "cache_miss_tokens": total_miss,
        },
    }

@app.post("/api/token_usage/clear_before")
async def clear_token_usage_before(request: Request):
    check_referer(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="请求体不是有效 JSON")
    date_str = (body.get("date") or "").strip()
    if not date_str:
        raise HTTPException(status_code=400, detail="缺少 date 参数（格式 YYYY-MM-DD）")
    try:

        before_ts = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
    except Exception:
        raise HTTPException(status_code=400, detail="date 格式错误，应为 YYYY-MM-DD")
    removed = _clear_token_usage_before(before_ts)
    logger.info(f"已清除 {date_str} 之前的 token 消耗记录，共 {removed} 条")
    return {"status": "cleared", "date": date_str, "removed": removed}

@app.get("/api/thinking_levels")
async def thinking_levels(request: Request):
    check_referer(request)
    pt = request.query_params.get("provider_type", "openai")
    profile = THINKING_PROFILES.get(pt, THINKING_PROFILES["_default"])
    return {"provider_type": pt, "levels": profile["levels"]}

@app.get("/api/session")
async def get_session(request: Request):
    check_referer(request)
    user_id = request.query_params.get("user_id", "")
    if not user_id:
        raise HTTPException(status_code=400, detail="缺少 user_id")
    data = session_mgr.get_session(user_id)
    if data is None:
        raise HTTPException(status_code=404, detail="会话不存在")
    return data

@app.post("/api/clear_session")
async def clear_session(request: Request, req: ClearSessionRequest):
    check_referer(request)
    ok = session_mgr.clear_session_persist(req.user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="会话不存在")
    return {"status": "cleared", "user_id": req.user_id}

@app.post("/api/clear_group")
async def clear_group(request: Request, req: ClearGroupRequest):
    check_referer(request)
    ok = await session_mgr.clear_group(req.user_id, req.group_id)
    if not ok:
        raise HTTPException(status_code=404, detail="组不存在")
    return {"status": "cleared", "user_id": req.user_id, "group_id": req.group_id}

@app.post("/api/shutdown")
async def shutdown_app(request: Request):
    check_referer(request)
    logger.info("收到退出指令，服务即将关闭...")

    global bot, bot_task
    if bot:
        await bot.aclose()
        if bot_task:
            try:
                bot_task.cancel()
            except Exception as e:
                logger.warning(f"操作失败(可忽略): {e}")
        bot = None

    def _do_exit():
        time.sleep(0.3)
        _remove_pid()
        os._exit(0)
    threading.Thread(target=_do_exit, daemon=True).start()
    return {"status": "shutting_down"}


if __name__ == "__main__":







    if "--clear-sessions" in sys.argv:
        n = session_mgr.clear_all()
        print(f"已清空全部对话记录，共 {n} 个会话。")
        sys.exit(0)

    if "--list-sessions" in sys.argv:
        sessions = session_mgr.list_sessions()
        if not sessions:
            print("暂无对话记录。")
        else:
            print(f"共 {len(sessions)} 个会话：")
            for s in sessions:
                t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s["last_used"]))
                print(f"  [{s['user_id']}]  消息 {s['messages']} 条 / {s['rounds']} 轮 / 最近 {t}")
        sys.exit(0)

    if "--clear-session" in sys.argv:
        idx = sys.argv.index("--clear-session")
        if idx + 1 >= len(sys.argv):
            print("用法：python main.py --clear-session <user_id>")
            sys.exit(1)
        target = sys.argv[idx + 1]
        ok = session_mgr.clear_session_persist(target)
        if ok:
            print(f"已清除会话 {target}。")
        else:
            print(f"未找到会话 {target}（可用 --list-sessions 查看）。")
        sys.exit(0)

    if "--archive-stats" in sys.argv:
        total = session_mgr.store.archive_count()
        print(f"归档总条数: {total}")
        sys.exit(0)

    if "--archive-list" in sys.argv:
        idx = sys.argv.index("--archive-list")
        if idx + 1 >= len(sys.argv):
            print("用法：python main.py --archive-list <user_id> [条数]")
            sys.exit(1)
        target = sys.argv[idx + 1]
        n = 50
        if idx + 2 < len(sys.argv):
            try:
                n = max(1, min(500, int(sys.argv[idx + 2])))
            except ValueError:
                pass
        rows = session_mgr.store.archive_list(target, n)
        if not rows:
            print(f"{target} 没有归档记录。")
            sys.exit(0)
        print(f"{target} 最近 {len(rows)} 条归档：")
        for r in rows:
            t = time.strftime("%Y-%m-%d %H:%M", time.localtime(r.get("ts") or 0))
            who = "用户" if r.get("role") == "user" else "机器人"
            body = (r.get("content") or "").replace("\n", " ")[:100]
            print(f"  [{t}] 组{r.get('group_id')} {who}: {body}")
        sys.exit(0)

    if "--archive-search" in sys.argv:
        idx = sys.argv.index("--archive-search")
        if idx + 2 >= len(sys.argv):
            print("用法：python main.py --archive-search <user_id> <关键词>")
            sys.exit(1)
        target = sys.argv[idx + 1]
        kw = sys.argv[idx + 2]
        rows = session_mgr.store.archive_search(target, kw, 20, expand=False)
        if not rows:
            print("没有命中。")
            sys.exit(0)
        print(f"命中 {len(rows)} 条：")
        for r in rows:
            t = time.strftime("%Y-%m-%d %H:%M", time.localtime(r.get("ts") or 0))
            who = "用户" if r.get("role") == "user" else "机器人"
            print(f"  [{t}] {who}: {(r.get('content') or '')[:120]}")
        sys.exit(0)

    if "--archive-purge" in sys.argv:
        idx = sys.argv.index("--archive-purge")
        if idx + 1 >= len(sys.argv):
            print("用法：python main.py --archive-purge <user_id>")
            sys.exit(1)
        target = sys.argv[idx + 1]
        n = session_mgr.store.archive_purge(target)
        print(f"已删除 {target} 的 {n} 条归档。")
        sys.exit(0)

    if "--export-sessions" in sys.argv:
        idx = sys.argv.index("--export-sessions")
        out = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else ""
        fp = session_mgr.export_snapshot(out or None)
        if fp:
            print(f"已导出到 {fp}")
            print("注意：导出文件是明文 JSON，用完请自行删除。")
        else:
            print("导出失败，查看 data/app.log。")
        sys.exit(0)

    if "--stop" in sys.argv:
        pid = _read_pid()
        stopped = False
        if pid:
            print(f"正在停止服务进程 PID={pid} ...")
            stopped = _terminate_pid(pid)

        _free_port_8000()
        _remove_pid()
        if stopped or not _port_8000_in_use():
            print("已停止。")
        else:
            print("停止完成（已清理 8000 端口占用）。")
        sys.exit(0)



    if "--daemon" in sys.argv:
        print("正在以后台模式启动服务（关闭 PowerShell 不影响运行）...")
        pid = start_daemon()
        if pid:
            print(f"已在后台启动，PID={pid}。打开 http://127.0.0.1:8000 查看；用 `python main.py --stop` 停止。")
        else:
            print("服务已在运行，未重复启动。")
        sys.exit(0)



    if not sys.argv[1:]:
        bar = "=" * 64
        script_path = os.path.abspath(__file__)
        print()
        print(bar)
        print(f"  QQBotAgent {APP_VERSION}")
        print("-" * 64)
        print(f"  程序目录    {BASE_DIR}")
        print(f"  启动脚本    {script_path}")
        print(f"  数据目录    {DATA_DIR}")
        print(f"  解释器      {sys.executable}")
        print(f"  运行日志    {os.path.join(DATA_DIR, 'app.log')}")
        print("-" * 64)
        pid = start_daemon()
        if pid:
            print(f"  进程 PID    {pid}")
            print(f"  后台日志    {os.path.join(DATA_DIR, 'daemon.log')}")
            print(f"  启动方式    {os.path.basename(sys.executable)} {os.path.basename(script_path)} --serve")
        print(bar)
        print("  访问地址    http://127.0.0.1:8000")
        print("  停止服务    网页点「一键停止服务」，或 python main.py --stop")
        print(bar)
        print()


        # 就绪探测用纯 socket：_port_8000_in_use 每轮要拉起 netstat 子进程，
        # 探测一轮近半秒，服务早就绪了浏览器却要干等半分钟
        print("  等待服务就绪", end="", flush=True)
        ready = False
        for _ in range(120):
            try:
                with socket.create_connection(("127.0.0.1", 8000), timeout=0.4):
                    ready = True
                    break
            except OSError:
                time.sleep(0.25)
        print(" 完成" if ready else " 超时（浏览器打开后稍等片刻再刷新）")
        # 浏览器由 start.bat 在本进程退出后用系统 start 命令打开，
        # 比 python 的 webbrowser 更可靠；这里只负责等服务就绪，
        # 保证 bat 打开浏览器时页面已经可用。
        sys.exit(0)

    try:
        # 启动各阶段计时：之前子进程拉起到监听花了 24 秒却无从定位
        _t_boot = time.time()

        def _stage(msg: str) -> None:
            logger.info(f"[启动] {msg} (+{time.time() - _t_boot:.1f}s)")

        _write_pid()
        _stage("PID 写入")
        _check_bind_safety()
        _stage("绑定自检")

        # startup.log 只用来记录启动进度，和 app.log 重复，
        # 而且每次启动都会在 data 里留一个 81 字节的残渣。
        if not os.path.exists(CONFIG_FILE):
            save_config(DEFAULT_CONFIG)
        _stage("配置就绪")



        print("QQ 聊天机器人 Agent 启动中...")
        print(f"Web 管理界面: http://127.0.0.1:8000")
        print("仅本机访问（127.0.0.1），局域网其他设备不可访问。")
        print("后台运行：python main.py --daemon    退出：python main.py --stop 或网页「退出程序」")
        print("请确保配置文件 config.json 权限设置为 600 以保护密钥。")
        if not config.get("app_id") or not config.get("app_secret") or not config.get("api_key"):
            print("提示：尚未配置 AppID / AppSecret / API Key，机器人不会自动连接。")
            print("请打开网页 http://127.0.0.1:8000 在「基础配置」中填写后点「启动机器人」。")
        print("="*60)




        if sys.stdout is None:
            sys.stdout = open(os.devnull, "w", encoding="utf-8")
        if sys.stderr is None:
            sys.stderr = open(os.devnull, "w", encoding="utf-8")




        _last_bind_err = None
        _stage("进入 uvicorn")
        # 默认只绑回环。容器部署时由 QQBOT_HOST 覆盖为 0.0.0.0，
        # 否则容器外永远访问不到。
        _bind_host = (os.environ.get("QQBOT_HOST") or "127.0.0.1").strip() or "127.0.0.1"
        if _bind_host not in ("127.0.0.1", "0.0.0.0", "localhost"):
            print(f"QQBOT_HOST 值不受支持: {_bind_host}，回退 127.0.0.1")
            _bind_host = "127.0.0.1"
        if _bind_host != "127.0.0.1":
            print(f"警告：服务绑定到 {_bind_host}，接口来源校验仍只放行本机 Host，"
                  f"请自行确认网络边界。")
        for _attempt in range(30):
            try:
                uvicorn.run(app, host=_bind_host, port=8000)
                _last_bind_err = None
                break
            except OSError as _e:
                _last_bind_err = _e
                logger.warning(f"8000 端口绑定失败（第{_attempt+1}次），1 秒后重试: {_e}")
                time.sleep(1)
        if _last_bind_err is not None:
            raise _last_bind_err

    except Exception as e:

        error_msg = f"启动失败: {e}\n{traceback.format_exc()}"
        with open(os.path.join(DATA_DIR, "error.log"), "w", encoding="utf-8") as f:
            f.write(error_msg)
        print(error_msg)

        input("按 Enter 键退出...")
    finally:
        _remove_pid()