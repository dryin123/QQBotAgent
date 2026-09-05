





import json
import os
import asyncio
import logging
import time
import base64
import threading
import subprocess
import signal
import webbrowser
import sys
import traceback
from typing import List, Dict, Optional
from abc import ABC, abstractmethod
from urllib.parse import urlparse

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


AUX_DATA_DIR = os.path.join(BASE_DIR, "aux_data")
AUX_HISTORY_TEMP_DIR = os.path.join(AUX_DATA_DIR, "history_temp")

try:
    from logging.handlers import RotatingFileHandler
    _rfh = RotatingFileHandler(os.path.join(DATA_DIR, "app.log"),
                               maxBytes=2_000_000, backupCount=3, encoding="utf-8", delay=True)
    _rfh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(_rfh)
except Exception:
    pass

import re as _logre
class _RedactFilter(logging.Filter):
    _pat = _logre.compile(
        r"(sk-[A-Za-z0-9]{8,}|Bearer\s+[A-Za-z0-9._\-]{16,}|"
        r"(?:api[_-]?key|app_secret|app_id)[=:\s]+[A-Za-z0-9@$!%*#?&._\-]{6,})",
        _logre.I)
    def filter(self, record):
        try:
            if not record.args:
                record.msg = self._pat.sub("***", record.msg)
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


def _lockdown_dir(path: str) -> None:

    if not (sys.platform == "win32" and os.path.isdir(path)):
        return
    try:
        import subprocess as _sp
        _sp.run(["icacls", path, "/inheritance:r"], check=False, capture_output=True)
        _sp.run(["icacls", path, "/grant", f"{os.getlogin()}:F"], check=False, capture_output=True)
    except Exception as e:
        logger.warning(f"操作失败(可忽略): {e}")

def _lockdown_data_dir() -> None:
    _lockdown_dir(DATA_DIR)


def _ensure_aux_data_dir() -> str:
    os.makedirs(AUX_DATA_DIR, exist_ok=True)
    os.makedirs(AUX_HISTORY_TEMP_DIR, exist_ok=True)
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
    try:

        return base64.b64decode(s.encode()).decode()
    except Exception:
        return s


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
        with open(CONFIG_FILE, 'r') as f:
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
            with open(CONFIG_FILE) as f:
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
    "compression_enabled", "compression_token_limit",
    "history_temp_keep_groups", "history_temp_cleanup_enabled",
]
DEFAULT_AUX_CONFIG = {
    "app_id": "", "app_secret": "",
    "provider_type": "deepseek",
    "api_key": "", "base_url": "",
    "system_prompt": "",
    "max_rounds": 5, "temperature": 0.7, "thinking": "off", "model": "",
    "compression_enabled": False, "compression_token_limit": 60000,
    "history_temp_keep_groups": 10, "history_temp_cleanup_enabled": True,
}

def _ensure_aux_config_keys(cfg: dict) -> dict:
    out = dict(DEFAULT_AUX_CONFIG)
    out.update(cfg or {})
    return out

def load_aux_config():
    _ensure_aux_data_dir()
    if os.path.exists(AUX_CONFIG_FILE):
        with open(AUX_CONFIG_FILE, 'r') as f:
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
    else:
        save_aux_config(DEFAULT_AUX_CONFIG)
        return DEFAULT_AUX_CONFIG.copy()

def save_aux_config(cfg):
    _ensure_aux_data_dir()
    to_save = cfg.copy()
    old = {}
    if os.path.exists(AUX_CONFIG_FILE):
        try:
            with open(AUX_CONFIG_FILE) as f:
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

def check_referer(request: Request):




    host = (request.headers.get("host") or "").split(":")[0].lower().strip()
    if host not in ("127.0.0.1", "localhost"):
        raise HTTPException(status_code=403, detail="Forbidden: 仅允许本机访问")
    referer = request.headers.get("referer")
    if not referer:

        if request.method != "GET":
            raise HTTPException(status_code=403, detail="Forbidden: 写操作需同源 Referer")
        return
    parsed = urlparse(referer)
    if (parsed.netloc or "").split(":")[0].lower() != host:
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
            except Exception:
                pass
            if "app.py" not in cmdline:
                logger.info(f"8000 端口被非本程序占用 PID={pid}，跳过(不误杀)")
                continue
            _terminate_pid(pid)
    except Exception as e:
        logger.warning(f"操作失败(可忽略): {e}")


def _port_8000_in_use() -> bool:
    if sys.platform != "win32":
        return False
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True,
                             text=True, encoding="gbk", errors="ignore").stdout
        return any(":8000" in line and "LISTENING" in line.upper() for line in out.splitlines())
    except Exception:
        return False


def start_daemon() -> None:


    if _port_8000_in_use():
        print("服务已在运行（8000 端口已监听），无需重复启动。")
        print("访问 http://127.0.0.1:8000；停止用 `python app.py --stop`。")
        return

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
    subprocess.Popen(
        target,
        cwd=BASE_DIR,
        stdout=logf, stderr=logf,
        stdin=subprocess.DEVNULL,
        close_fds=True,
        creationflags=creationflags,
    )
    logf.close()


def _check_bind_safety() -> None:

    try:
        import socket as _socket
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
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


class Provider(ABC):

    def _register_secret(self, secret: str):
        self._secrets = getattr(self, "_secrets", [])
        if secret and secret not in self._secrets:
            self._secrets.append(secret)

    def _sanitize_messages(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:

        secrets = getattr(self, "_secrets", [])
        out: List[Dict[str, str]] = []
        for m in messages:
            out.append({"role": m.get("role", ""), "content": _isolate_content(m.get("content", ""), secrets)})
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
        except:
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
        async with session.post(f"{self.base_url}/chat/completions", headers=headers, json=payload) as resp:
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
            async with session.post(f"{self.base_url}/messages", headers=headers, json=payload) as resp:
                return resp.status == 200
        except:
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


def _temp_dir_for_group(user_id: str, group_id: int, base_dir: str = None) -> str:

    base = base_dir or HISTORY_TEMP_DIR
    os.makedirs(base, exist_ok=True)
    safe_uid = "".join(c for c in str(user_id) if c.isalnum() or c in "-_")[:40] or "unknown"
    d = os.path.join(base, f"{safe_uid}_g{group_id}")
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


def _save_summary(user_id: str, group_id: int, summary: str, base_dir: str = None) -> str:
    try:
        d = _temp_dir_for_group(user_id, group_id, base_dir)
        fp = os.path.join(d, "summary.txt")
        with open(fp, "w", encoding="utf-8") as f:
            f.write(summary)
        return fp
    except Exception as e:
        logger.warning(f"保存合并摘要失败: {e}")
        return ""


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
        d = os.path.join(base_dir or HISTORY_TEMP_DIR, f"{safe_uid}_g{group_id}")
        if os.path.isdir(d):
            import shutil
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
                import shutil
                shutil.rmtree(path, ignore_errors=True)
                logger.info(f"自动清理 history temp: 组 {gid}")
    except Exception as e:
        logger.warning(f"清理 history temp 失败: {e}")

class SessionManager:
    def __init__(self, max_rounds: int = 5, system_prompt: str = "", expire_minutes: int = 60,
                 store_file: str = None, history_temp_dir: str = None):
        self.max_rounds = max_rounds
        self.system_prompt = system_prompt
        self.expire_minutes = expire_minutes
        self.store_file = store_file or os.path.join(DATA_DIR, "sessions.json")

        self.history_temp_dir = history_temp_dir or HISTORY_TEMP_DIR
        self.sessions: Dict[str, Dict] = {}
        self._lock = asyncio.Lock()
        self._cleanup_task = None
        self.model = ""
        self._compressing = False

        self.compression_enabled = False
        self.compression_token_limit = 60000
        self.history_temp_keep_groups = 10
        self.history_temp_cleanup_enabled = True
        self._load()


    def _load(self):
        try:
            if os.path.exists(self.store_file):
                with open(self.store_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and not self.sessions:
                    self.sessions = data
                    logger.info(f"已加载对话记录: {len(self.sessions)} 个会话")
        except Exception as e:
            logger.warning(f"加载对话记录失败(将使用空会话): {e}")

    def _save(self):
        try:
            tmp = self.store_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.sessions, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.store_file)
            self._backup_once_per_hour()
        except Exception as e:
            logger.warning(f"保存对话记录失败: {e}")

    def _backup_once_per_hour(self):
        now = time.time()
        if getattr(self, "_last_backup", 0) and now - self._last_backup < 3600:
            return
        self._last_backup = now
        try:
            import shutil
            bdir = os.path.join(DATA_DIR, "backups")
            os.makedirs(bdir, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            shutil.copy2(self.store_file, os.path.join(bdir, f"sessions_{ts}.json"))
            items = sorted(os.listdir(bdir))
            for fn in items[:-10]:
                try:
                    os.remove(os.path.join(bdir, fn))
                except Exception:
                    pass
            logger.info(f"会话备份完成: backups/sessions_{ts}.json")
        except Exception as e:
            logger.warning(f"会话备份失败(可忽略): {e}")

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
                "last_summary": comp[-1].get("summary", "")[:100] if comp else "",
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
                import shutil
                for fn in os.listdir(self.history_temp_dir):
                    if fn.startswith(prefix):
                        shutil.rmtree(os.path.join(self.history_temp_dir, fn), ignore_errors=True)
        except Exception as e:
            logger.warning(f"操作失败(可忽略): {e}")
        self._save()
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
            self._save()
            return True

    def clear_all(self) -> int:
        n = len(self.sessions)
        self.sessions = {}
        try:
            if os.path.exists(self.store_file):
                os.remove(self.store_file)
        except Exception as e:
            logger.warning(f"删除对话记录文件失败: {e}")

        try:
            import shutil
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
                await self._cleanup_expired()
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
            if expired:
                self._save()
        if expired:
            logger.info(f"清理了 {len(expired)} 个过期会话")

    def set_system_prompt(self, prompt: str):
        self.system_prompt = prompt

    def set_max_rounds(self, rounds: int):
        self.max_rounds = rounds

    def set_compression(self, enabled: bool, token_limit: int,
                        history_temp_keep_groups: int, history_temp_cleanup: bool):
        self.compression_enabled = enabled
        if token_limit and token_limit > 0:
            self.compression_token_limit = token_limit
        self.history_temp_keep_groups = history_temp_keep_groups if history_temp_keep_groups and history_temp_keep_groups > 0 else 10
        self.history_temp_cleanup_enabled = history_temp_cleanup

    def get_compression_config(self) -> dict:
        return {
            "compression_enabled": self.compression_enabled,
            "compression_token_limit": self.compression_token_limit,
            "history_temp_keep_groups": self.history_temp_keep_groups,
            "history_temp_cleanup_enabled": self.history_temp_cleanup_enabled,
        }

    def _ensure_user(self, user_id: str) -> Dict:
        if user_id not in self.sessions:
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

        session["groups"].append({"history": [], "rounds": 0, "compressed": []})
        session["current_group"] = len(session["groups"]) - 1

        if self.history_temp_cleanup_enabled:
            _cleanup_old_temp_groups(user_id, len(session["groups"]), self.history_temp_keep_groups, self.history_temp_dir)
        self._save()
        logger.info(f"用户 {user_id} 第 {old_cur+1} 组已满，翻篇到第 {len(session['groups'])} 组")

    def get_current_group_messages(self, user_id: str) -> List[Dict[str, str]]:
        session = self._ensure_user(user_id)
        cur = self._current_group(session)
        group_id = session["current_group"] + 1
        messages = []

        comps = _load_all_temp_compressions(user_id, group_id, self.history_temp_dir)
        for c in comps:
            _r = c.get('round', '?')
            _lab = "滚动合并摘要" if str(_r) == "999999" else f"历史摘要(第{_r}次压缩)"
            _sum = c.get('summary', '')
            messages.append({"role": "system", "content": f"[{_lab}]\n{_sum}"})

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

            comps = _load_all_temp_compressions(user_id, group_id, self.history_temp_dir)
            for c in comps:
                _r = c.get('round', '?')
                _lab = "滚动合并摘要" if str(_r) == "999999" else f"历史摘要(第{_r}次压缩)"
                _sum = c.get('summary', '')
                messages.append({"role": "system", "content": f"[{_lab}]\n{_sum}"})

            messages.extend(cur.get("history", []))
            messages.append({"role": "user", "content": user_message})
            return messages

    async def maybe_compress(self, user_id: str, provider, usage_ctx: dict = None) -> bool:
        if not self.compression_enabled or self._compressing:
            return False
        async with self._lock:
            session = self._ensure_user(user_id)
            cur = self._current_group(session)
            group_id = session["current_group"] + 1
            if not cur.get("history"):
                return False
            comps = _load_all_temp_compressions(user_id, group_id, self.history_temp_dir)
            total_tokens = 0
            for c in comps:
                total_tokens += _estimate_tokens(c.get("summary", "")) + 10
            total_tokens += _estimate_messages_tokens(cur.get("history", []))
            if total_tokens < self.compression_token_limit:
                return False

        logger.info(f"用户 {user_id} 组{group_id} token {total_tokens} 超限，后台压缩(第{cur.get('rounds', 0)+1}次)")
        self._compressing = True
        asyncio.create_task(self._run_compress(user_id, provider, usage_ctx))
        return True

    async def _run_compress(self, user_id: str, provider, usage_ctx: dict = None):
        try:
            async with self._lock:
                session = self._ensure_user(user_id)
                cur = self._current_group(session)
                group_id = session["current_group"] + 1
                round_no = cur.get("rounds", 0) + 1
                hist = cur.get("history", [])
                if not hist:
                    return
                comps = _load_all_temp_compressions(user_id, group_id, self.history_temp_dir)
                old_sums = "\n".join(c.get("summary", "") for c in comps)
                hist_tokens = _estimate_messages_tokens(hist)
                summary = await self._generate_summary(provider, hist, usage_ctx, old_sums)
                if not summary:
                    return
                keep_n = min(2, max(1, (self.max_rounds or 5) - 1))
                cur["history"] = hist[-keep_n * 2:]
                cur["rounds"] = keep_n
                if old_sums:
                    _cleanup_temp_compressions(user_id, group_id, self.history_temp_dir)
                fp = _save_summary(user_id, group_id, summary, self.history_temp_dir)
                cur["compressed"].append({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "round": round_no, "file": fp})
                self._save()
                sum_tokens = _estimate_tokens(summary)
                saved = hist_tokens - sum_tokens
                logger.info(f"用户 {user_id} 组{group_id} 压缩完成(滚动合并第{round_no}次): "
                            f"本轮 {hist_tokens} token -> 摘要 {sum_tokens} token"
                            f"(省 {max(0, saved)} token / {100 * max(0, saved) // max(1, hist_tokens)}%), 保留近 {keep_n} 轮原文")
        except Exception as e:
            logger.error(f"后台压缩异常: {e}")
        finally:
            self._compressing = False

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
                "尽量控制在约 " + str(max(500, self.compression_token_limit // 20)) + " token 以内。"
            )
            msgs = [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": f"待压缩的对话：\n{prompt_content}"},
            ]
            reply = await provider.chat_completion(
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
            self._save()

    async def clear_session(self, user_id: str):
        async with self._lock:
            if user_id in self.sessions:
                self.sessions[user_id]["groups"] = [{"history": [], "rounds": 0, "compressed": []}]
                self.sessions[user_id]["current_group"] = 0
                self._save()


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

        self.known_users = {}
        self._users_file = os.path.join(self.data_dir, "users.json")

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
                    self._log_connect_error(f"获取access_token失败: status={resp.status} body={body[:500]}")
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
                    self._log_connect_error(f"获取WS地址失败: status={resp.status} body={body[:500]}")
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
                target_id = author.get("user_openid") or "unknown"
            else:
                target_id = author.get("member_openid") or "unknown"
            group_id = d.get("group_openid", "") if event_type == "GROUP_AT_MESSAGE_CREATE" else ""
            msg_id = d.get("id", "")
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

            usage_ctx = {"user_id": target_id, "provider_type": self.config.get("provider_type", "")}
            try:
                await self.session_mgr.maybe_compress(target_id, self.provider, usage_ctx)
            except Exception as e:
                logger.warning(f"压缩检查异常: {e}")
            messages = await self.session_mgr.get_context(target_id, content)
            try:
                reply = await self.provider.chat_completion(
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
        except Exception as e:
            logger.error(f"处理消息异常: {e}")

    async def _reply_message(self, event_type: str, target_id: str, group_id: str, reply_content: str, msg_id: str = ""):



        try:
            if event_type == "GROUP_AT_MESSAGE_CREATE":
                if not group_id:
                    logger.error("群消息缺少 group_openid，无法回复")
                    return
                url = f"https://api.sgroup.qq.com/v2/groups/{group_id}/messages"
            else:
                url = f"https://api.sgroup.qq.com/v2/users/{target_id}/messages"
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
                        last_err = f"status={resp.status} body={body[:200]}"
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
        url = f"https://api.sgroup.qq.com/v2/groups/{group_openid}/messages"
        headers = {"Authorization": f"QQBot {self.access_token}", "Content-Type": "application/json"}
        payload = {"content": content, "msg_type": 0}
        session = await _http()
        async with session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                body = await resp.text()
                raise RuntimeError(f"主动发消息失败: status={resp.status} body={body[:300]}")
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
                        await self._handle_message(data)
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
        max_retries = 5
        while self.running and not self._stop_flag and retries < max_retries:
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
                retries = 0
                logger.info("连接已断开，准备重新连接")
                await asyncio.sleep(3)
            except Exception as e:
                logger.error(f"连接失败 (尝试 {retries+1}/{max_retries}): {e}")

                try:
                    with open(os.path.join(self.data_dir, "qq_connect.log"), "a", encoding="utf-8") as _f:
                        _f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} 连接失败(尝试 {retries+1}/{max_retries}): {e}\n")
                except Exception as e:
                    logger.warning(f"操作失败(可忽略): {e}")
                retries += 1
                if retries < max_retries:
                    await asyncio.sleep(2 ** retries)
                else:
                    logger.error("达到最大重试次数，连接失败")
                    self.running = False

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
    session_mgr.start_cleanup()
    aux_session_mgr.start_cleanup()
    yield
    session_mgr.stop_cleanup()
    aux_session_mgr.stop_cleanup()
    global _http_shared
    if _http_shared and not _http_shared.closed:
        try:
            await _http_shared.close()
        except Exception as e:
            logger.warning(f"关闭HTTP连接失败(可忽略): {e}")
        _http_shared = None

app = FastAPI(title="QQ聊天机器人Agent", lifespan=_lifespan)
config = load_config()
session_mgr = SessionManager(
    max_rounds=config.get("max_rounds", 5),
    system_prompt=config.get("system_prompt", "")
)

session_mgr.set_compression(
    enabled=config.get("compression_enabled", False),
    token_limit=config.get("compression_token_limit", 60000),
    history_temp_keep_groups=config.get("history_temp_keep_groups", 10),
    history_temp_cleanup=config.get("history_temp_cleanup_enabled", True),
)
bot: Optional[QQBot] = None
bot_task: Optional[asyncio.Task] = None
provider_instance: Optional[Provider] = None





aux_config = load_aux_config()
aux_session_mgr = SessionManager(
    max_rounds=aux_config.get("max_rounds", 5),
    system_prompt=aux_config.get("system_prompt", ""),
    store_file=os.path.join(AUX_DATA_DIR, "sessions.json"),
    history_temp_dir=AUX_HISTORY_TEMP_DIR,
)
aux_session_mgr.set_compression(
    enabled=aux_config.get("compression_enabled", False),
    token_limit=aux_config.get("compression_token_limit", 60000),
    history_temp_keep_groups=aux_config.get("history_temp_keep_groups", 10),
    history_temp_cleanup=aux_config.get("history_temp_cleanup_enabled", True),
)
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
        body { font-family: Arial; margin: 20px; background: #f5f7fa; }
        .container { max-width: 800px; margin: auto; background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #2c3e50; }
        .form-group { margin-bottom: 15px; }
        label { display: block; font-weight: bold; margin-bottom: 5px; }
        input, select, textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        textarea { height: 80px; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; }
        .btn-primary { background: #3498db; color: white; }
        .btn-success { background: #2ecc71; color: white; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn-warning { background: #f39c12; color: white; }
        .row { display: flex; gap: 15px; flex-wrap: wrap; }
        .row .form-group { flex: 1; min-width: 200px; }
        .status { padding: 10px; border-radius: 4px; margin: 10px 0; }
        .status.online { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status.offline { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .status-panel { border: 1px solid #ddd; border-radius: 6px; padding: 10px 12px; background: #fafbfc; }
        .status-panel table td { border-bottom: 1px solid #f0f0f0; }
        .status-panel table tr:last-child td { border-bottom: none; }
        .st-ok { color: #27ae60; font-weight: bold; }
        .st-bad { color: #c0392b; font-weight: bold; }
        .st-neutral { color: #95a5a6; }
        .hint { font-size: 12px; color: #7f8c8d; }
        .sess-item { border: 1px solid #ddd; border-radius: 6px; margin-bottom: 6px; overflow: hidden; background: #fff; }
        .sess-head { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; cursor: pointer; background: #fafbfc; }
        .sess-head:hover { background: #eef2f7; }
        .sess-head .uid { font-weight: bold; color: #2c3e50; }
        .sess-head .meta { font-size: 12px; color: #95a5a6; margin-left: 12px; }
        .sess-head .arrow { color: #bdc3c7; transition: transform .15s; }
        .sess-head.open .arrow { transform: rotate(90deg); }
        .sess-body { display: none; padding: 10px 14px; border-top: 1px solid #eee; background: #fff; }
        .sess-body.open { display: block; }
        .sess-msg { margin-bottom: 8px; }
        .sess-msg .role { font-size: 11px; font-weight: bold; color: #3498db; }
        .sess-msg .role.assistant { color: #2ecc71; }
        .sess-msg .txt { font-size: 13px; color: #34495e; background: #f4f6f8; padding: 6px 9px; border-radius: 4px; margin-top: 2px; white-space: pre-wrap; word-break: break-word; }
        .sess-empty { color: #95a5a6; font-size: 13px; padding: 10px; }
        .sess-actions { margin-top: 10px; }
        .tok-list { font-size: 12px; }
        .tok-row { display: flex; flex-wrap: wrap; gap: 4px 14px; padding: 6px 2px; border-bottom: 1px dashed #eee; }
        .tok-row:last-child { border-bottom: none; }
        .tok-row .tok-time { color: #2c3e50; min-width: 150px; }
        .tok-row .tok-prov { color: #7f8c8d; }
        .tok-row .tok-uid { color: #2980b9; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .tok-row .tok-nums { color: #c0392b; font-weight: bold; margin-left: auto; }
        .model-list { background: #f8f9fa; padding: 10px; border-radius: 4px; margin-top: 10px; max-height: 150px; overflow-y: auto; }
        .hidden { display: none; }
        @media (max-width: 700px) {
            body { margin: 8px; }
            .container { padding: 14px; }
            h1 { font-size: 1.25rem; }
            .form-row, .row { flex-direction: column; }
            .nav-tabs { flex-wrap: wrap; }
            .tok-row .tok-uid { max-width: 90px; }
        }
    </style>
</head>
<body>
<div class="container">
    <h1>🤖 QQ机器人聊天Agent</h1>
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
            <span style="font-size:13px;color:#7f8c8d;">快速切换模型：</span>
            <select id="quick-model-switch" style="padding:5px;border:1px solid #ccc;border-radius:4px;min-width:180px;"></select>
            <button type="button" class="btn btn-primary" onclick="applyModelConfig()" style="padding:4px 12px;">应用</button>
            <button type="button" class="btn btn-warning" onclick="saveModelConfig()" style="padding:4px 12px;" title="把当前表单的 Provider/URL/Key/模型保存为一套配置">保存当前为模型配置</button>
            <button type="button" class="btn btn-danger" onclick="deleteModelConfig()" style="padding:4px 12px;" title="删除下拉列表中当前选中的已保存配置">删除所选配置</button>
            <button type="button" class="btn btn-danger" onclick="restartService()" style="padding:4px 12px;" title="重启整个服务（停 bot → 重新拉起）">重启服务</button>
        </div>
        <div class="hint" style="margin-top:4px;">状态为手动刷新：点「刷新状态」更新；不会自动轮询自检。</div>
    </div>

    <div style="margin:14px 0 10px; display:flex; gap:8px; align-items:center; border-bottom:2px solid #eee; padding-bottom:10px; flex-wrap:wrap;">
        <button type="button" class="btn btn-primary" id="tab-main" onclick="switchPanel('main')" style="padding:8px 22px;">主程序</button>
        <button type="button" class="btn" id="tab-aux" onclick="switchPanel('aux')" style="padding:8px 22px;background:#ecf0f1;color:#2c3e50;">辅助程序（独立 bot）</button>
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
            <button type="button" class="btn btn-danger" onclick="shutdownAll()" title="停止整个服务及所有相关进程">一键停止服务</button>
        </div>
        <div class="hint" style="margin-top:10px;">对话记录保存于程序同目录 <b>data/sessions.json</b>。「一键停止服务」会关闭整个程序（包括机器人），停止后本页面不可用；重新运行 <b>python app.py</b> 即可再次启动。</div>
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
        
        const comp = data._compression || {};
        const ce = document.getElementById('compression_enabled');
        if (ce) ce.checked = !!(comp.compression_enabled ?? false);
        const ctl = document.getElementById('compression_token_limit');
        if (ctl) ctl.value = comp.compression_token_limit ?? 60000;
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
            history_temp_keep_groups: parseInt(document.getElementById('history_temp_keep_groups')?.value || 10),
            history_temp_cleanup_enabled: !!(document.getElementById('history_temp_cleanup_enabled')?.checked),
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
            const current = sel.value;
            sel.innerHTML = models.map(m => `<option value="${m}">${m}</option>`).join('');
            
            sel.value = models.includes(current) ? current : models[0];
            msg.textContent = `已获取 ${models.length} 个模型，请从下拉列表选择。`;
        } else {
            msg.textContent = '获取模型列表失败';
        }
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
            alert('机器人启动中...');
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
        if (!confirm('确定要退出整个服务程序吗？\\n退出后需重新运行 python app.py 才能再访问本页面。')) {
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
        if (!confirm('确定要一键停止服务吗？\\n将关闭整个程序（包括机器人）。停止后本页面不可用，重新运行 python app.py 可再次启动。')) {
            return;
        }
        try {
            await fetch('/api/shutdown_all', { method: 'POST' });
        } catch (e) {  }
        alert('服务已停止。重新运行 python app.py 可再次启动。');
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
            menu.innerHTML = sessions.map((s, i) => {
                const t = new Date(s.last_used * 1000);
                const timeStr = t.toLocaleString('zh-CN', { hour12: false });
                const uid = s.user_id.replace(/"/g, '&quot;');
                const curTag = `<span style="color:#27ae60;font-size:12px;">（当前第 ${s.current_group} 组）</span>`;
                return `<div class="sess-item">
                    <div class="sess-head" onclick="toggleSession(this, '${uid}')">
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
            const uidEsc = uid.replace(/'/g, "\\'").replace(/"/g, '&quot;');
            const html = groups.map(g => {
                const cur = (g.group_id === data.current_group);
                const histHtml = (g.history && g.history.length)
                    ? g.history.map(m => {
                        const role = m.role === 'user' ? 'user' : 'assistant';
                        const content = (m.content || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                        return `<div class="sess-msg">
                            <div class="role ${role}">${role === 'user' ? '用户' : '机器人'}</div>
                            <div class="txt">${content}</div>
                        </div>`;
                    }).join('')
                    : '<div class="sess-empty">该组暂无消息。</div>';
                const compTag = (g.compressed_count > 0)
                    ? `<div class="hint" style="margin-top:4px;">已压缩 ${g.compressed_count} 次` + (g.last_summary ? `，摘要：${g.last_summary}...` : '') + `</div>`
                    : '';
                return `<div class="grp-block" style="border:1px solid #eee;border-radius:4px;margin-bottom:8px;padding:8px;">
                    <div class="grp-head" style="font-weight:bold;color:#2c3e50;margin-bottom:6px;">
                        第 ${g.group_id} 组（${g.rounds} 轮）${cur ? '<span style="color:#27ae60;">[当前]</span>' : ''}
                        <button type="button" class="btn btn-warning" style="float:right;font-size:12px;padding:2px 8px;" onclick="clearOneGroup('${uidEsc}', ${g.group_id})">删该组</button>
                    </div>
                    ${compTag}
                    ${histHtml}
                </div>`;
            }).join('');
            body.innerHTML = html +
                `<div class="sess-actions" style="margin-top:10px;">
                    <button type="button" class="btn btn-warning" onclick="clearOneSession('${uidEsc}')">删除该 QQ 号全部对话</button>
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
                    bar.textContent = '✅ QQ 已连接';
                } else {
                    bar.className = 'status offline';
                    bar.textContent = '❌ QQ 未连接';
                }
            }
            
            const ok = '<span class="st-ok">✅</span>';
            const bad = '<span class="st-bad">❌</span>';
            const stService = document.getElementById('st-service');
            const stQq = document.getElementById('st-qq');
            const stModelLink = document.getElementById('st-model-link');
            const stModel = document.getElementById('st-model');
            if (stService) stService.innerHTML = data.service_running ? ok + ' 运行中' : bad + ' 未运行';
            if (stQq) stQq.innerHTML = data.qq_connected ? ok + ' 已连接' : bad + ' 未连接';
            const hasModelCfg = data.provider_type && data.model;
            if (stModelLink) stModelLink.innerHTML = hasModelCfg ? ok + ` ${data.provider_type || ''}` : bad + ' 未配置';
            if (stModel) stModel.innerHTML = data.model ? `<span class="st-ok">${data.model}</span>` : '<span class="st-bad">未选择</span>';
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
                stErr.innerHTML = es.length ? es.map(function(x){ return '<div style="color:#c0392b;font-size:12px">' + x + '</div>'; }).join('') : '无';
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
        if (!confirm(`确定切换到模型配置「${name}」吗？\\n将更新 Provider/Base URL/API Key/模型，若机器人运行中会自动用新模型重连。`)) return;
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
        const name = prompt('给这套模型配置起个名字（如：DeepSeek-V4 / GLM-5.1 / 备用Key）：', '');
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
        if (!confirm(`确定要删除已保存的模型配置「${name}」吗？\\n仅删除该套配置，不影响当前正在使用的设置。`)) return;
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
            tabMain.style.background = '#ecf0f1';
            tabMain.style.color = '#2c3e50';
            tabAux.className = 'btn btn-primary';
            tabAux.style.background = '';
            tabAux.style.color = '';
            auxRefreshConfig();   
            auxRefreshStatus();
        } else {
            aux.classList.add('hidden');
            main.classList.remove('hidden');
            tabAux.className = 'btn';
            tabAux.style.background = '#ecf0f1';
            tabAux.style.color = '#2c3e50';
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
            history_temp_keep_groups: parseInt(document.getElementById('aux_history_temp_keep_groups')?.value || 10),
            history_temp_cleanup_enabled: !!(document.getElementById('aux_history_temp_cleanup_enabled')?.checked),
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
                    bar.textContent = '✅ 辅助程序 QQ 已连接';
                } else {
                    bar.className = 'status offline';
                    bar.textContent = '❌ 辅助程序 QQ 未连接';
                }
            }
            const ok = '<span class="st-ok">✅</span>';
            const bad = '<span class="st-bad">❌</span>';
            const stQq = document.getElementById('aux-st-qq');
            const stModel = document.getElementById('aux-st-model');
            if (stQq) stQq.innerHTML = data.qq_connected ? ok + ' 已连接' : bad + ' 未连接';
            if (stModel) stModel.innerHTML = data.model ? `<span class="st-ok">${data.model}</span>` : '<span class="st-bad">未选择</span>';
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
            sel.innerHTML = models.map(m => `<option value="${m}">${m}</option>`).join('');
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
        history_temp_keep_groups=update.history_temp_keep_groups,
        history_temp_cleanup=update.history_temp_cleanup_enabled,
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
    return {"status": "ok", "service": True, "qq_connected": bool(bot and bot.running)}


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
    safe["_compression"] = aux_session_mgr.get_compression_config()

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
    aux_session_mgr.set_system_prompt(update.system_prompt)
    aux_session_mgr.set_max_rounds(update.max_rounds)
    aux_session_mgr.set_compression(
        enabled=update.compression_enabled,
        token_limit=update.compression_token_limit,
        history_temp_keep_groups=update.history_temp_keep_groups,
        history_temp_cleanup=update.history_temp_cleanup_enabled,
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
    aux_session_mgr.set_max_rounds(aux_config.get("max_rounds", 5))
    aux_session_mgr.set_compression(
        enabled=aux_config.get("compression_enabled", False),
        token_limit=aux_config.get("compression_token_limit", 60000),
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
    aux_bot = QQBot(app_id, app_secret, provider, aux_session_mgr,
                    config=aux_config, data_dir=AUX_DATA_DIR)
    aux_bot.temperature = req.temperature
    aux_bot.model = req.model
    if req.thinking in ("off", "low", "medium", "high"):
        aux_bot.thinking = req.thinking
    aux_session_mgr.model = req.model

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
            print("用法：python app.py --clear-session <user_id>")
            sys.exit(1)
        target = sys.argv[idx + 1]
        ok = session_mgr.clear_session_persist(target)
        if ok:
            print(f"已清除会话 {target}。")
        else:
            print(f"未找到会话 {target}（可用 --list-sessions 查看）。")
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
        start_daemon()
        print("已在后台启动。打开 http://localhost:8000 查看；用 `python app.py --stop` 停止。")
        sys.exit(0)



    if not sys.argv[1:]:
        start_daemon()



        for _ in range(30):
            if _port_8000_in_use():
                break
            time.sleep(0.5)
        try:
            import webbrowser
            webbrowser.open("http://127.0.0.1:8000")
        except Exception as e:
            logger.warning(f"操作失败(可忽略): {e}")
        print("服务已启动。Web 管理界面: http://127.0.0.1:8000")
        print("停止服务：网页点「一键停止服务」，或运行 `python app.py --stop`。")
        sys.exit(0)

    try:
        _write_pid()
        _check_bind_safety()

        startup_log = os.path.join(DATA_DIR, "startup.log")
        with open(startup_log, "w", encoding="utf-8") as f:
            f.write(f"启动时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("正在初始化配置...\n")
        if not os.path.exists(CONFIG_FILE):
            save_config(DEFAULT_CONFIG)
        with open(startup_log, "a", encoding="utf-8") as f:
            f.write("配置加载完成\n")



        print("QQ 聊天机器人 Agent 启动中...")
        print(f"Web 管理界面: http://127.0.0.1:8000")
        print("仅本机访问（127.0.0.1），局域网其他设备不可访问。")
        print("后台运行：python app.py --daemon    退出：python app.py --stop 或网页「退出程序」")
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
        for _attempt in range(30):
            try:
                uvicorn.run(app, host="127.0.0.1", port=8000)
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