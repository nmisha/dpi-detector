import os
import ssl
import asyncio
import random
import string
import time
from typing import Tuple, Optional
import httpx
import config

# Предварительно генерируем пул случайных символов (100 КБ).
# Это нужно, чтобы брать из него куски и делать каждый запрос уникальным (защита от кэша WAF),
RANDOM_POOL = "".join(random.choices(string.ascii_letters + string.digits, k=100_000))

async def _fat_probe_keepalive(
    client: httpx.AsyncClient, ip: str, port: int, sni: Optional[str]
) -> Tuple[str, str, str]:

    scheme = "http" if port == 80 else "https"
    url = f"{scheme}://{ip}:{port}/"

    base_headers = {
        "User-Agent": config.USER_AGENT,
        "Connection": "keep-alive"
    }
    if sni:
        base_headers["Host"] = sni

    alive_str = "[dim]—[/dim]"
    # 16 запросов по 4кб через 1 TCP соединение
    chunks_count = 16
    chunk_size = 4000

    rtt_measurements = []
    dynamic_timeout = None

    extensions = {}
    if sni and port != 80:
        extensions["sni_hostname"] = sni

    for i in range(chunks_count):
        headers = base_headers.copy()

        # i=0 — чистый запрос без X-Pad: только проверяем что сервер живой.
        # i>=1 — добавляем мусор
        if i > 0:
            start_idx = random.randint(0, len(RANDOM_POOL) - chunk_size - 1)
            headers["X-Pad"] = RANDOM_POOL[start_idx:start_idx + chunk_size]

        current_timeout = dynamic_timeout if dynamic_timeout is not None else config.FAT_READ_TIMEOUT

        start_time = time.time()

        try:
            resp = await client.request(
                "HEAD",
                url,
                headers=headers,
                timeout=current_timeout,
                extensions=extensions if extensions else None
            )

            elapsed = time.time() - start_time
            status = resp.status_code

            if i == 0:
                alive_str = f"Yes ({status})"

            # Динамический таймаут по первым двум успешным запросам
            if i < 2:
                rtt_measurements.append(elapsed)
                if len(rtt_measurements) == 2:
                    base_rtt = max(rtt_measurements)
                    dyn_t = max(base_rtt * 3.0, 1.5)
                    dynamic_timeout = min(dyn_t, config.FAT_READ_TIMEOUT)

            if "close" in resp.headers.get("Connection", "").lower():
                if i == 0:
                    # Сервер не держит keep-alive — нельзя тестировать
                    return alive_str, "[yellow]WARN[/yellow]", "No keep-alive"
                if i < (chunks_count - 1):
                    # Закрыл соединение после того как пошёл мусор — блокировка
                    return alive_str, "[bold red]DETECTED[/bold red]", f"Conn closed at {i*4}KB"

            await asyncio.sleep(0.05)

        except (httpx.ConnectTimeout, httpx.ConnectError) as e:
            if i == 0:
                if "refused" in str(e).lower() or "10061" in str(e):
                    return "No", "[yellow]UNREACHABLE[/yellow]", "Refused"
                return "No", "[yellow]UNREACHABLE[/yellow]", "Connect Err"
            return alive_str, "[bold red]DETECTED[/bold red]", f"Conn Err at {i*4}KB"

        except (httpx.ReadTimeout, httpx.WriteTimeout) as e:
            if i == 0:
                return "No", "[red]ERR[/red]", "Timeout"
            return alive_str, "[bold red]DETECTED[/bold red]", f"Blackhole at {i*4}KB"

        except (httpx.ReadError, httpx.WriteError, httpx.RemoteProtocolError) as e:
            if i == 0:
                return "No", "[red]ERR[/red]", type(e).__name__

            err_str = str(e).lower()
            if "reset" in err_str or "10054" in err_str:
                tag = "TCP RST"
            elif "abort" in err_str or "10053" in err_str:
                tag = "TCP ABORT"
            elif "eof" in err_str or "closed" in err_str:
                tag = "TCP FIN"
            else:
                tag = "Drop"

            return alive_str, "[bold red]DETECTED[/bold red]", f"{tag} at {i*4}KB"

        except Exception as e:
            if i == 0:
                return "No", "[red]ERR[/red]", f"{type(e).__name__}"
            return alive_str, "[red]ERR[/red]", f"{type(e).__name__} at {i*4}KB"

    return alive_str, "[green]OK[/green]", "Passed DPI"


async def check_tcp_16_20(
    ip: str, port: int, sni: Optional[str], semaphore: asyncio.Semaphore
) -> Tuple[str, str, str]:
    async with semaphore:
        verify_ctx = ssl.create_default_context()
        verify_ctx.check_hostname = False
        verify_ctx.verify_mode = ssl.CERT_NONE

        # max_keepalive_connections=1 гарантирует, что httpx будет пытаться
        # переиспользовать один и тот же сокет для всех запросов к одному IP
        limits = httpx.Limits(max_keepalive_connections=1, max_connections=1)

        async with httpx.AsyncClient(verify=verify_ctx, http2=False, limits=limits) as client:
            return await _fat_probe_keepalive(client, ip, port, sni)