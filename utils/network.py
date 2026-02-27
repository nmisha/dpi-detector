import asyncio
import socket


async def get_resolved_ip(domain: str, family: int = socket.AF_INET) -> str | None:
    """
    Резолвит домен в IP-адрес. До 2 попыток при сбое.
    family: socket.AF_INET для IPv4, socket.AF_INET6 для IPv6.
    Использует системный DNS — если провайдер подменяет системный резолвер,
    но не прямой UDP/53, stub_ips из DNS-теста не совпадут с resolved_ip.
    """
    loop = asyncio.get_running_loop()
    for attempt in range(2):
        try:
            addrs = await loop.getaddrinfo(
                domain, 443, family=family, type=socket.SOCK_STREAM
            )
            if addrs:
                return addrs[0][4][0]
        except Exception:
            if attempt == 0:
                await asyncio.sleep(0.2)
                continue
            break
    return None