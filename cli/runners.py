import re
import socket
import asyncio

import httpx
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

import config
from cli.console import console
from cli.ui import clean_hostname, build_domain_row
from core.tls_scanner import check_domain_tls, check_http_injection, create_dpi_client
from core.tcp16_scanner import check_tcp_16_20
from utils.network import get_resolved_ip


# ── Воркеры ──────────────────────────────────────────────────────────────────

async def _resolve_worker(domain_raw: str, semaphore: asyncio.Semaphore, stub_ips: set) -> dict:
    """
    Фаза 0: DNS-резолв (IPv4).
    dns_fake: False = чисто, True = заглушка, None = DNS FAIL.

    Замечание по stub_ips: stub_ips собирается через прямой UDP к публичным серверам.
    Если провайдер подменяет только системный резолвер (DoH/DoT на уровне ОС),
    а прямой UDP честный — stub_ips будет пустой и подмена здесь не обнаружится.
    Для полной картины смотри результаты DNS-теста (тест 1).
    """
    domain = clean_hostname(domain_raw)

    async with semaphore:
        resolved_ipv4 = await get_resolved_ip(domain, family=socket.AF_INET)

    entry = {
        "domain":       domain,
        "resolved_ipv4": resolved_ipv4,
        "dns_fake":     False,
        "t13v4_res":    ("[dim]—[/dim]", "", 0.0),
        "t12_res":      ("[dim]—[/dim]", "", 0.0),
        "http_res":     ("[dim]—[/dim]", ""),
    }

    if resolved_ipv4 is None:
        fail = "[yellow]DNS FAIL[/yellow]"
        entry["t13v4_res"] = (fail, "Домен не найден", 0.0)
        entry["t12_res"]   = (fail, "Домен не найден", 0.0)
        entry["http_res"]  = (fail, "Домен не найден")
        entry["dns_fake"]  = None
        return entry

    if stub_ips and resolved_ipv4 in stub_ips:
        fake = "[bold red]DNS FAKE[/bold red]"
        detail = f"DNS подмена -> {resolved_ipv4}"
        entry["t13v4_res"] = (fake, detail, 0.0)
        entry["t12_res"]   = (fake, detail, 0.0)
        entry["http_res"]  = (fake, detail)
        entry["dns_fake"]  = True

    return entry


async def _tls_worker(
    entry: dict,
    client: httpx.AsyncClient,
    tls_key: str,
    semaphore: asyncio.Semaphore,
) -> None:
    """Фаза TLS: пишет результат в entry in-place."""
    if entry["dns_fake"] is not False:
        return
    try:
        result = await check_domain_tls(entry["domain"], client, semaphore)
    except Exception:
        result = ("[dim]ERR[/dim]", "Unknown error", 0.0)
    entry[tls_key] = result


async def _http_worker(
    entry: dict,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> None:
    """Фаза HTTP: пишет результат в entry in-place."""
    if entry["dns_fake"] is not False:
        return
    async with semaphore:
        try:
            result = await check_http_injection(entry["domain"], client, semaphore)
        except Exception:
            result = ("[dim]ERR[/dim]", "Unknown error")
    entry["http_res"] = result


async def _tcp16_worker(item: dict, semaphore: asyncio.Semaphore) -> list:
    ip   = item["ip"]
    port = int(item.get("port", 443))
    sni  = None if port == 80 else (item.get("sni") or config.FAT_DEFAULT_SNI)

    alive_str, status, detail = await check_tcp_16_20(ip, port, sni, semaphore)

    asn_raw = str(item.get("asn", "")).strip()
    asn_str = (
        f"AS{asn_raw}"
        if asn_raw and not asn_raw.upper().startswith("AS")
        else asn_raw.upper()
    ) or "-"

    return [item["id"], asn_str, item["provider"], alive_str, status, detail]


# ── Хелпер прогресс-бара ─────────────────────────────────────────────────────

async def _run_with_progress(tasks: list, description: str) -> list:
    results = []
    total = len(tasks)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task_id = progress.add_task(description, total=total)
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            done = len(results)
            progress.update(task_id, completed=done, description=f"{description} ({done}/{total})...")
    return results


async def _run_phase_with_progress(tasks: list, description: str) -> None:
    total = len(tasks)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task_id = progress.add_task(description, total=total)
        completed = 0
        for future in asyncio.as_completed(tasks):
            await future
            completed += 1
            progress.update(task_id, completed=completed, description=f"{description} ({completed}/{total})...")


# ── Тест 2: домены ────────────────────────────────────────────────────────────

async def run_domains_test(semaphore: asyncio.Semaphore, stub_ips: set, domains: list) -> dict:
    """Тест 2: TLS1.3 IPv4 → TLS1.2 → HTTP injection."""
    console.print(
        f"\n[bold]Проверка доступности доменов[/bold]  "
        f"[dim]Целей: {len(domains)} | timeout: {config.TIMEOUT}s[/dim]\n"
    )

    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("Домен",   style="cyan", no_wrap=True, width=18)
    table.add_column("HTTP",    justify="center")
    table.add_column("TLS1.2",  justify="center")
    table.add_column("TLS1.3",  justify="center")
    table.add_column("Детали",  style="dim", no_wrap=True)

    # Фаза 0: DNS-резолв
    entries = await _run_with_progress(
        [_resolve_worker(d, semaphore, stub_ips) for d in domains],
        "Фаза 0/3: DNS-резолв..."
    )

    client_t13 = create_dpi_client("TLSv1.3")
    client_t12 = create_dpi_client("TLSv1.2")
    client_http = create_dpi_client()

    try:
        await _run_phase_with_progress(
            [_tls_worker(e, client_t13, "t13v4_res", semaphore) for e in entries],
            "Фаза 1/3: TLS 1.3..."
        )
        await _run_phase_with_progress(
            [_tls_worker(e, client_t12, "t12_res", semaphore) for e in entries],
            "Фаза 2/3: TLS 1.2..."
        )
        await _run_phase_with_progress(
            [_http_worker(e, client_http, semaphore) for e in entries],
            "Фаза 3/3: HTTP..."
        )
    finally:
        await client_t13.aclose()
        await client_t12.aclose()
        await client_http.aclose()

    rows = sorted([build_domain_row(e) for e in entries], key=lambda x: x[0])

    dns_fail_count = 0
    resolved_ips_counter: dict = {}
    for r in rows:
        resolved_ip = r[5] if len(r) > 5 else None
        if resolved_ip and stub_ips and resolved_ip in stub_ips:
            resolved_ips_counter[resolved_ip] = resolved_ips_counter.get(resolved_ip, 0) + 1
        if any("DNS FAIL" in r[col] for col in (1, 2, 3)):
            dns_fail_count += 1

    for r in rows:
        table.add_row(*r[:5])
    console.print(table)

    confirmed_stubs = {ip: c for ip, c in resolved_ips_counter.items() if stub_ips and ip in stub_ips}
    if confirmed_stubs or dns_fail_count > 0:
        console.print(f"\n[bold yellow][i] ВОЗМОЖНО НЕ НАСТРОЕН DoH:[/bold yellow]")
        if confirmed_stubs:
            ips_text = [f"[red]{ip}[/red] у {c} домен(ов)" for ip, c in confirmed_stubs.items()]
            console.print(f"DNS вернул IP заглушки: {', '.join(ips_text)}")
        if dns_fail_count > 0:
            console.print(f"У {dns_fail_count} сайтов обнаружен DNS FAIL (Домен не найден)")
        console.print("[yellow]Рекомендация: Настройте DoH/DoT на вашем устройстве, роутере или VPN[/yellow]\n")

    block_markers = ("TLS DPI", "TLS MITM", "TLS BLOCK", "ISP PAGE", "BLOCKED", "TCP RST", "TCP ABORT")
    return {
        "total":    len(domains),
        "ok":       sum(1 for r in rows if "OK" in r[3] or "OK" in r[2]),
        "blocked":  sum(1 for r in rows if any(m in r[c] for c in (1,2,3) for m in block_markers)),
        "timeout":  sum(1 for r in rows if "TIMEOUT" in r[3] or "TIMEOUT" in r[2]),
        "dns_fail": sum(1 for r in rows if "DNS FAIL" in r[3]),
    }


# ── Тест 3: TCP 16-20KB ───────────────────────────────────────────────────────

async def run_tcp_test(semaphore: asyncio.Semaphore, tcp_items: list) -> dict:
    """Тест 3: FAT-header TCP блокировка."""
    console.print(
        f"\n[bold]Проверка TCP 16-20KB блокировки[/bold]  "
        f"[dim]Целей: {len(tcp_items)} | timeout: {config.FAT_CONNECT_TIMEOUT}s[/dim]"
    )

    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("ID",        style="white")
    table.add_column("ASN",       style="yellow")
    table.add_column("Провайдер", style="cyan")
    table.add_column("Alive",     justify="center")
    table.add_column("Статус",    justify="center")
    table.add_column("Детали",    style="dim")

    tcp_results = await _run_with_progress(
        [_tcp16_worker(item, semaphore) for item in tcp_items],
        "Проверка..."
    )

    def _provider_group(provider_str: str) -> str:
        clean = re.sub(r'[^\w\s\.-]', '', provider_str).strip()
        parts = clean.split()
        return parts[0] if parts else clean

    provider_counts: dict = {}
    for row in tcp_results:
        group = _provider_group(row[2])
        provider_counts[group] = provider_counts.get(group, 0) + 1

    def _sort_key(row):
        group = _provider_group(row[2])
        try:
            id_num = int(row[0].split('-')[-1])
        except (ValueError, IndexError):
            id_num = 99999
        return (-provider_counts.get(group, 0), group, id_num)

    tcp_results.sort(key=_sort_key)

    passed  = sum(1 for r in tcp_results if "OK"       in r[4])
    blocked = sum(1 for r in tcp_results if "DETECTED" in r[4])
    mixed   = sum(1 for r in tcp_results if "MIXED"    in r[4])

    for r in tcp_results:
        table.add_row(*r[:6])
    console.print(table)

    if mixed > 0:
        console.print("[dim]Смешанные результаты указывают на балансировку DPI у провайдера[/dim]")

    return {"total": len(tcp_items), "ok": passed, "blocked": blocked, "mixed": mixed}

# ── Тест 4: Поиск белых SNI для ASN ──────────────────────────────────────────

async def run_whitelist_sni_test(semaphore: asyncio.Semaphore, tcp_items: list, whitelist_sni: list) -> None:
    """Тест 4: Поиск белых SNI для ASN.

    Алгоритм:
      1. Для каждой AS берём один IP с портом 443.
      2. Запускаем стандартный TCP 16-20KB тест с дефолтным SNI.
      3. Для тех AS где DETECTED — перебираем SNI из whitelist_sni.txt до первого OK.
      4. Выводим таблицу: ASN | Провайдер | Alive | WL SNI | Найденный SNI / статус.
    """
    # Фильтрация: только порт 443, по одному IP на AS
    seen_asn: set = set()
    candidates = []
    for item in tcp_items:
        port = int(item.get("port", 443))
        if port != 443:
            continue
        asn_raw = str(item.get("asn", "")).strip()
        asn_key = asn_raw.upper().lstrip("AS") if asn_raw else item["ip"]
        if asn_key in seen_asn:
            continue
        seen_asn.add(asn_key)
        candidates.append(item)

    if not candidates:
        console.print("[yellow]Нет целей с портом 443 для теста белых SNI.[/yellow]")
        return

    console.print(
        f"\n[bold]Поиск белых SNI для ASN[/bold]  "
        f"[dim]AS: {len(candidates)} | SNI в списке: {len(whitelist_sni)} | timeout: {config.FAT_CONNECT_TIMEOUT}s[/dim]"
    )

    # Фаза 1: базовый тест с дефолтным SNI
    base_results = await _run_with_progress(
        [_tcp16_worker(item, semaphore) for item in candidates],
        "Фаза 1/2: Базовая проверка...",
    )
    # base_results[i] = [id, asn_str, provider, alive_str, status, detail]

    # Фаза 2: для DETECTED ищем белый SNI
    detected_indices = [
        i for i, r in enumerate(base_results) if "DETECTED" in r[4]
    ]

    # sni_result[i] = (wl_status_str, found_sni)
    sni_result: dict = {}

    async def _probe_sni(idx: int, item: dict) -> None:
        ip = item["ip"]
        for sni_candidate in whitelist_sni:
            sni_candidate = sni_candidate.strip()
            if not sni_candidate:
                continue
            # Используем внутренний семафор на 1, внешний semaphore уже захвачен в check_tcp_16_20
            _alive, status_s, _detail = await check_tcp_16_20(ip, 443, sni_candidate, semaphore)
            if "OK" in status_s:
                sni_result[idx] = ("[green]OK[/green]", sni_candidate)
                return
        sni_result[idx] = ("[red]НЕ НАЙДЕН[/red]", "")

    if detected_indices:
        total = len(detected_indices)
        probe_tasks = [_probe_sni(i, candidates[i]) for i in detected_indices]
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            task_id = progress.add_task(f"Фаза 2/2: Перебор SNI...", total=total)
            done_count = 0
            for future in asyncio.as_completed(probe_tasks):
                await future
                done_count += 1
                progress.update(task_id, completed=done_count,
                                description=f"Фаза 2/2: Перебор SNI... ({done_count}/{total})")

    # Вывод итоговой таблицы
    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("ASN",       style="yellow")
    table.add_column("Провайдер", style="cyan")
    table.add_column("Alive",     justify="center")
    table.add_column("WL SNI",    justify="center")
    table.add_column("Детали",    style="dim", no_wrap=True)

    found_count = 0
    for i, (item, base_row) in enumerate(zip(candidates, base_results)):
        asn_str     = base_row[1]
        provider    = base_row[2]
        alive_str   = base_row[3]
        base_status = base_row[4]
        base_detail = base_row[5]

        if "DETECTED" in base_status and i in sni_result:
            wl_status, found_sni = sni_result[i]
            if found_sni:
                detail_str = found_sni
                found_count += 1
            else:
                detail_str = base_detail
        elif "OK" in base_status:
            wl_status  = "[dim]—[/dim]"
            detail_str = "[dim]Не заблокирован[/dim]"
        else:
            wl_status  = "[dim]—[/dim]"
            detail_str = base_detail

        table.add_row(asn_str, provider, alive_str, wl_status, detail_str)

    console.print(table)

    if found_count > 0:
        console.print(
            f"[green]Найдено белых SNI: {found_count} из {len(detected_indices)} заблокированных AS[/green]"
        )
    elif detected_indices:
        console.print(
            f"[yellow]Белые SNI не найдены ни для одной из {len(detected_indices)} заблокированных AS[/yellow]"
        )