import asyncio
import os
import sys
import traceback
import warnings
import httpx
import signal

warnings.filterwarnings("ignore")

try:
    from rich.panel import Panel
except ImportError as e:
    print(f"Ошибка: {e}")
    print("Установите зависимости: python -m pip install -r requirements.txt")
    sys.exit(1)

import config
from cli.console import console
from cli.ui import ask_test_selection, print_legend
from cli.runners import run_domains_test, run_tcp_test
from core.dns_scanner import check_dns_integrity, collect_stub_ips_silently
from utils.files import load_domains, load_tcp_targets, get_exe_dir

CURRENT_VERSION = "1.4"
GITHUB_REPO     = "Runnin4ik/dpi-detector"

DOMAINS         = load_domains()
TCP_16_20_ITEMS = load_tcp_targets()


async def _fetch_latest_version() -> str | None:
    """Запрашивает последний тег с GitHub API. Возвращает строку версии или None."""
    url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url, headers={"Accept": "application/vnd.github+json"})
            if resp.status_code == 200:
                tag = resp.json().get("tag_name", "")
                return tag.lstrip("v") if tag else None
    except Exception:
        pass
    return None


def fast_exit_handler(sig, frame):
    """Принудительный выход по первому Ctrl+C."""
    # Используем системный принт, т.к. rich может быть заблокирован
    sys.stdout.write("\n\033[91m\033[1mПрервано пользователем.\033[0m\n")
    sys.stdout.flush()
    os._exit(0)

async def _readline_cancelable() -> str:
    loop = asyncio.get_running_loop()
    try:
        future = loop.run_in_executor(None, sys.stdin.readline)
        result = await future
        return result.rstrip("\n")
    except asyncio.CancelledError:
        raise KeyboardInterrupt

def _flush_stdin() -> None:
    """Сбрасывает накопившиеся данные в stdin чтобы буферные Enter не перезапускали тест."""
    try:
        import termios
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:
        # Windows и другие окружения — лучшее что можно сделать без блокировки
        try:
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getwch()
        except Exception:
            pass


def _format_summary(
    run_dns: bool, run_domains: bool, run_tcp: bool,
    dns_intercept: int, domain_stats: dict | None, tcp_stats: dict | None,
) -> list[str]:
    lines = []

    if run_dns:
        total_dns = len(config.DNS_CHECK_DOMAINS)
        ok_dns = total_dns - dns_intercept
        if dns_intercept == 0:
            lines.append(
                f"[bold]DNS[/bold]          "
                f"[green]√ {ok_dns}/{total_dns}  не подменяется[/green]"
            )
        elif dns_intercept == total_dns:
            lines.append(
                f"[bold]DNS[/bold]          "
                f"[bold red]× {dns_intercept}/{total_dns}  подменяется провайдером[/bold red]"
            )
        else:
            lines.append(
                f"[bold]DNS[/bold]          "
                f"[green]√ {ok_dns}/{total_dns} OK[/green]"
                f"  [red]× {dns_intercept}/{total_dns} подменяется провайдером[/red]"
            )

    if domain_stats:
        d = domain_stats
        pct = int(d["ok"] / d["total"] * 100) if d["total"] else 0
        line = (
            f"[bold]Домены[/bold]       "
            f"[green]√ {d['ok']}/{d['total']} OK[/green]"
            + (f"  [red]× {d['blocked']} заблок.[/red]" if d['blocked'] else "")
            + (f"  [yellow]⏱ {d['timeout']} таймаут[/yellow]" if d['timeout'] else "")
            + f"  [dim]({pct}%)[/dim]"
        )
        lines.append(line)

    if tcp_stats:
        t = tcp_stats
        pct = int(t["ok"] / t["total"] * 100) if t["total"] else 0
        line = (
            f"[bold]TCP 16-20KB[/bold]   "
            f"[green]√ {t['ok']}/{t['total']} OK[/green]"
            + (f"  [red]× {t['blocked']} блок.[/red]" if t['blocked'] else "")
            + (f"  [yellow]≈ {t['mixed']} смеш.[/yellow]" if t['mixed'] else "")
            + f"  [dim]({pct}%)[/dim]"
        )
        lines.append(line)

    return lines


async def main():
    console.clear()

    # Запрашиваем версию параллельно с выводом шапки
    version_task = asyncio.create_task(_fetch_latest_version())

    latest = await version_task
    version_suffix = ""
    if latest and latest != CURRENT_VERSION:
        version_suffix = f" | [bold yellow]Доступна версия {latest}[/bold yellow]"

    console.print(
        f"[bold cyan]DPI Detector v{CURRENT_VERSION}[/bold cyan]{version_suffix}"
    )
    console.print(
        f"[dim]Параллельных запросов: {config.MAX_CONCURRENT}[/dim]\n"
    )

    selection = await ask_test_selection()
    run_dns     = "1" in selection
    run_domains = "2" in selection
    run_tcp     = "3" in selection

    save_to_file = False
    result_path  = None
    try:
        console.print("\nСохранять результаты в файл? [y/N]: ", end="")
        raw = await _readline_cancelable()
        raw = raw.strip().lower()
    except KeyboardInterrupt:
        raise

    if raw in ("y", "yes", "д", "да"):
        save_to_file = True
        result_path = os.path.join(get_exe_dir(), "dpi_detector_results.txt")

    semaphore = asyncio.Semaphore(config.MAX_CONCURRENT)
    first_run = True

    while True:
        # ── DNS ───────────────────────────────────────────────────────────────
        stub_ips: set = set()
        dns_intercept_count = 0

        if run_dns and config.DNS_CHECK_ENABLED:
            stub_ips, dns_intercept_count = await check_dns_integrity()
        elif config.DNS_CHECK_ENABLED and (run_domains or run_tcp):
            stub_ips = await collect_stub_ips_silently()

        # ── Домены ────────────────────────────────────────────────────────────
        domain_stats = None
        if run_domains:
            domain_stats = await run_domains_test(semaphore, stub_ips, DOMAINS)

        # ── TCP 16-20KB ───────────────────────────────────────────────────────
        tcp_stats = None
        if run_tcp:
            tcp_stats = await run_tcp_test(semaphore, TCP_16_20_ITEMS)

        # ── Итоговая сводка ───────────────────────────────────────────────────
        active_tests = sum([run_dns, run_domains, run_tcp])
        if active_tests >= 2:
            console.print()
            summary_lines = _format_summary(
                run_dns, run_domains, run_tcp,
                dns_intercept_count, domain_stats, tcp_stats,
            )
            console.print(Panel(
                "\n".join(summary_lines),
                title="[bold]Итог[/bold]",
                border_style="cyan",
                padding=(0, 1),
                expand=False,
            ))

        if first_run:
            print_legend()
            first_run = False

        console.print("\n[bold green]Проверка завершена.[/bold green]")

        if save_to_file and result_path:
            try:
                with open(result_path, "w", encoding="utf-8") as f:
                    f.write(console.export_text())
                console.print(f"[dim]Результаты сохранены: [cyan]{result_path}[/cyan][/dim]")
            except Exception as e:
                console.print(f"[yellow]Не удалось сохранить файл: {e}[/yellow]")

        # ── Предложение повторить ─────────────────────────────────────────────
        console.print(
            "\nНажмите [bold green]Enter[/bold green] чтобы повторить проверку  "
            "или [bold red]Ctrl+C[/bold red] для выхода"
        )
        _flush_stdin()  # сбрасываем накопившиеся Enter чтобы не было авто-перезапуска
        try:
            await _readline_cancelable()
        except KeyboardInterrupt:
            raise
        console.print()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, fast_exit_handler)

    try:
        asyncio.run(main())
    except Exception as e:
        console.print(f"\n[bold red]Критическая ошибка:[/bold red] {e}")
        traceback.print_exc()
        if sys.platform == 'win32':
            print("\nНажмите Enter для выхода...")
            input()
        os._exit(1)