"""
Net Ward -- proxy daemon entrypoint

    python -m netward --config /etc/netward/config.json

Loads operator config, refreshes vendor definitions, then
binds the capture loop and runs until interrupted.
Management commands (install-patterns, list-patterns, etc.) live in
netward/cli.py and are not part of this entrypoint.
"""
import argparse
import asyncio
import signal
import sys

from netward.operator_layer import load_config, validate_storage_permissions
from netward.capture import start_capture_loop


async def _run_until_stopped(config) -> None:
    """Let SIGTERM unwind the capture loop and remove private snapshots."""
    loop = asyncio.get_running_loop()
    task = asyncio.create_task(start_capture_loop(config))
    stopping = False
    installed = False
    previous = signal.getsignal(signal.SIGTERM)

    def stop():
        nonlocal stopping
        if not stopping:
            stopping = True
            task.cancel()

    try:
        try:
            loop.add_signal_handler(signal.SIGTERM, stop)
            installed = True
        except (NotImplementedError, RuntimeError):
            # Platforms without loop signal support retain their OS behavior.
            pass
        try:
            await task
        except asyncio.CancelledError:
            if not stopping:
                raise
    finally:
        if installed:
            loop.remove_signal_handler(signal.SIGTERM)
            signal.signal(signal.SIGTERM, previous)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="netward",
        description="Net Ward passive deception proxy",
        epilog="For pattern management: python -m netward.cli --help (or netward-cli --help)",
    )
    parser.add_argument(
        "--config",
        required=True,
        metavar="PATH",
        help="Operator config JSON (see example_config.json for a template)",
    )
    parser.add_argument(
        "--allow-permissive-db",
        action="store_true",
        help="Allow startup even when the Net Ward DB path is world-writable.",
    )
    args = parser.parse_args()

    try:
        config = load_config(args.config)
        validate_storage_permissions(
            config,
            allow_permissive_db=args.allow_permissive_db,
        )
    except Exception as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        asyncio.run(_run_until_stopped(config))
    except KeyboardInterrupt:
        pass  # clean exit on Ctrl-C / SIGINT


if __name__ == "__main__":
    main()
