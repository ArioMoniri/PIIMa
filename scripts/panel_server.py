#!/usr/bin/env python3
"""Static file server for the browser panel and the no-upload proof page.

WHY THIS IS A FILE AND NOT A HEREDOC IN THE JUSTFILE:
it used to be a heredoc, which was fine while `just serve-panel` was the only
caller. `just up` is a second caller, and a second caller means a second copy of
the bind address. The one property this page exists to demonstrate is that
nothing leaves the machine; a detached copy of the server that drifted to
0.0.0.0 would break that silently and would look identical in `ps`. One file,
one bind, both callers.

I3: the host is a constant here and there is no flag that changes it. Not
"defaults to loopback" -- there is no other value this module can produce.
"""

from __future__ import annotations

import argparse
import functools
import http.server
import sys
from pathlib import Path
from typing import Final

# I3, structurally. Not an argparse default: a default is a thing an operator can
# override, and the whole claim of the panel is that the page cannot be reached
# from another machine.
HOST: Final[str] = "127.0.0.1"
DEFAULT_PORT: Final[int] = 8722


class NoStoreHandler(http.server.SimpleHTTPRequestHandler):
    """Serve with `Cache-Control: no-store`.

    WHY: `http.server` otherwise lets the browser hold a stale copy of the page
    and its wasm glue. Editing the panel and reloading then shows the OLD
    revision with no indication that it is old, which is an afternoon lost to
    debugging a bug that was already fixed on disk.
    """

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Log request lines to stderr, never to stdout.

        The base class writes to stderr already; this override exists to state
        that the format string is the stdlib's request line -- a method, a path
        and a status. The panel is a GET-only static surface: no document text
        is ever in a URL, because the page does its masking in the browser and
        posts nothing. See docs/DEPLOY.md for what this means once `just up`
        starts persisting these lines to a file (I4).
        """
        super().log_message(format, *args)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path.cwd(),
        help=(
            "document root. For the panel this must be bindings/wasm and NOT the "
            "page's own directory: both pages load the module from the sibling "
            "../pkg-web/, which a root at the page directory puts outside the "
            "served tree."
        ),
    )
    parser.add_argument(
        "--page",
        default="",
        help="page path to print in the ready line; purely cosmetic",
    )
    args = parser.parse_args(argv)

    root = args.directory.resolve()
    if not root.is_dir():
        print(f"panel_server: {root} is not a directory", file=sys.stderr)
        return 1

    handler = functools.partial(NoStoreHandler, directory=str(root))
    server = http.server.HTTPServer((HOST, args.port), handler)
    print(
        f"panel_server: serving {root} on http://{HOST}:{args.port}/{args.page}",
        flush=True,
    )
    print(
        "panel_server: loopback only. Nothing pasted into the page leaves this machine.",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
