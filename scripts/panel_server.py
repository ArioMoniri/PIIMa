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

    # -----------------------------------------------------------------------
    # Logging (I4)
    #
    # The stdlib's logger writes `self.requestline` verbatim -- method, FULL
    # path including the query string, and protocol -- and its error path
    # interpolates the raw request line into messages like
    # `Bad request version ('...')`. Streamed to a terminal that was survivable.
    # `just up` PERSISTS this output to logs/panel.log, and a file on a machine
    # that processes clinical text is a different object from a scrollback
    # buffer.
    #
    # Nothing in the panel's own operation puts document text in a URL: it masks
    # in the browser and posts nothing, so every legitimate request is a GET for
    # a static asset out of this repository. But "our UI would never send that"
    # is a claim about a client, and the log is written by the server. So the
    # rule below is the one bindings/service/src/http.rs already applies to
    # deid-serve: the query string is discarded, and a path is only written down
    # when it MATCHED something -- an unmatched request logs `<unmatched>` and
    # the bytes it asked for are never recorded.
    # -----------------------------------------------------------------------

    def _safe_path(self, code: int) -> str:
        """The request path, or `<unmatched>` when it did not resolve."""
        if not 200 <= code < 400:
            return "<unmatched>"
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        # A matched path is a filename from this repository's own tree, so it is
        # a closed vocabulary in practice. The length cap is belt-and-braces
        # against a matched-but-absurd path.
        return path[:200]

    def log_request(self, code: object = "-", size: object = "-") -> None:
        status = code.value if hasattr(code, "value") else code
        try:
            status_int = int(status)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            status_int = 0
        method = self.command if self.command in {"GET", "HEAD", "POST"} else "OTHER"
        self.log_message(
            "%s %s %s", method, self._safe_path(status_int), str(status_int)
        )

    def log_error(self, format: str, *args: object) -> None:
        """Report that an error happened, never what was sent.

        The base implementation interpolates attacker-supplied bytes -- a
        malformed request version is echoed back into the message. The count is
        the diagnostic; the payload is not.
        """
        self.log_message("request rejected before routing")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Write one diagnostic line to stderr.

        stderr, not stdout, so that redirecting one stream never captures the
        other -- the same split `deid-serve` keeps.
        """
        sys.stderr.write(
            "panel_server: %s - %s\n"
            % (self.log_date_time_string(), format % args if args else format)
        )
        sys.stderr.flush()


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
