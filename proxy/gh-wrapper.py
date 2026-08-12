#!/usr/bin/env python3
"""Guest-side `gh` wrapper for the Devbox GitHub credential proxy.

The real GitHub CLI still runs inside the VM, preserving its TTY, stdin, file
uploads, and working-tree behaviour. This wrapper only gives that one process a
GitHub-only HTTPS proxy plus a non-secret routing marker. The host proxy swaps
the marker for the host's `gh auth login` token after terminating TLS for the
GitHub API endpoints.
"""
import os
import sys


def real_gh() -> str | None:
    """Find the golden's gh binary without recursing back into this wrapper."""
    wrapper = os.path.realpath(__file__)
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory or ".", "gh")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            if os.path.realpath(candidate) != wrapper:
                return candidate
    return None


def main() -> None:
    arguments = sys.argv[1:]
    if arguments[:1] == ["auth"] and arguments[1:2] not in (["status"], ["--help"], ["-h"]):
        print(
            "devbox --proxy uses the host GitHub CLI login; run `gh auth login` on the host instead",
            file=sys.stderr,
        )
        raise SystemExit(2)

    executable = real_gh()
    if executable is None:
        print(
            "devbox GitHub proxy could not find the golden's gh executable; "
            "run `devbox build --force` and recreate this box",
            file=sys.stderr,
        )
        raise SystemExit(127)

    proxy_url = os.environ.get("DEVBOX_GH_PROXY_URL", "")
    certificate_dir = os.environ.get("DEVBOX_GH_PROXY_CERT_DIR", "")
    if not proxy_url or not certificate_dir:
        # A manually created box may retain the wrapper after --no-auth. Keep
        # the normal CLI usable in that case rather than failing unexpectedly.
        os.execv(executable, [executable, *arguments])

    environment = dict(os.environ)
    environment.update(
        {
            "GH_TOKEN": "devbox-proxy",
            "GITHUB_TOKEN": "devbox-proxy",
            "HTTPS_PROXY": proxy_url,
            "https_proxy": proxy_url,
            "HTTP_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "ALL_PROXY": proxy_url,
            "all_proxy": proxy_url,
        }
    )
    environment.pop("NO_PROXY", None)
    environment.pop("no_proxy", None)
    environment.pop("SSL_CERT_FILE", None)
    # Go keeps its normal system certificate-file bundle when only SSL_CERT_DIR
    # is set, then adds the Devbox CA directory. That lets release-asset URLs
    # use their public certificates while api.github.com trusts the local leaf.
    previous_dirs = environment.get("SSL_CERT_DIR", "")
    environment["SSL_CERT_DIR"] = certificate_dir + (
        os.pathsep + previous_dirs if previous_dirs else ""
    )
    os.execvpe(executable, [executable, *arguments], environment)


if __name__ == "__main__":
    main()
