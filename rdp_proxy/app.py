from __future__ import annotations

import argparse
import logging
import signal
import socket
import threading
import time
from datetime import datetime

from rdp_proxy.cloud.factory import create_provider
from rdp_proxy.config import load_config
from rdp_proxy.logging_utils import set_access_log_details, setup_logging
from rdp_proxy.notifications import Notifier
from rdp_proxy.proxy import RDPProxyApp


def _state_satisfies_operation(operation: str, state: str) -> bool:
    if operation == "start":
        return state in {"RUNNING", "STARTING"}
    if operation == "stop":
        return state in {"STOPPED", "STOPPING"}
    return False


def _state_blocks_operation(operation: str, state: str) -> bool:
    if operation == "start":
        return state == "STOPPING"
    if operation == "stop":
        return state == "STARTING"
    return False


def _is_non_retryable_auth_error(exc: Exception) -> bool:
    msg = f"{type(exc).__name__}: {exc}".lower()
    keywords = [
        "invalidsecretid",
        "signaturefailure",
        "authfailure",
        "unauthorizedoperation",
        "unauthorized",
        "invalidaccesskeyid",
        "signaturedoesnotmatch",
        "security token included in the request is invalid",
        "access key",
        "ak",
    ]
    return any(k in msg for k in keywords)


def _is_non_retryable_business_error(exc: Exception) -> bool:
    msg = f"{type(exc).__name__}: {exc}".lower()
    keywords = [
        "invalidinstanceid",
        "invalidparameter",
        "resource not found",
        "instance not found",
    ]
    return any(k in msg for k in keywords)


def _run_cloud_action_with_retry_for_self_check(target, provider, operation: str, notifier: Notifier, logger: logging.Logger) -> bool:
    max_retries = 3
    backoff_seconds = [5, 10, 20]
    attempts = 0
    last_exc: Exception | None = None
    wait_reason = ""

    for retry_index in range(max_retries + 1):
        attempts = retry_index + 1

        try:
            state = provider.get_instance_state()
        except Exception as exc:
            state = "UNKNOWN"
            last_exc = exc
            wait_reason = f"state-check-failed: {exc}"

        if _state_satisfies_operation(operation, state):
            notifier.send_cloud_operation_result(
                target=target,
                operation=operation,
                success=True,
                attempts=attempts,
                client_ip="self-check",
            )
            logger.info(
                "Cloud self-check action treated as success by current state target=%s operation=%s state=%s attempts=%s",
                target.name,
                operation,
                state,
                attempts,
            )
            return True

        if _state_blocks_operation(operation, state):
            wait_reason = f"state-blocked:{state}"
            if retry_index >= max_retries:
                break
            backoff = backoff_seconds[min(retry_index, len(backoff_seconds) - 1)]
            logger.warning(
                "Cloud self-check action blocked by transient state target=%s operation=%s state=%s attempt=%s next_retry_in_seconds=%s",
                target.name,
                operation,
                state,
                attempts,
                backoff,
            )
            time.sleep(backoff)
            continue

        try:
            if operation == "start":
                provider.start_instance()
            else:
                provider.stop_instance(target.cloud.stop_mode)

            notifier.send_cloud_operation_result(
                target=target,
                operation=operation,
                success=True,
                attempts=attempts,
                client_ip="self-check",
            )
            logger.info("Cloud self-check %s requested target=%s provider=%s", operation, target.name, target.cloud.provider)
            return True
        except Exception as exc:
            last_exc = exc

            try:
                latest_state = provider.get_instance_state()
            except Exception:
                latest_state = "UNKNOWN"

            if _state_satisfies_operation(operation, latest_state):
                notifier.send_cloud_operation_result(
                    target=target,
                    operation=operation,
                    success=True,
                    attempts=attempts,
                    client_ip="self-check",
                )
                logger.info(
                    "Cloud self-check action treated as success after exception target=%s operation=%s state=%s attempts=%s",
                    target.name,
                    operation,
                    latest_state,
                    attempts,
                )
                return True

            non_retryable = _is_non_retryable_auth_error(exc) or _is_non_retryable_business_error(exc)
            if non_retryable or retry_index >= max_retries:
                break

            backoff = backoff_seconds[min(retry_index, len(backoff_seconds) - 1)]
            logger.warning(
                "Cloud self-check action failed, retrying target=%s operation=%s attempt=%s next_retry_in_seconds=%s error=%s",
                target.name,
                operation,
                attempts,
                backoff,
                exc,
            )
            time.sleep(backoff)

    error_text = str(last_exc) if last_exc else "unknown error"
    if wait_reason:
        error_text = f"{error_text}; {wait_reason}"
    notifier.send_cloud_operation_result(
        target=target,
        operation=operation,
        success=False,
        attempts=attempts,
        error=error_text,
        client_ip="self-check",
    )
    logger.error(
        "Cloud self-check %s failed target=%s provider=%s attempts=%s error=%s",
        operation,
        target.name,
        target.cloud.provider,
        attempts,
        error_text,
    )
    return False


def _assert_bindable(host: str, port: int, name: str) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((host, port))
    except OSError as exc:
        raise RuntimeError(f"Startup aborted: {name} uses {host}:{port} but port is unavailable ({exc})") from exc
    finally:
        probe.close()


def _validate_ports(cfg) -> None:
    used: set[tuple[str, int]] = set()

    control_key = (cfg.server.control_http_bind, cfg.server.control_http_port)
    _assert_bindable(cfg.server.control_http_bind, cfg.server.control_http_port, "control_http")
    used.add(control_key)

    for target in cfg.targets:
        key = (cfg.server.bind, target.listen_port)
        if key in used:
            raise RuntimeError(
                f"Startup aborted: duplicate bind detected on {key[0]}:{key[1]} (control_http/target listen conflict or duplicate target)"
            )
        _assert_bindable(cfg.server.bind, target.listen_port, f"target:{target.name}")
        used.add(key)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="RDP On-Demand Proxy")
    parser.add_argument("--config", default="config.yml", help="Path to config JSON/YAML")
    parser.add_argument("--log-level", default="INFO", help="Log level")
    parser.add_argument(
        "--self-check",
        choices=["notifications", "cloud", "all"],
        help="Run one-time verification and exit",
    )
    parser.add_argument(
        "--cloud-check-operation",
        choices=["status", "start", "stop"],
        default="status",
        help="Cloud check operation when --self-check cloud/all",
    )
    return parser.parse_args()


def _run_self_check(cfg, check_type: str, cloud_op: str) -> int:
    logger = logging.getLogger("rdp_proxy.selfcheck")
    ok = True
    notifier = Notifier(cfg.notifications)

    if check_type in {"notifications", "all"}:
        msg = f"通知自检消息\n时间: {datetime.now().isoformat(sep=' ', timespec='seconds')}"
        results = notifier.send_test_message(msg)
        if not results:
            logger.warning("No notification channel is enabled")
            ok = False
        else:
            logger.info("Notification self-check result: %s", results)
            if not any(results.values()):
                ok = False

    if check_type in {"cloud", "all"}:
        for target in cfg.targets:
            if not target.cloud_control_enabled or target.cloud is None:
                logger.info("Skip cloud check for target=%s (cloud control disabled)", target.name)
                continue

            try:
                provider = create_provider(target.cloud)
                if cloud_op == "status":
                    state = provider.get_instance_state()
                    logger.info("Cloud self-check target=%s provider=%s state=%s", target.name, target.cloud.provider, state)
                elif cloud_op == "start":
                    ok = _run_cloud_action_with_retry_for_self_check(target, provider, "start", notifier, logger) and ok
                elif cloud_op == "stop":
                    ok = _run_cloud_action_with_retry_for_self_check(target, provider, "stop", notifier, logger) and ok
            except Exception as exc:
                logger.error("Cloud self-check failed target=%s error=%s", target.name, exc)
                ok = False

    return 0 if ok else 1


def main() -> None:
    args = parse_args()
    setup_logging(args.log_level)

    logger = logging.getLogger("rdp_proxy.app")

    try:
        cfg = load_config(args.config)
        set_access_log_details(cfg.server.access_log_details)
        if args.self_check is None:
            _validate_ports(cfg)
    except Exception as exc:
        logger.error("%s", exc)
        raise SystemExit(1)

    if args.self_check is not None:
        raise SystemExit(_run_self_check(cfg, args.self_check, args.cloud_check_operation))

    app = RDPProxyApp(cfg)
    stop_event = threading.Event()

    def _signal_handler(signum: int, frame: object) -> None:
        _ = frame
        logger.info("Signal received: %s", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    try:
        app.start()
    except Exception as exc:
        logger.error("Startup aborted: failed to initialize services (%s)", exc)
        raise SystemExit(1)

    try:
        while not stop_event.is_set():
            time.sleep(1)
    finally:
        app.stop()


if __name__ == "__main__":
    main()
