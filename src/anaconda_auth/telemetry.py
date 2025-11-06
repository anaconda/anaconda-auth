from datetime import datetime
from anaconda_opentelemetry.config import Configuration
from anaconda_opentelemetry.attributes import ResourceAttributes
from anaconda_opentelemetry import initialize_telemetry
from anaconda_opentelemetry.signals import (
    get_telemetry_logger_handler,
    record_histogram,
)

from anaconda_auth.config import AnacondaAuthSite
import logging

from anaconda_cli_base.console import console


def setup_telemetry(cfg: AnacondaAuthSite, version: str) -> None:
    try:
        config = Configuration(
            default_endpoint="example.com:4317",
            config_dict={"default_auth_token": cfg.otel_token},
        ).set_console_exporter(cfg.otel_console_exporter)
        config.set_metrics_export_interval_ms(
            cfg.otel_exporter_interval
        ).set_logging_level(cfg.otel_logging_level)

        attributes = ResourceAttributes(cfg.otel_service_name, version)

        initialize_telemetry(config=config, attributes=attributes)

    except:
        console.print("Otel failed to initialize.")
        pass


def get_telemetry_logger(name: str) -> logging.Logger:
    log = logging.getLogger(name)
    try:
        log.addHandler(get_telemetry_logger_handler())
        return log
    except:
        console.print("Otel logger failed to initialize.")

    return log


def record_command_duration(start: datetime, cmd: str) -> None:
    time_diff = datetime.now() - start
    record_histogram(
        "cmd_duration",
        value=time_diff.total_seconds() * 1000,
        attributes={"cmd": cmd},
    )
