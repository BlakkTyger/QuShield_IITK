"""
QuShield Logging Configuration

Comprehensive logging for all workflow stages with:
- Console output with colors and layer indicators
- File logging with rotation
- Structured JSON logging for analysis
- Performance timing decorators
- Process tracking and stage logging
- Real-time operation monitoring
"""

import logging
import logging.handlers
import json
import time
import functools
import threading
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Callable
from contextlib import contextmanager


# Log directory
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Process tracking
_current_process = threading.local()


def set_current_process(process_name: str, layer: int = None):
    """Set the current process name for logging context"""
    _current_process.name = process_name
    _current_process.layer = layer
    _current_process.start_time = time.perf_counter()


def get_current_process() -> tuple:
    """Get the current process name and layer"""
    return (
        getattr(_current_process, 'name', None),
        getattr(_current_process, 'layer', None),
        getattr(_current_process, 'start_time', None),
    )


@contextmanager
def process_context(process_name: str, layer: int = None, logger: logging.Logger = None):
    """Context manager for tracking process execution"""
    set_current_process(process_name, layer)
    start = time.perf_counter()
    
    if logger:
        logger.info(f"▶ Starting: {process_name}", extra={"layer": layer})
    
    try:
        yield
    finally:
        duration = (time.perf_counter() - start) * 1000
        if logger:
            logger.info(f"✓ Completed: {process_name}", extra={
                "layer": layer,
                "duration_ms": duration,
            })
        set_current_process(None, None)


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "process_id": os.getpid(),
            "thread_id": threading.current_thread().ident,
        }
        
        # Add current process context
        proc_name, proc_layer, proc_start = get_current_process()
        if proc_name:
            log_obj["current_process"] = proc_name
        if proc_layer:
            log_obj["process_layer"] = proc_layer
        
        # Add extra fields if present
        if hasattr(record, "data"):
            log_obj["data"] = record.data
        if hasattr(record, "duration_ms"):
            log_obj["duration_ms"] = record.duration_ms
        if hasattr(record, "target"):
            log_obj["target"] = record.target
        if hasattr(record, "layer"):
            log_obj["layer"] = record.layer
        if hasattr(record, "stage"):
            log_obj["stage"] = record.stage
        if hasattr(record, "operation"):
            log_obj["operation"] = record.operation
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_obj)


class ColoredFormatter(logging.Formatter):
    """Colored console formatter"""
    
    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        
        # Format timestamp
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Build message
        level = f"{color}{record.levelname:8}{self.RESET}"
        name = f"\033[90m{record.name:20}\033[0m"
        msg = record.getMessage()
        
        # Add layer indicator if present
        layer = ""
        if hasattr(record, "layer"):
            layer_colors = {
                1: "\033[94m[L1:DISCOVERY]\033[0m ",
                2: "\033[93m[L2:SCANNER]\033[0m ",
                3: "\033[92m[L3:ANALYSIS]\033[0m ",
                4: "\033[95m[L4:CERTIFY]\033[0m ",
            }
            layer = layer_colors.get(record.layer, "")
        
        formatted = f"{timestamp} {level} {name} {layer}{msg}"
        
        # Add data if present
        if hasattr(record, "data") and record.data:
            formatted += f"\n  └─ {json.dumps(record.data, indent=2)}"
        
        # Add duration if present
        if hasattr(record, "duration_ms"):
            formatted += f" \033[90m({record.duration_ms:.0f}ms)\033[0m"
        
        return formatted


def setup_logging(
    level: int = logging.INFO,
    console: bool = True,
    file: bool = True,
    json_file: bool = True,
) -> logging.Logger:
    """
    Setup logging for QuShield.
    
    Args:
        level: Logging level
        console: Enable console output
        file: Enable file logging
        json_file: Enable JSON structured logging
        
    Returns:
        Root logger for QuShield
    """
    # Create logger
    logger = logging.getLogger("qushield")
    logger.setLevel(level)
    logger.handlers = []  # Clear existing handlers
    
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(ColoredFormatter())
        logger.addHandler(console_handler)
    
    if file:
        file_handler = logging.handlers.RotatingFileHandler(
            LOG_DIR / "qushield.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        ))
        logger.addHandler(file_handler)
    
    if json_file:
        json_handler = logging.handlers.RotatingFileHandler(
            LOG_DIR / "qushield.json",
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
        )
        json_handler.setLevel(level)
        json_handler.setFormatter(JSONFormatter())
        logger.addHandler(json_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger for a specific module"""
    return logging.getLogger(f"qushield.{name}")


def log_with_data(
    logger: logging.Logger,
    level: int,
    message: str,
    data: Optional[Dict[str, Any]] = None,
    layer: Optional[int] = None,
    target: Optional[str] = None,
    duration_ms: Optional[float] = None,
):
    """Log a message with structured data"""
    extra = {}
    if data:
        extra["data"] = data
    if layer:
        extra["layer"] = layer
    if target:
        extra["target"] = target
    if duration_ms is not None:
        extra["duration_ms"] = duration_ms
    
    logger.log(level, message, extra=extra)


def timed(logger: Optional[logging.Logger] = None, layer: Optional[int] = None):
    """
    Decorator to time function execution and log it.
    
    Usage:
        @timed(logger=my_logger, layer=2)
        def scan_target(target):
            ...
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = get_logger(func.__module__)
            
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                duration = (time.perf_counter() - start) * 1000
                
                extra = {"duration_ms": duration}
                if layer:
                    extra["layer"] = layer
                
                logger.info(
                    f"{func.__name__} completed",
                    extra=extra,
                )
                return result
            except Exception as e:
                duration = (time.perf_counter() - start) * 1000
                extra = {"duration_ms": duration}
                if layer:
                    extra["layer"] = layer
                
                logger.error(
                    f"{func.__name__} failed: {e}",
                    extra=extra,
                    exc_info=True,
                )
                raise
        
        return wrapper
    return decorator


def timed_async(logger: Optional[logging.Logger] = None, layer: Optional[int] = None):
    """Async version of timed decorator"""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = get_logger(func.__module__)
            
            start = time.perf_counter()
            try:
                result = await func(*args, **kwargs)
                duration = (time.perf_counter() - start) * 1000
                
                extra = {"duration_ms": duration}
                if layer:
                    extra["layer"] = layer
                
                logger.info(
                    f"{func.__name__} completed",
                    extra=extra,
                )
                return result
            except Exception as e:
                duration = (time.perf_counter() - start) * 1000
                extra = {"duration_ms": duration}
                if layer:
                    extra["layer"] = layer
                
                logger.error(
                    f"{func.__name__} failed: {e}",
                    extra=extra,
                    exc_info=True,
                )
                raise
        
        return wrapper
    return decorator


# Initialize default logger
_root_logger = setup_logging()


# Layer-specific loggers
discovery_logger = get_logger("discovery")
scanner_logger = get_logger("scanner")
analysis_logger = get_logger("analysis")
certify_logger = get_logger("certify")
workflow_logger = get_logger("workflow")
