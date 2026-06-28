"""Windows Event Log collector.

Reads Windows Application and System event logs around the crash time.
Requires running with appropriate permissions.
"""

import re
from datetime import datetime, timedelta
from pathlib import Path

from ..context import AnalysisContext, SystemEventInfo
from .base import BaseCollector


class EventLogCollector(BaseCollector):
    """Collect Windows Event Log entries near crash time."""

    name = "eventlog_collector"

    WINDOW_MINUTES = 5

    # Event IDs of interest
    INTERESTING_APP_EVENTS = {1000, 1001, 1002, 1026}  # Application Error/Hang/Crash
    INTERESTING_SYS_EVENTS = {41, 1001, 2001, 6008}    # Kernel/Driver/Shutdown

    def is_applicable(self, ctx: AnalysisContext) -> bool:
        """Only applicable on Windows with explicit --system-logs flag.
        We check for --system-logs via a flag set on the context.
        """
        # This is set by CLI when --system-logs is passed
        return getattr(ctx, "_collect_system_logs", False)

    def collect(self, ctx: AnalysisContext) -> AnalysisContext:
        info = SystemEventInfo()
        crash_time = self._get_crash_time(ctx)

        if not crash_time:
            print(f"  [{self.name}] 无法确定崩溃时间，跳过")
            ctx.system_events = info
            return ctx

        print(f"  [{self.name}] 采集 Windows 事件日志 (崩溃时间: {crash_time})")

        try:
            import win32evtlog
        except ImportError:
            print(f"  [{self.name}] pywin32 未安装，跳过事件日志采集")
            ctx.system_events = info
            return ctx

        start = crash_time - timedelta(minutes=self.WINDOW_MINUTES)
        end = crash_time + timedelta(minutes=self.WINDOW_MINUTES + 5)

        info.application_events = self._read_log(
            win32evtlog, "Application", start, end
        )
        info.system_events = self._read_log(
            win32evtlog, "System", start, end
        )

        ctx.system_events = info
        total = len(info.application_events) + len(info.system_events)
        print(f"  [{self.name}] 采集 {total} 条相关事件")
        return ctx

    # ------------------------------------------------------------------

    def _get_crash_time(self, ctx: AnalysisContext) -> datetime | None:
        ts = ctx.dmp.metadata.timestamp
        if not ts:
            return None
        for fmt in [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%a %b %d %H:%M:%S.%f %Y",
            "%a %b %d %H:%M:%S %Y",
        ]:
            try:
                return datetime.strptime(ts[:26].strip(), fmt)
            except ValueError:
                continue
        m = re.search(
            r"(\d{4})[-/](\d{2})[-/](\d{2})\s+(\d{2}):(\d{2}):(\d{2})", ts
        )
        if m:
            return datetime(*map(int, m.groups()))
        return None

    def _read_log(
        self, evtlog, log_name: str, start: datetime, end: datetime
    ) -> list[dict]:
        """Read Windows event log entries in time window."""
        events = []
        try:
            handle = evtlog.OpenEventLog(None, log_name)
        except Exception:
            return events

        try:
            flags = evtlog.EVENTLOG_FORWARDS_READ | evtlog.EVENTLOG_SEQUENTIAL_READ
            total_read = 0

            while total_read < 5000:  # safety limit
                records = evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                for record in records:
                    total_read += 1
                    try:
                        event_time = datetime.fromtimestamp(
                            record.TimeGenerated.timestamp()
                        )
                    except Exception:
                        continue

                    if start <= event_time <= end:
                        events.append({
                            "time": event_time.isoformat(),
                            "source": record.SourceName or "",
                            "event_id": record.EventID,
                            "category": record.EventCategory or 0,
                            "message": (
                                str(record.StringInserts)[:500]
                                if record.StringInserts
                                else ""
                            ),
                        })
        finally:
            evtlog.CloseEventLog(handle)

        return events[:50]
