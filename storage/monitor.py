#!/usr/bin/env python3
"""
Storage Monitor
===============
Monitor storage usage and trigger cleanup when necessary.
"""

import os
import sys
import time
import logging
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from storage import StorageManager, CacheManager
from database.connection import get_db_connection

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class StorageMonitor:
    """Monitors storage and triggers cleanup actions."""

    def __init__(self):
        """Initialize storage monitor."""
        self.storage_manager = StorageManager()
        self.cache_manager = CacheManager()
        self.alert_sent = False

    def check_and_alert(self) -> None:
        """Check storage and send alerts if necessary."""
        status = self.storage_manager.check_disk_space()

        if status["status"] == "critical":
            self.handle_critical_space(status)
        elif status["status"] == "warning":
            self.handle_warning_space(status)
        else:
            if self.alert_sent:
                logger.info("Disk space returned to normal")
                self.alert_sent = False

    def handle_critical_space(self, status: dict) -> None:
        """
        Handle critical disk space situation.

        Args:
            status: Disk space status dictionary
        """
        logger.critical(f"Critical disk space: {status['percent_used']:.1f}% used")

        # Perform emergency cleanup
        cleanup_result = self.storage_manager.emergency_cleanup()
        logger.info(f"Emergency cleanup freed {cleanup_result['total_freed_mb']} MB")

        # Send alert to database
        try:
            self.log_alert_to_db("critical", status, cleanup_result)
        except Exception as e:
            logger.error(f"Failed to log alert to database: {e}")

        self.alert_sent = True

        # Check if cleanup helped
        new_status = self.storage_manager.check_disk_space()
        if new_status["percent_used"] > 85:
            logger.critical("Emergency cleanup insufficient, manual intervention required")

    def handle_warning_space(self, status: dict) -> None:
        """
        Handle warning disk space situation.

        Args:
            status: Disk space status dictionary
        """
        logger.warning(f"Warning disk space: {status['percent_used']:.1f}% used")

        # Perform standard cleanup
        cache_result = self.cache_manager.cleanup_old_files(days=3)
        archive_result = self.storage_manager.cleanup_archives(days=14)

        logger.info(f"Cleanup freed {cache_result['total_mb']} MB from cache")

        # Send alert to database
        try:
            self.log_alert_to_db("warning", status, {
                "cache_cleanup": cache_result,
                "archive_cleanup": archive_result
            })
        except Exception as e:
            logger.error(f"Failed to log alert to database: {e}")

        self.alert_sent = True

    def log_alert_to_db(self, level: str, status: dict, cleanup: dict) -> None:
        """
        Log storage alert to database.

        Args:
            level: Alert level (warning, critical)
            status: Disk space status
            cleanup: Cleanup results
        """
        conn = get_db_connection()
        if not conn:
            return

        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit.audit_log
                (event_type, event_timestamp, resource_type, action, details, risk_score)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                f"storage_{level}",
                datetime.now(),
                "storage",
                "cleanup",
                {
                    "status": status,
                    "cleanup": cleanup
                },
                90 if level == "critical" else 60
            ))
            conn.commit()
            cursor.close()
        finally:
            conn.close()

    def generate_daily_report(self) -> None:
        """Generate and save daily storage report."""
        report = self.storage_manager.generate_storage_report()

        # Add cache statistics
        report["cache_stats"] = self.cache_manager.get_cache_stats()

        # Save report
        report_path = self.storage_manager.save_report(report)
        logger.info(f"Daily storage report saved: {report_path}")

        # Log key metrics
        logger.info(f"Storage usage: {report['disk_status']['percent_used']:.1f}%")
        logger.info(f"Active repos: {len(self.storage_manager.list_repositories())}")

        # Log to database
        try:
            self.log_metrics_to_db(report)
        except Exception as e:
            logger.error(f"Failed to log metrics to database: {e}")

    def log_metrics_to_db(self, report: dict) -> None:
        """
        Log storage metrics to database.

        Args:
            report: Storage report dictionary
        """
        conn = get_db_connection()
        if not conn:
            return

        try:
            cursor = conn.cursor()

            # Log storage metrics
            for category, data in report["usage"]["categories"].items():
                cursor.execute("""
                    INSERT INTO system_metrics
                    (metric_name, metric_value, metric_unit, recorded_at)
                    VALUES (%s, %s, %s, %s)
                """, (
                    f"storage_{category}_mb",
                    data["mb"],
                    "MB",
                    datetime.now()
                ))

            # Log disk usage
            cursor.execute("""
                INSERT INTO system_metrics
                (metric_name, metric_value, metric_unit, recorded_at)
                VALUES (%s, %s, %s, %s)
            """, (
                "disk_usage_percent",
                report["disk_status"]["percent_used"],
                "%",
                datetime.now()
            ))

            conn.commit()
            cursor.close()
        except Exception as e:
            logger.error(f"Database error: {e}")
        finally:
            conn.close()

    def run_continuous(self, interval: int = 3600) -> None:
        """
        Run continuous monitoring.

        Args:
            interval: Check interval in seconds (default 1 hour)
        """
        logger.info(f"Starting continuous storage monitoring (interval: {interval}s)")

        while True:
            try:
                # Check disk space
                self.check_and_alert()

                # Generate report every 24 hours
                current_hour = datetime.now().hour
                if current_hour == 2:  # 2 AM daily report
                    self.generate_daily_report()

                # Sleep until next check
                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("Storage monitor stopped by user")
                break
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                time.sleep(60)  # Brief pause on error


def main():
    """Main entry point for storage monitor."""
    import argparse

    parser = argparse.ArgumentParser(description="Storage Monitor")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run single check"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate storage report"
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Perform cleanup"
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Run continuous monitoring"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=3600,
        help="Monitor interval in seconds"
    )

    args = parser.parse_args()

    monitor = StorageMonitor()

    if args.check:
        monitor.check_and_alert()
    elif args.report:
        monitor.generate_daily_report()
    elif args.cleanup:
        manager = StorageManager()
        result = manager.cleanup_archives()
        print(f"Archive cleanup: {result}")
        result = CacheManager().cleanup_old_files()
        print(f"Cache cleanup: {result}")
    elif args.monitor:
        monitor.run_continuous(args.interval)
    else:
        # Default: run single check
        monitor.check_and_alert()


if __name__ == "__main__":
    main()