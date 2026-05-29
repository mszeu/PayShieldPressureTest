# payShield test utility by Marco S. Zuppone - msz@msz.eu
# Project name: payShieldPressureTest
# Official GitHub Repository: https://github.com/mszeu/PayShieldPressureTest
# Copyright (C) 2020-2026 by Marco S. Zuppone - msz@msz.eu
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
updater.py
----------
Background version-checker that queries the GitHub Releases API and persists
the result to a local JSON file so the check is only performed once every
*check_interval_days* days.
"""

import json
import logging
import os
from datetime import datetime, timedelta

import requests
from packaging.version import Version

logger = logging.getLogger(__name__)


class UpdateChecker:
    """Checks GitHub for a newer release of payShieldPressureTest.

    The result of the last check is stored in a small JSON file inside the
    platform's application-data directory so the network is only hit at most
    once every ``check_interval_days`` days.

    Parameters
    ----------
    current_version : str
        The version string of the currently running application
        (e.g. ``'1.5.3'``).
    github_api_url : str, optional
        Full URL of the GitHub Releases API endpoint to query.
    config_file : str, optional
        Name of the JSON file used to record the date of the last check.
    pid_file : str, optional
        Name of the JSON file used to record the latest available version.
    check_interval_days : int, optional
        Minimum number of days between consecutive network checks.
    """

    def __init__(
            self,
            current_version: str,
            github_api_url: str = "https://api.github.com/repos/mszeu/PayShieldPressureTest/releases/latest",
            config_file: str = "pressure_test.json",
            pid_file: str = "pressureNew.pid",
            check_interval_days: int = 15,
    ):
        self.current_version = current_version
        self.github_api_url = github_api_url
        self.config_file = config_file
        self.pid_file = pid_file
        self.check_interval_days = check_interval_days

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def check_for_updates(self) -> None:
        """Query GitHub and persist the latest version to disk.

        Intended to be run in a daemon thread so it does not block the main
        flow.  Silently swallows network errors to avoid crashing the tool
        when the host has no internet access.
        """
        try:
            response = requests.get(self.github_api_url, timeout=5)
            response.raise_for_status()
            data = response.json()
            latest_version = data["tag_name"].lstrip("v")
            config_file = self.get_config_file_full(self.pid_file)
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            if Version(latest_version) > Version(self.current_version):
                try:
                    with open(config_file, 'w') as fp:
                        json.dump({"last_version": latest_version}, fp)
                except OSError:
                    pass
            else:
                if os.path.exists(config_file):
                    try:
                        os.remove(config_file)
                    except OSError:
                        pass
            self.save_last_check()
        except requests.exceptions.ConnectionError:
            logger.exception("No connection to the API. ConnectionError.")
        except requests.exceptions.HTTPError:
            logger.exception("No connection to the API. HTTPError.")
        except Exception:
            logger.exception("No connection to the API. Generic Exception.")

    def should_check_for_updates(self) -> bool:
        """Return ``True`` if more than *check_interval_days* have passed
        since the last network check.

        Falls back to ``True`` when the config file is missing or unreadable.
        """
        config_file = self.get_config_file_full(self.config_file)
        try:
            if not os.path.exists(config_file):
                return True
            with open(config_file, "r") as f:
                config = json.load(f)
            last_check = datetime.fromisoformat(config.get("last_update_check", "2000-01-01"))
            return datetime.now() - last_check > timedelta(days=self.check_interval_days)
        except Exception:
            logger.exception("Error reading or parsing JSON file")
            return True

    def update_available(self) -> bool:
        """Return ``True`` if a newer version was found during the last check.

        Reads the version cached on disk by :meth:`check_for_updates`; does
        not perform a live network request.
        """
        try:
            config_file = self.get_config_file_full(self.pid_file)
            if os.path.exists(config_file):
                with open(config_file, "r") as f:
                    config = json.load(f)
                if Version(config["last_version"]) > Version(self.current_version):
                    logger.info("New version available: " + config["last_version"])
                    return True
                else:
                    logger.info("No new version available")
                    return False
            else:
                logger.info(config_file + " not found")
                return False
        except Exception:
            logger.exception("Error reading the new version from the file " + self.config_file)
            return False

    def save_last_check(self) -> None:
        """Persist the current timestamp as the date of the last update check."""
        config_file = self.get_config_file_full(self.config_file)
        try:
            config = {}
            if os.path.exists(config_file):
                with open(config_file, "r") as f:
                    config = json.load(f)
            config["last_update_check"] = datetime.now().isoformat()
            with open(config_file, "w") as f:
                json.dump(config, f)
        except Exception:
            logger.exception("Error saving last check")

    # ------------------------------------------------------------------
    # Path helper
    # ------------------------------------------------------------------

    @staticmethod
    def get_config_file_full(my_file_name: str) -> str:
        """Return a platform-appropriate path for a configuration file.

        On Windows the file is placed under ``%APPDATA%\\pressureTest\\``;
        on all other platforms under ``~/.config/pressureTest/``.

        Parameters
        ----------
        my_file_name : str
            The bare filename (e.g. ``'pressure_test.json'``).

        Returns
        -------
        str
            The full absolute path.
        """
        if os.name == "nt":  # Windows
            config_dir = os.environ.get("APPDATA", os.path.expanduser("~"))
        else:
            config_dir = os.path.join(os.path.expanduser("~"), ".config")
        return os.path.join(config_dir, "pressureTest", my_file_name)
