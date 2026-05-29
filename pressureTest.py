#!/usr/bin/env python3
# payShield test utility by Marco S. Zuppone - msz@msz.eu
# Project name: payShieldPressureTest
# Python script name: pressureTest.py
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
# Please refer to the LICENSE file for more information about licensing
# and to the README.md file for more information about the usage of it.

"""
pressureTest.py
-------
Entry point for payShieldPressureTest.

"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from payshield.pressureTest import main

if __name__ == "__main__":
    main()