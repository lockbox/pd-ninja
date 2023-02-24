#!/usr/bin/env python3
from .pd_ninja.pd_view import PlayDateView
from .pd_ninja.pd_plugin import register_plugin

PlayDateView.register()
register_plugin()