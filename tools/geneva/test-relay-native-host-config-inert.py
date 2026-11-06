#!/usr/bin/env python3
"""Actual comparison/outer branches with retained public fixtures, no OS query.

These pure fixture results never accept the failed 6bcc run or a native binary.
"""
import copy
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value

d=module('host_config_actual_diagnostics',HERE/'relay_native_diagnostics.py')
terminal=module('host_config_terminal_adapter',HERE/'test-relay-native-ci-terminal-inert.py')
m=terminal.m
NS={'before':{'net':'net:[100]','mount':'mnt:[101]'},'after':{'net':'net:[100]','mount':'mnt:[101]'}}
IP=base64.b64decode('W3siaWZpbmRleCI6MSwiaWZuYW1lIjoibG8iLCJmbGFncyI6WyJMT09QQkFDSyIsIlVQIiwiTE9XRVJfVVAiXSwibXR1Ijo2NTUzNiwicWRpc2MiOiJub3F1ZXVlIiwib3BlcnN0YXRlIjoiVU5LTk9XTiIsImxpbmttb2RlIjoiREVGQVVMVCIsImdyb3VwIjoiZGVmYXVsdCIsInR4cWxlbiI6MTAwMCwibGlua190eXBlIjoibG9vcGJhY2siLCJhZGRyZXNzIjoiMDA6MDA6MDA6MDA6MDA6MDAiLCJicm9hZGNhc3QiOiIwMDowMDowMDowMDowMDowMCJ9LHsiaWZpbmRleCI6MiwiaWZuYW1lIjoiZXRoMCIsImZsYWdzIjpbIkJST0FEQ0FTVCIsIk1VTFRJQ0FTVCIsIlVQIiwiTE9XRVJfVVAiXSwibXR1IjoxNTAwLCJxZGlzYyI6Im1xIiwib3BlcnN0YXRlIjoiVVAiLCJsaW5rbW9kZSI6IkRFRkFVTFQiLCJncm91cCI6ImRlZmF1bHQiLCJ0eHFsZW4iOjEwMDAsImxpbmtfdHlwZSI6ImV0aGVyIiwiYWRkcmVzcyI6IjcwOmE4OmE1OjllOmZmOjYzIiwiYnJvYWRjYXN0IjoiZmY6ZmY6ZmY6ZmY6ZmY6ZmYifSx7ImlmaW5kZXgiOjMsImlmbmFtZSI6ImRvY2tlcjAiLCJmbGFncyI6WyJOTy1DQVJSSUVSIiwiQlJPQURDQVNUIiwiTVVMVElDQVNUIiwiVVAiXSwibXR1IjoxNTAwLCJxZGlzYyI6Im5vcXVldWUiLCJvcGVyc3RhdGUiOiJET1dOIiwibGlua21vZGUiOiJERUZBVUxUIiwiZ3JvdXAiOiJkZWZhdWx0IiwibGlua190eXBlIjoiZXRoZXIiLCJhZGRyZXNzIjoiMGE6N2Y6NDY6YWU6NmE6MjAiLCJicm9hZGNhc3QiOiJmZjpmZjpmZjpmZjpmZjpmZiJ9LHsiaWZpbmRleCI6NCwiaWZuYW1lIjoiZW5QMjgyNjBzMSIsImZsYWdzIjpbIkJST0FEQ0FTVCIsIk1VTFRJQ0FTVCIsIlNMQVZFIiwiVVAiLCJMT1dFUl9VUCJdLCJtdHUiOjE1MDAsInFkaXNjIjoibXEiLCJtYXN0ZXIiOiJldGgwIiwib3BlcnN0YXRlIjoiVVAiLCJsaW5rbW9kZSI6IkRFRkFVTFQiLCJncm91cCI6ImRlZmF1bHQiLCJ0eHFsZW4iOjEwMDAsImxpbmtfdHlwZSI6ImV0aGVyIiwiYWRkcmVzcyI6IjcwOmE4OmE1OjllOmZmOjYzIiwiYnJvYWRjYXN0IjoiZmY6ZmY6ZmY6ZmY6ZmY6ZmYiLCJ2ZmluZm9fbGlzdCI6W10sImFsdG5hbWVzIjpbImVuUDI4MjYwcDBzMiJdfV0K')
OLD=base64.b64decode('eyJuZnRhYmxlcyI6IFt7Im1ldGFpbmZvIjogeyJ2ZXJzaW9uIjogIjEuMC45IiwgInJlbGVhc2VfbmFtZSI6ICJPbGQgRG9jIFlhayAjMyIsICJqc29uX3NjaGVtYV92ZXJzaW9uIjogMX19LCB7InRhYmxlIjogeyJmYW1pbHkiOiAiaXAiLCAibmFtZSI6ICJzZWN1cml0eSIsICJoYW5kbGUiOiAxfX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJzZWN1cml0eSIsICJuYW1lIjogIk9VVFBVVCIsICJoYW5kbGUiOiAxLCAidHlwZSI6ICJmaWx0ZXIiLCAiaG9vayI6ICJvdXRwdXQiLCAicHJpbyI6IDE1MCwgInBvbGljeSI6ICJhY2NlcHQifX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogInNlY3VyaXR5IiwgImNoYWluIjogIk9VVFBVVCIsICJoYW5kbGUiOiAyLCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICI9PSIsICJsZWZ0IjogeyJwYXlsb2FkIjogeyJwcm90b2NvbCI6ICJpcCIsICJmaWVsZCI6ICJkYWRkciJ9fSwgInJpZ2h0IjogIjE2OC42My4xMjkuMTYifX0sIHsibWF0Y2giOiB7Im9wIjogIj09IiwgImxlZnQiOiB7InBheWxvYWQiOiB7InByb3RvY29sIjogInRjcCIsICJmaWVsZCI6ICJkcG9ydCJ9fSwgInJpZ2h0IjogNTN9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7ImFjY2VwdCI6IG51bGx9XX19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJzZWN1cml0eSIsICJjaGFpbiI6ICJPVVRQVVQiLCAiaGFuZGxlIjogMywgImV4cHIiOiBbeyJtYXRjaCI6IHsib3AiOiAiPT0iLCAibGVmdCI6IHsicGF5bG9hZCI6IHsicHJvdG9jb2wiOiAiaXAiLCAiZmllbGQiOiAiZGFkZHIifX0sICJyaWdodCI6ICIxNjguNjMuMTI5LjE2In19LCB7Im1hdGNoIjogeyJvcCI6ICI9PSIsICJsZWZ0IjogeyJwYXlsb2FkIjogeyJwcm90b2NvbCI6ICJpcCIsICJmaWVsZCI6ICJwcm90b2NvbCJ9fSwgInJpZ2h0IjogInRjcCJ9fSwgeyJ4dCI6IHsidHlwZSI6ICJtYXRjaCIsICJuYW1lIjogIm93bmVyIn19LCB7ImNvdW50ZXIiOiB7InBhY2tldHMiOiAzNDA0LCAiYnl0ZXMiOiAxMDM2Mzc4fX0sIHsiYWNjZXB0IjogbnVsbH1dfX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogInNlY3VyaXR5IiwgImNoYWluIjogIk9VVFBVVCIsICJoYW5kbGUiOiA0LCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICI9PSIsICJsZWZ0IjogeyJwYXlsb2FkIjogeyJwcm90b2NvbCI6ICJpcCIsICJmaWVsZCI6ICJkYWRkciJ9fSwgInJpZ2h0IjogIjE2OC42My4xMjkuMTYifX0sIHsibWF0Y2giOiB7Im9wIjogIj09IiwgImxlZnQiOiB7InBheWxvYWQiOiB7InByb3RvY29sIjogImlwIiwgImZpZWxkIjogInByb3RvY29sIn19LCAicmlnaHQiOiAidGNwIn19LCB7Inh0IjogeyJ0eXBlIjogIm1hdGNoIiwgIm5hbWUiOiAiY29ubnRyYWNrIn19LCB7ImNvdW50ZXIiOiB7InBhY2tldHMiOiAwLCAiYnl0ZXMiOiAwfX0sIHsiZHJvcCI6IG51bGx9XX19LCB7InRhYmxlIjogeyJmYW1pbHkiOiAiaXAiLCAibmFtZSI6ICJuYXQiLCAiaGFuZGxlIjogMn19LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAibmF0IiwgIm5hbWUiOiAiRE9DS0VSIiwgImhhbmRsZSI6IDF9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogIm5hdCIsICJuYW1lIjogIlBSRVJPVVRJTkciLCAiaGFuZGxlIjogMiwgInR5cGUiOiAibmF0IiwgImhvb2siOiAicHJlcm91dGluZyIsICJwcmlvIjogLTEwMCwgInBvbGljeSI6ICJhY2NlcHQifX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJuYXQiLCAibmFtZSI6ICJPVVRQVVQiLCAiaGFuZGxlIjogNCwgInR5cGUiOiAibmF0IiwgImhvb2siOiAib3V0cHV0IiwgInByaW8iOiAtMTAwLCAicG9saWN5IjogImFjY2VwdCJ9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogIm5hdCIsICJuYW1lIjogIlBPU1RST1VUSU5HIiwgImhhbmRsZSI6IDYsICJ0eXBlIjogIm5hdCIsICJob29rIjogInBvc3Ryb3V0aW5nIiwgInByaW8iOiAxMDAsICJwb2xpY3kiOiAiYWNjZXB0In19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJuYXQiLCAiY2hhaW4iOiAiRE9DS0VSIiwgImhhbmRsZSI6IDEwLCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICI9PSIsICJsZWZ0IjogeyJtZXRhIjogeyJrZXkiOiAiaWlmbmFtZSJ9fSwgInJpZ2h0IjogImRvY2tlcjAifX0sIHsiY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJyZXR1cm4iOiBudWxsfV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAibmF0IiwgImNoYWluIjogIlBSRVJPVVRJTkciLCAiaGFuZGxlIjogMywgImV4cHIiOiBbeyJ4dCI6IHsidHlwZSI6ICJtYXRjaCIsICJuYW1lIjogImFkZHJ0eXBlIn19LCB7ImNvdW50ZXIiOiB7InBhY2tldHMiOiAwLCAiYnl0ZXMiOiAwfX0sIHsianVtcCI6IHsidGFyZ2V0IjogIkRPQ0tFUiJ9fV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAibmF0IiwgImNoYWluIjogIk9VVFBVVCIsICJoYW5kbGUiOiA1LCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICIhPSIsICJsZWZ0IjogeyJwYXlsb2FkIjogeyJwcm90b2NvbCI6ICJpcCIsICJmaWVsZCI6ICJkYWRkciJ9fSwgInJpZ2h0IjogeyJwcmVmaXgiOiB7ImFkZHIiOiAiMTI3LjAuMC4wIiwgImxlbiI6IDh9fX19LCB7Inh0IjogeyJ0eXBlIjogIm1hdGNoIiwgIm5hbWUiOiAiYWRkcnR5cGUifX0sIHsiY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSIn19XX19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJuYXQiLCAiY2hhaW4iOiAiUE9TVFJPVVRJTkciLCAiaGFuZGxlIjogOSwgImV4cHIiOiBbeyJtYXRjaCI6IHsib3AiOiAiPT0iLCAibGVmdCI6IHsicGF5bG9hZCI6IHsicHJvdG9jb2wiOiAiaXAiLCAiZmllbGQiOiAic2FkZHIifX0sICJyaWdodCI6IHsicHJlZml4IjogeyJhZGRyIjogIjE3Mi4xNy4wLjAiLCAibGVuIjogMTZ9fX19LCB7Im1hdGNoIjogeyJvcCI6ICIhPSIsICJsZWZ0IjogeyJtZXRhIjogeyJrZXkiOiAib2lmbmFtZSJ9fSwgInJpZ2h0IjogImRvY2tlcjAifX0sIHsiY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJ4dCI6IHsidHlwZSI6ICJ0YXJnZXQiLCAibmFtZSI6ICJNQVNRVUVSQURFIn19XX19LCB7InRhYmxlIjogeyJmYW1pbHkiOiAiaXAiLCAibmFtZSI6ICJmaWx0ZXIiLCAiaGFuZGxlIjogM319LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgIm5hbWUiOiAiRE9DS0VSIiwgImhhbmRsZSI6IDF9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkRPQ0tFUi1GT1JXQVJEIiwgImhhbmRsZSI6IDJ9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkRPQ0tFUi1CUklER0UiLCAiaGFuZGxlIjogM319LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgIm5hbWUiOiAiRE9DS0VSLUNUIiwgImhhbmRsZSI6IDR9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkRPQ0tFUi1JU09MQVRJT04tU1RBR0UtMSIsICJoYW5kbGUiOiA1fX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJmaWx0ZXIiLCAibmFtZSI6ICJET0NLRVItSVNPTEFUSU9OLVNUQUdFLTIiLCAiaGFuZGxlIjogNn19LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgIm5hbWUiOiAiRk9SV0FSRCIsICJoYW5kbGUiOiA3LCAidHlwZSI6ICJmaWx0ZXIiLCAiaG9vayI6ICJmb3J3YXJkIiwgInByaW8iOiAwLCAicG9saWN5IjogImRyb3AifX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJmaWx0ZXIiLCAibmFtZSI6ICJET0NLRVItVVNFUiIsICJoYW5kbGUiOiAxOH19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJmaWx0ZXIiLCAiY2hhaW4iOiAiRE9DS0VSIiwgImhhbmRsZSI6IDIyLCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICIhPSIsICJsZWZ0IjogeyJtZXRhIjogeyJrZXkiOiAiaWlmbmFtZSJ9fSwgInJpZ2h0IjogImRvY2tlcjAifX0sIHsibWF0Y2giOiB7Im9wIjogIj09IiwgImxlZnQiOiB7Im1ldGEiOiB7ImtleSI6ICJvaWZuYW1lIn19LCAicmlnaHQiOiAiZG9ja2VyMCJ9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7ImRyb3AiOiBudWxsfV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkRPQ0tFUi1GT1JXQVJEIiwgImhhbmRsZSI6IDExLCAiZXhwciI6IFt7ImNvdW50ZXIiOiB7InBhY2tldHMiOiAwLCAiYnl0ZXMiOiAwfX0sIHsianVtcCI6IHsidGFyZ2V0IjogIkRPQ0tFUi1DVCJ9fV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkRPQ0tFUi1GT1JXQVJEIiwgImhhbmRsZSI6IDEwLCAiZXhwciI6IFt7ImNvdW50ZXIiOiB7InBhY2tldHMiOiAwLCAiYnl0ZXMiOiAwfX0sIHsianVtcCI6IHsidGFyZ2V0IjogIkRPQ0tFUi1JU09MQVRJT04tU1RBR0UtMSJ9fV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkRPQ0tFUi1GT1JXQVJEIiwgImhhbmRsZSI6IDksICJleHByIjogW3siY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSLUJSSURHRSJ9fV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkRPQ0tFUi1GT1JXQVJEIiwgImhhbmRsZSI6IDIxLCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICI9PSIsICJsZWZ0IjogeyJtZXRhIjogeyJrZXkiOiAiaWlmbmFtZSJ9fSwgInJpZ2h0IjogImRvY2tlcjAifX0sIHsiY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJhY2NlcHQiOiBudWxsfV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkRPQ0tFUi1CUklER0UiLCAiaGFuZGxlIjogMjQsICJleHByIjogW3sibWF0Y2giOiB7Im9wIjogIj09IiwgImxlZnQiOiB7Im1ldGEiOiB7ImtleSI6ICJvaWZuYW1lIn19LCAicmlnaHQiOiAiZG9ja2VyMCJ9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7Imp1bXAiOiB7InRhcmdldCI6ICJET0NLRVIifX1dfX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJET0NLRVItQ1QiLCAiaGFuZGxlIjogMjMsICJleHByIjogW3sibWF0Y2giOiB7Im9wIjogIj09IiwgImxlZnQiOiB7Im1ldGEiOiB7ImtleSI6ICJvaWZuYW1lIn19LCAicmlnaHQiOiAiZG9ja2VyMCJ9fSwgeyJ4dCI6IHsidHlwZSI6ICJtYXRjaCIsICJuYW1lIjogImNvbm50cmFjayJ9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7ImFjY2VwdCI6IG51bGx9XX19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJmaWx0ZXIiLCAiY2hhaW4iOiAiRE9DS0VSLUlTT0xBVElPTi1TVEFHRS0xIiwgImhhbmRsZSI6IDI1LCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICI9PSIsICJsZWZ0IjogeyJtZXRhIjogeyJrZXkiOiAiaWlmbmFtZSJ9fSwgInJpZ2h0IjogImRvY2tlcjAifX0sIHsibWF0Y2giOiB7Im9wIjogIiE9IiwgImxlZnQiOiB7Im1ldGEiOiB7ImtleSI6ICJvaWZuYW1lIn19LCAicmlnaHQiOiAiZG9ja2VyMCJ9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7Imp1bXAiOiB7InRhcmdldCI6ICJET0NLRVItSVNPTEFUSU9OLVNUQUdFLTIifX1dfX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJET0NLRVItSVNPTEFUSU9OLVNUQUdFLTIiLCAiaGFuZGxlIjogMjYsICJleHByIjogW3sibWF0Y2giOiB7Im9wIjogIj09IiwgImxlZnQiOiB7Im1ldGEiOiB7ImtleSI6ICJvaWZuYW1lIn19LCAicmlnaHQiOiAiZG9ja2VyMCJ9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7ImRyb3AiOiBudWxsfV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkZPUldBUkQiLCAiaGFuZGxlIjogMjAsICJleHByIjogW3siY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSLVVTRVIifX1dfX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJGT1JXQVJEIiwgImhhbmRsZSI6IDgsICJleHByIjogW3siY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSLUZPUldBUkQifX1dfX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJET0NLRVItVVNFUiIsICJoYW5kbGUiOiAxOSwgImV4cHIiOiBbeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7InJldHVybiI6IG51bGx9XX19LCB7InRhYmxlIjogeyJmYW1pbHkiOiAiaXA2IiwgIm5hbWUiOiAibmF0IiwgImhhbmRsZSI6IDR9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwNiIsICJ0YWJsZSI6ICJuYXQiLCAibmFtZSI6ICJET0NLRVIiLCAiaGFuZGxlIjogMX19LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogIm5hdCIsICJuYW1lIjogIlBSRVJPVVRJTkciLCAiaGFuZGxlIjogMiwgInR5cGUiOiAibmF0IiwgImhvb2siOiAicHJlcm91dGluZyIsICJwcmlvIjogLTEwMCwgInBvbGljeSI6ICJhY2NlcHQifX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAibmF0IiwgIm5hbWUiOiAiT1VUUFVUIiwgImhhbmRsZSI6IDQsICJ0eXBlIjogIm5hdCIsICJob29rIjogIm91dHB1dCIsICJwcmlvIjogLTEwMCwgInBvbGljeSI6ICJhY2NlcHQifX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwNiIsICJ0YWJsZSI6ICJuYXQiLCAiY2hhaW4iOiAiUFJFUk9VVElORyIsICJoYW5kbGUiOiAzLCAiZXhwciI6IFt7Inh0IjogeyJ0eXBlIjogIm1hdGNoIiwgIm5hbWUiOiAiYWRkcnR5cGUifX0sIHsiY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSIn19XX19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAibmF0IiwgImNoYWluIjogIk9VVFBVVCIsICJoYW5kbGUiOiA1LCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICIhPSIsICJsZWZ0IjogeyJwYXlsb2FkIjogeyJwcm90b2NvbCI6ICJpcDYiLCAiZmllbGQiOiAiZGFkZHIifX0sICJyaWdodCI6ICI6OjEifX0sIHsieHQiOiB7InR5cGUiOiAibWF0Y2giLCAibmFtZSI6ICJhZGRydHlwZSJ9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7Imp1bXAiOiB7InRhcmdldCI6ICJET0NLRVIifX1dfX0sIHsidGFibGUiOiB7ImZhbWlseSI6ICJpcDYiLCAibmFtZSI6ICJmaWx0ZXIiLCAiaGFuZGxlIjogNX19LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkRPQ0tFUiIsICJoYW5kbGUiOiAxfX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAiZmlsdGVyIiwgIm5hbWUiOiAiRE9DS0VSLUZPUldBUkQiLCAiaGFuZGxlIjogMn19LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkRPQ0tFUi1CUklER0UiLCAiaGFuZGxlIjogM319LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkRPQ0tFUi1DVCIsICJoYW5kbGUiOiA0fX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAiZmlsdGVyIiwgIm5hbWUiOiAiRE9DS0VSLUlTT0xBVElPTi1TVEFHRS0xIiwgImhhbmRsZSI6IDV9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwNiIsICJ0YWJsZSI6ICJmaWx0ZXIiLCAibmFtZSI6ICJET0NLRVItSVNPTEFUSU9OLVNUQUdFLTIiLCAiaGFuZGxlIjogNn19LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkZPUldBUkQiLCAiaGFuZGxlIjogNywgInR5cGUiOiAiZmlsdGVyIiwgImhvb2siOiAiZm9yd2FyZCIsICJwcmlvIjogMCwgInBvbGljeSI6ICJhY2NlcHQifX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAiZmlsdGVyIiwgIm5hbWUiOiAiRE9DS0VSLVVTRVIiLCAiaGFuZGxlIjogMTJ9fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJET0NLRVItRk9SV0FSRCIsICJoYW5kbGUiOiAxMSwgImV4cHIiOiBbeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7Imp1bXAiOiB7InRhcmdldCI6ICJET0NLRVItQ1QifX1dfX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwNiIsICJ0YWJsZSI6ICJmaWx0ZXIiLCAiY2hhaW4iOiAiRE9DS0VSLUZPUldBUkQiLCAiaGFuZGxlIjogMTAsICJleHByIjogW3siY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSLUlTT0xBVElPTi1TVEFHRS0xIn19XX19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkRPQ0tFUi1GT1JXQVJEIiwgImhhbmRsZSI6IDksICJleHByIjogW3siY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSLUJSSURHRSJ9fV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJGT1JXQVJEIiwgImhhbmRsZSI6IDE0LCAiZXhwciI6IFt7ImNvdW50ZXIiOiB7InBhY2tldHMiOiAwLCAiYnl0ZXMiOiAwfX0sIHsianVtcCI6IHsidGFyZ2V0IjogIkRPQ0tFUi1VU0VSIn19XX19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkZPUldBUkQiLCAiaGFuZGxlIjogOCwgImV4cHIiOiBbeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7Imp1bXAiOiB7InRhcmdldCI6ICJET0NLRVItRk9SV0FSRCJ9fV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJET0NLRVItVVNFUiIsICJoYW5kbGUiOiAxMywgImV4cHIiOiBbeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7InJldHVybiI6IG51bGx9XX19XX0K')
NEW=base64.b64decode('eyJuZnRhYmxlcyI6IFt7Im1ldGFpbmZvIjogeyJ2ZXJzaW9uIjogIjEuMC45IiwgInJlbGVhc2VfbmFtZSI6ICJPbGQgRG9jIFlhayAjMyIsICJqc29uX3NjaGVtYV92ZXJzaW9uIjogMX19LCB7InRhYmxlIjogeyJmYW1pbHkiOiAiaXAiLCAibmFtZSI6ICJzZWN1cml0eSIsICJoYW5kbGUiOiAxfX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJzZWN1cml0eSIsICJuYW1lIjogIk9VVFBVVCIsICJoYW5kbGUiOiAxLCAidHlwZSI6ICJmaWx0ZXIiLCAiaG9vayI6ICJvdXRwdXQiLCAicHJpbyI6IDE1MCwgInBvbGljeSI6ICJhY2NlcHQifX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogInNlY3VyaXR5IiwgImNoYWluIjogIk9VVFBVVCIsICJoYW5kbGUiOiAyLCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICI9PSIsICJsZWZ0IjogeyJwYXlsb2FkIjogeyJwcm90b2NvbCI6ICJpcCIsICJmaWVsZCI6ICJkYWRkciJ9fSwgInJpZ2h0IjogIjE2OC42My4xMjkuMTYifX0sIHsibWF0Y2giOiB7Im9wIjogIj09IiwgImxlZnQiOiB7InBheWxvYWQiOiB7InByb3RvY29sIjogInRjcCIsICJmaWVsZCI6ICJkcG9ydCJ9fSwgInJpZ2h0IjogNTN9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7ImFjY2VwdCI6IG51bGx9XX19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJzZWN1cml0eSIsICJjaGFpbiI6ICJPVVRQVVQiLCAiaGFuZGxlIjogMywgImV4cHIiOiBbeyJtYXRjaCI6IHsib3AiOiAiPT0iLCAibGVmdCI6IHsicGF5bG9hZCI6IHsicHJvdG9jb2wiOiAiaXAiLCAiZmllbGQiOiAiZGFkZHIifX0sICJyaWdodCI6ICIxNjguNjMuMTI5LjE2In19LCB7Im1hdGNoIjogeyJvcCI6ICI9PSIsICJsZWZ0IjogeyJwYXlsb2FkIjogeyJwcm90b2NvbCI6ICJpcCIsICJmaWVsZCI6ICJwcm90b2NvbCJ9fSwgInJpZ2h0IjogInRjcCJ9fSwgeyJ4dCI6IHsidHlwZSI6ICJtYXRjaCIsICJuYW1lIjogIm93bmVyIn19LCB7ImNvdW50ZXIiOiB7InBhY2tldHMiOiAzNDI5LCAiYnl0ZXMiOiAxMDUzOTIyfX0sIHsiYWNjZXB0IjogbnVsbH1dfX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogInNlY3VyaXR5IiwgImNoYWluIjogIk9VVFBVVCIsICJoYW5kbGUiOiA0LCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICI9PSIsICJsZWZ0IjogeyJwYXlsb2FkIjogeyJwcm90b2NvbCI6ICJpcCIsICJmaWVsZCI6ICJkYWRkciJ9fSwgInJpZ2h0IjogIjE2OC42My4xMjkuMTYifX0sIHsibWF0Y2giOiB7Im9wIjogIj09IiwgImxlZnQiOiB7InBheWxvYWQiOiB7InByb3RvY29sIjogImlwIiwgImZpZWxkIjogInByb3RvY29sIn19LCAicmlnaHQiOiAidGNwIn19LCB7Inh0IjogeyJ0eXBlIjogIm1hdGNoIiwgIm5hbWUiOiAiY29ubnRyYWNrIn19LCB7ImNvdW50ZXIiOiB7InBhY2tldHMiOiAwLCAiYnl0ZXMiOiAwfX0sIHsiZHJvcCI6IG51bGx9XX19LCB7InRhYmxlIjogeyJmYW1pbHkiOiAiaXAiLCAibmFtZSI6ICJuYXQiLCAiaGFuZGxlIjogMn19LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAibmF0IiwgIm5hbWUiOiAiRE9DS0VSIiwgImhhbmRsZSI6IDF9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogIm5hdCIsICJuYW1lIjogIlBSRVJPVVRJTkciLCAiaGFuZGxlIjogMiwgInR5cGUiOiAibmF0IiwgImhvb2siOiAicHJlcm91dGluZyIsICJwcmlvIjogLTEwMCwgInBvbGljeSI6ICJhY2NlcHQifX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJuYXQiLCAibmFtZSI6ICJPVVRQVVQiLCAiaGFuZGxlIjogNCwgInR5cGUiOiAibmF0IiwgImhvb2siOiAib3V0cHV0IiwgInByaW8iOiAtMTAwLCAicG9saWN5IjogImFjY2VwdCJ9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogIm5hdCIsICJuYW1lIjogIlBPU1RST1VUSU5HIiwgImhhbmRsZSI6IDYsICJ0eXBlIjogIm5hdCIsICJob29rIjogInBvc3Ryb3V0aW5nIiwgInByaW8iOiAxMDAsICJwb2xpY3kiOiAiYWNjZXB0In19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJuYXQiLCAiY2hhaW4iOiAiRE9DS0VSIiwgImhhbmRsZSI6IDEwLCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICI9PSIsICJsZWZ0IjogeyJtZXRhIjogeyJrZXkiOiAiaWlmbmFtZSJ9fSwgInJpZ2h0IjogImRvY2tlcjAifX0sIHsiY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJyZXR1cm4iOiBudWxsfV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAibmF0IiwgImNoYWluIjogIlBSRVJPVVRJTkciLCAiaGFuZGxlIjogMywgImV4cHIiOiBbeyJ4dCI6IHsidHlwZSI6ICJtYXRjaCIsICJuYW1lIjogImFkZHJ0eXBlIn19LCB7ImNvdW50ZXIiOiB7InBhY2tldHMiOiAwLCAiYnl0ZXMiOiAwfX0sIHsianVtcCI6IHsidGFyZ2V0IjogIkRPQ0tFUiJ9fV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAibmF0IiwgImNoYWluIjogIk9VVFBVVCIsICJoYW5kbGUiOiA1LCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICIhPSIsICJsZWZ0IjogeyJwYXlsb2FkIjogeyJwcm90b2NvbCI6ICJpcCIsICJmaWVsZCI6ICJkYWRkciJ9fSwgInJpZ2h0IjogeyJwcmVmaXgiOiB7ImFkZHIiOiAiMTI3LjAuMC4wIiwgImxlbiI6IDh9fX19LCB7Inh0IjogeyJ0eXBlIjogIm1hdGNoIiwgIm5hbWUiOiAiYWRkcnR5cGUifX0sIHsiY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSIn19XX19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJuYXQiLCAiY2hhaW4iOiAiUE9TVFJPVVRJTkciLCAiaGFuZGxlIjogOSwgImV4cHIiOiBbeyJtYXRjaCI6IHsib3AiOiAiPT0iLCAibGVmdCI6IHsicGF5bG9hZCI6IHsicHJvdG9jb2wiOiAiaXAiLCAiZmllbGQiOiAic2FkZHIifX0sICJyaWdodCI6IHsicHJlZml4IjogeyJhZGRyIjogIjE3Mi4xNy4wLjAiLCAibGVuIjogMTZ9fX19LCB7Im1hdGNoIjogeyJvcCI6ICIhPSIsICJsZWZ0IjogeyJtZXRhIjogeyJrZXkiOiAib2lmbmFtZSJ9fSwgInJpZ2h0IjogImRvY2tlcjAifX0sIHsiY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJ4dCI6IHsidHlwZSI6ICJ0YXJnZXQiLCAibmFtZSI6ICJNQVNRVUVSQURFIn19XX19LCB7InRhYmxlIjogeyJmYW1pbHkiOiAiaXAiLCAibmFtZSI6ICJmaWx0ZXIiLCAiaGFuZGxlIjogM319LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgIm5hbWUiOiAiRE9DS0VSIiwgImhhbmRsZSI6IDF9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkRPQ0tFUi1GT1JXQVJEIiwgImhhbmRsZSI6IDJ9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkRPQ0tFUi1CUklER0UiLCAiaGFuZGxlIjogM319LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgIm5hbWUiOiAiRE9DS0VSLUNUIiwgImhhbmRsZSI6IDR9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkRPQ0tFUi1JU09MQVRJT04tU1RBR0UtMSIsICJoYW5kbGUiOiA1fX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJmaWx0ZXIiLCAibmFtZSI6ICJET0NLRVItSVNPTEFUSU9OLVNUQUdFLTIiLCAiaGFuZGxlIjogNn19LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgIm5hbWUiOiAiRk9SV0FSRCIsICJoYW5kbGUiOiA3LCAidHlwZSI6ICJmaWx0ZXIiLCAiaG9vayI6ICJmb3J3YXJkIiwgInByaW8iOiAwLCAicG9saWN5IjogImRyb3AifX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJmaWx0ZXIiLCAibmFtZSI6ICJET0NLRVItVVNFUiIsICJoYW5kbGUiOiAxOH19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJmaWx0ZXIiLCAiY2hhaW4iOiAiRE9DS0VSIiwgImhhbmRsZSI6IDIyLCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICIhPSIsICJsZWZ0IjogeyJtZXRhIjogeyJrZXkiOiAiaWlmbmFtZSJ9fSwgInJpZ2h0IjogImRvY2tlcjAifX0sIHsibWF0Y2giOiB7Im9wIjogIj09IiwgImxlZnQiOiB7Im1ldGEiOiB7ImtleSI6ICJvaWZuYW1lIn19LCAicmlnaHQiOiAiZG9ja2VyMCJ9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7ImRyb3AiOiBudWxsfV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkRPQ0tFUi1GT1JXQVJEIiwgImhhbmRsZSI6IDExLCAiZXhwciI6IFt7ImNvdW50ZXIiOiB7InBhY2tldHMiOiAwLCAiYnl0ZXMiOiAwfX0sIHsianVtcCI6IHsidGFyZ2V0IjogIkRPQ0tFUi1DVCJ9fV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkRPQ0tFUi1GT1JXQVJEIiwgImhhbmRsZSI6IDEwLCAiZXhwciI6IFt7ImNvdW50ZXIiOiB7InBhY2tldHMiOiAwLCAiYnl0ZXMiOiAwfX0sIHsianVtcCI6IHsidGFyZ2V0IjogIkRPQ0tFUi1JU09MQVRJT04tU1RBR0UtMSJ9fV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkRPQ0tFUi1GT1JXQVJEIiwgImhhbmRsZSI6IDksICJleHByIjogW3siY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSLUJSSURHRSJ9fV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkRPQ0tFUi1GT1JXQVJEIiwgImhhbmRsZSI6IDIxLCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICI9PSIsICJsZWZ0IjogeyJtZXRhIjogeyJrZXkiOiAiaWlmbmFtZSJ9fSwgInJpZ2h0IjogImRvY2tlcjAifX0sIHsiY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJhY2NlcHQiOiBudWxsfV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkRPQ0tFUi1CUklER0UiLCAiaGFuZGxlIjogMjQsICJleHByIjogW3sibWF0Y2giOiB7Im9wIjogIj09IiwgImxlZnQiOiB7Im1ldGEiOiB7ImtleSI6ICJvaWZuYW1lIn19LCAicmlnaHQiOiAiZG9ja2VyMCJ9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7Imp1bXAiOiB7InRhcmdldCI6ICJET0NLRVIifX1dfX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJET0NLRVItQ1QiLCAiaGFuZGxlIjogMjMsICJleHByIjogW3sibWF0Y2giOiB7Im9wIjogIj09IiwgImxlZnQiOiB7Im1ldGEiOiB7ImtleSI6ICJvaWZuYW1lIn19LCAicmlnaHQiOiAiZG9ja2VyMCJ9fSwgeyJ4dCI6IHsidHlwZSI6ICJtYXRjaCIsICJuYW1lIjogImNvbm50cmFjayJ9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7ImFjY2VwdCI6IG51bGx9XX19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcCIsICJ0YWJsZSI6ICJmaWx0ZXIiLCAiY2hhaW4iOiAiRE9DS0VSLUlTT0xBVElPTi1TVEFHRS0xIiwgImhhbmRsZSI6IDI1LCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICI9PSIsICJsZWZ0IjogeyJtZXRhIjogeyJrZXkiOiAiaWlmbmFtZSJ9fSwgInJpZ2h0IjogImRvY2tlcjAifX0sIHsibWF0Y2giOiB7Im9wIjogIiE9IiwgImxlZnQiOiB7Im1ldGEiOiB7ImtleSI6ICJvaWZuYW1lIn19LCAicmlnaHQiOiAiZG9ja2VyMCJ9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7Imp1bXAiOiB7InRhcmdldCI6ICJET0NLRVItSVNPTEFUSU9OLVNUQUdFLTIifX1dfX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJET0NLRVItSVNPTEFUSU9OLVNUQUdFLTIiLCAiaGFuZGxlIjogMjYsICJleHByIjogW3sibWF0Y2giOiB7Im9wIjogIj09IiwgImxlZnQiOiB7Im1ldGEiOiB7ImtleSI6ICJvaWZuYW1lIn19LCAicmlnaHQiOiAiZG9ja2VyMCJ9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7ImRyb3AiOiBudWxsfV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXAiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkZPUldBUkQiLCAiaGFuZGxlIjogMjAsICJleHByIjogW3siY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSLVVTRVIifX1dfX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJGT1JXQVJEIiwgImhhbmRsZSI6IDgsICJleHByIjogW3siY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSLUZPUldBUkQifX1dfX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwIiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJET0NLRVItVVNFUiIsICJoYW5kbGUiOiAxOSwgImV4cHIiOiBbeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7InJldHVybiI6IG51bGx9XX19LCB7InRhYmxlIjogeyJmYW1pbHkiOiAiaXA2IiwgIm5hbWUiOiAibmF0IiwgImhhbmRsZSI6IDR9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwNiIsICJ0YWJsZSI6ICJuYXQiLCAibmFtZSI6ICJET0NLRVIiLCAiaGFuZGxlIjogMX19LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogIm5hdCIsICJuYW1lIjogIlBSRVJPVVRJTkciLCAiaGFuZGxlIjogMiwgInR5cGUiOiAibmF0IiwgImhvb2siOiAicHJlcm91dGluZyIsICJwcmlvIjogLTEwMCwgInBvbGljeSI6ICJhY2NlcHQifX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAibmF0IiwgIm5hbWUiOiAiT1VUUFVUIiwgImhhbmRsZSI6IDQsICJ0eXBlIjogIm5hdCIsICJob29rIjogIm91dHB1dCIsICJwcmlvIjogLTEwMCwgInBvbGljeSI6ICJhY2NlcHQifX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwNiIsICJ0YWJsZSI6ICJuYXQiLCAiY2hhaW4iOiAiUFJFUk9VVElORyIsICJoYW5kbGUiOiAzLCAiZXhwciI6IFt7Inh0IjogeyJ0eXBlIjogIm1hdGNoIiwgIm5hbWUiOiAiYWRkcnR5cGUifX0sIHsiY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSIn19XX19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAibmF0IiwgImNoYWluIjogIk9VVFBVVCIsICJoYW5kbGUiOiA1LCAiZXhwciI6IFt7Im1hdGNoIjogeyJvcCI6ICIhPSIsICJsZWZ0IjogeyJwYXlsb2FkIjogeyJwcm90b2NvbCI6ICJpcDYiLCAiZmllbGQiOiAiZGFkZHIifX0sICJyaWdodCI6ICI6OjEifX0sIHsieHQiOiB7InR5cGUiOiAibWF0Y2giLCAibmFtZSI6ICJhZGRydHlwZSJ9fSwgeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7Imp1bXAiOiB7InRhcmdldCI6ICJET0NLRVIifX1dfX0sIHsidGFibGUiOiB7ImZhbWlseSI6ICJpcDYiLCAibmFtZSI6ICJmaWx0ZXIiLCAiaGFuZGxlIjogNX19LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkRPQ0tFUiIsICJoYW5kbGUiOiAxfX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAiZmlsdGVyIiwgIm5hbWUiOiAiRE9DS0VSLUZPUldBUkQiLCAiaGFuZGxlIjogMn19LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkRPQ0tFUi1CUklER0UiLCAiaGFuZGxlIjogM319LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkRPQ0tFUi1DVCIsICJoYW5kbGUiOiA0fX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAiZmlsdGVyIiwgIm5hbWUiOiAiRE9DS0VSLUlTT0xBVElPTi1TVEFHRS0xIiwgImhhbmRsZSI6IDV9fSwgeyJjaGFpbiI6IHsiZmFtaWx5IjogImlwNiIsICJ0YWJsZSI6ICJmaWx0ZXIiLCAibmFtZSI6ICJET0NLRVItSVNPTEFUSU9OLVNUQUdFLTIiLCAiaGFuZGxlIjogNn19LCB7ImNoYWluIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJuYW1lIjogIkZPUldBUkQiLCAiaGFuZGxlIjogNywgInR5cGUiOiAiZmlsdGVyIiwgImhvb2siOiAiZm9yd2FyZCIsICJwcmlvIjogMCwgInBvbGljeSI6ICJhY2NlcHQifX0sIHsiY2hhaW4iOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAiZmlsdGVyIiwgIm5hbWUiOiAiRE9DS0VSLVVTRVIiLCAiaGFuZGxlIjogMTJ9fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJET0NLRVItRk9SV0FSRCIsICJoYW5kbGUiOiAxMSwgImV4cHIiOiBbeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7Imp1bXAiOiB7InRhcmdldCI6ICJET0NLRVItQ1QifX1dfX0sIHsicnVsZSI6IHsiZmFtaWx5IjogImlwNiIsICJ0YWJsZSI6ICJmaWx0ZXIiLCAiY2hhaW4iOiAiRE9DS0VSLUZPUldBUkQiLCAiaGFuZGxlIjogMTAsICJleHByIjogW3siY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSLUlTT0xBVElPTi1TVEFHRS0xIn19XX19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkRPQ0tFUi1GT1JXQVJEIiwgImhhbmRsZSI6IDksICJleHByIjogW3siY291bnRlciI6IHsicGFja2V0cyI6IDAsICJieXRlcyI6IDB9fSwgeyJqdW1wIjogeyJ0YXJnZXQiOiAiRE9DS0VSLUJSSURHRSJ9fV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJGT1JXQVJEIiwgImhhbmRsZSI6IDE0LCAiZXhwciI6IFt7ImNvdW50ZXIiOiB7InBhY2tldHMiOiAwLCAiYnl0ZXMiOiAwfX0sIHsianVtcCI6IHsidGFyZ2V0IjogIkRPQ0tFUi1VU0VSIn19XX19LCB7InJ1bGUiOiB7ImZhbWlseSI6ICJpcDYiLCAidGFibGUiOiAiZmlsdGVyIiwgImNoYWluIjogIkZPUldBUkQiLCAiaGFuZGxlIjogOCwgImV4cHIiOiBbeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7Imp1bXAiOiB7InRhcmdldCI6ICJET0NLRVItRk9SV0FSRCJ9fV19fSwgeyJydWxlIjogeyJmYW1pbHkiOiAiaXA2IiwgInRhYmxlIjogImZpbHRlciIsICJjaGFpbiI6ICJET0NLRVItVVNFUiIsICJoYW5kbGUiOiAxMywgImV4cHIiOiBbeyJjb3VudGVyIjogeyJwYWNrZXRzIjogMCwgImJ5dGVzIjogMH19LCB7InJldHVybiI6IG51bGx9XX19XX0K')

def dump(value):return json.dumps(value,separators=(',',':'),allow_nan=False).encode()
def rule(value):return value['nftables'][4]['rule']

class Configuration(unittest.TestCase):
    def evaluate(self,after=NEW,before=OLD,ip_after=IP,namespaces=NS):
        return d.host_configuration_comparison(IP,before,ip_after,after,namespaces)
    def rejects(self,mutation,before=OLD):
        value=json.loads(NEW);mutation(value)
        try:
            result=self.evaluate(dump(value),before)
        except (RuntimeError,ValueError,RecursionError):return
        self.assertFalse(result['configuration_unchanged'])
        with self.assertRaises(RuntimeError):d.verify_host_configuration_record(result,IP,before,IP,dump(value),NS)

    def test_actual_retained_fixture_config_only_raw_false_complete_exact_delta(self):
        result=self.evaluate()
        self.assertTrue(result['configuration_unchanged']);self.assertTrue(result['nft_configuration_equal'])
        self.assertTrue(result['exact_raw_ip_equal']);self.assertFalse(result['exact_raw_nft_equal'])
        self.assertEqual(result['refused_differences'],[])
        self.assertEqual(result['anonymous_counter_deltas'],[{
            'path':'/nftables/4/rule/expr/3/counter','nftables_index':4,'expression_index':3,
            'rule_identity':{'family':'ip','table':'security','chain':'OUTPUT','handle':3},
            'before':{'packets':3404,'bytes':1036378},'after':{'packets':3429,'bytes':1053922},
            'delta':{'packets':25,'bytes':17544}}])
        for name,body in [('ip_before',IP),('ip_after',IP),('nft_before',OLD),('nft_after',NEW)]:
            self.assertEqual(result['raw'][name],{'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()})
        self.assertEqual(d.verify_host_configuration_record(result,IP,OLD,IP,NEW,NS),result)
        # Historical raw diagnostic meaning and retained bytes remain unchanged.
        old_difference=json.loads(base64.b64decode('eyJhY2NlcHRhbmNlX25vcm1hbGl6YXRpb25fcGVyZm9ybWVkIjpmYWxzZSwiY2hhbmdlZF9KU09OX3BhdGhzIjpbIi9uZnQvbmZ0YWJsZXMvNC9ydWxlL2V4cHIvMy9jb3VudGVyL2J5dGVzIiwiL25mdC9uZnRhYmxlcy80L3J1bGUvZXhwci8zL2NvdW50ZXIvcGFja2V0cyJdLCJleGFjdF9yYXdfaXBfZXF1YWwiOnRydWUsImV4YWN0X3Jhd19uZnRfZXF1YWwiOmZhbHNlLCJwYXRoX2ludmVudG9yeV9tYXlfYmVfdHJ1bmNhdGVkIjpmYWxzZSwic2NvcGUiOiJib3VuZGVkIHB1YmxpYyBob3N0IHJlYWRiYWNrIG9ubHk7IGluc3BlY3QgdmFsdWVzIG9mZmxpbmU7IGV4YWN0IGFjY2VwdGFuY2UgdW5jaGFuZ2VkIn0='))
        self.assertEqual(d.host_difference(IP,OLD,IP,NEW),old_difference)
        self.assertFalse(old_difference['exact_raw_nft_equal'])
        self.assertFalse(old_difference['acceptance_normalization_performed'])

    def test_raw_equal_still_requires_valid_complete_shape_and_typed_counters(self):
        self.assertTrue(self.evaluate(OLD)['configuration_unchanged'])
        invalid=json.loads(OLD);rule(invalid)['expr'][3]['counter']['packets']=True
        for before,after in [(b'{}',b'{}'),(b'{"nftables":false}',b'{"nftables":false}'),(dump(invalid),dump(invalid))]:
            with self.assertRaises(RuntimeError):self.evaluate(after,before)

    def test_counter_type_bound_reset_and_unknown_shape_refuse(self):
        for key in ('packets','bytes'):
            for value in (True,False,-1,1<<64,1.5,'3429',None,0):
                self.rejects(lambda nft,k=key,v=value:rule(nft)['expr'][3]['counter'].__setitem__(k,v))
        self.rejects(lambda nft:rule(nft)['expr'][3]['counter'].__setitem__('name','foreign'))
        self.rejects(lambda nft:rule(nft)['expr'][3].__setitem__('hidden-policy',{'accept':None}))
        self.rejects(lambda nft:rule(nft)['expr'][3].__setitem__('counter','named'))

    def test_counter_add_remove_and_expression_membership_order_refuse(self):
        self.rejects(lambda nft:rule(nft)['expr'].pop(3))
        self.rejects(lambda nft:rule(nft)['expr'].insert(3,{'counter':{'packets':0,'bytes':0}}))
        self.rejects(lambda nft:rule(nft)['expr'].reverse())
        self.rejects(lambda nft:nft['nftables'].reverse())
        self.rejects(lambda nft:nft['nftables'].append(copy.deepcopy(nft['nftables'][4])))

    def test_exact_rule_identity_and_every_other_policy_leaf_refuse(self):
        for key,value in [('handle',30),('family','inet'),('table','foreign'),('chain','INPUT')]:
            self.rejects(lambda nft,k=key,v=value:rule(nft).__setitem__(k,v))
        self.rejects(lambda nft:rule(nft)['expr'][0]['match'].__setitem__('right','192.0.2.9'))
        self.rejects(lambda nft:rule(nft)['expr'][1]['match'].__setitem__('right','udp'))
        self.rejects(lambda nft:rule(nft)['expr'][2]['xt'].__setitem__('name','foreign'))
        self.rejects(lambda nft:rule(nft)['expr'].__setitem__(4,{'drop':None}))
        self.rejects(lambda nft:nft['nftables'][0]['metainfo'].__setitem__('json_schema_version',2))
        self.rejects(lambda nft:rule(nft).__setitem__('comment','foreign'))

    def test_no_broad_state_or_named_counter_normalization(self):
        for expression in ({'queue':{'num':9,'flags':['bypass']}},{'meta':{'key':'mark','value':32}},
                           {'quota':{'bytes':10,'used':1}},{'limit':{'rate':2,'burst':3}},
                           {'counter':{'name':'shared','packets':0,'bytes':0}},
                           {'mystery':{'packets':0,'bytes':0}}):
            self.rejects(lambda nft,e=expression:rule(nft)['expr'].insert(0,e))
        for obj in ({'set':{'family':'ip','table':'security','name':'owned','elem':[1]}},
                    {'counter':{'family':'ip','table':'security','name':'owned','packets':0,'bytes':0}}):
            before=json.loads(OLD);after=json.loads(NEW);before['nftables'].append(copy.deepcopy(obj));after['nftables'].append(copy.deepcopy(obj))
            key='elem' if 'set' in obj else 'packets';row=after['nftables'][-1][next(iter(obj))]
            row[key]=[2] if key=='elem' else 1
            self.assertFalse(self.evaluate(dump(after),dump(before))['configuration_unchanged'])

    def test_ip_and_each_namespace_drift_refuse(self):
        self.assertFalse(self.evaluate(ip_after=b'[]')['configuration_unchanged'])
        for key in ('net','mount'):
            namespaces=copy.deepcopy(NS);namespaces['after'][key]='net:[999]' if key=='net' else 'mnt:[999]'
            self.assertFalse(self.evaluate(namespaces=namespaces)['configuration_unchanged'])
        malformed=[{},None,{'before':{},'after':{}}]
        for pair in ({'net':'HOST','mount':'HOST'}, {'net':'net:[0]','mount':'mnt:[101]'},
                     {'net':'mnt:[100]','mount':'net:[101]'}, {'net':100,'mount':'mnt:[101]'},
                     {'net':'net:[100]','mount':'mnt:[101]','extra':True}):
            malformed.append({'before':pair,'after':pair})
        for ns in malformed:
            with self.assertRaises(RuntimeError):self.evaluate(namespaces=ns)

    def test_duplicate_truncated_bound_nonfinite_and_structure_refuse(self):
        for raw in (b'{"nftables":[],"nftables":[]}',b'{"nftables":[{"rule":{"expr":[],"expr":[]}}]}',
                    NEW.rstrip()[:-1],b' '+b' '*(d.METADATA_LIMIT),b'{"nftables":[NaN]}',b'{"nftables":[1]}'):
            with self.assertRaises((RuntimeError,ValueError,RecursionError)):self.evaluate(raw)
        nested=0
        for _ in range(66):nested=[nested]
        with self.assertRaises(RuntimeError):self.evaluate(dump({'nftables':[{'unknown':nested}]}))
        with patch.object(d,'HOST_CONFIGURATION_NODE_LIMIT',5):
            with self.assertRaises(RuntimeError):self.evaluate()

    def test_future_verifier_recomputes_not_label_or_boolean_equality(self):
        result=self.evaluate()
        for mutation in (lambda v:v.__setitem__('configuration_unchanged',1),
                         lambda v:v['raw']['nft_before'].__setitem__('sha256','0'*64),
                         lambda v:v['anonymous_counter_deltas'][0]['delta'].__setitem__('bytes',0),
                         lambda v:v.__setitem__('unknown',True)):
            record=copy.deepcopy(result);mutation(record)
            with self.assertRaises(RuntimeError):d.verify_host_configuration_record(record,IP,OLD,IP,NEW,NS)
        with self.assertRaises(RuntimeError):d.verify_host_configuration_record(result,IP,OLD,IP,OLD,NS)
        other=copy.deepcopy(NS);other['after']['net']='net:[999]'
        with self.assertRaises(RuntimeError):d.verify_host_configuration_record(result,IP,OLD,IP,NEW,other)

class ActualOuter(unittest.TestCase):
    def run_outer(self,drift=False):
        with tempfile.TemporaryDirectory(prefix='aegis-host-config-INERT-') as td:
            stage=Path(td)/'stage';binary=Path(td)/'probe';binary.write_bytes(b'INERT_NOT_EXECUTABLE')
            adapter=terminal.OuterAdapter(stage,None,RuntimeError);count=0
            original=adapter.command
            def command(argv,**kwargs):
                nonlocal count
                if argv[0]=='nft':
                    count+=1
                    if count==1:return OLD
                    if drift:
                        nft=json.loads(NEW);rule(nft)['handle']=999;return dump(nft)
                    return NEW
                if argv[0]=='ip':return IP
                return original(argv,**kwargs)
            adapter.command=command
            with adapter.patches():
                if drift:
                    with self.assertRaises(RuntimeError):m.outer(str(binary),str(stage))
                else:m.outer(str(binary),str(stage))
            receipt=json.loads((stage/'receipt.json').read_bytes())
            comparison=json.loads((stage/'host-config-comparison.json').read_bytes())
            self.assertEqual((stage/'host-nft-before.json').read_bytes(),OLD)
            self.assertFalse(json.loads((stage/'host-difference.json').read_bytes())['exact_raw_nft_equal'])
            self.assertEqual(receipt['host_configuration_comparison']['sha256'],hashlib.sha256((stage/'host-config-comparison.json').read_bytes()).hexdigest())
            self.assertEqual(receipt['host_configuration_comparison']['configuration_unchanged'],not drift)
            self.assertEqual(receipt['cleanup']['host_network_rules_unchanged'],not drift)
            self.assertTrue(receipt['cleanup']['owned_session_absent']);self.assertTrue(receipt['cleanup']['watchdog_terminal'])
            self.assertFalse(receipt['production_or_target_network_or_independent_capture_or_signed_release_acceptance'])
            self.assertEqual(comparison['configuration_unchanged'],not drift)
            self.assertEqual(receipt['host_namespace_observations'],comparison['namespaces'])
            self.assertIsNotNone(receipt['host_namespace_observations']['before'])
            self.assertIsNotNone(receipt['host_namespace_observations']['after'])
            self.assertEqual(count,2)
    def test_actual_outer_config_only_path_preserves_raw_false(self):self.run_outer()
    def test_actual_outer_policy_drift_still_fails_and_retains_cleanup(self):self.run_outer(True)

    def test_invalid_counter_baseline_retained_then_refused_before_any_consumer(self):
        with tempfile.TemporaryDirectory(prefix='aegis-host-config-INERT-') as td:
            stage=Path(td)/'stage';binary=Path(td)/'probe';binary.write_bytes(b'INERT_NOT_EXECUTABLE')
            nft=json.loads(OLD);rule(nft)['expr'][3]['counter']['packets']=True;bad=dump(nft)
            adapter=terminal.OuterAdapter(stage,None,RuntimeError);original=adapter.command
            def command(argv,**kwargs):
                if argv[0]=='nft':return bad
                if argv[0]=='ip':return IP
                return original(argv,**kwargs)
            adapter.command=command
            with adapter.patches():
                with self.assertRaises(RuntimeError):m.outer(str(binary),str(stage))
            receipt=json.loads((stage/'receipt.json').read_bytes())
            self.assertEqual((stage/'host-nft-before.json').read_bytes(),bad)
            self.assertEqual((stage/'host-nft-after.json').read_bytes(),bad)
            self.assertEqual(adapter.processes,[])
            self.assertIsNone(receipt['host_configuration_comparison'])
            self.assertFalse(receipt['cleanup']['host_network_rules_unchanged'])
            self.assertFalse(receipt['owned_child_started']);self.assertFalse(receipt['independent_guard_started'])
            self.assertTrue(receipt['status'].startswith('FAIL'))

    def test_comparison_write_failure_retains_terminal_null_reference(self):
        with tempfile.TemporaryDirectory(prefix='aegis-host-config-INERT-') as td:
            stage=Path(td)/'stage';binary=Path(td)/'probe';binary.write_bytes(b'INERT_NOT_EXECUTABLE')
            adapter=terminal.OuterAdapter(stage,None,RuntimeError)
            original=m.d.write_json
            def write(root,name,value):
                if name=='host-config-comparison.json':raise PermissionError('INERT_WRITE_REFUSAL')
                return original(root,name,value)
            with adapter.patches(),patch.object(m.d,'write_json',side_effect=write):
                with self.assertRaises(RuntimeError):m.outer(str(binary),str(stage))
            receipt=json.loads((stage/'receipt.json').read_bytes())
            self.assertIsNone(receipt['host_configuration_comparison'])
            self.assertFalse((stage/'host-config-comparison.json').exists())
            self.assertTrue(receipt['cleanup']['owned_session_absent']);self.assertTrue(receipt['cleanup']['watchdog_terminal'])
            self.assertIn({'phase':'host_readback','type':'PermissionError'},receipt['errors'])
            self.assertTrue(receipt['status'].startswith('FAIL'))

if __name__=='__main__':unittest.main()
