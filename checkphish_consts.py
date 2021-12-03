# File: checkphish_consts.py
#
# Copyright (c) Splunk Community, 2021
#
# Licensed under the Apache License, Version 2.0 (the "License");

CHECKPHISH_CHECK_STATUS_ENDPOINT = "/neo/scan/status"
CHECKPHISH_DETONATE_URL_ENDPOINT = "/neo/scan/"
CHECKPHISH_SCAN_TYPE_VALUE_LIST = ["quick", "full"]

# constants relating to "get_error_msg_from_exception"
CHECKPHISH_ERR_CODE_MSG = "Error code unavailable"
CHECKPHISH_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
CHECKPHISH_PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
