""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

messages_codes = {
    400: 'Invalid input',
    401: 'Unauthorized: Invalid credentials',
    500: 'Invalid input',
    404: 'Invalid input',
    'ssl_error': 'SSL certificate validation failed',
    'timeout_error': 'The request timed out while trying to connect to the remote server. Invalid Server URL.'
}

remediation_state_mapping = {
    "Remediated": "remediated",
    "Not Remediated False Positive": "not_remediated_false_positive",
    "Not Remediated Sanctioned Activity": "not_remediated_sanctioned_activity",
    "Not Remediated Unwarranted": "not_remediated_unwarranted"
}

endpoint_order_by_mapping = {
    "Hostname": "hostname",
    "ID": "id"
}

action_input_parameters = {
    "list_detections": ["page", "per_page", "since"],
    "get_detection": ["detection_id"],
    "list_detection_marked_indicators_of_compromise": ["detection_id", "page", "per_page"],
    "acknowledge_detection": ["detection_id"],
    "update_remediation_state": ["detection_id", "remediation_state", "comment"],
    "list_endpoints": ["page", "per_page", "order_by", "filter_query"],
    "get_endpoint": ["endpoint_id"],
    "isolate_endpoint": ["ids"],
    "deisolate_endpoint": ["ids"]
}
