""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
import json
from datetime import datetime
from connectors.core.connector import get_logger, ConnectorError
from .constants import *

logger = get_logger('red-canary')


class RedCanary():
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if self.server_url.startswith('https://') or self.server_url.startswith('http://'):
            self.server_url = self.server_url.strip('/') + '/openapi/v3/'
        else:
            self.server_url = 'https://{0}'.format(self.server_url.strip('/')) + '/openapi/v3/'
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')

    def make_api_call(self, method='GET', endpoint=None, params=None, data=None,
                      json=None, flag=False):
        if endpoint:
            url = '{0}{1}'.format(self.server_url, endpoint)
        else:
            url = '{0}'.format(self.server_url)
        logger.info('Request URL {0}'.format(url))
        headers = {"Accept": "application/json", "Content-Type": "application/json", "X-Api-Key": self.api_key}
        try:
            response = requests.request(method=method, url=url, params=params, data=data, json=json,
                                        headers=headers,
                                        verify=self.verify_ssl)
            if response.ok:
                result = response.json()
                if result.get('error'):
                    raise ConnectorError('{}'.format(result.get('error').get('message')))
                if response.status_code == 204 or response.status_code == 201:
                    return {"Status": "Success", "Message": "Executed successfully"}
                return result
            elif messages_codes[response.status_code]:
                logger.error('{0}'.format(messages_codes[response.status_code]))
                raise ConnectorError('{0}'.format(messages_codes[response.status_code]))
            else:
                logger.error(
                    'Fail To request API {0} response is : {1} with reason: {2}'.format(str(url),
                                                                                        str(response.content),
                                                                                        str(response.reason)))
                raise ConnectorError(
                    'Fail To request API {0} response is :{1} with reason: {2}'.format(str(url),
                                                                                       str(response.content),

                                                                                       str(response.reason)))

        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(messages_codes['ssl_error']))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(messages_codes['timeout_error']))
        except Exception as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))


def build_payload(params, input_params_list):
    result = {k: v for k, v in params.items() if v is not None and v != '' and k in input_params_list}
    return result


def handle_datetime(date_ts):
    try:
        conv_date_time = datetime.strptime(date_ts, '%Y-%m-%dT%H:%M:%S.%fZ').strftime("%Y-%m-%dT%H:%M:%SZ")
    except:
        import sys
        ver = sys.version_info
        if ver.major == 3 and ver.minor == 6:
            date_ts = date_ts[0:-3] + date_ts[-2:]
        conv_date_time = datetime.strptime(date_ts, '%Y-%m-%dT%H:%M:%S.%fZ').strftime("%Y-%m-%dT%H:%M:%SZ")
    return conv_date_time


def check_health(config):
    try:
        logger.info("Invoking check_health")
        redcanary = RedCanary(config)

        if redcanary.make_api_call(endpoint='managed_portal_users'):
            return True
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def list_detections(config, params):
    try:
        obj = RedCanary(config)
        result = build_payload(params, action_input_parameters.get('list_detections'))

        if result:
            if result.get('since'):
                since_time = handle_datetime(result.get('since'))
                result['since'] = since_time

        response = obj.make_api_call(endpoint='detections', params=result)
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def get_detection(config, params):
    try:
        obj = RedCanary(config)
        result = build_payload(params, action_input_parameters.get('get_detection'))

        response = obj.make_api_call(
            endpoint='detections/{detection_id}'.format(detection_id=result.get('detection_id')))
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def list_detection_marked_indicators_of_compromise(config, params):
    try:
        obj = RedCanary(config)
        result = build_payload(params, action_input_parameters.get('list_detection_marked_indicators_of_compromise'))
        result.pop('detection_id')
        response = obj.make_api_call(endpoint='detections/{detection_id}/marked_indicators_of_compromise'.format(
            detection_id=params.get('detection_id')), params=result)
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def acknowledge_detection(config, params):
    try:
        obj = RedCanary(config)
        result = build_payload(params, action_input_parameters.get('acknowledge_detection'))

        response = obj.make_api_call(method='PATCH', endpoint='detections/{detection_id}/mark_acknowledged'.format(
            detection_id=result.get('detection_id')))
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def update_remediation_state(config, params):
    try:
        obj = RedCanary(config)
        result = build_payload(params, action_input_parameters.get('update_remediation_state'))
        result.pop('detection_id')
        if result:
            if result.get('remediation_state'):
                result['remediation_state'] = remediation_state_mapping.get(result.get('remediation_state'))

        response = obj.make_api_call(method='PATCH',
                                     endpoint='detections/{detection_id}/update_remediation_state'.format(
                                         detection_id=params.get('detection_id')), data=result)
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def list_endpoints(config, params):
    try:
        obj = RedCanary(config)
        result = build_payload(params, action_input_parameters.get('list_endpoints'))

        if result:
            if result.get('order_by'):
                result['order_by'] = endpoint_order_by_mapping.get(result.get('order_by'))

        response = obj.make_api_call(endpoint='endpoints', params=result)
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def get_endpoint(config, params):
    try:
        obj = RedCanary(config)
        result = build_payload(params, action_input_parameters.get('get_endpoint'))

        response = obj.make_api_call(endpoint='endpoints/{endpoint_id}'.format(endpoint_id=result.get('endpoint_id')))
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def isolate_endpoint(config, params):
    try:
        obj = RedCanary(config)
        result = build_payload(params, action_input_parameters.get('isolate_endpoint'))

        if not isinstance(result.get('ids'), list):
            ids = [str(x) for x in result.get('ids')]
            result['ids'] = ids

        response = obj.make_api_call(method='POST', endpoint='endpoints/isolate', data=result)
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def deisolate_endpoint(config, params):
    try:
        obj = RedCanary(config)
        result = build_payload(params, action_input_parameters.get('deisolate_endpoint'))

        if not isinstance(result.get('ids'), list):
            ids = [str(x) for x in result.get('ids')]
            result['ids'] = ids

        response = obj.make_api_call(method='DELETE', endpoint='endpoints/isolate', data=result)
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


operations = {
    'list_detections': list_detections,
    'get_detection': get_detection,
    'list_detection_marked_indicators_of_compromise': list_detection_marked_indicators_of_compromise,
    'acknowledge_detection': acknowledge_detection,
    'update_remediation_state': update_remediation_state,
    'list_endpoints': list_endpoints,
    'get_endpoint': get_endpoint,
    'isolate_endpoint': isolate_endpoint,
    'deisolate_endpoint': deisolate_endpoint
}
