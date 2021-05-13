import os
import json

import sqlite3

import uuid
import time
from time import sleep
from datetime import datetime, timedelta

import requests


class CarbonBlackCloud:
    '''
        This is a wrapper around CBC's APIs.
        Import this class to interact with the various CBC endpoints.
    '''

    def __init__(self, config, log):
        '''
            Initialize the CarbonBlackCloud class. Assign self variables for use
                throughout the script.

            Inputs:
                config loaded with the settings from the config.ini

            Outputs:
                self
        '''
        try:
            self.class_name = 'CarbonBlackCloud'
            self.log = log
            self.log.info('[%s] Initializing', self.class_name)

            self.config = config
            self.url = clean_url(config['CarbonBlack']['url'])
            self.org_key = config['CarbonBlack']['org_key']
            self.api_id = config['CarbonBlack']['api_id']
            self.api_key = config['CarbonBlack']['api_key']
            self.cust_api_id = config['CarbonBlack']['custom_api_id']
            self.cust_api_key = config['CarbonBlack']['custom_api_key']
            self.lr_api_id = config['CarbonBlack']['lr_api_id']
            self.lr_api_key = config['CarbonBlack']['lr_api_key']
            self.headers = {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache',
                'User-Agent': '{0} / {1} v{2} / {3}'.format(config['general']['description'],
                                                            config['general']['name'],
                                                            config['general']['version'],
                                                            config['general']['author'])
            }
            self.feed = None
            self.iocs = None
            self.new_reports = []
            self.device_id = None
            self.session_id = None
            self.supported_commands = None

        except Exception as err:
            self.log.exception(err)

    #
    # CBC Platform
    #
    def get_processes(self, sha256, window):
        '''
            The Get Processes API is asyncronous. We first make the request for the search,
                then use the `job_id` to get the results. Pagination may occur.
        '''
        self.log.info('[%s] Getting processes for {} within the last {}'.format(sha256, window), self.class_name)

        try:
            # Define the request basics
            url = '/'.join([self.url, 'api/investigate/v2/orgs', self.org_key, 'processes/search_jobs'])
            headers = self.headers
            headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
            body = {
                'query': 'process_hash:{0}'.format(sha256),
                'rows': 5000,
                'time_range': {
                    'window': '-{0}'.format(window)
                }
            }
            
            # Request the data from the endpoint
            r = requests.post(url, headers=headers, data=json.dumps(body))

            # If the request was successful
            if r.status_code == 200:
                # Get the job_id
                job_id = r.json()['job_id']

                # Prep recursion
                start = 0
                rows = 500
                page = 0
                total = rows
                processes = None

                while start < total:
                    process_results = self.get_process_results(job_id, start, rows)
                    
                    # Make sure the search has completed before moving on
                    tries = 0
                    while process_results['contacted'] != process_results['completed']:
                        if tries > 5:
                            self.log.error('[%s] !!! Tried {0} times to get {1}. Giving up.'.format(tries, job_id), self.class_name)
                            raise RuntimeError('[%s] !!! Tried {0} times to get {1}. Giving up.'.format(tries, job_id), self.class_name)

                        tries += 1

                        # Slowly increase the wait time
                        sleep(tries)

                        process_results = self.get_process_results(job_id, start, rows)

                    if processes is None:
                        processes = process_results
                    else:
                        processes['results'] += process_results['results']

                    total = process_results['num_available']
                    start = start + rows
                    page += 1

                processes['pages'] = page

                return processes

            else:
                self.log.error('[%s] Error {0}: {1}'.format(r.status_code, r.text), self.class_name)
                raise Exception('Error {0}: {1}'.format(r.status_code, r.text))
            
        except Exception as err:
            self.log.exception(err)

    def get_process_results(self, job_id, start, rows):
        '''
        '''
        self.log.info('[%s] Getting process results for job {0} starting from {1} with {2} rows.'.format(job_id, start, rows), self.class_name)

        # Define the request basics
        url = '/'.join([self.url, 'api/investigate/v2/orgs', self.org_key, 'processes/search_jobs', job_id, 'results'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
        params = {
            'start': start,
            'rows': rows
        }

        r = requests.get(url, headers=headers, params=params)

        if r.status_code == 200:
            data = r.json()

            return data

        self.log.error('[%s] Error {0}: {1}'.format(r.status_code, r.text), self.class_name)
        raise Exception('Error {0}: {1}'.format(r.status_code, r.text))

    def get_device(self, device_id):
        '''
            !!! comment here
        '''
        self.log.info('[%s] Getting device information: {0}.'.format(device_id), self.class_name)

        # Define the request basics
        url = '/'.join([self.url, 'appservices/v6/orgs', self.org_key, 'devices/_search'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
        body = {
            'criteria': {
                'id': ['{0}'.format(device_id)]
            }
        }

        # Request the data from the endpoint
        r = requests.post(url, headers=headers, data=json.dumps(body))

        # If the request was successful
        if r.status_code == 200:
            self.log.info('[%s] Pulled device information: {0}.'.format(device_id), self.class_name)
            data = r.json()
            return data
        
        self.log.error('[%s] Error {0}: {1}'.format(r.status_code, r.text), self.class_name)
        raise Exception('Error {0}: {1}'.format(r.status_code, r.text))

    def isolate_device(self, device_id):
        '''
            Isolate a device.

            Inputs
                device_id (int):    The ID of the device

            Raises
                TypeError when device_id is not an integer

            Output
                An object of the device
        '''

        if isinstance(device_id, int) is False:
            raise TypeError('Expected device_id input type is int.')

        try:
            url = '/'.join([self.url, 'appservices/v6/orgs', self.org_key, 'device_actions'])
            headers = self.headers
            headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
            body = {
                'action_type': 'QUARANTINE',
                'device_id': [device_id],
                'options': {
                    'toggle': 'ON'
                }
            }

            # Request the data from the endpoint
            r = requests.post(url, headers=headers, data=json.dumps(body))

            # If the request was successful
            if r.status_code == 204:
                return True

            else:
                self.log.error('[%s] Error {0}: {1}'.format(r.status_code, r.text), self.class_name)
                raise Exception('Error {0}: {1}'.format(r.status_code, r.text))

        except Exception as err:
            self.log.exception(err)

    def update_policy(self, device_id, policy):
        '''
            Updates a device's policy to the given policy name or id.

            Inputs
                device_id (int):    The ID of the device
                policy (str|int):  The name of the policy, or the id of the policy as an int

            Raises
                TypeError when device_id is not an integer

            Output
                An object of the device
        '''

        self.log.info('[%s] update_policy()', self.class_name)

        if isinstance(device_id, int) is False:
            raise TypeError('Expected device_id input type is integer.')
        if isinstance(policy, str):
            search_type = 'name'
            policy_id = self.get_policy_id(policy)
            if policy_id is None:
                self.log.info('[%s] No Policy with name "{0}" found.'.format(policy), self.class_name)
                return None
        elif isinstance(policy, int):
            search_type = 'id'
            policy_id = policy
        else:
            raise TypeError('Expected policy input type is string or integer.')

        try:
            url = '/'.join([self.url, 'appservices/v6/orgs', self.org_key, 'device_actions'])
            headers = self.headers
            headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
            body = {
                'action_type': 'UPDATE_POLICY',
                'device_id': [device_id],
                'options': {
                    'policy_id': policy_id
                }
            }
            r = requests.post(url, headers=headers, data=json.dumps(body))
            if r.status_code == 204:
                self.log.info('[%s] Moved device with id {0} to policy "{1}".'.format(device_id, policy), self.class_name)
                return True

            else:
                self.log.exception('[%s] update_policy(): Error: {0}'.format(r.status_code), self.class_name)

        except Exception as err:
            self.log.exception('[%s] update_policy(): %s', self.class_name, err)

    def get_policy_id(self, policy_name):
        self.log.info('[%s] Looking for policy with name "{0}".'.format(policy_name), self.class_name)

        url = '/'.join([self.url, 'integrationServices/v3/policy'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.api_key, self.api_id)

        r = requests.get(url, headers=headers)

        if r.status_code == 200:
            data = r.json()
            policies = data['results']

            for policy in policies:
                if policy['name'] == policy_name:
                    self.log.info('[%s] Found policy "{0}" with id "{1}".'.format(policy_name, policy['id']), self.class_name)

                    return int(policy['id'])

            self.log.info('[%s] No Policy with name "{0}" found.'.format(policy_name), self.class_name)
            return None

    #
    # CBC Endpoint Standard
    #
    def search_reputations(self, sha256):
        '''
            In CBC Endpoint Standard we can configure a reputation override (ban a hash).
            This functionality is coming soon to CBC Enterprise EDR.

            Inputs
                sha256 (str):   The has to search for
            
            Outputs
                An object of the results
            
            Raises
                TypeError when sha256 is not a string
                Something when the length is not 64 characters
        '''

        self.log.info('[%s] Searching for reputation override with SHA256 {0}'.format(sha256), self.class_name)

        url = '{0}/appservices/v6/orgs/{1}/reputations/overrides/_search'.format(self.url, self.org_key)
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
        body = {
            'query': '{0}'.format(sha256),
            'sort_field': 'create_time',
            'sort_order': 'asc'
        }
        r = requests.get(url, headers=headers, body=json.loads(body))

        if r.status_code == 200:
            data = r.json()
            reputations = data['results']

            self.log.info('[%s] Found {0} reputation overrides for {1}'.format(len(reputations), sha256), self.class_name)                    

    def configure_reputation(self):
        pass

    #
    # CBC Enterprise EDR
    #
    def get_all_feeds(self):
        '''
            Pull all feeds from Enterprise EDR.

            Inputs: None

            Output
                An object of the feeds
        '''

        self.log.info('[%s] Getting all feeds', self.class_name)

        url = '/'.join([self.url, 'threathunter/feedmgr/v2/orgs', self.org_key, 'feeds'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)

        try:
            r = requests.get(url, headers=headers)
            feeds = r.json()
            self.log.info('[%s] Pulled {0} feeds'.format(len(feeds['results'])), self.class_name)
            return feeds['results']

        except Exception as err:
            self.log.exception(err)

    def get_feed(self, feed_id=None, feed_name=None, use_cache=True):
        '''
            Gets the details for a single feed. If feed_name is provided, it will
                pull all feeds and filter by name. If feed_id is provided, it
                pulls based on that id.

            Inputs
                feed_id (str):      ID of the feed to pull
                feed_name (str):    Name of the feed to pull

            Raises
                TypeError when feed_id is not an integer
                TypeError when feed_name is not a string

            Outputs
                Object  an object of found feed
                None    no feed was found
                False   both feed_id and feed_name provided
                False   neither feed_id nor feed_name provided
        '''

        self.log.info('[%s] Getting feed', self.class_name)

        if isinstance(feed_id, str) is False and feed_id is not None:
            raise TypeError('Expected feed_id input type is string.')
        if isinstance(feed_name, str) is False and feed_name is not None:
            raise TypeError('Expected feed_name input type is string.')

        if feed_id is None and feed_name is None:
            self.log.info('[%s] Missing feed_id and feed_name. Need at least one', self.class_name)
            raise Exception('Missing feed_id and feed_name. Need at least one')

        if feed_id is not None and feed_name is not None:
            self.log.info('[%s] Both feed_id and feed_name provided. Please only provide one', self.class_name)
            raise Exception('Both feed_id and feed_name provided. Please only provide one')

        if self.feed is not None and use_cache is True:
            return self.feed

        try:
            # If the feed_name was provided, get all the feeds and check their names
            if feed_name is not None:
                feeds = self.get_all_feeds()
                for feed in feeds:
                    if feed['name'] == feed_name:
                        feed_id = feed['id']
                        break

            # If no feeds were found, return None
            if feed_id is None:
                self.log.info('[%s] No feed found with name "{0}"'.format(feed_name), self.class_name)
                return None

            try:
                url = '/'.join([self.url, 'threathunter/feedmgr/v2/orgs', self.org_key, 'feeds', feed_id])
                headers = self.headers
                headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)

                r = requests.get(url, headers=headers)
                feed = r.json()

                # Save to cache
                self.feed = feed

                # Build a cache of the existing IOCs in the feed
                # This is used for deduplication when IOCs are added
                if self.iocs is None:
                    self.iocs = []

                for report in feed['reports']:
                    for ioc in report['iocs_v2']:
                        for value in ioc['values']:
                            self.iocs.append(value)

                self.log.info('[%s] Pulled feed "{}"'.format(feed['feedinfo']['name']), self.class_name)
                return feed

            except Exception as err:
                self.log.exception(err)

        except Exception as err:
            self.log.exception(err)

    def create_feed(self, name, url, summary):
        '''
            Creates a new feed in CBC Enterprise EDR

            Inputs
                name (str):     Name of the feed to create
                url (str):      URL of the feed
                summary (str):  Summary of the feed

            Raises
                TypeError when name is not a string
                TypeError when url is not a string
                TypeError when summary is not a string

            Output
                An object of the newly created feed
        '''
        self.log.info('[%s] Creating feed "{}"'.format(name), self.class_name)

        if isinstance(name, str) is False:
            raise TypeError('Expected name input type is string.')
        if isinstance(url, str) is False:
            raise TypeError('Expected url input type is string.')
        if isinstance(summary, str) is False:
            raise TypeError('Expected summary input type is string.')

        try:
            feed_info = {
                'name': name,
                'owner': self.org_key,
                'provider_url': url,
                'summary': summary,
                'category': 'Partner',
                'access': 'private',
            }

            feed = {
                'feedinfo': feed_info,
                'reports': []
            }

            url = '/'.join([self.url, 'threathunter/feedmgr/v2/orgs', self.org_key, 'feeds'])
            headers = self.headers
            headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)

            r = requests.post(url, headers=headers, json=feed)

            if r.status_code == 200:
                new_feed = r.json()
                feed['feedinfo']['id'] = new_feed['id']


                self.log.info('[%s] Created feed "{0}" with 0 indicators'.format(name), self.class_name)
            else:
                self.log.error('[%s] Error creating feed: {0} {1}'.format(r.status_code, r.text), self.class_name)

            return feed

        except Exception as err:
            self.log.exception(err)

    def update_feed(self, feed_name):
        # If watchlists are enabled in take_action() and there were bad emails, update the watchlist
        if self.new_reports is None or len(self.new_reports) == 0:
            return None

        # Get the feed so we can get the id
        feed = self.get_feed(feed_name=feed_name)
        for report in self.new_reports:
            feed['reports'].append(report)
        feed_id = feed['feedinfo']['id']

        url = '/'.join([self.url, 'threathunter/feedmgr/v2/orgs', self.org_key, 'feeds', feed_id, 'reports'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
        body = { "reports": feed['reports'] }


        r = requests.post(url, headers=headers, json=body)
        data = r.json()
        return data

    def create_report(self, timestamp, title, description, severity, link, tags, sha256):
        '''
            Creates a report for Enterprise EDR feeds

            Inputs
                timestamp (int):    Epoch timestamp to be added to the report
                title (str):        Title of the report
                description (str):  Description of the report
                severity (int):     Severity of the report [1-10]
                link (str):         Link to report
                tags (list of str): List of tags
                md5 (str):          Hash IOC to be added to the report

            Raises
                TypeError if timestamp is not an integer
                TypeError if title is not a string
                TypeError if description is not a string
                TypeError if severity is not a string
                TypeError if link is not a string
                TypeError if tags is not a list
                TypeError if md5 is not a string
                ValueError if md5 is not 32 characters long

            Output
                An object of the newly created report
        '''

        if isinstance(timestamp, int) is False:
            raise TypeError('Expected timestamp input type is integer.')
        if isinstance(title, str) is False:
            raise TypeError('Expected title input type is string.')
        if isinstance(description, str) is False:
            raise TypeError('Expected description input type is string.')
        if isinstance(severity, int) is False:
            raise TypeError('Expected severity input type is integer.')
        if isinstance(link, str) is False:
            raise TypeError('Expected link input type is string.')
        if isinstance(tags, list) is False:
            raise TypeError('Expected tags input type is a list of strings.')
        if isinstance(sha256, str) is False:
            raise TypeError('Expected sha256 input type is string.')
        if len(sha256) != 64:
            raise ValueError('Expected sha256 to be 64 characters long')

        self.log.info('[%s] Creating new report', self.class_name)

        if self.iocs is None:
            self.iocs = []

        try:
            report = {
                'id': str(uuid.uuid4()),
                'timestamp': timestamp,
                'title': title,
                'description': description,
                'severity': severity,
                'link': link,
                'tags': tags,
                'iocs_v2': [{
                    'id': sha256,
                    'match_type': 'equality',
                    'values': [sha256],
                    'field': 'process_hash'
                }]
            }

            # Keep track of reports for batch submission
            self.new_reports.append(report)
            # Keep track of IOCs for deduplication
            self.iocs.append(sha256)

            self.log.info('[%s] Created report: {}'.format(report), self.class_name)

            return report

        except Exception as err:
            self.log.exception(err)

    #
    # CBC Live Response helpers
    #
    def start_session(self, device_id, wait=False):
        '''
            Starts a CBC LiveResponse session. The session_id is saved in
                self.session_id

            Inputs
                device_id (int):    ID of the device to start the session on
                wait (bool):        Overrides default wait action. Checks get_session() every 15 seconds if True

            Raises
                TypeError when device_id is not an integer
                TypeError when wait is not a boolean
                Exception when response status_code is anything other than 200

            Output
                data (dict):    Raw JSON of get_session() response if wait is True
                data (dict):    Raw JSON of request to start session if wait is False
        '''

        if isinstance(device_id, int) is False:
            raise TypeError('Expected device_id input type is integer.')
        if isinstance(wait, bool) is False:
            raise TypeError('Expected wait input type is boolean.')

        try:
            self.log.info('[%s] Starting Live Response session', self.class_name)
            url = '{0}/integrationServices/v3/cblr/session/{1}'.format(self.url, device_id)
            headers = {
                'Content-Type': 'application/json',
                'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
            }
            r = requests.post(url, headers=headers)

            if r.status_code == 200:
                data = r.json()

                self.device_id = device_id
                self.session_id = data['id']
                self.supported_commands = data['supported_commands']

                self.log.debug('[%s] {}'.format(json.dumps(data, indent=4)), self.class_name)

                if wait:
                    while data['status'] == 'PENDING':
                        sleep(15)
                        data = self.get_session()

                return data

            else:
                raise Exception('{0}: {1}'.format(r.status_code, r.text))

        except Exception as err:
            self.log.exception(err)

    def get_session(self):
        '''
            Get the status of a session

            Inputs: None

            Raises
                Exception if no session is established
                Exception if response status_code is not 200

            Output
                data (dict):    Returns the raw JSON of the request
        '''

        try:
            if self.session_id is None:
                self.log.info('[%s] Cannot get session status. No session established for session ID {0}'.format(self.session_id),
                              self.class_name)
                raise Exception('No session established')

            self.log.info('[%s] Getting status of session: {0}'.format(self.session_id), self.class_name)
            # url = '{0}/appservices/v6/orgs/{1}/liveresponse/sessions/{2}'.format(self.url, self.org_key, self.session_id)
            url = '{0}/integrationServices/v3/cblr/session/{1}'.format(self.url, self.session_id)
            headers = {
                'Content-Type': 'application/json',
                'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
            }
            r = requests.get(url, headers=headers)

            if r.status_code == 200:
                data = r.json()
                self.log.debug('[%s] {}'.format(json.dumps(data, indent=4)), self.class_name)
                self.supported_commands = data['supported_commands']

                return data

            elif r.status_code == 404:
                # If a session request times out, this message is given:
                #   404: {"reason":"Session not found", "success":false, "status":"NOT_FOUND"}
                data = r.json()
                if data['reason'] == 'Session not found':
                    self.log.error('[%s] Session timed out.')
                
                return False

            else:
                raise Exception('{0}: {1}'.format(r.status_code, r.text))

        except Exception as err:
            self.log.exception(err)

    def send_command(self, command, argument=None, wait=False):
        '''
            Sends a LiveResponse command to an endpoint

            Inputs
                command (str):      Command to execute
                arguments (str):    Supporting arguments for the command
                wait (bool):        If True, wait until command is finished and return result
                                    If False, send response from request

            Raises
                TypeError if command is not a string
                TypeError if argument is not a string or None

            Outputs
                data (dict): Raw JSON from command_status(data[id]) if wait is True
                data (dict): Raw JSON from response to request if wait is False
        '''

        if isinstance(command, str) is False:
            raise TypeError('Expected command input type is string.')
        if argument is not None and isinstance(argument, str) is False:
            raise TypeError('Expected argument input type is string or None.')

        self.log.info('[%s] Sending command to LR session: {0}'.format(command), self.class_name)

        try:
            if self.session_id is None:
                self.log.error('Error: no session')
                return 'Error: no session'

            if command not in self.supported_commands:
                self.log.error('Error: command not in available commands: {0}'.format(command))
                return 'Error: command not in available commands: {0}'.format(command)

            try:
                url = '{0}/integrationServices/v3/cblr/session/{1}/command'.format(self.url, self.session_id)
                headers = {
                    'Content-Type': 'application/json',
                    'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
                }

                body = {
                    'session_id': self.session_id,
                    'name': command
                }
                if argument is not None:
                    body['object'] = argument

                r = requests.post(url, headers=headers, json=body)

                data = r.json()

                self.log.debug('[%s] {}'.format(json.dumps(data, indent=4)), self.class_name)

                if wait:
                    sleep(1)
                    while data['status'] == 'pending':
                        sleep(5)
                        data = self.command_status(data['id'])

                return data

            except Exception as err:
                self.log.exception(err)

        except Exception as err:
            self.log.exception(err)

    def command_status(self, command_id):
        '''
            Get the status of a previously submitted command

            Inputs
                command_id (int):   ID of the command previously submitted

            Raises
                TypeError if command_id is not an integer
                Exception if no session is established

            Output:
                Raw JSON of the response
        '''

        if isinstance(command_id, int) is False:
            raise TypeError('Expected command_id input type is integer.')

        self.log.info('[%s] Getting status of LR command: {0}'.format(command_id), self.class_name)

        try:
            if self.session_id is None:
                self.log.info('[%s] Cannot get session status. No session established for session with ID {0}'.format(self.session_id),
                              self.class_name)
                raise Exception('No session established')

            self.log.info('[%s] Getting status of command: {0}'.format(command_id), self.class_name)

            url = '{0}/integrationServices/v3/cblr/session/{1}/command/{2}'.format(self.url, self.session_id,
                                                                                   command_id)
            headers = {
                'Content-Type': 'application/json',
                'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
            }
            r = requests.get(url, headers=headers)

            if r.status_code == 200:
                data = r.json()

                self.log.debug('[%s] {}'.format(json.dumps(data, indent=4)), self.class_name)
                return data

            else:
                raise Exception('{0}: {1}'.format(r.status_code, r.text))

        except Exception as err:
            self.log.exception(err)

    def close_session(self):
        '''
            Closes a LiveResponse session.

            Inputs: None

            Outputs
                Raw JSON response from the request

            > Note: When closing a LR session on an endpoint, if there are any
                other active sessions on that endpoint they will be closed as well.
        '''

        self.log.info('[%s] Closing session: {0}'.format(self.session_id), self.class_name)

        try:
            if self.session_id is None:
                self.log.info('Error: no session')
                return 'Error: no session'

            url = '{0}/integrationServices/v3/cblr/session'.format(self.url)
            headers = {
                'Content-Type': 'application/json',
                'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
            }

            body = {
                'session_id': self.session_id,
                'status': 'CLOSE'
            }

            r = requests.put(url, headers=headers, json=body)

            data = r.json()

            self.log.debug('[%s] {}'.format(json.dumps(data, indent=4)), self.class_name)
            return data

        except Exception as err:
            self.log.exception(err)


class Proofpoint:
    def __init__(self, config, log):
        '''
            Initialize the Proofpoint class

            Inputs
                config: Dict containing settings from config.ini

            Output
                self
        '''
        try:
            self.class_name = 'Proofpoint'
            self.log = log
            self.log.info('[%s] Initializing', self.class_name)
            self.config = config

            self.url = clean_url(config['Proofpoint']['url'])
            self.username = config['Proofpoint']['principal']
            self.password = config['Proofpoint']['secret']
            self.headers = {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache',
                'User-Agent': '{0} / {1} v{2} / {3}'.format(config['general']['description'],
                                                            config['general']['name'],
                                                            config['general']['version'],
                                                            config['general']['author'])
            }

        except Exception as err:
            self.log.exception(err)

    def get_messages_delivered(self, interval):
        self.log.info('[%s] Getting delivered messages within {0}'.format(interval), self.class_name)

        url = self.url + '/v2/siem/messages/delivered'
        params = {
            'interval': interval,
            'format': 'JSON',
            'threatType': 'attachment'
        }
        r = requests.get(url, headers=self.headers, params=params,
                         auth=(self.username, self.password))

        if r.status_code == 200:
            data = json.loads(r.text)

            messages_delivered = []

            for message in data['messagesDelivered']:
                for info in message['threatsInfoMap']:
                    if info['threatType'] == 'attachment' and info['classification'] == 'malware':
                        for part in message['messageParts']:
                            if part['disposition'] == 'attached':
                                # for testing / debug
                                if 'debug' in self.config:
                                    if self.config['debug']['sample']:
                                        part['sha256'] = self.config['debug']['sample']

                                messages_delivered.append(message)
                                continue

            self.log.info('[%s] Found {0} malicious emails delivered'.format(len(messages_delivered)), self.class_name)
            return messages_delivered
        else:
            self.log.warning('[%s] Unable to pull delivered messages: {0} {1}'.format(r.status_code, r.text), self.class_name)
            raise Exception('{0}: {1}'.format(r.status_code, r.text))

    def get_messages_blocked(self, interval):
        self.log.info('[%s] Getting blocked messages within {0}'.format(interval), self.class_name)

        url = self.url + '/v2/siem/messages/blocked'
        params = {
            'interval': interval,
            'format': 'JSON',
            'threatType': 'attachment'
        }
        r = requests.get(url, headers=self.headers, params=params,
                         auth=(self.username, self.password))

        if r.status_code == 200:
            data = json.loads(r.text)

            messages_blocked = []

            for message in data['messagesBlocked']:
                for info in message['threatsInfoMap']:
                    if info['threatType'] == 'attachment' and info['classification'] == 'malware':
                        for part in message['messageParts']:
                            if part['disposition'] == 'attached':
                                # for testing / debug
                                if 'debug' in self.config:
                                    if self.config['debug']['sample']:
                                        part['sha256'] = self.config['debug']['sample']

                                messages_blocked.append(message)
                                continue

            self.log.info('[%s] Found {0} malicious emails blocked'.format(len(messages_blocked)), self.class_name)
            return messages_blocked
        else:
            self.log.warning('[%s] Unable to pull blocked messages: {0} {1}'.format(r.status_code, r.text), self.class_name)
            raise Exception('{0}: {1}'.format(r.status_code, r.text))


class NSX:
    def __init__(self, config, log):
        '''
            Initialize the NSX class

            Inputs
                config: Dict containing settings from config.ini

            Output
                self
        '''
        self.url = None
        self.username = None
        self.password = None
        self.headers = None

        try:
            self.class_name = 'NSX'
            self.log = log
            self.log.info('[%s] Initializing', self.class_name)
            self.config = config

            if 'url' in config['NSX']:
                self.url = clean_url(config['NSX']['url'])
            if 'username' in config['NSX']:
                self.username = config['NSX']['username']
            if 'password' in config['NSX']:
                self.password = config['NSX']['password']
            if 'general' in config:
                self.headers = {
                    'Content-Type': 'application/json',
                    'Cache-Control': 'no-cache',
                    'User-Agent': '{0} / {1} v{2} / {3}'.format(config['general']['description'],
                                                                config['general']['name'],
                                                                config['general']['version'],
                                                                config['general']['author'])
                }

        except Exception as err:
            self.log.exception(err)

    def search_devices(self, device_name):
        '''
            !!! comment here
        '''
        self.log.info('[%s] Searching for device: {0}.'.format(device_name), self.class_name)

        # Define the request basics
        url = '/'.join([self.url, 'api/v1/fabric/virtual-machines'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
        params = {
            'display_name': device_name
        }

        # Request the data from the endpoint
        r = requests.post(url, headers=headers, params=params,
                          auth=(self.username, self.password))

        # If the request was successful
        if r.status_code == 200:
            self.log.info('[%s] Pulled device information: {0}.'.format(device_name), self.class_name)
            data = r.json()
            return data
        
        self.log.error('[%s] Error {0}: {1}'.format(r.status_code, r.text), self.class_name)
        raise Exception('Error {0}: {1}'.format(r.status_code, r.text))

    def add_tag(self, resource_id, tag_name):
        '''
            !!! comment here
        '''
        self.log.info('[%s] Adding tag {0} to device with resource_id {1}.'.format(tag_name, resource_id), self.class_name)

        # Define the request basics
        url = '/'.join([self.url, 'policy/api/v1/infra/tags/tag-operations/win-vm-update'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
        body = {
            'external_id': resource_id,
            'tags': [{
                'tag': tag_name
            }]
        }
        params = {
            'action': 'add_tags'
        }

        # Request the data from the endpoint
        r = requests.post(url, headers=headers, params=params, body=json.dumps(body),
                          auth=(self.username, self.password))

        # If the request was successful
        if r.status_code == 204:
            self.log.info('[%s] Added tag {0} to device with resource_id {1}.'.format(tag_name, resource_id), self.class_name)
            return True
        
        self.log.error('[%s] Error {0}: {1}'.format(r.status_code, r.text), self.class_name)
        raise Exception('Error {0}: {1}'.format(r.status_code, r.text))


class Database:
    '''
        A helper class for working with the database actions requires for this integration.
    '''

    def __init__(self, config, log):
        '''
            Initialise the database object. Create database and tables if they
                don't exist.
            Inputs
                config (str):   Dict containing settings from config.ini
            Output:
                self
        '''

        try:
            self.class_name = 'Database'
            self.log = log
            self.log.info('[%s] Initializing', self.class_name)

            self.config = config
            self.conn = None
            self.connect(config['sqlite3']['filename'])

            sql = [
                '''CREATE TABLE IF NOT EXISTS records (
                    id integer PRIMARY KEY,
                    timestamp text,
                    device_id text,
                    process_guid text,
                    sha256 text
                );'''
            ]

            try:
                cursor = self.conn.cursor()
                cursor.execute(sql[0])

            except Exception as err:
                self.log.exception(err)

        except Exception as err:
            self.log.exception(err)

    def connect(self, db_file):
        '''
            Connects to the sqlite3 database
            Inputs
                db_file (str):  The name of the database file (str)
            Raises
                TypeError if db_file is not a string
            Output
                conn (obj): Returns an object of the connection
        '''

        if isinstance(db_file, str) is False:
            raise TypeError('Expected type of db_file is string.')

        self.log.info('[%s] Connecting to database: {0}'.format(db_file), self.class_name)

        try:
            if self.conn is not None:
                self.log.info('[%s] Connection is already established', self.class_name)
                return self.conn

            try:
                self.conn = sqlite3.connect(os.path.join(os.getcwd(), db_file))
                self.log.info('[%s] Connected to {0} using sqlite {1}'.format(db_file, sqlite3.version),
                              self.class_name)
                return self.conn

            except Exception as err:
                self.log.exception(err)

        except Exception as err:
            self.log.exception(err)

    def close(self):
        '''
            Closes the database connection
            Inputs: None
            Output
                Object of the closed connection
        '''

        self.log.info('[%s] Closing connection', self.class_name)

        try:
            if self.conn:
                self.conn.close()
                self.conn = None

            self.log.info('[%s] Connection closed', self.class_name)

        except Exception as err:
            self.log.exception(err)

    def get_record(self, device_id=None, process_guid=None, sha256=None):
        '''
            Looks for any rows in the database with the provided hash
            Inputs
                md5 (str):      MD5 hash to search for in the database
                sha256 (str):   SHA256 hash to search for in the database
            Raises
                TypeError if md5 is not a string
                ValueError if md5 is not 32 characters long
                TypeError if sha256 is not a string
                ValueError if sha256 is not 64 characters long
            Output
                Returns any rows found matching the provided hash. If no results
                    were found, returns None
        '''

        sql_filter_keys = []
        sql_filter_values = []

        if device_id is not None:
            if isinstance(device_id, int) is False:
                raise TypeError('Expected device_id input type is integer.')
            sql_filter_keys.append('device_id = ?')
            sql_filter_values.append(device_id)

        if process_guid is not None:
            if isinstance(process_guid, str) is False:
                raise TypeError('Expected process_guid input type is string.')
            sql_filter_keys.append('process_guid = ?')
            sql_filter_values.append(process_guid)

        if sha256 is not None:
            if isinstance(sha256, str) is False:
                raise TypeError('Expected sha256 input type is string.')
            if len(sha256) != 64:
                raise ValueError('Expected sha256 to be 64 characters long')
            sql_filter_keys.append('sha256 = ?')
            sql_filter_values.append(sha256)

        if len(sql_filter_keys) == 0:
            self.log.error('[%s] No filter criteria provided', self.class_name)
            raise Exception('No filter criteria provided')

        sql_filter_values = tuple(sql_filter_values)
        sql_filter_keys = ' and '.join(sql_filter_keys)

        self.log.info('[%s] Getting record with filter(s): {0}'.format(sql_filter_keys), self.class_name)

        try:
            sql = 'SELECT * FROM records WHERE {0};'.format(sql_filter_keys)

            cursor = self.conn.cursor()
            cursor.execute(sql, sql_filter_values)
            rows = cursor.fetchall()
            if len(rows) > 0:
                self.log.info('[%s] Found {0} records'.format(len(rows)), self.class_name)
                return rows

            self.log.info('[%s] Unable to find any records', self.class_name)
            return None

        except Exception as err:
            self.log.exception(err)

    def add_record(self, device_id, process_guid, sha256):
        '''
            Adds a file to the database

            Inputs
                device_id (str):
                process_guid (str):
                sha256 (str):

            Raises
                Exception if not connection exists
                TypeError if md5 is not a string
                ValueError if md5 is not 32 characters long
                TypeError if sha256 is not a string
                ValueError if sha256 is not 64 characters long
                TypeError if status is not a string

            Output
                row_id (int):   Returns the row ID of the new entry
        '''

        if self.conn is None:
            raise Exception('No connection to database')

        if isinstance(device_id, int) is False:
            raise TypeError('device_id must be an int')
        if isinstance(process_guid, str) is False:
            raise TypeError('process_guid must be a string')
        if isinstance(sha256, str) is False:
            raise TypeError('sha256 must be a string')
        if len(sha256) != 64:
            raise ValueError('sha256 must be 64 characters long')

        self.log.info('[%s] Adding process: {0}'.format(process_guid), self.class_name)

        try:
            if self.get_record(process_guid=process_guid):
                raise Exception('Process already exists: {0}'.format(process_guid))

            timestamp = convert_time('now')
            file_info = (timestamp, device_id, process_guid, sha256,)
            sql = 'INSERT INTO records(timestamp,device_id,process_guid,sha256) VALUES(?,?,?,?)'
            cur = self.conn.cursor()
            cur.execute(sql, file_info)
            self.conn.commit()
            return cur.lastrowid

        except Exception as err:
            self.log.exception(err)

    def trim_records(self, table, deprecation):
        sql_query = 'DELETE FROM {0} WHERE timestamp < date("now", "{1} days")'.format(table, deprecation)
        # sql_values = (deprecation,)

        try:
            cur = self.conn.cursor()
            # cur.execute(sql_query, sql_values)
            cur.execute(sql_query)
            self.conn.commit()
            return cur.lastrowid

        except Exception as err:
            self.log.exception(err)


def convert_time(timestamp):
    '''
        Converts epoch or ISO8601 formatted timestamp

        Inputs
            timestamp
                epoch time (int)
                ISO8601 time (str)
                'now' (str)

        Raises
            TypeError if timestamp is not a string or integer

        Output
            If timestamp was epoch, returns ISO8601 version of timestamp
            If timestamp was ISO8601, returns epoch version of timestamp
            If timestamp was 'now', returns ISO8601 of current time

        > Note: All times are treated as GMT
    '''

    if isinstance(timestamp, (str, int)) is False:
        raise TypeError('timestamp is expected to be an integer or string.')

    try:
        if isinstance(timestamp, int):
            if len(str(timestamp)) == 13:
                timestamp = int(timestamp / 1000)

            utc_dt = datetime(1970, 1, 1) + timedelta(seconds=timestamp)
            converted_time = utc_dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')

        else:
            if timestamp == 'now':
                return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            utc_dt = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')
            converted_time = int((utc_dt - datetime(1970, 1, 1)).total_seconds())

        return converted_time

    except Exception as err:
        print(err)


def str2bool(item):
    return item.lower() in ['true', '1']


def config2dict(config):
    '''
        This method converts a configparser variable to a dict to
            enable addition of new values.
        Source: https://stackoverflow.com/a/57024021/1339829
    '''
    return { i: { i[0]: i[1] for i in config.items(i) } for i in config.sections() }


def clean_url(url):
    # if missing protocol, add https
    url = 'https://' + url if url[:8] != 'https://' else url
    # if it has a / at the end, remove it
    url = url[0:-1] if url[-1] == '/' else url
    return url

''' Used to track action script executions '''
script_queue = {}
