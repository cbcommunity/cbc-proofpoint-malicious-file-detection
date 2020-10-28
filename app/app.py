# -*- coding: utf-8 -*-

import os
import sys
import configparser
import argparse
import logging as log
import requests
import subprocess
import json
from datetime import datetime, timedelta

# Import helpers
from lib.helpers import CarbonBlackCloud, Proofpoint, Database, convert_time, str2bool

# Globals
config = None
db = None
cb = None
pp = None

def init():
    '''
        Initialze all of the objects for use in the integration

        Inputs: None

        Outputs:
            config: A dictionary of the settings loaded from config.conf
            db: An object with everything needed for this script to work with sqlite3
            cb: An object with everything needed for this script to work with CarbonBlack Cloud
            pp: An object with everything needed for this script to work with Proofpoint SIEM endpoints
    '''

    global config, db, cb, pp

    # Get setting from config.ini
    config = configparser.ConfigParser()
    config.read('config.conf')

    # Configure logging
    log.basicConfig(filename=config['logging']['filename'], format='[%(asctime)s] <pid:%(process)d> %(message)s',
                    level=log.DEBUG)
    log.info('\n\n[APP.PY] Sarted Proofpoint Connector for VMware Carbon Black Cloud')

    # Configure CLI input arguments
    parser = argparse.ArgumentParser(description='Fetch events for messages delivered in the specified time period which contained a known threat')
    parser.add_argument('--last-pull', help='Set the last pull time in ISO8601 format')
    parser.add_argument('--start-time', default=None, help='Set the start time in ISO8601 format')
    parser.add_argument('--end-time', default=None, help='Set the end time in ISO8601 format')
    parser.add_argument('--now', action='store_true', default=False, help='Output the current GMT time in ISO8601 format. Does not pull any data.')
    args = parser.parse_args()

    if args.now:
        print('Current time GMT in ISO8601 format: {0}'.format(convert_time('now')))
        sys.exit(0)

    # Init database
    db = Database(config, log)

    # If a last_pull was provided, update the database with it
    if args.last_pull:
        db.last_pull(args.last_pull)


    print(args.end_time)
    config['Proofpoint']['start_time'] = args.start_time if args.start_time else None
    config['Proofpoint']['end_time'] = args.end_time if args.end_time else None

    # Init CarbonBlackCloud
    cb = CarbonBlackCloud(config, log)

    # Init Proofpoint
    pp = Proofpoint(config, log)

    return config, db, cb, pp


def take_action(email, sha256, cb_processes):
    '''
        This method will identify which actions are enabled in the config file
            and execute each appropriately.

        Inputs:
            email: An object from Proofpoint with details about the email (and attachments)
            sha256: A string of the SHA256 of the malicous attachment
            cb_processes: An array of objects containing processes related to the hash

        Outputs:
            config: A dictionary of the settings loaded from config.conf
            db: An object with everything needed for this script to work with sqlite3
            cb: An object with everything needed for this script to work with CarbonBlack Cloud
            pp: An object with everything needed for this script to work with Proofpoint SIEM endpoints
    '''

    # Populate actions with either None or the action defined
    actions = {}
    for action in config['actions']:
        if config['actions'][action] == '':
            actions[action] = None
        else:
            actions[action] = config['actions'][action]

    # The watchlist action should only be run once per hash, not per process
    # Create/update watchlist feed
    if 'watchlist' in actions and actions['watchlist'] is not None:
        # The threats are in an array. We need to figure out which one
        #   represents the hash being processed
        for threat in email['threatsInfoMap']:
            if threat['threat'] == sha256:
                break

        # Build the Report arguments
        timestamp = convert_time(convert_time('now'))
        title = '{} {} {}: {}'.format(threat['threatStatus'],
                                      threat['classification'],
                                      threat['threatType'], sha256)

        # !!! need to populate threat feed description
        description = 'A description can go here.'

        severity = email['malwareScore'] if email['malwareScore'] != 0 else 1

        url = threat['threatUrl']
        tags = [threat['threatStatus'], threat['threatType'], threat['classification']]

        # Get the feed ready
        if cb.iocs is None:
            cb.iocs = []

        # If the feed has already been pulled, it is cached in cb.feed
        if cb.feed is None:
            # Get the feed
            feed = cb.get_feed(feed_name=actions['watchlist'])

            # If the feed doesn't exist, create it
            if feed is None:
                summary = 'SHA256 indicators that tested positive in Proofpoint'
                feed = cb.create_feed(actions['watchlist'], 'https://www.proofpoint.com', summary)

        # If IOC is not tracked in watchlist, add it
        if sha256 not in cb.iocs:
            # Build the Report. cb.create_report caches the new reports in cb.new_reports
            cb.create_report(timestamp, title, description, severity, url, tags, sha256)

    # The rest of the actions we want to run once per process, not per hash
    # Save a list of devices so we don't run the action on a device twice
    for process in cb_processes:
        device_id = int(process['device_id'])
        process_guid = process['process_guid']

        records = db.get_record(process_guid=process_guid)

        # If the process has already been analyzed, skip it
        if records is not None:
            continue

        # Send data to webhook
        if 'webhook' in actions and actions['webhook'] is not None:
            url = actions['webhook']
            headers = {
                'Content-Type': 'application/json'
            }
            body = {
                'email': email,
                'sha256': sha256,
                'process': process
            }
            requests.post(url, headers=headers, json=body)

        # Run a script
        if 'script' in actions and actions['script'] is not None:
            process_pid = process['process_pid'][0]
            action_script(device_id, pid=process_pid, file_path=process['process_name'])

        # Isolate endpoint
        if 'isolate' in actions and str2bool(actions['isolate']):
            cb.isolate_device(device_id)

        # Change device's policy
        if 'policy' in actions and actions['policy'] is not None:
            cb.update_policy(device_id, actions['policy'])

        db.add_record(device_id, process_guid, sha256)


def action_script(device_id, pid=None, file_path=None):
    '''
        This method take the command from the config file and runs the provided script.
        This method should be customized to fit any unique needs for a custom action script.

        Inputs:
            device_id: The id of the device to connect to. This should be an integer
            pid: The id of the process to kill if it is running. This should be an integer
            file_path: The path to the file that should be deleted if found. This should be a string

        Outputs:
            All outputs are directed to the log file configured in the config file under the logging section
    '''

    log.info('[action_script()] Running Script {0}'.format(config['actions']['script']))
    script_cwd = os.path.dirname(os.path.realpath(__file__))
    stdin = stdout = subprocess.PIPE

    if isinstance(device_id, int) is False:
        device_id = int(device_id)

    if isinstance(pid, int) is False:
        pid = int(pid)

    # Replace elements
    script = config['actions']['script']
    script = script.replace('{device_id}', str(device_id))
    script = script.replace('{pid}', str(pid))
    script = script.replace('{file_path}', file_path)
    script = script.split(' ')

    # This is the command that is sent, with the arguments
    cmd = [os.path.join(script_cwd, script[0])]

    # The command and arguments are passed as an array to the script execution where each argument is an
    #   item in the array. Some of the args could have spaces (like file_path). This section will concatenate
    #   arguments as a string and correctly organize them by items in the array
    args = []
    arg_tmp = []
    for arg in script[1:]:
        # If the first 2 chars are --, it is an arg key
        if arg[0:2] == '--':
            # Add any arg values and clear the cache
            if len(arg_tmp):
                args.append(' '.join(arg_tmp))
                arg_tmp = []
            # Add the arg key
            args.append(arg)

        # Otherwise it is (or is a part of) an arg value
        else:
            # Add the value to the cache of values
            arg_tmp.append(arg)

    # Add any remaining arg values
    args.append(' '.join(arg_tmp))

    log.info('[APP.PY] Running action script: {0} {1}'.format(cmd, args))

    # Run the script
    subprocess.Popen(cmd + args, stdout=stdout, stdin=stdin)


def main():
    # Get inits
    init()

    if config['Proofpoint']['start_time'] is None:
        # Get Proofpoint events from the last pull until 30 minutes ago
        last_pull = db.last_pull()
    else:
        last_pull = config['Proofpoint']['start_time']

    delta_time = datetime.now() - timedelta(minutes=int(config['Proofpoint']['delta']))

    if config['Proofpoint']['end_time'] is None:
        end_time = datetime.strftime(delta_time, '%Y-%m-%dT%H:%M:%SZ')
    else:
        end_time = config['Proofpoint']['end_time']

    # sample interval: '2020-10-12T03:00:00Z/2020-10-12T04:00:00Z'
    interval = '{0}/{1}'.format(last_pull, end_time)

    # Convert interval to difference in seconds
    search_span = datetime.strptime(end_time,'%Y-%m-%dT%H:%M:%SZ') - datetime.strptime(last_pull,'%Y-%m-%dT%H:%M:%SZ')
    search_span = int(search_span.total_seconds())

    # if search_span < 30 seconds
    if search_span < 30:
        print('Error: Search timeframe too short. Timeframe must be > 30 seconds and < 1 hour: {0}'.format(interval))
        log.info('[APP.PY] Search timeframe too short. Timeframe must be > 30 seconds and < 1 hour: {0}'.format(interval))
        sys.exit(0)

    # if search_span > 1 hour
    if search_span > 3600:
        print('Error: Search timeframe too long. Timeframe must be > 30 seconds and < 1 hour: {0}'.format(interval))
        log.info('[APP.PY] Search timeframe too long. Timeframe must be > 30 seconds and < 1 hour: {0}'.format(interval))
        sys.exit(0)

    log.info('[APP.PY] Searching for delivered emails from Proofpoint between {0} and {1}'.format(last_pull, end_time))

    bad_emails = pp.get_messages_delivered(interval)

    # Prevent processing of the same hash
    hash_tracker = []

    # Find malicous attachments in the emails and process them
    for email in bad_emails:
        for part in email['messageParts']:
            if part['disposition'] == 'attached':
                sha256 = part['sha256']
                log.info('[APP.PY] Found email with malicous hash of {0}'.format(sha256))

                if sha256 not in hash_tracker:
                    hash_tracker += [sha256]
                    cb_processes = cb.get_processes(sha256, config['CarbonBlack']['window'])

                    log.info('[APP.PY] Found {0} processes with malicous hash of {1}'.format(len(cb_processes['results']), sha256))

                    # Take action on the processes
                    take_action(email, sha256, cb_processes['results'])
                    
                else:
                    log.info('[APP.PY] Hash was already processed')

    # Once all of the emails and processes have been analyzed, check to see if any new IOCs
    #   are cached and waiting to be added to the watchlist. If so, add them.
    if 'watchlist' in config['actions'] and config['actions']['watchlist'] is not None:
        cb.update_feed(config['actions']['watchlist'])

    if config['Proofpoint']['end_time'] is None:
        # Update the last_pull time for the next execution
        db.last_pull(timestamp=end_time)

    # Close the connection to the database
    db.close()


if __name__ == '__main__':
    main()
