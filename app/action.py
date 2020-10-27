#!/usr/bin/env python

import sys
import argparse
import configparser
import logging as log

from lib.helpers import CarbonBlackCloud

log.basicConfig(filename='app.log', format='[%(asctime)s] <pid:%(process)d> %(message)s', level=log.DEBUG)
log.info('Sarted action script')


def init():
    log.debug('Initializing script')

    # Get configs
    log.debug('Getting configs')
    config = configparser.ConfigParser()
    config.read('config.conf')
    log.debug('Finished getting configs')

    # Get inputs
    log.debug('Getting cli inputs')
    parser = argparse.ArgumentParser(description='Take action on an endpoint via LiveResponse')
    parser.add_argument("--device_id", help='Log activity to a file', required=True)
    parser.add_argument('--pid', help='Process ID to kill if running', required=True)
    parser.add_argument('--file_path', help='Process path to delete the file', default=None)
    parser.add_argument('--close', action='store_true', help='Close the session when script completes')
    args = parser.parse_args()
    log.debug('Finished cli inputs')

    # Init CarbonBlack
    cb = CarbonBlackCloud(config, log)

    return cb, args


def main():
    cb, args = init()

    device_id = int(args.device_id)
    pid = args.pid
    file_path = args.file_path

    cb.start_session(device_id, wait=True)

    log.debug('[Main] Connected to endpoint: {0}'.format(device_id))

    # Check to see if the process is still running
    lr_command = cb.send_command('process list', wait=True)

    found = False
    for process in lr_command['processes']:
        if str(process['pid']) == pid:
            log.debug('[Main] Process is running, killing process')

            found = True
            # Send kill command
            lr_command = cb.send_command('kill', argument=pid, wait=True)

    if found is False:
        log.debug('[Main] Process {0} was not running on device {1}'.format(pid, device_id))

    # Send kill command
    log.debug('[Main] Deleting file from endpoint')
    lr_command = cb.send_command('delete file', argument=file_path, wait=True)

    # if args.close:
    #     cb.close_session()
    #     log.debug('[Main] Closed session')


if __name__ == "__main__":
    sys.exit(main())
