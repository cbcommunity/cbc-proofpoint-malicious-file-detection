
# Proofpoint TAP Connector for VMware Carbon Black Cloud

This is an integration between Proofpoint's TAP product and VMware Carbon Black Cloud (CBC).

**Latest Version:** v1.3  
**Release Date:** February 2021


## Overview

This is an integration between **Proofpoint TAP** and **VMware Carbon Black Cloud** (CBC).  Depending on the configuration of Proofpoint TAP, users are able to access attachments while they're being analyzed by Proofpoint. If the attachment is found to be malicious, Proofpoint TRAP can remove the email from all corporate inboxes, however, if the attachment was downloaded prior to the email being deleted, the malicious file could still be present in the environment on end-user machines.

This integration will pull all email deliveries from *x* minutes ago (configurable, allows time for detonation, default 30) from Proofpoint TAP. For each attachment collected from Proofpoint, Carbon Black Cloud will search for any processes that match the malicious attachments' SHA256 hash value for a preset, custom time frame (up to 2 weeks). The process GUID's are stored in a local database to prevent duplication in searches and minimize API queries. Once the processes have been identified, the script will take action.

Action options consist of:
   - Adding to a CBC Enterprise EDR Watchlist Feed
   - Passing the SHA256, process information, and email information to a webhook
   - Running a script (kills process/deletes file with CBC Live Response by default)
   - Isolating the endpoint
   - Moving the endpoint into a different or updated policy

## Requirements
    - Python 3.x with sqlite3
    - VMware Carbon Black Cloud Endpoint Standard or Enterprise EDR
    - Proofpoint TAP

## License
Use of the Carbon Black API is governed by the license found in the [LICENSE.md](https://github.com/cbcommunity/cbc-proofpoint-malicous-file-detection/blob/main/LICENSE.md) file.

## Support
This integration is an open sourced project. Please submit a Pull Request for any changes.

----

## Installation

Clone the repository into a local folder.

    git clone https://github.com/cbcommunity/cbc-proofpoint-malicous-file-detection.git

Install the requirements

    pip install -r requirements.txt

Edit the `config.conf` file and update with your configurations

## Configuration

All of the configurable settings for the integration can be found in [`config.conf`](https://github.com/cbcommunity/cbc-proofpoint-malicous-file-detection/blob/main/app/config.conf).

### Carbon Black Configuration
You will need to create 1 API Access Level and 2 API keys

#### Custom Access Level Permissions

|    **Category**   | **Permission Name**   | **.Notation Name**       |        **Create**       |         **Read**        |        **Update**       | **Delete**              |       **Execute**       |
|:-----------------:|:---------------------:|:------------------------:|:-----------------------:|:-----------------------:|:-----------------------:|:-----------------------:|:-----------------------:|
| Custom Detections | Feeds                 | org.feeds                | :ballot_box_with_check: | :ballot_box_with_check: |                         |                         |                         |
| Device            | Quarantine            | device.quarantine        |                         |                         |                         |                         | :ballot_box_with_check: |
| Device            | General Information   | device                   |                         | :ballot_box_with_check: |                         |                         |                         |
| Device            | Policy Assignment     | device.policy            |                         |                         | :ballot_box_with_check: |                         |                         |
| Live Response     | Live Response Session | org.liveresponse.session | :ballot_box_with_check: | :ballot_box_with_check: |                         | :ballot_box_with_check: |                         |
| Live Response     | Live Response File    | org.liveresponse.file    |                         |                         |                         | :ballot_box_with_check: |                         |
| Live Response     | Live Response Process | org.liveresponse.process |                         | :ballot_box_with_check: |                         | :ballot_box_with_check: |                         |
| Search            | Events                | org.search.events        | :ballot_box_with_check: | :ballot_box_with_check: |                         |                         |                         |

#### Access Levels (API key type)
1. Custom [select your Custom Access Level]
2. API

The Organization Key can be found in the upper-left of the **Settings** > **API Keys** page.

| CarbonBlack         | Configure Carbon Black Cloud                                   |
|:--------------------|:---------------------------------------------------------------|
| `url`               | URL of CBC instance                                            |
| `org_key`           | Org Key                                                        |
| `api_id`            | API ID                                                         |
| `api_key`           | API Secret Secret Key                                          |
| `custom_api_id`     | Custom API ID                                                  |
| `custom_api_key`    | Custom API Secret Key                                          |
| `window`            | Window of time to search for SHA256 processes. Maximum 2 weeks |

----

### Proofpoint Configuration

The Service Credentials section allows you to define sets of credentials which are used to authenticate to Proofpoint TAP’s Application Program Interfaces ("API"). You can define as many sets of credentials as you need for different purposes.

To create a service principal, navigate to the Connected Applications tab, click the Create New Credential button. You will then be prompted to define a friendly name, which should be descriptive of the purpose of the credential. After hitting Generate, a lightbox will be displayed with the service principal (username) and secret (password). It is important that you copy these credentials; they will not be redisplayed and are not retrievable after the lightbox has been dismissed.

| **Proofpoint**      | **Configure Proofpoint TAP**                                                |
|:--------------------|:----------------------------------------------------------------------------|
| `url`               | URL for Proofpoint                                                          |
| `api_key`           | API Key                                                                     |
| `principal`         | Login Username                                                              |
| `secret`            | Login Password                                                              |
| `include_delivered` | Search for the hashes of attachments that Proofpoint delivered to the inbox |
| `include_blocked`   | Search for the hashes of attachments that Proofpoint blocked                |
| `delta`             | Duration of time to search for delivered messages. Max 1 hour               |

----

### NSX Configuration

An optional action is to add a NSX tag to a device. This could be used to isolate the endpoint on a VLAN, enable certain features to inspect network traffic, or just segreate for investigation.

Ensure to add a tag to the `actions` section if you complete this section.

| **NSX**    | **Configure NSX** |
|------------|-------------------|
| `url`      | URL for NSX       |
| `username` | API username      |
| `password` | API password      |

----

Python 3.x ships by default with sqlite. If for some reason you don't have sqlite, you will need to install it (`pip install sqlite3`). This database is used to keep track of and de-dupe lookups on the same process.

| **sqlite3**         | **Configure sqlite3**                                |
|:--------------------|:-----------------------------------------------------|
| `filename`          | Filename of the sqlite3 database                     |
| `deprecation`       | Amount of time the records will live in the database |

----

When a process with the a malicious hash is detected, actions are triggered. By default all actions are disabled. Uncomment and populate with a value to enable.

| **actions**         | **Configure Actions**                                       |
|:--------------------|:------------------------------------------------------------|
| `watchlist`         | Name of watchlist to populate                               |
| `webhook`           | URL to `POST` a JSON object of the event and sandbox report |
| `script`            | A script to execute                                         |
| `isolate`           | Isolate the endpoint?                                       |
| `policy`            | Policy to move offending devices                            |
| `nsx_tag`           | Add a NSX tag to the device                                 |

## Running the Script

The script has the following CLI options:

    optional arguments:
      -h, --help            show this help message and exit
      --start-time START_TIME
                            Set the start time in ISO8601 format
      --end-time END_TIME   Set the end time in ISO8601 format
      --now                 Output the current GMT time in ISO8601 format. Does not pull any data.

To manually specify a timeframe (min 30 seconds, max 1 hour) use the `--start-time` and `--end-time` arguments.

### Examples

Typical usage:

    python app.py

Specify a timeframe:

    python app.py --start-time 2021-01-01T12:00:00Z --end-time 2021-01-01T13:00:00Z

## Docker

A Dockerfile is included. First build the image using the following command from the project's root folder:

    docker build -t cbc-proofpoint .

Make sure your [app/config.conf](https://github.com/cbcommunity/cbc-proofpoint-malicous-file-detection/blob/main/app/config.conf) file is populated with the correct values.

Run the script with the following command:

    docker run --rm -it -v $PWD/app:/app --name=cbc-proofpoint cbc-proofpoint
   
## Development

Want to load a dev environment locally to test and tweak the code? Use the following command in the root of the repo folder to launch a dev environment on port 3000 of your local machine.

	# Linux, macOS, or PowerShell
	docker run -it --init \
		--name cbc-proofpoint \
		-p 3000:3000 \
		-v "$(pwd):/home/project:cached" \
		theiaide/theia-python:next

	# Windows (cmd.exe)
	docker run -it --init \
		--name cbc-proofpoint \
		-p 3000:3000 \
		-v "%cd%:/home/project:cached" \
		theiaide/theia-python:next

Once the container is running, open a browser and go to http://localhost:3000. After the console loads, run the following command in the IDE's terminal:

	./dev-setup.sh

This will update the instance and install the required modules. Use `python3` to execute the scripts.
