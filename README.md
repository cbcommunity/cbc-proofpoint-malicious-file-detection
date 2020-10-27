# cbc-proofpoint-malicous-file-detection
This is an integration with Proofpoint's TRAP product and VMware Carbon Black Cloud.

Latest Version: 0.1
Release Date: TBD


## Overview

This is an integration between **Proofpoint TRAP** and **VMware Carbon Black Cloud** (CBC) and **CBC Enterprise EDR**.  A feature of Proofpoint is that it can scan for malicious attachments. An option is to allow the attachment during detonation and if found to be malicious, remove the email from the inbox. What if the attachment is download prior to the removal of the email from the inbox?

This integration will pull from Proofpoint all email deliveries from *x* minutes ago (configurable, allows time for detonation, default 30). For each attachment, search CBC for any processes with attachment's SHA256 for the last *y* timeframe (up to 2 weeks). The process GUID's are stored in a local database to prevent duplication in searches and minimize API queries. Once the processes have been identified, the script will take action.

Action options consist of:
   - Adding to a CBC Enterprise EDR Watchlist Feed
   - Passing the SHA256, process information, and email information to a webhook
   - Running a script (kills process/deletes file with CBC Live Response by default)
   - Isolating the endpoint
   - Moving the endpoint into a policy

## Requirements
    - Python 3.x with sqlite3
    - VMware Carbon Black Cloud Endpoint Standard or Enterprise EDR
    - Proofpoint TRAP

## License
Use of the Carbon Black API is governed by the license found in [!!! LICENSE]().

## Support
What is the support policy?

----

## Installation

Clone the repository into a local folder.

    git clone git@github.com:cbcommunity/cbc-proofpoint-malicous-file-detection.git

Install the requirements

    pip install -r requirements.txt

Edit the `config.conf` file and update with your configurations

## Configuration

All of the configurable settings for the integration can be found in [`config.conf`](cbcommunity/cbc-proofpoint-malicous-file-detection/blob/master/app/config.conf).

### Carbon Black Configuration
You will need to create 1 API Access Level and 3 API keys

#### Custom Access Level Permissions

|       Category       |   Permission Name   |    .Notation Name   |       Create       |        Read        |       Update       | Delete | Execute |
|:--------------------|:-------------------|:-------------------|:------------------:|:------------------:|:------------------:|:------:|:-------:|
| Custom Detections   | Feeds               | org.feeds           | :ballot_box_with_check: | :ballot_box_with_check: | :ballot_box_with_check: |        |         |
| Device               | Policy assignment   | device.policy       |                    |                    | :ballot_box_with_check: |        |         |
| Search               | Events              | org.search.events.  | :ballot_box_with_check: | :ballot_box_with_check: |                    |        |         |


#### Access Levels (API key type)
1. Custom [select your Custom Access Level]
2. API
3. Live Response (optional, used in action.py)

The Organization Key can be found in the upper-left of the **Settings** > **API Keys** page.

| CarbonBlack         | Configure Carbon Black Cloud       |
|:--------------------|:-----------------------------------|
| `url`               | URL of CBC instance                |
| `org_key`           | Org Key                            |
| `api_id`            | API ID                             |
| `api_key`           | API Secret Secret Key              |
| `custom_api_id`     | Custom API ID                      |
| `custom_api_key`    | Custom API Secret Key              |
| `lr_api_id`         | LiveResponse API ID                |
| `lr_api_key`        | LiveResponse API Secret Key        |
| `window`       | Window of time to search for SHA256 processes. Maximum 2 weeks |

API endpoints used:

- api/investigate/v2/orgs/ORG_KEY/processes/search_jobs'
- appservices/v6/orgs', self.org_key, 'device_actions
- integrationServices/v3/policy
- threathunter/feedmgr/v2/orgs', self.org_key, 'feeds
- threathunter/feedmgr/v2/orgs', self.org_key, 'feeds/{FEED_ID}
- threathunter/feedmgr/v2/orgs', self.org_key, 'feeds/{FEED_ID}/reports
- integrationServices/v3/cblr/session/{1}
- integrationServices/v3/cblr/session/{1}/command
- integrationServices/v3/cblr/session/{1}/command/{2}
- integrationServices/v3/cblr/session

----

### Proofpoint Configuration

The API key can be found in **!!! ENTER LOCATION**

| **Proofpoint**  | **Configure Proofpoint TAP**   |
|:----------------|:-------------------------------|
| `url`           | URL for Proofpoint             |
| `api_key`       | API Key                        |
| `principal`     | Login Username                 |
| `secret`        | Login Password                 |
| `delta`         | Durration of time to search for delivered messages. Max 1 hour |

----

Python 3.x ships by default with sqlite. If for some reason you don't have sqlite, you will need to install it (`pip install sqlite3`. This database is used to keep track of and de-dupe lookups on the same process.

| **sqlite3**         | **Configure sqlite3**              |
|:--------------------|:-----------------------------------|
| `filename`          | Filename of the sqlite3 database   |

----

When a process with the a malicious hash is detected, actions are triggered. By default all actions are disabled. Uncomment and populate with a value to enable.

| **actions**         | **Configure Actions**              |
|:--------------------|:-----------------------------------|
| `watchlist`         | Name of watchlist to populate      |
| `webhook`           | URL to `POST` a JSON object of the event and sandbox report |
| `script`            | A script to execute                |
| `isolate`           | Isolate the endpoint?              |
| `policy`            | Policy to move offending devices   |

## Running the Script

The script has the following CLI options:

    optional arguments:
      -h, --help            show this help message and exit
      --last_pull LAST_PULL
                            Set the last pull time in ISO8601 format
      --now                 Output the current time is ISO8601 format

The `--last_pull` option overwrites the `last_pull` value stored in the database and will pull Cloud EDR processes since that time.

### Examples

Typical usage:

    python app.py
    
Specify Cloud EDR start date:

    python app.py --last_pull 2020-01-01T12:34:56Z
