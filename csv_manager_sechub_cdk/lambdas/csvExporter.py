#!/usr/local/bin/python3
"""
Convert SecurityHub findings to CSV and store in an S3 bucket

This program can be invoked as an AWS Lambda function or from the command line.
If invoked from the command line, an assumable role is required. If invoked
from Lambda no parameters are required.

python3 csvExporter.py 
       --role-arn=[assumeableRoleArn] 
       --regions=[commaSeaparatedRegionList]
       --bucket=[s3BucketName]
       --filters=[cannedFilterName|jsonObject]
"""

import json
import argparse
import csv
import sys
import os
import csvObjects as csvo
import logging
import traceback
import re

# Default regions in list and string form
_DEFAULT_REGION_STRING = ""
_DEFAULT_REGION_LIST = [] #_DEFAULT_REGION_STRING.split(",")

# Retrieves the name of the current function (for logging purposes)
this = lambda frame=0 : sys._getframe(frame+1).f_code.co_name

_DEFAULT_LOGGING_LEVEL = logging.INFO
""" Default logging level """

# Set up logging
logging.basicConfig(level=_DEFAULT_LOGGING_LEVEL)

# Retrieve the logging instance
_LOGGER = logging.getLogger()
_LOGGER.setLevel(_DEFAULT_LOGGING_LEVEL)
""" Initialized logging RootLogger instance """

################################################################################
#### 
################################################################################
def choose (default=None, *choices):
    """
    Choose between an option and an environment variable (the option always
    has priority, if specified)
    """
    answer = default

    for choice in choices:
        _LOGGER.debug(f'csvExport.493010i choice {choice}')

        if choice:
            answer = choice
            break

    return answer
################################################################################
#### 
################################################################################
def getFilters ( candidate = None ):
    """
    Process filters, which are specified as a JSON object or as a string, in 
    this case "HighActive." If the filter can't be parsed, a messagae is issued
    but a null filter is returned. 
    """
    if not candidate:
        filters = {}
    elif candidate != "HighActive":
        try:
            if type(candidate) is dict:
                filters = candidate
            else:
                filters = json.loads(candidate)
        except Exception as thrown:
            _LOGGER.error(f'493020e filter parsing failed: {thrown}')
            filters = {}
    else:
        _LOGGER.info("493030i canned HighActive filter selects active high- " + \
            "and critical-severity findings")
        filters = {
            "SeverityLabel": 
            [ 
                {"Value": "CRITICAL", "Comparison": "EQUALS" }, 
                {"Value": "HIGH", "Comparison": "EQUALS"}
            ], 
            "RecordState": 
            [ 
                { "Comparison": "EQUALS", "Value": "ACTIVE"}
            ]
        }

    return filters

################################################################################
#### Invocation-independent process handler
################################################################################
def executor (role=None, region=None, filters=None, bucket=None, limit=0, 
    retain=False):
    """
    Carry out the actions necessary to download and export SecurityHub findings,
    whether invoked as a Lambda or from the command line.
    """
    # Get the SSM parameters and a client for further SSM operations
    ssmActor = csvo.SsmActor(role=role, region=region)

    # Get a list of Security Hub regions we wish to act on
    regions = choose(
        os.environ.get("CSV_SECURITYHUB_REGIONLIST"),
        re.compile("\s*,\s*").split(getattr(ssmActor, "/csvManager/regionList", region)),
        ssmActor.getSupportedRegions(service="securityhub")
    )
    
    _LOGGER.info("493040i selected SecurityHub regions %s" % regions)

    # Get information about the bucket
    folder = getattr(ssmActor, "/csvManager/folder/findings", None)
    bucket = bucket if bucket else getattr(ssmActor, "/csvManager/bucket", None)

    _LOGGER.debug(f'493050d writing to s3://{bucket}/{folder}/*') 

    # A client to act on the bucket
    s3Actor = csvo.S3Actor(
        bucket=bucket, 
        folder=folder, 
        region=region, 
        role=role
    )

    # Filename where file can be stored locally
    localFile = s3Actor.filePath()

    # Now obtain a client for SecurityHub regions
    hubActor = csvo.HubActor(
        role=role,
        region=regions
    )

    # Obtain the findings for all applicable regions
    hubActor.downloadFindings(filters=filters,limit=limit)

    if hubActor.count <= 0:
        _LOGGER.warning("493060w no findings downloaded")
    else:
        _LOGGER.info(f'493070i preparing to write {hubActor.count} findings')

        first = True

        with open(localFile, 'w') as target:
            for finding in hubActor.getFinding():
                findingObject = csvo.Finding(finding, actor=hubActor)

                # Start the CSV file with a header
                if first:
                    _LOGGER.debug("493080d finding object %s keys %s" \
                        % (findingObject, findingObject.columns))

                    writer = csv.DictWriter(target, 
                        fieldnames=findingObject.columns)

                    writer.writeheader()

                # Write the finding
                writer.writerow(findingObject.rowMap)

                first = False

        # Announce completion of write
        _LOGGER.info("493090i findings written to %s" % localFile)

        # Place the object in the S3 bucket
        s3Actor.put()

        _LOGGER.info('493100i uploaded to ' + 
            f's3://{s3Actor.bucket}/{s3Actor.objectKey}')

        # Determine whether to retain the local file or not
        if retain:
            _LOGGER.warning("493110w local file %s retained" % localFile)
        else:
            os.unlink(localFile)

            _LOGGER.info("493120i local file deleted")

        # Return details to caller
        answer = {
            "success" : True ,
            "message" : "Export succeeded" ,
            "bucket" : s3Actor.bucket ,
            "exportKey" : s3Actor.objectKey
        }

    return answer
################################################################################
#### Lambda handler
################################################################################
def lambdaHandler ( event = None, context = None ):
    """
    Perform the operations necessary if CsvExporter is invoked as a Lambda
    function. 
    """
    # The event keys we care about are processed below
    role = event.get("role")
    region = event.get("region")
    if 'filters' in (event.keys()):
        filters=getFilters(event.get("filters", {}))
    else:
        filters=event
    bucket = event.get("bucket")
    retain = event.get("retainLocal", False)
    limit = event.get("limit", 0)
    eventData = event.get("event")

    # If no region is specified it must be obtains from the environments
    if not region:
        region = os.environ.get("CSV_PRIMARY_REGION")
        _LOGGER.info(f"493130i obtained region {region} from environment")

    # This is where we will store the result
    answer = {}

    # Determine if Lambda was invoked manually or via an event
    if eventData:
        eventType = eventData.get("detail-type", "UNKNOWN")
        _LOGGER.info("493140i Lambda invoked by %s" % eventType)
    else:
        _LOGGER.info("493150i Lambda invoked extemporaneously")

    # Perform the real work
    try:
        result = executor(
            role=role,
            region=region,
            filters=filters,
            bucket=bucket,
            retain=retain,
            limit=limit
        )

        answer = {
            "message": result.get("message"),
            "bucket": result.get("bucket"),
            "exportKey": result.get("exportKey"),
            "resultCode": 200 if result.get("success") else 400
        }

    # Catnch any errors
    except Exception as thrown:
        errorType = type(thrown).__name__
        errorTrace = traceback.format_tb(thrown.__traceback__, limit=5)

        _LOGGER.error("493160e Lambda failed (%s): %s\n%s" \
            % (errorType, thrown, errorTrace))
        
        answer = { 
            "message" : thrown ,
            "traceback" : traceback.format_tb(thrown.__traceback__, limit=5),
            "bucket" : None ,
            "exportKey" : None ,
            "resultCode" : 500
        }

    return answer

################################################################################
#### Main body is invoked if this is a command invocation
################################################################################
if __name__ == "__main__":
    """
    Need to make regions etc. configurable
    """
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--role-arn", required=False, dest="roleArn",
            help="The assumable role ARN to access SecurityHub")
        parser.add_argument("--filters", default='{}', required=False, 
            help="Filters to apply to findings")
        parser.add_argument("--bucket", required=False, 
            help="S3 bucket to store findings")
        parser.add_argument("--limit", required=False, type=int, default=0,
            help="Limit number of findings retrieved")
        parser.add_argument("--retain-local", action="store_true", 
            dest="retainLocal", default=False, help="Retain local file")
        parser.add_argument("--primary-region", dest="region", required=True,
            help="Primary region for operations")

        arguments = parser.parse_args()

        executor(
            role=arguments.roleArn, 
            filters=getFilters(arguments.filters),
            bucket=arguments.bucket, 
            limit=arguments.limit, 
            retain=arguments.retainLocal,
            region=arguments.region
        )

    except Exception as thrown:
        _LOGGER.exception("493170t unexpected command invocation error %s" \
            % str(thrown))
