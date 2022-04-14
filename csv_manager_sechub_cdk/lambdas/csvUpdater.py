#!/usr/local/bin/python3
"""
Update Security Hub findings en bloc/en masse from a CSV file

This program can be invoked as an AWS Lambda function or from the command line.

REVISION 20210225 Make work in GovCloud
REVISION 20210930 Actually make work in GovCloud
"""

import argparse
import csv
import sys
import os
import re
import logging
import csvObjects as csvo
import traceback
import re

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
#
################################################################################
class InputDiscriminator:
    """
    Parse the input parameter into an S3 bucket and key or a local file path.
    Resulting object has the following properties:

    isLocal     - boolean   - the input is a local file
    bucket      - string    - if an S3 input, the bucket name
    key         - string    - if an S3 input, the object key
    path        - string    - if a local file, the file path
    """
    #---------------------------------------------------------------------------
    def __init__ (self, input=None):
        """ See class definition """
        match = re.match(r'^s3://([^/]+)/(.*)', input, re.IGNORECASE)

        if match:
            self.isLocal = False
            self.bucket = match.group(1)
            self.key = match.group(2)
            self.path = None
        else:
            self.isLocal = True
            self.bucket = None
            self.key = None
            self.path = input
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
        if choice:
            answer = choice
            break

    return answer
################################################################################
#### Invocation-independent process handler
################################################################################
def executor (role=None, region=None, debug=False, input=None):
    """
    Called from either the command or Lambda invocations. Obtains the necessary
    API clients, gathers updates from the input CSV file, and then applies 
    updates using the securityhub:batch_update_findings API.
    """
    processed = []
    unprocessed = []

    # Get the SSM parameters and a client for further SSM operations
    ssmActor = csvo.SsmActor(role=role, region=region)

    # Get a list of Security Hub regions we wish to act on
    regions = choose(
        os.environ.get("CSV_SECURITYHUB_REGIONLIST"),
        re.compile("\s*,\s*").split(getattr(ssmActor, "/csvManager/regionList")),
        ssmActor.getSupportedRegions(service="securityhub")
    )
    
    _LOGGER.info("494010i selected SecurityHub regions %s" % regions)

    # Determine if input is S3 or local file
    source = InputDiscriminator(input)

    try:
        # Will handle input in S3 or local file
        s3Actor = csvo.S3Actor(
            bucket=source.bucket,
            region=regions,
            role=role
        )

        # Use SecurityHub to update findings
        hubActor = csvo.HubActor(
            role=role,
            region=regions
        )

        # Determine whether the input is coming from local file or S3
        if source.isLocal:
            raw = s3Actor.get(file=source.path, split=True)
        else:
            raw = s3Actor.get(bucket=source.bucket, key=source.key, split=True)

        # Reader for CSV input
        reader = csv.reader(raw, delimiter=',')

        # This object creates a minimum set of updates 
        updates = csvo.MinimumUpdateList()
        count = 0

        # Report start of export
        _LOGGER.info("494020i processing %d records from CSV" % len(raw))
        
        for rowNumber, row in enumerate(reader):
            # Skip the column header row
            if row[0] == "Id":
                continue

            # Process each finding
            try:
                finding = csvo.Finding(row, actor=hubActor)

            # If there is a problem with the finding, just skip it--user
            # can re-run later after corrections
            except csvo.FindingValueError as thrown:
                _LOGGER.error("494030e row %d error: %s" \
                    % (rowNumber + 1, str(thrown)))

                continue

            count += 1

            updates.add(finding)

            # Report progress
            if (count % 1000) == 0:
                _LOGGER.info("494040i ... %8d findings processed" % count)

        # Report the results of the preprocessing
        _LOGGER.info("494050i processed %d findings and identified %d update sets" \
            % (count, updates.sets)) 

        # Now apply the updates
        if (updates.sets > 0):
            _LOGGER.info("494060i processing update sets")

            for region, update in updates.parameterSets():
                # Actually apply the update set -- this is a per-region operation
                response = csvo.MinimumUpdateList.apply(
                    update=update,
                    region=region,
                    actor=hubActor
                )

                # Keep track of successes and failures
                processed += response.get("ProcessedFindings")
                unprocessed += response.get("UnprocessedFindings")

            # Report the results of the update
            _LOGGER.info(
                "494070i %d findings processed, %d findings not processed" \
                % (len(processed), len(unprocessed))
            )

            # If some findings were not processed, report those findings
            if len(unprocessed) > 0:
                _LOGGER.error(
                    "494080e the following findings were not processed"
                )

                for failed in unprocessed:
                    finding = failed.get("FindingIdentifier", {}).get("Id")
                    code = failed.get("ErrorCode")
                    message = failed.get("ErrorMessage")

                    _LOGGER.error("494090e %s\n\t%s - %s" \
                        % (finding, code, message))
    
    # Handle any errors that arise
    except Exception as thrown:
        message = "(s) Unexpected executor error %s" % str(thrown)

        if arguments.debug:
            _LOGGER.exception("494100t %s" % message)
        else:
            _LOGGER.critical("494110t %s" % message)

        answer = {
            "success" : False ,
            "message" : str(thrown) ,
            "input" : input 
        }

    # What to do if there are no errors
    else:
        answer = {
            "processed": processed,
            "unprocessed": unprocessed
        }

        if len(unprocessed) == 0:
            answer["message"] = "Updated succeeded"
            answer["success"] = True
        else:
            if len(processed) > 0:
                answer["message"] = "Update partially succeeded"
                answer["success"] = True
            else:
                answer["message"] = "Update failed"
                answer["success"] = False 

    return answer

################################################################################
#### Lambda handler
################################################################################
def lambdaHandler ( event = None, context = None ):
    """
    Stub for Lambda handler.
    """
    try:
        # These data come from the event
        roleArn = event.get("roleArn")
        input = event.get("input")
        debug = event.get("debug")
        region = event.get("primaryRegion")

        # Do the work
        answer = executor(
            role=roleArn,
            input=input,
            debug=debug,
            region=region
        )

    # Handle trouble if it arises
    except Exception as thrown:
        errorType = type(thrown).__name__
        errorTrace = traceback.format_tb(thrown.__traceback__, limit=5)
        message = "lambda raised exception (%s): %s\n%s" % \
            (errorType, thrown, errorTrace)

        response = {
            "message": str(thrown),
            "traceback": traceback.format_tb(thrown.__traceback__, limit=5),
            "input": input,
            "resultCode": 500
        }

    # No trouble so far
    else:
        response = {
            "message": "Success",
            "details": answer,
            "input": input,
            "resultCode": 200
        }

    return response
################################################################################
#
################################################################################
if __name__ == "__main__":
    """
    This section is executed when csvUpdater.py is invoked as a command-line command.
    (need to make regions and other parameters configurable)
    """
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--role-arn", dest="roleArn", required=False, 
            help="The assumable role ARN to access SecurityHub")
        parser.add_argument("--input", required=True, 
            help="S3 or file system file that holds findings to update")
        parser.add_argument("--debug", action="store_true", default=False,
            help="Provide more debugging details")
        parser.add_argument("--primary-region", dest="region", required=True,
            help="Primary region for operations")

        arguments = parser.parse_args()

        # Do the work
        executor(
            role=arguments.roleArn, 
            input=arguments.input,
            region=arguments.region , 
            debug=arguments.debug 
        )

    # Catch trouble
    except Exception as thrown:
        message = "command invocation raised (%s): %s" % \
            (type(thrown).__name__, thrown)

        # This will generate a traceback
        if arguments.debug:
            _LOGGER.exception("494120i %s" % message)

        # This will not generate a traceback
        else:
            _LOGGER.critical("494130i %s" % message)
