#!/usr/local/bin/python3
# Objects used in CsvManager
# Update 20200827
# Update 20210225 - Make it work with GovCloud

import boto3
import botocore
import time
import re
import logging
from botocore import exceptions
from botocore.exceptions import ClientError
from boto3.session import Session

# The current supported version
_CURRENT_VERSION = "2021-01-01"

_DEFAULT_LOGGING_LEVEL = logging.INFO
""" Default logging level """

# Set up logging
logging.basicConfig(level=_DEFAULT_LOGGING_LEVEL)

# Retrieve the logging instance
_LOGGER = logging.getLogger()
_LOGGER.setLevel(_DEFAULT_LOGGING_LEVEL)

# Simplify the extraction of error detail from botocore.exception.ClientError
errorCode = lambda exception: exception.response \
    .get("Error", {}) \
    .get("Code", "INVALID") if getattr(exception, "response") \
    else type(exception).__name__

################################################################################
# 
################################################################################
class FindingValueError (Exception):
    """
    This exception is thrown if some value in a finding is out of bounds, or
    if there are other problems in the import or update of a finding.
    """
    pass
################################################################################
# 
################################################################################
class FindingColumn:
    """
    Map a SecurityHub finding dictionary to a set of CSV column. This object
    represents a single column.

    If you will be using more than one list of FindingColumns, you must start
    each successive list with a reset=True parameter.

    Parameters
    ----------
    columnName : str 
        The name assigned to the CSV column
    keys : list of str
        A list of keys used to access the value for this column in a 
        securityhub:get_findings API response.
    isKey : boolean
        True if this column will act as a key to uniquely identify a finding
    isUpdatable : boolean
        True if this column can be updated using securityhub:batch_update_findings
    d2l : callable, None, or other
        A transformation between the API dictionary and the CSV record value
    d2lParameters : dict
        A ** dictionary to be passed to the d2l transform if it is callable
    l2d : callable, None, or other
        A transformation between the cSV record and API dictionary value
    l2dParameters : dict
        A ** dictionary to be passed to the l2d transform if it is callable

    Notes
    -----
    The d2l and l2d transforms should be combined, since in all cases so far
    identified, the transform is the same in both directions. 
    """
    #---------------------------------------------------------------------------
    def __init__ (self, columnNumber=0, columnName=None, keys=None, isKey=False, 
        isUpdatable=False, d2l=None, d2lParameters={}, l2d=None, l2dParameters={}):
        """
        See class definition for details.
        """
        self.columnNumber = columnNumber
        self.columnName = columnName
        self.keys = keys
        self.isKey = isKey
        self.isUpdatable = isUpdatable
        self.d2lParameters = d2lParameters
        self.d2l = d2l
        self.l2dParameters = l2dParameters
        self.l2d = l2d
        self.transform = None
        self.parameters = {}
        self._value = None
    #---------------------------------------------------------------------------
    @property 
    def rawValue (self):
        """
        The raw value that came from the API finding dictionary or the CSV 
        column, depending on how this finding was initialized.
        """
        return self._value
    #---------------------------------------------------------------------------
    @property
    def value (self):
        """
        Return the value transformed according to its source (the API finding 
        or the CSV column)
        """    
        return self._value
    #---------------------------------------------------------------------------
    @value.setter
    def value (self, initializer=None):
        """
        The setter is invoked against a dictionary of values, or a list of values
        as in:

            self.value = { "key":  "value", "key2"; "value2" }
            self.value = [ "value", "value2" ]

        If a list is specified, values are subject to l2d transformations; If a
        dict is specified, values are subject to d2l transformations.

        Object attributes are set to facilitate the processing of the value
        when the value property is used.

        1. If the transform is missing, the original value is used
        2. If the transform is callable, the transform return value is used
        3. Else, the transform value is used
        """
        _LOGGER.debug("496010d FindingColumn.value %s" % initializer)

        # An API result dict is supplied
        if isinstance(initializer, dict):
            candidate = self.deep(initializer)

            _LOGGER.debug("496020d processing an API result %s = '%s'" % \
                (self.columnName, candidate))

            self.transform = self.d2l 
            self.parameters = self.d2lParameters
        # A CSV list is supplied
        elif isinstance(initializer, list):
            try:
                candidate = initializer[self.columnNumber]
            except (ValueError, IndexError):
                candidate = None
                
            _LOGGER.debug("496030d processing a CSV column %d (%s) = '%s'" % \
                (self.columnNumber, self.columnName, candidate))
            
            self.transform = self.l2d
            self.parameters = self.l2dParameters
        # Neither is an error
        else:
            raise FindingValueError("496040t must be passed a list or dict")

        # Case 1 - No transform
        if not self.transform:
            answer = candidate

        # Case 2 - Callable transform
        elif callable(self.transform):
            answer = self.transform(candidate, **self.parameters)

        # Case 3 - Fixed transform
        else:
            answer = self.transform 

        _LOGGER.debug("496050d %s source is %s candidate is [%s]" \
            % (self.columnName, type(initializer).__name__, candidate))

        self._value = answer if answer != '' else None

        _LOGGER.debug("496060d %s transformed is [%s]" \
            % (self.columnName, answer))
    #---------------------------------------------------------------------------
    def key (self):
        """
        If this column is a key column, return its value. This method will
        return "none" if the self.value setter is not called first!
        """
        return None if not self.isKey else self.value
    #---------------------------------------------------------------------------
    def update (self):
        """
        If this column is an updatable column, return its value. This method
        will return "None" if self.value setter is not called first!
        """
        return None if not self.isUpdatable else self.value
    #---------------------------------------------------------------------------
    def deep (self, dictionary = {}):
        """
         Retrieve a nested item from a dict. For example, given { "A" : "B": {1}}
         and a self.keys attribute of ["A", "B"], this will return 1.
        """
        for key in self.keys:
            dictionary = dictionary.get(key, None)

            if not dictionary: 
                break

        return dictionary   
################################################################################
# 
################################################################################
class FindingColumnMap:
    """
    Maps all API values to CSV columns, essentially flattening the API dict
    into a list that can be appended to a CSV file. This class automatically
    numbers the columns.
    """
    #---------------------------------------------------------------------------
    def __init__ (self, map=[]):
        """
        See the class definition for details
        """
        self.columns = 0
        self.itemList = []
        self.itemMap = {}

        for item in map:
            if not isinstance(item, FindingColumn):
                raise FindingValueError("496070t all FindingColumnMap items " + \
                    "must be FindingColumn objects")

            # Set the column number automatically
            item.columnNumber = self.columns

            self.itemList.append(item)
            self.itemMap[item.columnName] = item
            self.columns += 1

            _LOGGER.debug("496080d mapped column number %d to column name %s"
                % (item.columnNumber, item.columnName))
    #---------------------------------------------------------------------------
    def __getitem__ (self, item=None):
        """
        Return an item if indexed by a column number object[number] or a dict
        key object[key].
        """
        if isinstance(item, int) and (item >= 0) and (item <= len(self.itemList)):
            answer = self.itemList[item]
        elif item != None:
            answer = self.itemMap[item]
        else:
            answer = None

        return answer
    #---------------------------------------------------------------------------
    def __len__ (self):
        """
        Return the length of the column map.
        """
        return len(self.itemList)         
################################################################################
# 
################################################################################
class Finding:
    """
    Represents an AWS SecurityHub finding. 

    Parameters
    ----------
    initializer : dict or list
        *   The dictionary for a SecurityHub finding from the 
            securityhub:get_findings API call.

        *   A list containing the values of a CSV record containing finding 
            fields in specific columns

    Attributes
    ----------
    mapping : list of FindingColumn
        A list of FindingColumn objects mapping the securityhub:get_findings 
        dictionary to a CSV record with particular column names
    rowList : list
        A list of values representing a CSV row
    rowMap : dict
        A dict keyed by the column name, with each value being the value for
        that column.
    finding : dict
        The nested dict returned by the securityhub:get_findings API, or built
        from a CSV initializer (see below)
    source : type
        Set to dict if initialized by a finding dict, and list if it is initialized
        from a CSV row list
    """
    #---------------------------------------------------------------------------
    def __init__ (self, initializer = None, actor=None):
        """
        See class description for details
        """
        self.actor = actor
        self.mapping = self.fullMap()
        self.findingColumn = {}

        # These values msut exist in the fullMap
        self.Id = None
        self.ProductArn = None

        if isinstance(initializer, dict):
            self.rowMap = self.mapColumns(initializer)
            self.rowList = [ value for key, value in self.rowMap.items() ]
            self.finding = initializer
            self.source = dict
        elif isinstance(initializer, (list, tuple)):
            self.rowList = list(initializer)
            self.rowMap = dict(zip(self.columns, self.rowList))
            self.finding = self.mapFinding(initializer)
            self.source = list
        else:
            raise FindingValueError("496090s initializer must be dict or list")
    #---------------------------------------------------------------------------
    @property
    def keys (self):
        """
        Return a dict of key values for this finding. Key values are attributes
        with the isKey attribute that uniquely identify the finding.
        """
        answer = {}

        for map in self.mapping:
            if map.isKey:
                answer[map.columnName] = getattr(self, map.columnName)
        
        return answer
    #---------------------------------------------------------------------------
    @property
    def columns (self):
        """
        Return a list of CSV column names.
        """
        return [ map.columnName for map in self.mapping ]
    #---------------------------------------------------------------------------
    def mapColumns (self, initializer = None):
        """
        Convert a SecurityHub findings dictionary to a CSV row
        """
        row = {}

        for descriptor in self.mapping:
            # There is magic here -- see the FindingColumn class value setter
            descriptor.value = initializer

            value = descriptor.value
            name = descriptor.columnName

            row[name] = value

            setattr(self, name, value)
            self.findingColumn[name] = descriptor

            _LOGGER.debug("496100d mapped %s to column %s with value [%s]" \
                % (descriptor.keys, name, value))

        return row
    #---------------------------------------------------------------------------
    def mapFinding (self, initializer=None):
        """
        Convert an CSV Manager record to a SecurityHub finding dictionary
        """
        finding = {}

        for value, descriptor in zip(initializer, self.mapping):
            # There is magic here -- see the FindingColumn class value setter
            descriptor.value = initializer

            value = descriptor.value
            name = descriptor.columnName

            setattr(self, name, value)
            self.findingColumn[name] = descriptor

            # Now we build up the finding 
            _LOGGER.debug("496110d %s deep set %s = %s" % \
                (name, descriptor.keys, value))

            Finding._deepSet(finding, descriptor.keys, value)

        return finding
    #---------------------------------------------------------------------------
    def getFindingColumn (self, name=None):
        """
        Return the FindingColumn object associated with a named column.
        """
        return self.findingColumn.get(name)
    #---------------------------------------------------------------------------
    @staticmethod
    def _deepSet (dictionary={}, keys=[], value=None, skipNone=False):
        """
        Given a nested dictionary and a list of keys, set the given value in 
        the nested ditionary based on the key list. I.e., 
        _deepset({}, ["a","b"], 1) results in a dictionary {"a": {"b": 1 }}
        """

        if not keys:
            _LOGGER.debug("496120d deepset called with no keys")
        elif not skipNone or (value != None):
            key = keys[0]

            if len(keys) <= 1:
                dictionary[key] = value
            else:
                keys = keys[1:]

                if not(key in dictionary):
                    dictionary[key] = {}
                elif not isinstance(dictionary[key], dict):
                    dictionary[key] = {}  

                Finding._deepSet(dictionary[key], keys, value)
        
        return dictionary
    #---------------------------------------------------------------------------
    def fullMap (self):
        """
        This list maps CSV column names to sequences of nested keys in the
        Security Hub findings dictionary. See the FindingColumn object for
        details.
        """
        map = FindingColumnMap([
            FindingColumn(
				columnName="Id", 
                keys=["Id"], 
                isKey=True
            ),
            FindingColumn(
                columnName="ProductArn", 
                keys=["ProductArn"], 
                isKey=True
            ), 
            #### BEGIN Updatable fields using securityhub:batch_update_findings()
            FindingColumn(
                columnName="Criticality", 
                keys=["Criticality"], 
                isUpdatable=True,
                d2l=FindingActions.forceInteger,
                l2d=FindingActions.forceInteger
            ),
            FindingColumn(
                columnName="Confidence", 
                keys=["Confidence"], 
                isUpdatable=True,
                d2l=FindingActions.forceInteger,
                l2d=FindingActions.forceInteger,
            ),
            FindingColumn(
                columnName="NoteText",
                keys=["Note", "Text"],
                isUpdatable=True
            ),
            FindingColumn(
                columnName="NoteUpdatedBy",
                keys=["Note", "UpdatedBy"],
                isUpdatable=True,
                d2l=FindingActions.noteUpdater,
                d2lParameters={"actor" : self.actor , "finding": self },
                l2d=FindingActions.noteUpdater,
                l2dParameters={"actor" : self.actor , "finding": self }
            ),
            FindingColumn(
                columnName="CustomerOwner",
                keys=["UserDefinedFields", "Owner"],
                isUpdatable=True
            ),
            FindingColumn(
                columnName="CustomerIssue",
                keys=["UserDefinedFields", "Issue"],
                isUpdatable=True
            ),
            FindingColumn(
				columnName="CustomerTicket",
                keys=["UserDefinedFields", "Ticket"],
                isUpdatable=True
            ),
            FindingColumn(
				columnName="ProductSeverity",
                keys=["Severity", "Product"],
                isUpdatable=True,
                d2l=FindingActions.checkSeverity,
                l2d=FindingActions.checkSeverity,
            ),
            FindingColumn(
				columnName="NormalizedSeverity",
                keys=["Severity", "Normalized"],
                isUpdatable=True,
                d2l=FindingActions.checkSeverity,
                l2d=FindingActions.checkSeverity
            ),
            FindingColumn(
				columnName="SeverityLabel",
                keys=["Severity", "Label"],
                isUpdatable=True,
                d2l=FindingActions.checkSeverityLabel,
                l2d=FindingActions.checkSeverityLabel
            ),
            FindingColumn(
				columnName="VerificationState",
                keys=["VerificationState"],
                isUpdatable=True,
                d2l=FindingActions.checkVerificationState,
                l2d=FindingActions.checkVerificationState
            ),
            FindingColumn(
				columnName="Workflow",
                keys=["Workflow", "Status"],
                isUpdatable=True,
                d2l=FindingActions.checkWorkflow,
                l2d=FindingActions.checkWorkflow
            ),
            #### END Updatable fields using securityhub:batch_update_findings()
            FindingColumn(
				columnName="UpdateVersion",
                keys=[],
                d2l=str(_CURRENT_VERSION),
                l2d=str(_CURRENT_VERSION)
            ),
            FindingColumn(
				columnName="GeneratorId",
                keys=["GeneratorId"]
            ),
            FindingColumn(
				columnName="AwsAccountId",
                keys=["AwsAccountId"]
            ),
            FindingColumn(
				columnName="Types",
                keys=["Types"],
                d2l=FindingActions.delist
            ) ,
            FindingColumn(
				columnName="FirstObservedAt",
                keys=["FirstObservedAt"]
            ),
            FindingColumn(
				columnName="LastObservedAt",
                keys=["LastObservedAt"]
            ),
            FindingColumn(
				columnName="CreatedAt",
                keys=["CreatedAt"]
            ),
            FindingColumn(
				columnName="UpdatedAt",
                keys=["UpdatedAt"]
            ),
            FindingColumn(
				columnName="Title",
                keys=["Title"]
            ),
            FindingColumn(
				columnName="Description",
                keys=["Description"]
            ),
            FindingColumn(
				columnName="StandardsArn",
                keys=["ProductFields", "StandardsArn"]
            ),
            FindingColumn(
				columnName="StandardsSubscriptionArn",
                keys=["ProductFields", "StandardsSubscriptionArn"]
            ),
            FindingColumn(
				columnName="ControlId",
                keys=["ProductFields", "ControlId"]
            ),
            FindingColumn(
				columnName="RecommendationUrl",
                keys=["ProductFields", "RecommendationUrl"]
            ),
            FindingColumn(
				columnName="StandardsControlArn",
                keys=["ProductFields", "StandardsControlArn"]
            ),
            FindingColumn(
				columnName="ProductName",
                keys=["ProductFields", "aws/securityhub/ProductName"]
            ),
            FindingColumn(
				columnName="CompanyName",
                keys=["ProductFields", "aws/securityhub/CompanyName"]
            ),
            FindingColumn(
				columnName="Annotation",
                keys=["ProductFields", "aws/securityhub/annotation"]
            ),
            FindingColumn(
				columnName="FindingId",
                keys=["ProductFields", "aws/securityhub/FindingId"]
            ),
            FindingColumn(
				columnName="Resources",
                keys=["Resources"],
                d2l=FindingActions.resources
            ),
            FindingColumn(
				columnName="ComplianceStatus",
                keys=["Compliance", "Status"]
            ),
            FindingColumn(
				columnName="WorkflowState",
                keys=["WorkflowState"]
            ),
            FindingColumn(
				columnName="RecordState",
                keys=["RecordState"]
            )
        ])

        return map
################################################################################
# 
################################################################################
class FindingActions:
    """
    A class containing static methods used to pre- and post-process values 
    used in SecurityHub finding dictionaries and CSV records
    """
    _SEVERITY_LABELS = [
        "INFORMATIONAL", 
        "LOW", 
        "MEDIUM", 
        "HIGH", 
        "CRITICAL"
    ]

    _VERIFICATION_STATES = [
         "UNKNOWN", 
         "TRUE_POSITIVE", 
         "FALSE_POSITIVE", 
         "BENIGN_POSITIVE"
    ]

    _WORKFLOWS = [
        "NEW", 
        "NOTIFIED", 
        "RESOLVED", 
        "SUPPRESSED"
    ]
    #---------------------------------------------------------------------------
    @staticmethod
    def noteUpdater (value=None, actor=None, finding=None):
        """
        Return the principal ID of the user who is updating a note. This value
        is only set if there is a corresponding update to the NoteText 
        attribute of the finding.
        """
        if not isinstance(actor, Actor) or not isinstance(finding, Finding):
            _LOGGER.warning("496130w missing actor or finding for '%s'" % value)
            answer = None
        else:
            if finding.NoteText:
                answer = actor.principal.get("UserId")
            else:
                answer = None

        return answer
    #---------------------------------------------------------------------------
    @staticmethod
    def delist (list = []):
        """
        Convert a list into a newline-separated string
        """
        return "".join(list)
    #---------------------------------------------------------------------------
    @staticmethod
    def resources (resources = []):
        """
        Convert a list of SecurityHub resources to a newline-separated string
        """
        answer = []

        for resource in resources:
            _type = resource.get("Type")
            _id = resource.get("Id")
            _partition = resource.get("Partition")
            _region = resource.get("Region")

            answer.append("%s, %s, %s, %s" % (_type, _id, _partition, _region))

        return "".join(answer)
    #---------------------------------------------------------------------------
    @staticmethod
    def checkSeverity (value=0): 
        """
        Verify a Security Hub severity value, which must be an integer between
        0 and 100, or a floating point number provided by the source application
        """
        if value == None:
            answer = None
        elif isinstance(value, str):
            try:
                answer = int(value)

                if (answer < 0) or (answer > 100):
                    raise FindingValueError(
                        "%d is not an int between 0 and 100" % value
                    )
            except:
                try:
                    answer = float(value)
                except:
                    answer = None
        elif isinstance(value, float):
            answer = value
        elif isinstance(value, int) and (value >= 0) and (value <= 100):
            answer = value
        else:
            raise FindingValueError(
                "%d is not a float or int between 0 and 100" % value
            )

        return answer
    #---------------------------------------------------------------------------
    @staticmethod
    def checkSeverityLabel (value=None):
        """
        Verify a Security Hub severity label which must be one of the values in 
        the list below. The comparison is case insensitive and an uppercase 
        value is always returned.

        Valid values are stored in FindingActions._SEVERITY_LABELS
        """
        if not isinstance(value, str) or value == '':
            answer = None
        else:
            if value.upper() in FindingActions._SEVERITY_LABELS:
                answer = value.upper()
            else:
                raise FindingValueError(
                    "'%s' is not a valid severity label" % value
                )

        return answer
    #---------------------------------------------------------------------------
    @staticmethod
    def checkVerificationState (value=None):
        """
        Verify a Security Hub verification state which must be one of the values 
        in the list below. The comparison is case insensitive, converts 
        whitespace to a single underscore ("_") and an uppercase value is always 
        returned.

        Valid values are in FindingActions._VERIFICATION_STATES
        """
        if not isinstance(value, str) or value == '':
            answer = None
        else:
            candidate = re.sub(r'\s+', "_", value).upper()

            if candidate in FindingActions._VERIFICATION_STATES:
                answer = candidate
            else:
                raise FindingValueError(
                    "'%s' is not a valid verification state" % value
                )

        return answer
    #---------------------------------------------------------------------------
    @staticmethod
    def checkWorkflow (value=None):
        """
        Verify a Security Hub workflow label which must be one of the values in 
        the list below. The comparison is case insensitive and an uppercase 
        value is always returned.

        Valid values are in FindingActions._WORKFLOWS
        """
        if not isinstance(value, str) or value == '':
            answer = None
        else:
            if value.upper() in FindingActions._WORKFLOWS:
                answer = value.upper()
            else:
                raise FindingValueError(
                    "'%s' is not a valid workflow state" % value
                )

        return answer
    #---------------------------------------------------------------------------
    @staticmethod
    def forceInteger (value=None):
        """
        Force a value to be an integer.
        """
        try:
            answer = int(value)
        except:
            answer = None

        return answer
################################################################################
# 
################################################################################
class ActorException (Exception):
    pass
################################################################################
# 
################################################################################
class Actor:
    _REGION_MODE_SINGLE = 1    # A simple, single-region client
    _REGION_MODE_MULTIPLE = 1   # Requires a ServiceRegionBroker
    """
    An abstract class for API functions. The class defines clients in each of 
    a set of supported regions, and then carries out actions using those
    clients.

    The following APIs are used by the abstract class:
    sts:AssumeRole
    sts:GetCallerIdentity
    """
    #---------------------------------------------------------------------------
    def __init__ (self, service=None, region=None, role=None):
        """
        See the class definition for details.
        """
        self.role = role
        self.authorized = False
        self.accessKeyId = None
        self.accessKey = None
        self.sessionToken = None
        self.client = {}
        self.principal = None
        self.service = service

        # Some things depend on whether we were passed a region or a list 
        if isinstance(region, list):
            self.regions = region
            self.mode = Actor._REGION_MODE_MULTIPLE

            _LOGGER.debug(f'496140d service {service} set to _REGION_MODE_MULTIPLE')

        elif isinstance(region, str):
            self.regions = [ region ]
            self.mode = Actor._REGION_MODE_SINGLE

        else:
            raise ActorException("496150t region must be a region name or list of regions [%s]" % region)

        # Get authorization
        self.authorize(regions=self.regions)

        # Create a client for the specified regions
        for region in self.regions:
            _LOGGER.debug("496160d create %s client in region %s" 
                % (self.service, region))

            self.client[region] = self.getClient(region)
    #---------------------------------------------------------------------------
    def getPartition(self, region:str) -> str:
        """
        Get an AWS partition name from a given region. This must be possible to
        do more elegantly later
        """
        candidate = region if region else self.primaryRegion
        answer = "aws"
        
        if re.match(r'^us-gov.*', candidate):
            answer = "aws-us-gov"

        _LOGGER.debug(f'496180d mapped region {candidate} to partition {answer}')
        
        return answer
    #---------------------------------------------------------------------------
    def getSupportedRegions(self, region:str=None, service:str=None) -> list:
        """
        Return a list of supported regions for this servce
        """
        region = self.primaryRegion if not region else region
        partition = self.getPartition(region)
        service = self.service if not service else service

        answer = Session(region_name=region) \
            .get_available_regions(
                service,
                partition_name=partition
            )

        return answer
    #---------------------------------------------------------------------------
    def getClient (self, region:str) -> object:
        """
        Create an AWS API client associated with a specific region
        """
        try:
            client = boto3.client(
                self.service,
                aws_access_key_id=self.accessKeyId, 
                aws_secret_access_key=self.accessKey, 
                aws_session_token=self.sessionToken ,
                region_name=region             
           )

        except Exception as thrown:
            _LOGGER.critical(f'496190s error obtaining client for {self.service} ' + 
                f'in {region}: {thrown}') 
            client = None

        return client
    #---------------------------------------------------------------------------
    @property
    def primaryRegion (self):
        """
        Return the SRB's primary region or just use the supplied region
        """
        return self.regions[0]
    #---------------------------------------------------------------------------
    @property
    def primaryClient (self):
        """
        Return the client for the primary region
        """
        return self.client[self.primaryRegion]
    #---------------------------------------------------------------------------
    def authorize (self, regions=None):
        """
        If no role is supplied to the actor, the authorization is implicit
        through the credentials already in the environment. Otherwise, use
        sts:assume_role to gain the privileges associated with the supplied
        role ARN.
        """
        _LOGGER.debug("496200d request to authorize %s client region %s"
            % (self.service, regions[0]))

        # Obtain an STS client
        try:
            # Obtain an STS client
            client = boto3.client("sts", region_name=regions[0])
            _LOGGER.debug("496210d obtained STS client %s" % client)

            # No role supplied - use environment credentials
            if not self.role:
                self.authorized = True
                _LOGGER.debug("496220d authorized from environment")

            # Role supplied, try to assume the role
            else:
                _LOGGER.debug("496230d attempt to assume role %s" % self.role)

                answer = client.assume_role(
                    RoleArn=self.role, 
                    RoleSessionName=("%s-access" % self.service)
                )

                self.accessKeyId = answer["Credentials"]["AccessKeyId"]
                self.accessKey = answer["Credentials"]["SecretAccessKey"]
                self.sessionToken = answer["Credentials"]["SessionToken"]
                self.authorized = True

                _LOGGER.info("496240i assumed role %s for service %s" \
                    % (self.role, self.service))

            # Now get the principal name of the authorized identity
            self.principal = client.get_caller_identity()
        
        # Catch client errors
        except ClientError as thrown:
            _LOGGER.critical(f'496250d threw {errorCode(thrown)}: {thrown}')
            self.authorized = False

        # If we got this far, we're authorized
        else:
            self.authorized = True

        # Complain if we aren't authorized
        if not self.authorized:
            raise ActorException('496260t authorization failed')

        return self
################################################################################
# 
################################################################################
class SsmActor (Actor):
    """
    Perform systems manager (SSM) actions. The following SSM APIs are used 
    in this concrete class:

    ssm:PutParameter
    ssm:GetParameters
    """
    _PARAMETERS = [
        "/csvManager/bucket", 
        "/csvManager/folder/code", 
        "/csvManager/folder/findings", 
        "/csvManager/object/codeArchive",
        "/csvManager/partition",
        "/csvManager/regionList"
    ]
    #---------------------------------------------------------------------------
    def __init__ (self, region=None, role=None, resolve=_PARAMETERS):
        """
        See the class definition for details.
        """
        super().__init__(
            service="ssm",
            region=region,
            role=role
        )

        if resolve:
            answers = self.getValue(resolve)

            for name, value in answers.items():
                setattr(self, name, value)
    #---------------------------------------------------------------------------
    # Set an SSM parameter value
    def putValue (self, name=None, description=None, value=None, type="String"):
        """
        Set the value of an SSM parameter.
        """
        try:
            answer = self.primaryClient.put_parameter(
                Name=name,
                Description=description,
                Type=type,
                Value=value,
                Overwrite=True
           )

        except Exception as thrown:
            _LOGGER.info(f'496270s cannot set parameter: {thrown}')

            answer = None

        return answer
    #---------------------------------------------------------------------------
    # Get SSM parameter values
    def getValue (self, names:list[str]=[]):
        """
        Retrieve the value of an SSM parameter.
        """
        if isinstance(names, list):
            single = False
            answer = {}
        else:
            names = [names]
            single = True
            answer = None

        try:
            answer = self.primaryClient.get_parameters(Names=names)

            _LOGGER.debug("496280d result from ssm:get_parameters %s" % answer)

            for candidate in answer["Parameters"]:
                name = candidate["Name"]
                value = candidate["Value"]

                if single:
                    answer = value
                else:
                    answer[name] = value

                _LOGGER.debug(f'496290i SSM {name} = {value}')

            for name in answer["InvalidParameters"]:
                _LOGGER.info("496300d parameter '%s' not found" % name)
                answer[name] = None

        except Exception as thrown:
            _LOGGER.error("496310e cannot get parameters: %s" % str(thrown))

            if not single:
                for name in names:
                    _LOGGER.info("496320d parameter '%s' set to None" % name)
                    answer[name] = None

        return answer
################################################################################
# 
################################################################################
class S3Actor(Actor):
    """
    Perform AWS Simple Storage Service (S3) API operations. The following S3
    API operations are used by this concrete class:

    s3:PutObject
    s3:GetObject
    """
    _PREFIX = "SecurityHub"
    _SUFFIX = ".csv"
    _FOLDER = "SecurityHub"
    #---------------------------------------------------------------------------
    def __init__ (self, bucket=None, folder=_FOLDER, prefix=_PREFIX, 
        suffix=_SUFFIX, region=None, role=None):
        """
        See the class definition for details
        """
        super().__init__("s3", region=region, role=role)

        self.prefix = prefix
        self.suffix = suffix
        self.folder = folder 
        self.bucket = bucket
        self._filename = None
    #---------------------------------------------------------------------------
    def buildFilename (self, bucket=None, folder=None, name=None, 
        extension=None):
        """
        Construct an fully qualified S3 name from the bucket, folder, 
        filename, and extention.
        """
        answer = (bucket if bucket else self.bucket) + "/" + \
            (folder if folder else self.folder) + "/" + \
            ((name + "." + extension) if extension else name)

        return answer
    #---------------------------------------------------------------------------
    @property
    def filename (self):
        """
        Return the unique S3 key associated with this object.
        """
        if self._filename:
            answer = self._filename
        else:
            answer = self.prefix + "-" + \
                time.strftime("%Y%m%d-%H%M%S") + \
                self.suffix

            self._filename = answer

        return answer
    #---------------------------------------------------------------------------
    def filePath (self, directory = "/tmp"):
        """
        Return a local fully qualified file path.
        """
        return "/".join([directory, self.filename])
    #---------------------------------------------------------------------------
    @property
    def objectKey (self):
        """
        Return an S3 object key from the "folder" and unique filename.
        """
        return "/".join([self.folder, self.filename]) 
    #---------------------------------------------------------------------------
    def put (self, inputFile = None, outputObject = None ):
        """
        Store an object in the S3 bucket. The inputFile is read from
        the local filesystem and stored to S3 as outputObject.
        """
        source = inputFile if inputFile else self.filePath()
        target = outputObject if outputObject else self.objectKey

        try:
            with open(source, "rb") as source:
                answer = self.primaryClient.put_object(
                    Bucket=self.bucket,
                    Key=target,
                    Body=source
                )

        except botocore.exceptions.ClientError as thrown:
            answer = None
            _LOGGER.critical("496330s cannot put object %s to bucket %s: %s" \
                % (target, self.bucket, str(thrown)))

        return answer
    #---------------------------------------------------------------------------
    def parseS3Url (self, url=None):
        """
        Parse an S3 url into bucket and key components.
        """
        # This pattern will match s3://[bucket]/[key]
        pattern = re.compile(
            r'^s3://(?!^(\d{1,3}\.){3}\d{1,3}$)(^[a-z0-9]([a-z0-9-]*(\.[a-z0-9])?)*$)(/*(.*))',
            flags=re.IGNORECASE
        )

        # Perform the match
        match = pattern.match(url) if url else None

        if not match:
            answer = None
        else:
            answer = ( match.group(1), match.group(3) )

        return answer
    #---------------------------------------------------------------------------
    def get (self, file=None, bucket=None, key=None, split=False):
        """
        Retrieve an object from S3 or a local file and return the entire body.

        Parameters
        ----------
        file : str 
            A local file path 
        bucket : str
            Mutually exclusive with file, specifies an S3 bucket name
        key : str
            Mutually exclusive with file, specifies an S3 object key
        """
        # Specifying a local file overrides S3
        if file:
            source = file

            try:
                with open(source, "r") as input:
                    candidate = input.read()

                if not split:
                    answer = candidate
                else:
                    answer = [ line.strip() for line in candidate.splitlines() ]
            except Exception as thrown:
                answer = None
                _LOGGER.critical("496340s cannot read file %s: %s" \
                    % (source, str(thrown)))
        else:
            bucket = bucket if bucket else self.bucket
            key = key if key else self.objectKey

            try:
                response = self.primaryClient.get_object(
                    Bucket=bucket,
                    Key=key
                )

                candidate = response.get("Body").read().decode("utf-8")

                if not split:
                    answer = candidate
                else:
                    answer = [ line.strip() for line in candidate.splitlines() ]
            except botocore.exceptions.ClientError as thrown:
                answer = None
                _LOGGER.critical("496350s cannot get object %s from bucket %s: %s" \
                    % (key, bucket, str(thrown)))

        return answer   
################################################################################
# 
################################################################################
class HubActor (Actor):
    """
    Perform Security Hub API actions. The following API actions are used 
    by this concrete class:

    securityhub:GetFindings
    securityhub:BatchUpdateFindings
    """
    #---------------------------------------------------------------------------
    def __init__ (self, region=None, role = None):
        """
        See class definition for details/
        """
        super().__init__(
            "securityhub",
            region=region,
            role=role
        )

        self.findings = []
        self.count = 0
    #---------------------------------------------------------------------------
    def updateFindings (self, region=None, parameters=None):
        """
        Update a finding. Parameters are generated by the MinimalUpdateList
        parameterSets method. This method returns the untouched response
        structure from the API call.
        """
        client = self.getClient(region)

        try:
            response = client.batch_update_findings(**parameters)
        except Exception as thrown:
            response = None

            _LOGGER.critical("496360t securityhub:batch_update_findings: %s" \
                % str(thrown))

        return response
    #---------------------------------------------------------------------------
    def downloadFindings (self, regions=None, filters={}, limit=0):
        """
        Get findings from Security Hub using the securityhub:get_findings API,
        applying filters as necessary, and limiting results as necessary.
        """
        regions = self.regions

        self.findings = []
        downloaded = 0

        # Get findings for each region
        for region in regions:
            _LOGGER.info(f'496370i retrieving findings from region {region}')

            # Get SecurityHub client for this region
            client = self.client[region]

            try:
                token = None
    
                while True:
                    if not token:
                        answer = client.get_findings(
                            Filters=filters, 
                            MaxResults=100
                        ) 
                    else:
                        answer = client.get_findings(
                            Filters=filters, 
                            MaxResults=100, 
                            NextToken=token
                        )
    
                    token = answer.get("NextToken", None)
                    findings = answer.get("Findings", [])
                    downloaded += len(findings)

                    if (downloaded % 1000) == 0:
                        _LOGGER.info("496380i ... %8d findings retrieved" \
                            % downloaded)
    
                    self.findings += findings
    
                    # This is the last set of findings if there is no "nexttoken"
                    if not token: 
                        break

                    # If we've exceeded the finding limit, we're done
                    if (limit != 0) and (downloaded > limit):
                        _LOGGER.info("496390i %d findings exceeds limit of %d" \
                            % (downloaded, limit))
                        break
    
                self.count = len(self.findings)

                if (limit != 0) and (downloaded > limit):
                    break
    
            except client.exceptions.InvalidAccessException as thrown:
                _LOGGER.error('496400e cannot retrieve findings for ' 
                    + f'region {region}: {thrown.response["Error"]["Message"]}')

        _LOGGER.info("496410i retrieved %d total findings from all regions" \
            % downloaded)

        return self.findings
    #---------------------------------------------------------------------------
    def getFinding (self):
        """
        Generator yields each successive finding from a previous 
        downloadFindings operation.
        """
        for finding in self.findings:
            yield finding
################################################################################
# 
################################################################################
class MalformedUpdate (Exception):
    """
    There were errors in the uppdate request
    """
    pass
################################################################################
# 
################################################################################
class FindingUpdate:
    """
    Represents an update to a Security Hub finding. The update is separated
    into a key signature and an update signature. See MinimumUpdateList for
    more details.
    """
    #---------------------------------------------------------------------------
    def __init__ (self, finding=None):
        """
        See the class description for details.
        """
        if not isinstance(finding, Finding):
            raise MalformedUpdate("496420t findings must be Finding objects")

        self.finding = finding
        self.changes = 0
        self.update = {}
        self.attributes = []
        self.keys = {}

        # Handle the updates - map is assigned to a FindingColumn object
        for column in finding.mapping:
            name = column.columnName
            value = getattr(finding, name)

            # Keep track of keys
            if column.isKey:
                _LOGGER.debug("496430d column %s value '%s' is a key" \
                    % (name, value))

                self.keys[name] = getattr(finding, name)

            # Do not process non-updatable columns
            if not column.isUpdatable:
                _LOGGER.debug("496440d skipping column %s - not updatable" \

                    % name)
                continue

            # Do not process empty strings or None
            if (value != 0) and not value:
                _LOGGER.debug("496450d skipping column %s value '%s'" \
                    % (name, value))

                continue

            _LOGGER.debug("496460d column %s value '%s'" % (name, value))

            # Save the change (we know this is an updatable column)
            self.attributes.append(name)

            Finding._deepSet(
                self.update, 
                finding.getFindingColumn(name).keys, 
                value
            )
                    
            self.changes += 1

            setattr(self, name, value)

        _LOGGER.debug("496470d finding %s\n\tsignature %s\n\tchanges %d" % \
            (self.keyString, self.signature, self.changes))
    #---------------------------------------------------------------------------
    @property
    def updateRegion (self):
        """
        Return the region associated with this finding. The region is parsed
        from the Id value of the associated finding, which should be an ARN.
        """
        identity = getattr(self.finding, "Id", None)
        answer  = None

        if not identity:
            raise MalformedUpdate("496480t finding does not contain an Id")
        else:
            try:
                answer = identity.split(":")[3]
            except Exception as thrown:
                raise MalformedUpdate("496490t malformed finding ID %s: %s" \
                    % (identity, thrown))

        return answer
    #---------------------------------------------------------------------------
    @property
    def signature (self):
        """
        Returns an update signature as a string composed of the sorted 
        attribute names to be changed and their proposed values.
        """
        answer = []

        for attribute in sorted(self.attributes):
            value = getattr(self, attribute)

            if value:
                answer.append("%s=%s" % (attribute, value))

        answer = self.updateRegion + "|".join(answer)

        return answer
    #---------------------------------------------------------------------------
    @property
    def keyString (self):
        """
        Returns a string containing the key values for the finding as
        key=value pairs separated by vertical bars.
        """
        answer = []

        for key in sorted(self.keys.keys()):
            answer.append("%s=%s" % (key, self.keys.get(key)))

        answer = "|".join(answer)

        return answer
################################################################################
# 
################################################################################
class StartNextUpdateBatch (Exception): 
    """
    Raise this exception when an update set has 100 findings
    """
    pass
################################################################################
# 
################################################################################
class MinimumUpdateList:
    """
    Accumulate finding updates and structure the updates so that multiple
    findings with the same changes will only be submitted once.
    """
    #---------------------------------------------------------------------------
    def __init__ (self):
        """
        See class definition for details.
        """
        self.update = {}
        self.findings = {}
        self.regions = {}
        self.sets = 0
    #---------------------------------------------------------------------------
    def add (self, finding=None):
        """
        Add a finding to the minimum update list. Findings are aggregated by 
        their update signature (a unique string of keys and values to be 
        changed). Multiple findings with the same update signature will be
        submitted as a single update to Security Hub.
        """
        update = FindingUpdate(finding)

        if update.changes > 0:
            region = update.updateRegion
            signature = region + "|" + update.signature

            _LOGGER.debug("496500d found signature '%s'" % signature)

            # This is the first time we've seen this signature
            if not (signature in self.update):
                _LOGGER.debug("496510d saved update for signature '%s'" \
                    % signature)

                self.update[signature] = update
        
            # This is the first time we've seen this finding
            if not (signature in self.findings):
                _LOGGER.debug("496520d initialized findings and region for '%s'" \
                    % signature)

                self.findings[signature] = []
                self.regions[signature] = region
                self.sets += 1

            # Track all findings for a signature
            self.findings[signature].append(finding)
            _LOGGER.debug("496530d added finding to '%s'" % signature)
    #---------------------------------------------------------------------------
    @staticmethod
    def updateCount (update=[]):
        """
        How many updates are in this batch
        """
        return len(update.get("FindingIdentifiers", []))
    #---------------------------------------------------------------------------
    def parameterSets (self):
        """
        Generator to yield each update as a set of parameters to the 
        securityhub:batch_update_findings API.
        """
        signatures = 0

        # Go through each update signature and findings
        for signature, findings in self.findings.items():
            region = self.regions[signature]
            update = self.update.get(signature).update

            update["FindingIdentifiers"] = []

            _LOGGER.debug(f'496540d signature {signature} update {update}')

            signatures += 1

            _LOGGER.info(f'496550i processing update set {signatures}...')

            # Now loop through findings to build an update set
            for finding in findings:
                update["FindingIdentifiers"].append(finding.keys)
                _LOGGER.debug(f'496560d adding {len(finding.keys)} to update now {self.updateCount(update)}')

                # The upate set can be contain no more than 100 finding IDs --
                # yield the updaet set and then clear it out
                if self.updateCount(update) >= 100:
                    _LOGGER.debug(f'496570d batch has >=100 finding IDs, yielding to {region}')
                    yield region, update
 
                    update["FindingIdentifiers"] = []

            # We end up here whenever the number of findings is < 100
            if self.updateCount(update) > 0:
                _LOGGER.debug(f'496580d yielding {self.updateCount(update)} finding IDs to {region}')
                yield region, update
    #----------------------------------------------------------------------------
    @staticmethod
    def apply (update=None, region=None, actor=None):
        """
        Static method to apply an update to SecurityHub findings. The update
        must be the value yielded by the parameterSets generator, and the
        actor must be a HubActor object.

        This method should probably be moved to HubActor as an object method,
        it but suffices for now.
        """
        response = {}

        if not isinstance(actor, HubActor):
            raise MalformedUpdate("496590t MinimumUpdateList.apply requires a " + \
                "HubActor object")
        try:
            response = actor.updateFindings(region=region, parameters=update)
        except Exception as thrown:
            response = None
            _LOGGER.critical("496600s unexpected error %s" % str(thrown))

        if (response == None):
            _LOGGER.critical("496610s bad things in MinimumUpdateList.apply")

        return response
