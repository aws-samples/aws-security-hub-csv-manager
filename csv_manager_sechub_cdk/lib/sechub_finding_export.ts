import { Stack, StackProps, Duration, CfnParameter, Fn, RemovalPolicy } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { join } from 'path';
import { Function, Runtime, Code } from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events'
import { LambdaFunction } from 'aws-cdk-lib/aws-events-targets';
import { StringParameter, CfnDocument } from 'aws-cdk-lib/aws-ssm';
import { principalsJson } from '../config.json';
import { Key } from 'aws-cdk-lib/aws-kms';
import { BlockPublicAccess, Bucket, BucketEncryption, ObjectOwnership, StorageClass } from 'aws-cdk-lib/aws-s3';


export class SecHubExportStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Stack Parameters
    const Frequency = new CfnParameter(this, 'Frequency', {
      type: 'String',
      description: 'A cron or rate expression for how often the export occurs.',
      default: 'cron(0 8 ? * SUN *)'
    });

    const Partition = new CfnParameter(this, 'Partition', {
      type: 'String',
      description: 'The partition in which CSV Manager for Security Hub will operate.',
      default: 'aws'
    });

    const Regions = new CfnParameter(this, 'Regions', {
      type: 'String',
      description: 'The comma-delimeted list of regions in which CSV Manager for Security Hub will operate.',
      default: this.region
    });

    const PrimaryRegion = new CfnParameter(this, 'PrimaryRegion', {
      type: 'String',
      description: 'The region in which the S3 bucket and SSM parameters are stored.',
      default: this.region
    });

    const FindingsFolder = new CfnParameter(this, 'FindingsFolder', {
      type: 'String',
      description: 'Folder that will contain Lambda code & CloudFormation templates.',
      default: 'Findings'
    });

    const CodeFolder = new CfnParameter(this, 'CodeFolder', {
      type: 'String',
      description: 'Folder that will contain Lambda code & CloudFormation templates.',
      default: 'Code'
    });

    const ExpirationPeriod = new CfnParameter(this, 'ExpirationPeriod', {
      type: 'Number',
      description: 'Maximum days to retain exported findings.',
      default: 365
    });

    const GlacierTransitionPeriod = new CfnParameter(this, 'GlacierTransitionPeriod', {
      type: 'Number',
      description: 'Maximum days before exported findings are moved to AWS Glacier.',
      default: 31
    });

    //// Data Store Resources

    // S3 Bucket Resources
    // KMS Key for S3 Bucket for Security Hub Export
    const s3_kms_key = new Key(this, 's3_kms_key', {
      removalPolicy: RemovalPolicy.DESTROY,
      pendingWindow: Duration.days(7),
      description: 'KMS key for security hub findings in S3.',
      enableKeyRotation: false,
      alias: 'sh_export_key'
    });

    // S3 Bucket for Security Hub Export
    const security_hub_export_bucket = new Bucket(this, 'security_hub_export_bucket', {
      removalPolicy: RemovalPolicy.RETAIN,
      bucketKeyEnabled: true,
      encryption: BucketEncryption.KMS,
      encryptionKey: s3_kms_key,
      enforceSSL: true,
      versioned: true,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      objectOwnership: ObjectOwnership.BUCKET_OWNER_ENFORCED,
      publicReadAccess: false,
      lifecycleRules: [{
        expiration: Duration.days(ExpirationPeriod.valueAsNumber),
        transitions: [{
            storageClass: StorageClass.GLACIER,
            transitionAfter: Duration.days(GlacierTransitionPeriod.valueAsNumber)
        }]
    }]
    });

    principalsJson.principals.forEach((principal: string) => {
      security_hub_export_bucket.addToResourcePolicy(new iam.PolicyStatement({
        actions: [
          's3:GetObject*',
          's3:ListBucket',
          's3:PutObject*'
        ],
        resources: [
          security_hub_export_bucket.bucketArn,
          security_hub_export_bucket.arnForObjects('*')
        ],
        principals: [
          new iam.ArnPrincipal(principal)],
      }));
  })

    // Lambda Function for CSV exporter 
    const secub_csv_manager_role = new iam.Role(this, 'secub_csv_manager_role', {
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal("lambda.amazonaws.com"),
        new iam.ServicePrincipal("ec2.amazonaws.com"),
        new iam.ServicePrincipal("ssm.amazonaws.com")
    ),
      roleName: "SecurityHub_CSV_Exporter",
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaExporterSHLogExecutionPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
      ]
    });

    security_hub_export_bucket.addToResourcePolicy(new iam.PolicyStatement({
      actions: [
        's3:GetObject*',
        's3:ListBucket',
        's3:PutObject*'
      ],
      resources: [
        security_hub_export_bucket.bucketArn,
        security_hub_export_bucket.arnForObjects('*')
      ],
      principals: [
        new iam.ArnPrincipal(secub_csv_manager_role.roleArn)],
    }));

    const sh_csv_exporter_function = new Function(this, 'secub_csv_exporter_function', {
      runtime: Runtime.PYTHON_3_9,
      functionName: this.stackName + '_' + this.account + '_sh_csv_exporter',
      code: Code.fromAsset(join(__dirname, "../lambdas")),
      handler: 'csvExporter.lambdaHandler',
      description: 'Export SecurityHub findings to CSV in S3 bucket.',
      timeout: Duration.seconds(900),
      memorySize: 512,
      role: secub_csv_manager_role,
      reservedConcurrentExecutions: 100,
      environment:{
        CSV_PRIMARY_REGION: PrimaryRegion.valueAsString
      },
    });

    const sh_csv_updater_function = new Function(this, 'secub_csv_updater_function', {
      runtime: Runtime.PYTHON_3_9,
      functionName: this.stackName + '_' + this.account + '_sh_csv_updater',
      code: Code.fromAsset(join(__dirname, "../lambdas")),
      handler: 'csvUpdater.lambdaHandler',
      description: 'Update SecurityHub findings to CSV in S3 bucket.',
      timeout: Duration.seconds(900),
      memorySize: 512,
      role: secub_csv_manager_role,
      reservedConcurrentExecutions: 100,
      environment:{
        CSV_PRIMARY_REGION: PrimaryRegion.valueAsString
      },
    });

    const export_sechub_finding_policy_doc = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "IAMAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "iam:PassRole",
            "iam:PassRole",
            "iam:CreateServiceLinkedRole"
          ],
          resources: [
            Fn.join('', ["arn:", this.partition ,":iam::", this.account,':role/*']),
          ]   
        }),
        new iam.PolicyStatement({
          sid: "STSAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "sts:AssumeRole",
            "sts:GetCallerIdentity"
          ],
          resources: [
            '*'
          ]   
        }),
        new iam.PolicyStatement({
          sid: "SecurityHubAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "securityhub:GetFindings",
            "securityhub:BatchUpdateFindings"
          ],
          resources: [
            '*'
          ]   
        }),
        new iam.PolicyStatement({
          sid: "S3Allow",
          effect: iam.Effect.ALLOW,
          actions: [
            "s3:PutObject",
            "s3:GetObject"
          ],
          resources: [
            security_hub_export_bucket.bucketArn,
            security_hub_export_bucket.arnForObjects("*")
          ]   
        }),
        new iam.PolicyStatement({
          sid: "KMSAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "kms:Describe*",
            "kms:Encrypt",
            "kms:GenerateDataKey",
            "kms:Decrypt"
          ],
          resources: [
            s3_kms_key.keyArn
          ]   
        }),
        new iam.PolicyStatement({
          sid: "InvokeLambdaAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "lambda:InvokeFunction"
          ],
          resources: [
            sh_csv_exporter_function.functionArn,
            sh_csv_updater_function.functionArn
          ]   
        }),
        new iam.PolicyStatement({
          sid: "SSMAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "ssm:PutParameter",
            "ssm:GetParameters"
          ],
          resources: [
            Fn.join('', ["arn:", this.partition, ':ssm:', this.region, ':', this.account,':parameter/csvManager/*']),
          ]   
        }),
      ],
    });

    new iam.ManagedPolicy(this, 'sechub_csv_managed_policy', {
      description: '',
      document:export_sechub_finding_policy_doc,
      managedPolicyName: 'sechub_csv_manager',
      roles: [secub_csv_manager_role]
    });

    new events.Rule(this, 'Rule', {
      schedule: events.Schedule.expression(Frequency.valueAsString),
      enabled: false,
      description: "Invoke Security Hub findings exporter periodically.",
      targets: [
        new LambdaFunction(sh_csv_exporter_function, {
          event: events.RuleTargetInput.fromObject(
            {
            "event": events.EventField.fromPath('$.event')      
            }
           )
        })
      ]
    });
    
    // SSM Document for SSM Account configuration
    const create_sh_export_document = new CfnDocument(this, 'create_sh_export_document', {
      documentType: 'Automation',
      name: 'start_sh_finding_export',
      content: {
        "schemaVersion": "0.3",
        "assumeRole": secub_csv_manager_role.roleArn,
        "description": "Generate a Security Hub Findings Export (CSV Manager for Security Hub) outside of the normal export.",
        "parameters": {
          "Filters": {
            "type": "String",
            "description": "The canned filter \"HighActive\" or a JSON-formatted string for the GetFindings API filter.",
            "default": 'HighActive'
          },
          "Partition": {
            "type": "String",
            "description": "The partition in which CSV Manager for Security Hub will operate.",
            "default": this.partition
          },
          "Regions": {
            "type": "String",
            "description": "The comma-separated list of regions in which CSV Manager for Security Hub will operate.",
            "default": PrimaryRegion.valueAsString
          }
        },
        "mainSteps": [{
          "action": "aws:invokeLambdaFunction",
          "name": "InvokeLambdaforSHFindingExport",
          "inputs": {
            "InvocationType": 'RequestResponse',
            "FunctionName": sh_csv_exporter_function.functionName,
            "Payload": "{ \"filters\" : \"{{Filters}}\" , \"partition\" : \"{{Partition}}\", \"regions\" : \"[ {{Regions}} ]\"}"
          },
          'description':'Invoke the CSV Manager for Security Hub lambda function.',
          'outputs':[
            {
              'Name': 'resultCode',
              'Selector': '$.Payload.resultCode',
              'Type': 'Integer'
            },
            {
              'Name': 'bucket',
              'Selector': '$.Payload.bucket',
              'Type': 'String'
            },
            {
              'Name': 'exportKey',
              'Selector': '$.Payload.exportKey',
              'Type': 'String'
            }
          ],
          'isEnd': true
        }]
      } 
    });
    
    // SSM Document for SSM Account configuration
    const update_sh_export_document = new CfnDocument(this, 'update_sh_export_document', {
      documentType: 'Automation',
      name: 'start_sechub_csv_update',
      content: {
        "schemaVersion": "0.3",
        "assumeRole": secub_csv_manager_role.roleArn,
        "description": "Update a Security Hub Findings Update (CSV Manager for Security Hub) outside of the normal Update.",
        "parameters": {
          "Source": {
            "type": "String",
            "description": "An S3 URI containing the CSV file to update. i.e. s3://<bucket_name>/Findings/SecurityHub-20220415-115112.csv",
            "default": ''
          },
          "PrimaryRegion": {
            "type": "String",
            "description": "Region to pull the CSV file from.",
            "default": PrimaryRegion
          }
        },
        "mainSteps": [{
          "action": "aws:invokeLambdaFunction",
          "name": "InvokeLambdaforSHFindingUpdate",
          "inputs": {
            "InvocationType": 'RequestResponse',
            "FunctionName": sh_csv_updater_function.functionName,
            "Payload": "{ \"input\" : \"{{Source}}\" , \"primaryRegion\" : \"{{PrimaryRegion}}\"}"
          },
          'description':'Invoke the CSV Manager Update for Security Hub lambda function.',
          'outputs':[
            {
              'Name': 'resultCode',
              'Selector': '$.Payload.resultCode',
              'Type': 'Integer'
            }
          ],
          'isEnd':true
        }]
      } 
    });

    //SSM Parameters
    new StringParameter(this, 'BucketNameParameter', {
      description: 'The S3 bucket where Security Hub are exported.',
      parameterName: '/csvManager/bucket',
      stringValue: security_hub_export_bucket.bucketName,
    });
    
    const KMSKeyParameter = new StringParameter(this, 'KMSKeyParameter', {
      description: 'The KMS key encrypting the S3 bucket objects.',
      parameterName: '/csvManager/key',
      stringValue: s3_kms_key.keyArn,
    });

    const CodeFolderParameter = new StringParameter(this, 'CodeFolderParameter', {
      description: 'The folder where CSV Manager for Security Hub code is stored.',
      parameterName: '/csvManager/folder/code',
      stringValue: CodeFolder.valueAsString,
    });

    const FindingsFolderParameter = new StringParameter(this, 'FindingsFolderParameter', {
      description: 'The folder where CSV Manager for Security Hub findings are exported.',
      parameterName: '/csvManager/folder/findings',
      stringValue: FindingsFolder.valueAsString,
    });

    const ArchiveKeyParameter = new StringParameter(this, 'ArchiveKeyParameter', {
      description: 'The name of the ZIP archive containing CSV Manager for Security Hub Lambda code.',
      parameterName: '/csvManager/object/codeArchive',
      stringValue: 'Not Initialized',
    });

    const PartitionParameter = new StringParameter(this, 'PartitionParameter', {
      description: 'The partition in which CSV Manager for Security Hub will operate.',
      parameterName: '/csvManager/partition',
      stringValue: Partition.valueAsString,
    });

    const RegionParameter = new StringParameter(this, 'RegionParameter', {
      description: 'The list of regions in which CSV Manager for Security Hub will operate.',
      parameterName: '/csvManager/regionList',
      stringValue: Regions.valueAsString,
    });

}
}
