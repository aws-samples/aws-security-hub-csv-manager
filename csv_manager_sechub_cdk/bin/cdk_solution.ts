#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SecHubExportStack } from '../lib/sechub_finding_export';

const app = new cdk.App();

new SecHubExportStack(app, 'SecHubExportStack', {
  env: { 
    account: process.env.CDK_DEFAULT_ACCOUNT, 
    region: process.env.CDK_DEFAULT_REGION 
}
});