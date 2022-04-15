## CSV Manager for AWS Security Hub

CSV Manager for AWS Security Hub exports Security Hub findings to a CSV file and allows you to mass-update SecurityHub findings by modifying that CSV file. For more information, please consult the `README.pdf` file in this repository.

The solution can be deployed on a workstation or through [`Cloud Development Kit`](https://docs.aws.amazon.com/cdk/v2/guide/home.html) (CDK), which can be found below. For instructions on deploying the solution to a separate workstation, follow the [`Workstation Deployment`](/Workstation%20Deployment.pdf). 

## Build

To build this app, you need to be in the cdk project root folder [`csv_manager_sechub_cdk`](/csv_manager_sechub_cdk/). Then run the following:

npm install -g aws-cdk
npm install
npm run build

    $ npm install -g aws-cdk
    <installs AWS CDK>

    $ npm install
    <installs appropriate packages>

    $ npm run build
    <build TypeScript files>

To add additional IAM principals to access the S3 bucket where findings will be exported, add the IAM principal ARN to [`config.json`](/csv_manager_sechub_cdk/config.json)
## Deploy

    $ cdk bootstrap aws://<INSERT_AWS_ACCOUNT>/<INSERT_REGION>
    <build S3 bucket to store files to perform deployment>

    $ cdk deploy
    <deploys the cdk project into the authenticated AWS account>

## CDK Toolkit

The [`cdk.json`](/csv_manager_sechub_cdk/cdk.json) file in the root of this repository includes
instructions for the CDK toolkit on how to execute this program.

After building your TypeScript code, you will be able to run the CDK toolkits commands as usual:

    $ cdk ls
    <list all stacks in this program>

    $ cdk synth
    <generates and outputs cloudformation template>

    $ cdk deploy
    <deploys stack to your account>

    $ cdk diff
    <shows diff against deployed stack>

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

