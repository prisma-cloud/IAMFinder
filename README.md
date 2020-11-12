```
 _____          __  __ ______ _           _           
 |_   _|   /\   |  \/  |  ____(_)         | |          
   | |    /  \  | \  / | |__   _ _ __   __| | ___ _ __ 
   | |   / /\ \ | |\/| |  __| | | '_ \ / _` |/ _ \ '__|
  _| |_ / ____ \| |  | | |    | | | | | (_| |  __/ |   
 |_____/_/    \_\_|  |_|_|    |_|_| |_|\__,_|\___|_|   
```
# IAMFinder
IAMFinder enumerates and finds users and IAM roles in a target AWS account. Upon successfully identifying an IAM role, IAMFinder can also check if this role can be [assumed anonymously](https://aws.amazon.com/premiumsupport/knowledge-center/s3-object-change-anonymous-ownership/). The tool was developed during a [red team exercise]() and it implemented the technique described in this [blog](). Some notable features include:

+ **Stealthy**. The target account won't notice that its users or roles are being enumerated. Because the enumeration performed in your accounts, the logs only show up in your accounts. However, the target account will notice if IAMFinder attempts to assume roles.
+ **Scalable**. IAMFinder can achieve a higher enumeration rate by:
    + Concurrently invoking APIs of multiple AWS services (e.g., S3, KMS, IAM). 
    + Concurrently using multiple AWS accounts. 
+ **Modularized and extensible**. One can implement and integrate additional AWS APIs described in the [blog]()
+ **Cross-partitions**. IAMFinder has been tested in all three AWS [partitions](https://docs.amazonaws.cn/en_us/general/latest/gr/aws-arns-and-namespaces.html), AWS Standard (aws), AWS GovCloud U.S. (aws-us-gov), and AWS China (aws-cn).
+ **Zero cost**. The resources that IAMFinder creates in each service don’t have actual workloads and should not incur any costs.


# Prerequisites
IAMFinder is built with Python 3 and [AWS Boto3 SDK](https://aws.amazon.com/sdk-for-python/). An active AWS account and a Python 3.5+ interpreter are needed to run the tool. 

   + [Create an AWS account](https://aws.amazon.com/premiumsupport/knowledge-center/create-and-activate-aws-account/)
   + [Python3](https://www.python.org/downloads/)
   + [Python package manager](https://pip.pypa.io/en/stable/installing/)

## AWS credentials
IAMFinder needs an [access key](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) or a [security token](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html) to invoke AWS APIs programmatically. The users or roles that IAMFinder uses need to have necessary [permissions]() to call a set of AWS APIs. 

   + [Create an IAM user access key](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_CreateAccessKey)
   + [Obtain a security token through AssumeRole](https://aws.amazon.com/premiumsupport/knowledge-center/iam-assume-role-cli/)

## Permissions
The required permissions depend on the AWS services that IAMFinder uses. IAMFinder can work with one or multiple AWS services. Using multiple services concurrently can achieve a higher enumeration rate because AWS API gateway enforces a rate-limit on each API. IAMFinder currently implements the APIs for four AWS services, IAM, S3, SQS, and KMS. These services can be enabled or disabled in the [config.json](https://github.com/prisma-cloud/IAMFinder/blob/main/config_dir/config.json) file. [AWS_Policy.json](https://github.com/prisma-cloud/IAMFinder/blob/main/AWS_Policy.json) contains the minimal set of permissions needed to use all four services. The exact permissions required for each service are as follows:

#### `S3`
```bash
"s3:PutBucketPublicAccessBlock"
"s3:CreateBucket"
"s3:ListAllMyBuckets"
"s3:PutBucketPolicy"
"s3:GetBucketLocation"
"s3:DeleteBucket"
```

#### `KMS`
```bash
"kms:PutKeyPolicy"
"kms:GetKeyPolicy"
"kms:DisableKey"
"kms:ListKeys"
"kms:ScheduleKeyDeletion"
"kms:ListAliases"
"kms:CreateAlias"
"kms:CreateKey"
```

#### `SQS`
```bash
"sqs:ListQueues"
"sqs:DeleteQueue"
"sqs:CreateQueue"
"sqs:SetQueueAttributes"
```

#### `IAM`
```json
"iam:UpdateAssumeRolePolicy"
"iam:ListRoles"
"iam:CreateRole"
"iam:DeleteRole"
```

Note that we plan to integrate more AWS services described in the [blog](). The permissions policy will be updated when new services are added.

   + [Create an IAM policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_create-console.html#access_policies_create-json-editor)
   + [Create an IAM user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html#id_users_create_console)
   + [Create an IAM role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html)


# Installation
IAMFinder has only two dependent libraries, [boto3](https://pypi.org/project/boto3/) and [requests](https://pypi.org/project/requests/). It is straightforward to run in any platform and environment. We also provide a Dockerfile for users who prefer to run it inside a container. 

### Install on a host:
```bash
git clone https://github.com/prisma-cloud/IAMFinder.git
cd IAMFinder
pip3 install -r requirements.txt
```

### Build a Docker image 
```bash
git clone https://github.com/prisma-cloud/IAMFinder.git
cd IAMFinder
docker build -t iamfinder .
```

# Configuration
IAMFinder needs a configuration file ([config_dir/config.json]()) and a credential file ([config_dir/creds.json]()) to start. 

`config.json`
```json
{
    "CREDS_PATH": "./config_dir/creds.json",
    "ROLENAMES_FILE_PATH": "./config_dir/rolelist.txt",
    "USERNAMES_FILE_PATH": "./config_dir/userlist.txt",
    "SERVICES_CONFIG":{
        "s3":{
            "enabled": true,
            "resource_type":"s3",
            "resource_prefix":"iamcheckers3",
            "resource_count":3
        },
        "kms":{
            "enabled": true,
            "resource_type":"kms",
            "resource_prefix":"iamcheckerkms",
            "resource_count":3
        },
        "sqs":{
            "enabled": true,
            "resource_type":"sqs",
            "resource_prefix":"iamcheckersqs",
            "resource_count":2
        },
        "iam":{
            "enabled": true,
            "resource_type":"iam",
            "resource_prefix":"iamcheckeriam",
            "resource_count":2
        }
    }
}
```
Each AWS service can be individually configured in `config.json`. One can enable or disable a service by toggling the "enabled" field. The "resource_prefix" is an identifier used for naming and locating the resources created in AWS accounts. It should not be changed after the resources have been created with the `init` command.  

`creds.json`
```json
{
    "account1": {
        "Region": "us-west-1",
        "Active": true,
        "AccessKeyId": "",
        "SecretAccessKey": ""
    },
    "account2": {
        "Region": "us-east-1",
        "Active": false,
        "AccessKeyId": "",
        "SecretAccessKey": ""
    },
    "account3": {
        "Region": "us-east-2",
        "Active": true,
        "AccessKeyId": "",
        "SecretAccessKey": "",
        "SessionToken": ""
    }
}
```
IAMFinder can use multiple AWS accounts to enumerate identities concurrently. Due to the rate-limit on AWS API gateway, using multiple AWS accounts is the most effective way to boost enumeration rate. Each account can be enabled or disabled by toggling the "Active" field in `creds.json`. Either a user's [access key](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) or [security token](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html) can be provided for each account. 

# Usage
```
usage: iamfinder.py [-h]
                    {init,cleanup,enum_role,enum_user,assu_role,check_awsid}
                    ...

IAMFinder checks for existing users and IAM roles in an AWS account

optional arguments:
  -h, --help            show this help message and exit

subcommand:
  The subcommand to execute

  {init,cleanup,enum_role,enum_user,assu_role,check_awsid}
                        Enter a command to execute
    init                Create aws resoruces necessary for IAMFinder
    cleanup             Remove aws resoruces created by the init command
    enum_role           Check if any role in the role file (default:
                        ./config_dir/rolelist.txt) exists in the target
                        account. Required argument: --aws_id. Optional
                        arguments: --file_path, --aws_part, --assume. If
                        --assume is specified, the scanner will attempt to
                        assume the identified roles
    enum_user           Check if any user in the user file (default:
                        ./config_dir/userlist.txt) exists in the target
                        account. Required argument: --aws_id. Optional
                        arguments: --file_path, --aws_part
    assu_role           Check if any role in the role file (default:
                        ./config_dir/rolelist.txt) can be assumed. Required
                        argument: --aws_id. Optional arguments: --file_path,
                        --aws_part.
    check_awsid         Check if an AWS ID is valid and exist. Required
                        argument: --aws_id. Optional arguments: --aws_part
```

## Initialization
`init` command creates necessary AWS resources for IAMFinder to perform the test. `init` only needs to be run once. 
```bash
python3 iamfinder.py init
```

## Enumerate Identities
Enumerte users in AWS account 123456789012 using the default wordlist `./config_dir/userlist.txt`. 
```bash
python3 iamfinder.py enum_user --aws_id 123456789012
```

Enumerte IAM roles in AWS account 123456789012 usig wordlist `myrolelist.txt`
```bash
python3 iamfinder.py enum_role --aws_id 987654321098 --file_path ./config_dir/myrolelist.txt
```

Enumerte IAM roles in aws-us-gov account 987654321098. Note that you need an aws-us-gov account in order to enumerate an aws-us-gov target. Same as aws-cn
```bash
python3 iamfinder.py enum_role --aws_id 987654321098 --aws_part aws-us-gov
```

Check if 135792468100 is a valid account in aws-cn partition. `check_awsid` can be performed without an active AWS account and `init` process. 
```bash
python3 iamfinder.py check_awsid --aws_id 135792468100 --aws_part aws-cn
```

Delete all the AWS resources created by `init` command.
```bash
python3 iamfinder.py cleanup
```

## Run in Docker

Place the config and credential files in config_dir and mount this directory to the container.
```
docker run --rm -it -v [absolute path to config_dir]:/home/iamuser/config_dir/ iamfinder [command]
```
Examples:
```bash
docker run --rm -it -v /home/user0/projects/IAMFinder/:/home/iamuser/config_dir/ iamfinder init

docker run --rm -it -v /home/user0/projects/IAMFinder/:/home/iamuser/config_dir/ iamfinder enum_user --aws_id 123456789012
```
