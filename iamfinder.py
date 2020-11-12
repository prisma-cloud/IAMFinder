#!/usr/bin/env python3
import os
import sys
import re
import argparse
import json
import signal
import logging
import requests
from multi_accounts_handler import MultiAccountsHandler


BANNER = '''
  _____          __  __ ______ _           _           
 |_   _|   /\   |  \/  |  ____(_)         | |          
   | |    /  \  | \  / | |__   _ _ __   __| | ___ _ __ 
   | |   / /\ \ | |\/| |  __| | | '_ \ / _` |/ _ \ '__|
  _| |_ / ____ \| |  | | |    | | | | | (_| |  __/ |   
 |_____/_/    \_\_|  |_|_|    |_|_| |_|\__,_|\___|_|   
'''
config_path = './config_dir/config.json'

def enum_ids(target_account, id_type, id_file_path, aws_partition = 'aws'):
    ''' Enumerate users in the target_account '''
    if not aws_scan.precheck(aws_partition):
        sys.exit('Please run --init command first to create necessary resources for testing')

    id_list = _get_id_list(id_file_path)    
    logging.info('Starting to enumerate {} {} against AWS account {} ...'.format(len(id_list), id_type, target_account))
    if id_type == 'user':
        return aws_scan.check_existing_users(target_account, id_list)
    elif id_type == 'role':
        return aws_scan.check_existing_roles(target_account, id_list)
    else:
        logging.error('unsupported identity type')

def assume_roles(target_account, role_file_path, aws_partition = 'aws'):
    ''' Assume roles in the target_account '''
    role_list = _get_id_list(role_file_path)    
    logging.info('Attempting to assume {} roles in AWS account {} ...'.format(len(role_list), target_account))
    return aws_scan.check_assumable_roles(target_account, role_list)

def enum_assume_roles(target_account, aws_partition = 'aws'):
    ''' Enumerate a list of roles and attempt to assume the existing roles '''
    existing_roles = enum_ids(target_account, 'role', scanner_config['ROLENAMES_FILE_PATH'], aws_partition=aws_partition)
    return aws_scan.check_assumable_roles(target_account, existing_roles, aws_partition=aws_partition)

def _get_id_list(file_path):
    ''' Read ids stored in the text file and return as as list '''
    if not (os.path.exists(file_path) and os.path.isfile(file_path)):
        sys.exit('Identity file does not exist. Please check the file path')

    ids = list()
    with open(file_path) as fp: 
        for _, line in enumerate(fp):            
            ids.append(line.strip())
    return ids

def validAWSPartition(aws_partition):
    ''' Check if the AWS partition name is valid '''
    if not aws_partition in {'aws', 'aws-cn', 'aws-us-gov'}:
        logging.error('{} is not a valid aws partition'.format(aws_partition))
        return False
    return True

def validAWSId(aws_id, aws_partition = 'aws'):
    ''' Check if aws_id is a valid aws ID in aws_partition. Expected input is a string of 12 digits '''
    awsid_re = re.compile(r'\d{12}')
    if not awsid_re.match(aws_id.strip()):
        logging.error('AWS ID must be 12 digits. {} is not valid format.'.format(aws_id))
        return False
    
    if not validAWSPartition(aws_partition):
        return False

    if aws_partition == 'aws':
        testURL = 'https://{}.signin.aws.amazon.com/console/'.format(aws_id)
    elif aws_partition == 'aws-us-gov':
        testURL = 'https://{}.signin.amazonaws-us-gov.com/console/'.format(aws_id)
    elif aws_partition == 'aws-cn':  
        testURL = 'https://{}.signin.amazonaws.cn/console/'.format(aws_id)
    
    try:
        resp = requests.request(url=testURL, method='GET')
        if resp.status_code == 200:            
            return True
        else:
            logging.error('AWS ID {} does not exist in partiion {}.'.format(aws_id, aws_partition))
            return False
    except requests.RequestException as err:
        logging.error(err)
        return False    

def load_config():
    ''' Read the json config file  '''
    global scanner_config
    if not (os.path.exists(config_path) and os.path.isfile(config_path)):
        sys.exit('Config file does not exist. Please add a config file to {}'.format(config_path))
    with open(config_path, newline='', encoding='utf-8') as fhand:
        try:
            scanner_config = json.load(fhand)
        except json.decoder.JSONDecodeError as e:
            sys.exit('Fail to load config file. Please check the config file at {}.\n{} '.format(config_path, e))
            
def parseArgs():
    load_config()

    def _add_common_args(parser, file_path=None):
        if file_path:
            parser.add_argument('--file_path', default=file_path, help='Specify the file containing a list identities.')
        parser.add_argument('--aws_id', help='Specify the 12 digits aws account ID of the target.')
        parser.add_argument('--aws_part', default='aws', help='Specify partition of the AWS account. Must be either aws, aws-cn, or aws-us-gov')

    def _check_common_args(args):
        if not args.aws_id:
            sys.exit('Pleaase provide --aws_id')
        if not validAWSId(args.aws_id, aws_partition=args.aws_part):
            sys.exit('Please address the issues and restart')       

    def _display_enum_id_result(id_type, result):        
        if result:
            logging.info('Found {} {} in account {}'.format(len(result), id_type, args.aws_id))
            for r in result:
                logging.info(r)
        else:
            logging.info('IAMFinder did not find any {} 😔'.format(id_type))
    
    def _display_assu_role_result(result):
        if result:
            logging.info('Successfully assume {} roles in account {}\n'.format(len(result), args.aws_id))
            for r in result:
                r = r[0]
                logging.info('Role ARN:{}'.format(r['AssumedRoleUser']['Arn']))
                logging.info('AccessKeyId: {}\nSecretAccessKey: {}\nSessionToken: {}\n\n'.format(
                    r['Credentials']['AccessKeyId'],r['Credentials']['SecretAccessKey'],r['Credentials']['SessionToken']
                ))
        else:
            logging.info('IAMFinder could not successfully assume any role 😔')

    # Add commands and arguments
    parser = argparse.ArgumentParser(description='IAMFinder checks for existing users and IAM roles in an AWS account')    
    subparser = parser.add_subparsers(
        title='Command',
        description='The action to perform',
        dest='sub_cmd',
        help='Enter a command to execute'
    )    
    subparser.add_parser('init', help='Create aws resoruces necessary for IAMFinder')
    
    subparser.add_parser('cleanup', help='Remove aws resoruces created by the init command')

    er_parser = subparser.add_parser('enum_role', help='Check if any role in the role file (default: ./config_dir/rolelist.txt) exists in the target account. Required argument: --aws_id. Optional arguments: --file_path, --aws_part, --assume.  If --assume is specified, the scanner will attempt to assume the identified roles' )
    _add_common_args(er_parser, file_path=scanner_config['ROLENAMES_FILE_PATH'])
    er_parser.add_argument('--assume', action='store_true', help='If specified, IAMFinder will attempt to assume the identified roles.')

    # https://github.com/danielmiessler/SecLists/tree/master/Usernames
    eu_parser = subparser.add_parser('enum_user', help='Check if any user in the user file (default: ./config_dir/userlist.txt) exists in the target account. Required argument: --aws_id. Optional arguments: --file_path, --aws_part' )
    _add_common_args(eu_parser, file_path=scanner_config['USERNAMES_FILE_PATH'])

    ar_parser = subparser.add_parser('assu_role', help='Check if any role in the role file (default: ./config_dir/rolelist.txt) can be assumed. Required argument: --aws_id. Optional arguments: --file_path, --aws_part.')
    _add_common_args(ar_parser, file_path=scanner_config['ROLENAMES_FILE_PATH'])

    ca_parser = subparser.add_parser('check_awsid', help='Check if an AWS ID is valid and exist. Required argument: --aws_id. Optional arguments: --aws_part')
    _add_common_args(ca_parser)
    
    # subparser.add_parser('test', help='For testing purpose')
    args = parser.parse_args()

    # Handle commands and arguments  
    if args.sub_cmd == 'check_awsid':
        # This is a special command that doesn't need aws_scan object.
        _check_common_args(args)
        logging.info('{} is a valid and confirmed AWS ID in partition {}'.format(args.aws_id, args.aws_part))
        return

    global aws_scan
    aws_scan = MultiAccountsHandler(scanner_config)
    
    if args.sub_cmd == 'init':
        logging.info(BANNER)
        aws_scan.create_resources()
    elif args.sub_cmd == 'cleanup':
        logging.info(BANNER)
        aws_scan.delete_resources()
    elif args.sub_cmd == 'enum_user':
        _check_common_args(args)        
        result = enum_ids(args.aws_id, 'user', args.file_path, aws_partition=args.aws_part)
        _display_enum_id_result('user', result)
    elif args.sub_cmd == 'enum_role':
        _check_common_args(args)        
        result = enum_ids(args.aws_id, 'role', args.file_path, aws_partition=args.aws_part)
        _display_enum_id_result('role', result)
        if args.assume:
            logging.info('\nAttempting to assume the identified roles ...')
            result = assume_roles(args.aws_id, args.file_path)
            _display_assu_role_result(result)
    elif args.sub_cmd == 'assu_role':
        _check_common_args(args)
        result = assume_roles(args.aws_id, args.file_path)
        _display_assu_role_result(result)
    elif args.sub_cmd == 'test':
        pass

def _signal_handler(sig, frame):    
    ''' Interrupt signal handler '''
    sys.exit('\nInterrupt signal received. Exit IAMFinder ...')

signal.signal(signal.SIGINT, _signal_handler)

def main():
    logging.config.dictConfig({
        'version': 1,
        'disable_existing_loggers': True,
    })    
    logging.basicConfig(level=logging.INFO, format='%(module)s: %(message)s')

    parseArgs()

if __name__ == '__main__':
    '''
    Executed only when the script is directly called from python, i.e., not imported as a module
    '''
    main()