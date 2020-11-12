import os
import sys
import json
import boto3
import botocore
import multiprocessing
import logging
import logging.config
from itertools import cycle

from multiprocessing.pool import ThreadPool
from account_handler import ACCOUNTHandler

class MultiAccountsHandler:
    ''' Manage multiple AWS accounts (account_handler) '''
    def __init__(self, acc_config):
        self.acc_list = list()
        self.acc_config = acc_config
        self._load_creds(acc_config['CREDS_PATH'])
        self.acc_cycle = cycle(self.acc_list)

    def _load_creds(self, creds_path):
        ''' Read AWS credentials from a json file and create an AWS account '''
        if not (os.path.exists(creds_path) and os.path.isfile(creds_path)):
            sys.exit('Credential file does not exist. Please add a credential file to {}'.format(creds_path))
        with open(creds_path, newline='', encoding='utf-8') as fhand:
            try:
                accounts_dict = json.load(fhand)
                acc_nums = dict()   # used to track keys in the same AWS account
                for key_name, cred_data in accounts_dict.items():
                    if 'Active' in cred_data and not cred_data['Active']:
                        continue
                    if 'SessionToken' in cred_data:
                        sessionTkn = cred_data['SessionToken']
                    else:
                        sessionTkn = None
                    
                    session = boto3.Session( 
                        aws_access_key_id=cred_data['AccessKeyId'], 
                        aws_secret_access_key=cred_data['SecretAccessKey'], 
                        aws_session_token=sessionTkn,
                        region_name=cred_data['Region'])
                    
                    # Validate the keys
                    resp = self._verify_access_token(session)
                    if resp is None:
                        logging.error('The access key of {} is invalid. Skiped ...'.format(key_name))
                        continue
                    if resp['Account'] in acc_nums:
                        logging.error('Key {} and key {} belong to the same account (awsID: {}). Only the first key will be used.'.format(
                            acc_nums[resp['Account']], key_name, resp['Account'])) 
                        continue
                
                    acc_nums[resp['Account']] = key_name
                    aws_acc = ACCOUNTHandler(session, key_name, self.acc_config['SERVICES_CONFIG'])
                    self.acc_list.append(aws_acc)                
            except json.decoder.JSONDecodeError as e:
                sys.exit('Fail to load credential file. Please check the credential file at {}.\n{} '.format(creds_path, e))
            except ValueError:
                sys.exit('There is no active aws credential. Please check the credential file at {}'.format(creds_path))

    def _verify_access_token(self, session):
        ''' Verfy if the AWS key is valid '''
        try:
            client = session.client('sts')
            resp = client.get_caller_identity()
            if 'Account' in resp and 'Arn' in resp:
                return {'Account':resp['Account'], 'Arn':resp['Arn']}
        except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError):
            pass
        return None
    
    def _get_next_account(self):
        try:
            return next(self.acc_cycle)
        except StopIteration:
            logging.error('Empty account cycle')
            return None

    def create_resources(self):
        ''' Create AWS resrouces used for checking identities '''
        for acc in self.acc_list:
            acc.create_resources()

    def delete_resources(self):
        ''' Delete AWS resrouces created by create_resources() '''
        for acc in self.acc_list:
            acc.delete_resources() # Number of resources in each service  
        self.acc_list = list()
        self.acc_cycle = cycle(self.acc_list)

    def check_existing_user(self, aws_id, target_user, aws_partition = 'aws'):
        ''' Check if the target_role exists in AWS account aws_id '''
        return self._get_next_account().check_existing_user(aws_id, target_user, aws_partition=aws_partition)
    
    def check_existing_role(self, aws_id, target_role, aws_partition = 'aws'):
        ''' Check if the target_role exists in AWS account aws_id '''
        return self._get_next_account().check_existing_role(aws_id, target_role, aws_partition=aws_partition)

    def check_existing_roles(self, aws_id, role_list, aws_partition = 'aws'):
        ''' Concurently check a list of roles. '''
        return self._check_existing_identities('role', aws_id, role_list, aws_partition)
    
    def check_existing_users(self, aws_id, user_list, aws_partition = 'aws'):
        ''' Concurently check a list of users. '''
        return self._check_existing_identities('user', aws_id, user_list, aws_partition)
    
    def _check_existing_identities(self, id_type, aws_id, id_list, aws_partition = 'aws'):
        ''' Concurently check a list of identities. id_type is either user or role '''
        def _check_id(id_name):
            ''' Handler function for imap().  '''
            if id_type == 'user':
                result = self.check_existing_user(aws_id, id_name, aws_partition=aws_partition)
            else :  # default to role
                result = self.check_existing_role(aws_id, id_name, aws_partition=aws_partition)  
            return (result, id_name)
        
        # Total number of resources
        thread_count = 0
        for _, svc_config in self.acc_config['SERVICES_CONFIG'].items():
            if 'enabled' in svc_config and svc_config['enabled']:
                thread_count += svc_config['resource_count']
        thread_count *= len(self.acc_list)

        # print("{} threads are created".format(thread_count))
        pool = ThreadPool(thread_count)
        imap_it = pool.imap_unordered(_check_id, id_list)  
        exist_role_list = list()  
        for _ in range(len(id_list)):
            try:
                result_tuple = imap_it.next(3)  # wait timeout
                if not result_tuple:
                    continue
                if result_tuple[0]:
                    exist_role_list.append(result_tuple[1])
            except StopIteration:
                break
            except multiprocessing.TimeoutError:            
                continue
        pool.close()
        pool.join()
        return exist_role_list

    def check_assumable_role(self, aws_id, role, aws_partition = 'aws'):
        return self._get_next_account().check_assumable_role(aws_id, role, aws_partition = aws_partition)

    def check_assumable_roles(self, aws_id, role_list, aws_partition = 'aws'):
        ''' Concurently assume a list of roles '''
        def _check_assumable(role):
            result = self.check_assumable_role(aws_id, role, aws_partition=aws_partition)
            return (result, role)
        
        thread_count = len(self.acc_list) * 2   # Account# * 2 
        pool = ThreadPool(thread_count)
        imap_it = pool.imap_unordered(_check_assumable, role_list)  
        assumable_list = list()  
        for _ in range(len(role_list)):
            try:
                result_tuple = imap_it.next(3)            
                if not result_tuple:
                    continue
                if result_tuple[0]:
                    assumable_list.append(result_tuple)

            except StopIteration:
                break
            except multiprocessing.TimeoutError:            
                continue
        pool.close()
        pool.join()
        return assumable_list

    def precheck(self, target_partition):
        ''' Check if there is at least one available resrouce to perform the test '''
        if len(self.acc_list) < 1:
            logging.error('There is no available account to perform test')
            return False

        is_available = False
        empty_acc = list()  # Store the account_handler to be removed
        for acc_obj in self.acc_list:
            # Check if this account is in the same partition as the target account
            acc_region = acc_obj.boto3_session.region_name
            if acc_region.startswith('us-gov-'):
                acc_part = 'aws-us-gov'
            elif acc_region.startswith('cn-'):
                acc_part = 'aws-cn'
            else:
                acc_part = 'aws'
            
            if acc_part.lower().strip() != target_partition.lower().strip():
                logging.warning('Account {} is in different parition as the target account. It will not be used to perform test'.format(acc_obj.account_name))
                # remove the account
                empty_acc.append(acc_obj)
                continue

            # Check if there are available AWS resources in this account to perform the test 
            if acc_obj.precheck():
                is_available = True
            else:
                logging.warning('Account {} has no available resource to perform test'.format(acc_obj.account_name))
                # remove the account
                empty_acc.append(acc_obj)
        
        if empty_acc:
            for acc_obj in empty_acc:
                self.acc_list.remove(acc_obj)
            self.acc_cycle = cycle(self.acc_list)
        return is_available

