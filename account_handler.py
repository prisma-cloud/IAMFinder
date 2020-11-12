import sys
import boto3
import botocore
import random, string
import logging
from itertools import cycle
from aws_svc.iam_handler import IAMHandler
from aws_svc.s3_handler import S3Handler
from aws_svc.kms_handler import KMSHandler
from aws_svc.sqs_handler import SQSHandler
from aws_svc.aws_service_base import AWS_SVC_TYPE

class ACCOUNTHandler:
    ''' An AWS account that manages multiple services '''
    def __init__(self, boto3_session, account_name, services_config_dict):
        self.boto3_session = boto3_session        
        self.account_name = account_name
        self.services_config = services_config_dict
        self.svc_list = list()
        self.add_svc_handlers()
        self.svc_cycle = cycle(self.svc_list)

    def _get_next_service(self):
        try:
            return next(self.svc_cycle)
        except StopIteration:
            logging.error('Empty resource cycle')
            return None

    def add_svc_handlers(self):
        ''' Create multiple service_handlers and add to the account '''
        # Need some delay beofre the created resources can be used
        for svc_name, svc_config in self.services_config.items():
            if 'enabled' in svc_config and not svc_config['enabled']:
                continue
            if svc_name == AWS_SVC_TYPE.IAM.value:
                self.svc_list.append(IAMHandler(self.boto3_session, svc_config))
            elif svc_name == AWS_SVC_TYPE.S3.value:
                self.svc_list.append(S3Handler(self.boto3_session, svc_config))
            elif svc_name == AWS_SVC_TYPE.KMS.value:
                self.svc_list.append(KMSHandler(self.boto3_session, svc_config))
            elif svc_name == AWS_SVC_TYPE.SQS.value:
                self.svc_list.append(SQSHandler(self.boto3_session, svc_config))   
        

    def create_resources(self):
        ''' Create rsc_count number of workers for each service '''
        for svc_obj in self.svc_list:
            svc_obj.create_workers()

    def delete_resources(self):
        ''' Delete the resources created by create_resources() function '''
        for svc_obj in self.svc_list:
            svc_obj.delete_workers()
        self.svc_list = list()
        self.svc_cycle = cycle(self.svc_list)

    def check_existing_role(self, aws_id, target_role, aws_partition = 'aws'):
        ''' Check if the target_role exists in AWS account aws_id '''
        return self._get_next_service().check_existing_role(aws_id, target_role, aws_partition=aws_partition)

    def check_existing_user(self, aws_id, target_user, aws_partition = 'aws'):
        ''' Check if the target_user exists in AWS account aws_id '''
        return self._get_next_service().check_existing_user(aws_id, target_user, aws_partition=aws_partition)

    def check_assumable_role(self, aws_id, role, aws_partition = 'aws'):
        sts_client = self.boto3_session.client('sts')
        role_arn = 'arn:{}:iam::{}:role/{}'.format(aws_partition, aws_id, role)        
        try:
            resp = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=18)),
                DurationSeconds=3600    # 60 mins
            )
            if 'Credentials' in resp:
                return resp
        except botocore.exceptions.ClientError as e:
            logging.debug('Error when attempting to assume role. {}'.format(e))

    def precheck(self):
        ''' Check if there is at least one available resrouce to perform the test on the target account'''
        if len(self.svc_list) < 1:
            logging.error('There is no available service in account {}'.format(self.account_name))
            return False

        is_available = False
        empty_svc = list()  # Store the service_handler to be removed
        for svc_obj in self.svc_list:            
            if svc_obj.precheck():
                is_available = True
            else:
                logging.warning('Service {} in account {} has no available resource to perform test'.format(svc_obj.service_type.value, self.account_name))
                # Remove it from the list
                empty_svc.append(svc_obj)
        if empty_svc:
            for svc_obj in empty_svc:
                self.svc_list.remove(svc_obj)
            self.svc_cycle = cycle(self.svc_list)    
        return is_available
