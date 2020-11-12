from abc import ABC, abstractmethod
import threading 
import boto3
import botocore
import sys
import logging
import logging.config
from enum import Enum
from itertools import cycle
from botocore.config import Config
from botocore.endpoint import MAX_POOL_CONNECTIONS
from collections.abc import Iterable

class AWS_SVC_BASE(ABC):
    ''' Represent an AWS service that contain multiple resources(workers) '''
    aws_config = Config(
        retries=dict(
            total_max_attempts=25,
            mode='adaptive'
        ),
        max_pool_connections=MAX_POOL_CONNECTIONS,            
    )
    
    def __init__(self, svc_type, session, svc_config):   
        if not isinstance(session, boto3.Session):
            logging.error('session must be of type boto3.Session')
            raise(ValueError)     
        if not isinstance(svc_type, AWS_SVC_TYPE):
            logging.error('svc_type must be of type AWS_SVC_TYPE')
            raise(ValueError)
        if not isinstance(svc_config, dict):
            logging.error('svc_config must be of type AWS_SVC_TYPE')
            raise(ValueError)
        self.session = session
        self.account_id = 0
        self.service_type = svc_type
        self.svc_config = svc_config
        self.rsc_prefix = svc_config['resource_prefix']
        self._key_lock = threading.Lock()
        self.worker_cycle = cycle(list())
        super().__init__()

    @abstractmethod
    def get_existing_workers(self):
        ''' Query the existing workers based on the rsc_prefix '''
        # pass    

    @abstractmethod
    def create_workers(self):
        ''' Create workers/resources of this service '''
        # pass

    @abstractmethod
    def delete_workers(self):
        ''' Delete the workers created by create_workers() function '''
        # pass

    @abstractmethod
    def _check_existing_identity(self, identiy_arn):
        ''' Check if identiy_arn exists in AWS '''
        # pass
    
    def check_existing_user(self, aws_id, target_user, aws_partition = 'aws'):
        ''' Check if the target_user exists in AWS account aws_id '''
        user_arn = 'arn:{}:iam::{}:user/{}'.format(aws_partition, aws_id, target_user)
        return self._check_existing_identity(user_arn)

    def check_existing_role(self, aws_id, target_role, aws_partition = 'aws'):
        ''' Check if the target_role exists in AWS account aws_id '''        
        role_arn = 'arn:{}:iam::{}:role/{}'.format(aws_partition, aws_id, target_role)
        return self._check_existing_identity(role_arn)

    
    def precheck(self):
        ''' Check if there is at least one resrouce to perform the test '''
        # If no object is in the cycle, the default value None will be returned
        if next(self.worker_cycle, None) is None:
            return False
        return True

    def _get_next_worker(self):
        with self._key_lock: 
            try:
                return next(self.worker_cycle)
            except StopIteration:
                logging.error('Empty worker cycle')
                return None
    
    def _set_worker_cycle(self, iterable_obj):
        if not isinstance(iterable_obj, Iterable):
            logging.error('set_worker_cycle function expects an Iterable input')
            return
        self.worker_cycle = cycle(iterable_obj)

    def _check_boto3_response(self, resp):
        return 'ResponseMetadata' in resp and resp['ResponseMetadata']['HTTPStatusCode'] >= 200 and resp['ResponseMetadata']['HTTPStatusCode'] < 300

    def _enable_logging(self):
        logging.config.dictConfig({
            'version': 1,
            'disable_existing_loggers': True,
        })    
        logging.basicConfig(level=logging.DEBUG, format='%(module)s: %(message)s')

class AWS_SVC_TYPE(Enum):
    IAM = 'iam'
    S3 = 's3'
    KMS = 'kms'
    SQS = 'sqs'
