import sys, os
# sys.path.insert(1, os.path.join(sys.path[0], '..'))
from aws_svc.aws_service_base import AWS_SVC_BASE, AWS_SVC_TYPE
import boto3
import botocore
import random 
import json
import string
import logging
from itertools import cycle


class SQSHandler(AWS_SVC_BASE):
    def __init__(self, boto3_session, sqs_config):
        super().__init__(AWS_SVC_TYPE.SQS, boto3_session, sqs_config)
        self.sqs_client = boto3_session.client('sqs', config=AWS_SVC_BASE.aws_config)
        self.created_queue = list()
        self.get_existing_workers()
        self._set_worker_cycle(self.created_queue)

    def get_existing_workers(self):
        q_count = self.svc_config['resource_count']
        try:
            resp = self.sqs_client.list_queues(
                QueueNamePrefix = self.rsc_prefix,
                MaxResults=1000
            )
            if not (self._check_boto3_response(resp) and 'QueueUrls' in resp):
                return
            
            for q_url in resp['QueueUrls']:
                self.created_queue.append(q_url)
                q_count -= 1
                if q_count <= 0: 
                    break
        except botocore.exceptions.ClientError as error:   
            logging.error('Fail to list queues. {}'.format(error))
            return
        
        return self.created_queue

    def create_workers(self):
        ''' Create multiple SQS queues. Return a dictionary of queues '''
        q_count = self.svc_config['resource_count']
        if len(self.created_queue) >= q_count:
            # Don't need to create more buckets
            logging.info('No need to create more resources for SQS')
            return self.created_queue
        else:
            needed = q_count - len(self.created_queue)

        for _ in range(0, needed, 1):
            qName = '{}-{}'.format(self.rsc_prefix, ''.join(random.choices(string.ascii_lowercase + string.digits, k=20)))
            try:
                resp = self.sqs_client.create_queue(
                    QueueName=qName
                )
                if not self._check_boto3_response(resp):
                    continue                
                self.created_queue.append(resp['QueueUrl'])
                logging.info('Queue {} has been successfully created'.format(qName))
            except (self.sqs_client.exceptions.QueueDeletedRecently, self.sqs_client.exceptions.QueueNameExists) as e:
                logging.error('Fail to create queue. {}'.format(e))


    def delete_workers(self):
        for q_url in self.created_queue:
            try:
                resp = self.sqs_client.delete_queue(
                    QueueUrl=q_url
                )
                if not self._check_boto3_response(resp):
                    logging.error('Fail to delete queue {}'.format(q_url))
                    continue
                logging.info('Queue {} has been successfully deleted'.format(q_url))
            except botocore.exceptions.ClientError as error:
                logging.error('Fail to delete queue {}. {}'.format(q_url, error))
        self.created_queue = list()
        self._set_worker_cycle(self.created_queue)
    
    def _check_existing_identity(self, identiy_arn):
        ''' Check if identiy_arn exists in AWS '''
        test_policy_obj = '{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":{{"AWS":"{}"}},"Action":"SQS:*","Resource":"*"}}]}}'.format(identiy_arn)        
    
        q_url = self._get_next_worker()
        if q_url is None:
            logging.error('No available worker/resource in sqs_handler')
            return

        q_name = q_url.split('/')[-1]
        try:
            resp = self.sqs_client.set_queue_attributes(
                QueueUrl=q_url,
                Attributes={
                    'Policy': test_policy_obj
                }
            )
            if self._check_boto3_response(resp):
                return True
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAttributeValue':
                logging.debug('Invalid principal identified using queue {}!'.format(q_name))
                return False 
                            
