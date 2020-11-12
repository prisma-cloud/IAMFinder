from aws_svc.aws_service_base import AWS_SVC_BASE, AWS_SVC_TYPE
import boto3
import botocore
import random 
import json
import string
import sys, os
import logging
from itertools import cycle

class S3Handler(AWS_SVC_BASE):
    
    def __init__(self, boto3_session, s3_config):
        super().__init__(AWS_SVC_TYPE.S3, boto3_session, s3_config)
        self.s3_client = boto3_session.client('s3', config=AWS_SVC_BASE.aws_config)
        self.created_bkt = list()
        self.get_existing_workers()
        self._set_worker_cycle(self.created_bkt)

    def get_existing_workers(self):
        try:
            resp = self.s3_client.list_buckets()
            if not self._check_boto3_response(resp):
                logging.error('Fail to list existing S3 buckets.')
                return
        except botocore.exceptions.ClientError as error:            
            logging.error('Fail to list buckets. {}'.format(error))
            return
        
        key_count = self.svc_config['resource_count']
        for bkt in resp['Buckets']:
            bkt_name = bkt['Name']
            if not bkt_name.startswith(self.rsc_prefix):
                continue
            # Find bucket region
            try:
                resp2 = self.s3_client.get_bucket_location(
                    Bucket = bkt_name
                )
                if not self._check_boto3_response(resp2):
                    continue
                region = resp2['LocationConstraint']                
                self.created_bkt.append({'BucketName': bkt_name, 'Region':region})
                key_count -= 1
                if key_count <= 0: 
                    break
            except botocore.exceptions.ClientError as error:   
                logging.error('Fail to get bucket location.')
                continue
        return self.created_bkt

    def create_workers(self):
        ''' Create multiple S3 buckets. Return a dictionary of bucketName and its region '''
        bkt_count = self.svc_config['resource_count']
        if len(self.created_bkt) >= bkt_count:
            # Don't need to create more buckets
            logging.info('No need to create more resources for S3')
            return self.created_bkt
        else:
            needed = bkt_count - len(self.created_bkt)
        
        for _ in range(0, needed, 1):
            reg = self.session.region_name
            bucketName = '{}-{}'.format(self.rsc_prefix, ''.join(random.choices(string.ascii_lowercase + string.digits, k=20)))
            # AWS-CN needs additional permissions for this function call to work ....
            if reg != 'us-east-1':
                resp = self.s3_client.create_bucket(Bucket=bucketName, ACL='private', 
                    CreateBucketConfiguration={'LocationConstraint': reg},            
                    ObjectLockEnabledForBucket=True)
            else:
                resp = self.s3_client.create_bucket(Bucket=bucketName, ACL='private',                     
                    ObjectLockEnabledForBucket=True)

            if not self._check_boto3_response(resp):
                continue
            
            # Block any access to the bucket
            self.s3_client.put_public_access_block(
                Bucket=bucketName,            
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            self.created_bkt.append({'BucketName': bucketName, 'Region':reg})

            logging.info('S3 bucket {} has been successfully created in region {}'.format(bucketName, reg))
        self._set_worker_cycle(self.created_bkt)
        return self.created_bkt

    def delete_workers(self):
        for bkt in self.created_bkt:
            bucketName = bkt['BucketName'] 
            reg = bkt['Region'] 
            resp = self.s3_client.delete_bucket(
                Bucket=bucketName,
            )
            if self._check_boto3_response(resp):
                logging.info('S3 bucket {} has been successfully deleted in region {}'.format(bucketName, reg))
            else:                
                logging.info('Fail to delete S3 bucket {} in region {}'.format(bucketName, reg))
        self.created_bkt = list()
        self._set_worker_cycle(self.created_bkt)

    def _check_existing_identity(self, identiy_arn):
        ''' Check if identiy_arn exists in AWS '''
        s3_policy = '{{"Version":"2012-10-17","Statement":[{{"Sid":"iamcheck","Effect":"Deny","Principal":{{"AWS":"{}"}},"Action":["s3:*"],"Resource":["{}"]}}]}}'
        bucketName = self._get_next_worker()['BucketName']
        if bucketName is None:
            logging.error('No available worker/resource in s3_handler')
            return

        # role_arn = 'arn:{}:iam::{}:role/{}'.format(aws_partition, aws_id, target_role)
        aws_partition = identiy_arn.split(':')[1]
        root_path = 'arn:{}:s3:::{}/*'.format(aws_partition, bucketName)

        try:
            resp = self.s3_client.put_bucket_policy(
                Bucket=bucketName,
                ConfirmRemoveSelfBucketAccess=True,
                # Policy=json.dumps(policy_obj)
                Policy=s3_policy.format(identiy_arn, root_path)
            )
            if self._check_boto3_response(resp):
                return True  
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'MalformedPolicy' and 'Invalid principal' in e.response['Error']['Message']:
                logging.debug('Invalid principal identified using bucket {}!'.format(bucketName))
                return False
        except botocore.exceptions.ClientError as e:
            logging.error(e)
        return None

