from aws_svc.aws_service_base import AWS_SVC_BASE, AWS_SVC_TYPE
import boto3
import botocore
import sys, os
import random, string
import json
import logging

class KMSHandler(AWS_SVC_BASE):    

    def __init__(self, boto3_session, kms_config):
        super().__init__(AWS_SVC_TYPE.KMS, boto3_session, kms_config)
        self.kms_client = boto3_session.client('kms', config=AWS_SVC_BASE.aws_config)
        self.created_keys = list()
        self.get_existing_workers()
        self._set_worker_cycle(self.created_keys)
        

    def get_existing_workers(self):
        try:
            resp = self.kms_client.list_keys(Limit=1000)    # result may be truncated
            if not self._check_boto3_response(resp):
                return
        except botocore.exceptions.ClientError as error:
            logging.error('Fail to list KMS keys. {}'.format(error))
            return
        
        key_count = self.svc_config['resource_count']
        for key_obj in resp['Keys']:
            key_id = key_obj['KeyId']   # {KeyId:"", KeyArn:""}
            
            # Check key alias
            try:
                resp2 = self.kms_client.list_aliases(KeyId=key_id)
                if not self._check_boto3_response(resp2):
                    continue
                if len(resp2['Aliases']) != 1:
                    continue
            except botocore.exceptions.ClientError as error:
                logging.error('Fail to list key alias. {}'.format(error))
                continue
                            
            for alias_obj in resp2['Aliases']:
                alias_name = alias_obj['AliasName']
                if alias_name.startswith('alias/{}-'.format(self.rsc_prefix)):
                    self.created_keys.append(key_obj)
                    key_count -= 1
                    break
            # Don't use more keys than the resource count specified in the config file
            if key_count <= 0: 
                break
            
        # Get key policies
        for key_obj in self.created_keys:
            resp3 = self.kms_client.get_key_policy(
                KeyId=key_obj['KeyId'],
                # The name of the key policy to retrieve.
                PolicyName='default',
            )
            if not self._check_boto3_response(resp3):
                continue
            key_obj['Policy'] = resp3['Policy']
        
        return self.created_keys
        

    def create_workers(self):
        ''' Create multiple IAM Roles '''
        key_count = self.svc_config['resource_count']
        if len(self.created_keys) >= key_count:
            # Don't need to create more keys
            logging.info('No need to create more resources for KMS')
            return self.created_keys
        else:
            needed = key_count - len(self.created_keys)
        
        for _ in range(0, needed, 1):
            rnd_str = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=10))
            try:
                resp = self.kms_client.create_key(        
                    Description='{}_test_key'.format(self.rsc_prefix),
                    KeyUsage='ENCRYPT_DECRYPT'                   
                )
                if not self._check_boto3_response(resp):
                    logging.error('Fail to create a test KMS key')
                    continue
                key_id = resp['KeyMetadata']['KeyId']
                key_arn = resp['KeyMetadata']['Arn']
                
                # Create a key alias 
                alias_name = 'alias/{}-{}'.format(self.rsc_prefix, rnd_str)
                resp2 = self.kms_client.create_alias(
                        AliasName = alias_name,
                        TargetKeyId = key_id                        
                    )
                if not self._check_boto3_response(resp2):
                    logging.error('Fail to create a test KMS key alias')
                    continue

                # Disable this
                self.kms_client.disable_key(
                    KeyId=key_id,
                )

                self.created_keys.append({"KeyId":key_id, "KeyArn":key_arn})
                logging.info('Key alias {} has been successfully created'.format(alias_name))
            except botocore.exceptions.ClientError as error:
                logging.error('Fail to create KMS key. {}'.format(error))

        self._set_worker_cycle(self.created_keys)
        return self.created_keys

    def delete_workers(self):
        for key_obj in self.created_keys:
            key_id = key_obj['KeyId']
            try:
                resp = self.kms_client.schedule_key_deletion(
                    KeyId=key_id,
                    PendingWindowInDays=7
                )
                if not self._check_boto3_response(resp):
                    continue
                logging.info('Key {} is scheduled to be deleted on {}'.format(key_id, resp['DeletionDate']))
            except botocore.exceptions.ClientError as error:
                logging.error('Fail to delete kms key {}. {}'.format(key_id, error))
        self.created_keys = list()
        self._set_worker_cycle(self.created_keys)

     
    def _check_existing_identity(self, identiy_arn):
        ''' Check if identiy_arn exists in AWS '''
        test_policy_obj = '''{"Sid":"roleFinder","Effect":"Deny","Principal":{},"Action":"kms:*","Resource":"*"}'''
        test_policy_obj = json.loads(test_policy_obj)
        # role_arn = 'arn:{}:iam::{}:role/{}'.format(aws_partition, aws_id, target_role)
        
        key_obj = self._get_next_worker()
        if key_obj is None:
            logging.error('No available worker/resource in kms_handler')
            return
        policy_obj = json.loads(key_obj['Policy'])        
        test_policy_obj['Principal']['AWS'] = identiy_arn

        if len(policy_obj['Statement']) == 1:
            policy_obj['Statement'].append(test_policy_obj)
        else:
            policy_obj['Statement'][1] = test_policy_obj

        try:
            resp = self.kms_client.put_key_policy(
                KeyId=key_obj['KeyId'],
                Policy=json.dumps(policy_obj),
                PolicyName='default'
            )
            if self._check_boto3_response(resp):
                return True
        except self.kms_client.exceptions.MalformedPolicyDocumentException as e:
            if e.response['Error']['Code'] == 'MalformedPolicyDocumentException' and 'invalid principals' in e.response['Error']['Message']:
                logging.debug('Invalid principal identified using kms key {}!'.format(key_obj['KeyId']))            
                return False
        except botocore.exceptions.ClientError as e:
            logging.error(e)
        return None
    