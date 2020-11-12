import boto3
import botocore
import sys, os
import random, string
import logging
from aws_svc.aws_service_base import AWS_SVC_BASE, AWS_SVC_TYPE

class IAMHandler(AWS_SVC_BASE):
    def __init__(self, boto3_session, iam_config):
        super().__init__(AWS_SVC_TYPE.IAM, boto3_session, iam_config)
        self.iam_client = boto3_session.client('iam', config=AWS_SVC_BASE.aws_config)
        self.created_roles = list()
        self.role_path = '{}{}{}'.format('/', self.rsc_prefix, '/')
        self.get_existing_workers()
        self._set_worker_cycle(self.created_roles)

    def get_existing_workers(self):
        try:
            key_count = self.svc_config['resource_count']
            resp = self.iam_client.list_roles(PathPrefix=self.role_path, MaxItems=1000)  # result may be truncated
            if not self._check_boto3_response(resp):
                return
            for role in resp['Roles']:
                role_name = role['RoleName']
                self.created_roles.append(role_name)
                key_count -= 1
                if key_count <= 0: 
                    break
            return self.created_roles
        except botocore.exceptions.ClientError as error:
            logging.error('Fail to list rolefinder roles. {}'.format(error))
        

    def create_workers(self):
        ''' Create multiple IAM Roles '''
        trust_policy = '''{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'''
        role_count = self.svc_config['resource_count']
        if len(self.created_roles) >= role_count:
            # Don't need to create more roles
            logging.info('No need to create more resources for IAM')
            return self.created_roles
        else:
            needed = role_count - len(self.created_roles)
        
        for _ in range(0, needed, 1):
            rnd_str = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=12))
            try:
                resp = self.iam_client.create_role(RoleName=rnd_str, Path=self.role_path, AssumeRolePolicyDocument = trust_policy)
                if not self._check_boto3_response(resp):
                    continue

                role_name = resp['Role']['RoleName']
                self.created_roles.append(role_name)
                logging.info('Role {} has been successfully created'.format(role_name))
            except botocore.exceptions.ClientError as error:
                logging.error('Fail to create IAM role. {}'.format(error))

        self._set_worker_cycle(self.created_roles)
        return self.created_roles

    def delete_workers(self):
        for role_name in self.created_roles:
            try:
                self.iam_client.delete_role(
                    RoleName=role_name
                )
                logging.info('Role {} has been successfully deleted'.format(role_name))
            except botocore.exceptions.ClientError as error:
                logging.error('Fail to delete role {}. {}'.format(role_name, error))
        self.created_roles = list()
        self._set_worker_cycle(self.created_roles)
    
    def _check_existing_identity(self, identiy_arn):
        # check if the identiy_arn exists
        test_role = self._get_next_worker()
        if test_role is None:
            logging.error('No available worker/resource in IAM handler')
            return None

        trust_policy = '{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":{{"AWS":"{}"}},"Action":"sts:AssumeRole"}}]}}'.format(identiy_arn)
        try:
            resp = self.iam_client.update_assume_role_policy(
                RoleName=test_role,
                PolicyDocument=trust_policy
            )
            if self._check_boto3_response(resp):
                return True
        except self.iam_client.exceptions.MalformedPolicyDocumentException as e:
            # Role does not exist
            if e.response['Error']['Code'] == 'MalformedPolicyDocument' and 'Invalid principal' in e.response['Error']['Message']:
                logging.debug('Invalid principal identified using role {}!'.format(test_role))            
                return False 
        except botocore.exceptions.ClientError as e:
            logging.debug(e)
        return False

