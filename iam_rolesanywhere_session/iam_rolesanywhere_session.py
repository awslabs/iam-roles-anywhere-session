"""
  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0
     
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
"""

#!/bin/env python3
import base64
import hashlib
import json
import logging
from datetime import datetime
from typing import Union

import requests
from boto3.session import Session
from botocore.credentials import DeferredRefreshableCredentials
from botocore.session import get_session as get_botocore_session
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto
from OpenSSL.crypto import PKey

log = logging.getLogger(__name__)


class IAMRolesAnywhereSession():
    """
       Class enabling the creation of a refreshable botocore Session object.
       to use with IAM Roles Anywhere.
    """
    def __init__(self,
        profile_arn: str,
        role_arn: str,
        trust_anchor_arn: str,
        certificate: Union[str, bytes],
        private_key: Union[str, bytes],
        **kwargs
    ) -> None:
                
        self.profile_arn = profile_arn
        self.role_arn = role_arn
        self.trust_anchor_arn = trust_anchor_arn
        self.certificate = self.__load_certificate(certificate)
        
        self.private_key_passphrase = self.__get_passphrase(kwargs.get('private_key_passphrase', None))
        self.private_key = self.__load_private_key(private_key)
        self.private_key_type = self.__get_privatekey_type()
        self.algorithm = self.__get_algorithm()
        
        self.session_duration = int(kwargs.get('session_duration', 3600))
        self.region_name = kwargs.get('region', 'us-east-1')
        self.service_name = kwargs.get('service_name', 'rolesanywhere')
        self.endpoint = kwargs.get('endpoint', f'{self.service_name}.{self.region_name}.amazonaws.com')
        
    def get_session(self, **kwargs) -> Session:
        """Get a botocore session
        
        Args:
            kwargs (dict): Key value of configuration parameter for Session object
            
        Returns:
            Session: Botocore session object
        """
        session = get_botocore_session()
        session._credentials = DeferredRefreshableCredentials(
            refresh_using=self.__get_credentials,
            method='custom-process'
        )
    
        # Default session region
        session.set_config_variable("region", self.region_name)
        for k, v in kwargs.items():
            session.set_config_variable(k,v)
        return Session(botocore_session=session)

    def __get_credentials(self) -> dict:
        """Compute and make the request to rolesanywhere endpoint to retrieve IAM Credentials

        Returns:
            dict: Dict of AWS Credentials acquired from rolesanywhere: {
                "access_key": accessKeyId,
                "secret_key": secretAccessKey,
                "token": sessionToken,
                "expiry_time": expirationTime,
            }
        """
        
        time = datetime.utcnow()
        
        amz_date = time.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = time.strftime('%Y%m%d')


        log.debug(f'Using algorithm {self.algorithm}')
        log.debug(f'Use AMZ Date {amz_date}')
        
        req_params = json.dumps({
            "durationSeconds": self.session_duration, 
            "profileArn": self.profile_arn, 
            "roleArn": self.role_arn,
            "trustAnchorArn": self.trust_anchor_arn 
        })

        log.debug(f'Request Params : {req_params}')

        x509_der_b64 = base64.b64encode(
                    self.certificate.public_bytes(
                        serialization.Encoding.DER
                    )
                ).decode("utf-8").strip()
        
        log.debug(f'x509 Certificate, DER Base64 {x509_der_b64}')
        
        req_headers = {
            'Host': self.endpoint,
            'Content-Type': "application/x-amz-json-1.0",
            'X-Amz-Date': amz_date,
            'X-Amz-X509': x509_der_b64
        }

        req_headers_lower = {
            'host': self.endpoint,
            'content-type': "application/x-amz-json-1.0",
            'x-amz-date': amz_date,
            'x-amz-x509': x509_der_b64
        }

        # Task 1

        log.debug("Starting AWS Signature V4 - Task 1")

        headers_to_sign = sorted(filter(lambda h: h,
                                        map(lambda h_key: h_key.lower(), req_headers.keys())))
        
        
        canonical_headers = ''.join(map(lambda h: ":".join((h, req_headers_lower[h])) + '\n', headers_to_sign))
        
        signed_headers = ';'.join(headers_to_sign)

        payload_hash = hashlib.sha256(req_params.encode('utf-8')).hexdigest()

        canonical_querystring = ''

        # Combine elements to create canonical request
        canonical_request = '\n'.join([
                'POST',
                '/sessions', 
                canonical_querystring,
                canonical_headers, 
                signed_headers, 
                payload_hash])
        

        # Task 2 : Create a string to sign 
        log.debug("Starting AWS Signature V4 - Task 2")
        credential_scope = '/'.join([date_stamp, self.region_name, self.service_name, 'aws4_request'])
        string_to_sign = '\n'.join([self.algorithm, amz_date,
                                    credential_scope, hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()])

        
        # Task 3: Calculate signature
        log.debug("Starting AWS Signature V4 - Task 3")
        signature = crypto.sign(self.private_key, (string_to_sign).encode('utf-8'), "sha256").hex()
        log.debug(f'Signature {signature}')

        x509_serial_number = '%d' % self.certificate.serial_number
        
        req_headers['Authorization'] = f'{self.algorithm} Credential={x509_serial_number}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}'

        credentials_request = requests.post(f'https://{self.endpoint}/sessions',data=req_params, headers=req_headers)
        
        credentials_request.raise_for_status()

        log.debug(credentials_request.text)
        aws_creds = credentials_request.json().get('credentialSet')[0].get('credentials')
        
        return {
                "access_key": aws_creds.get("accessKeyId"),
                "secret_key": aws_creds.get("secretAccessKey"),
                "token": aws_creds.get("sessionToken"),
                "expiry_time": aws_creds.get("expiration"),
            }

    def __load_certificate(self, certificate: Union[str, bytes]) -> x509.Certificate:
        """Load the certificate

        Args:
            certificate (Union[str, bytes]): Representation of the certificate in PEM format.

        Returns:
            x509.Certificate: return the certificate
        """
        if isinstance(certificate, bytes):
            return x509.load_pem_x509_certificate(certificate, default_backend())
        cert_pem_file = open(certificate, "rb")
        _ = x509.load_pem_x509_certificate(cert_pem_file.read(), default_backend())
        cert_pem_file.close()
        return _
    
    def __load_private_key(self, private_key: Union[str, bytes]) -> PKey:
        """Load the private key 

        Args:
            private_key (Union[str, bytes]): Representation of the private key in PEM format.

        Returns:
            PKey: return a Pkey object
        """
        if isinstance(private_key, bytes):
            return crypto.load_privatekey(crypto.FILETYPE_PEM, private_key, passphrase=self.private_key_passphrase)
        key_pem_file = open(private_key, 'rb')
        _ = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem_file.read(), passphrase=self.private_key_passphrase)
        key_pem_file.close()
        return _
    
    def __get_privatekey_type(self) -> str:
        """Get the private key type and raise an error for unsupported type

        Raises:
            Exception: Private key is not supported
            Exception: The object provided is not a PKey object

        Returns:
            str: Type of the key, RSA or ECDSA.
        """
        if isinstance(self.private_key, PKey):            
            if self.private_key.type() == crypto.TYPE_EC:
                return "ECDSA"
            elif self.private_key.type() == crypto.TYPE_RSA:
                return "RSA"
            else:
                raise Exception("Private Key type is not supported")
        else:
            raise Exception("Object is not a Pkey instance")
    
    def __get_passphrase(self, passphrase: str) -> bytes:
        """Return an encoded version of the passphrase or none 

        Args:
            passphrase (str): the passphrase to encode

        Returns:
            bytes: passphrase in bytes format
        """
        return passphrase.encode() if passphrase else None
    
    def __get_algorithm(self) -> str:
        """Compute the AlgorithmId with key type and hash algorithm of the key

        Returns:
            str: AlgorithmId
        """
        return f'AWS4-X509-{self.private_key_type}-{self.certificate.signature_hash_algorithm.name.upper()}'
