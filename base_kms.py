#!/usr/bin/env python3
import boto3

def new_kms_client(profile_name=None, region_name='us-east-1'):

    if profile_name:
        session = boto3.session.Session(profile_name=profile_name)
    else:
        session = boto3.session.Session()

    client = session.client(
        service_name='kms',
        region_name=region_name
    )

    return client