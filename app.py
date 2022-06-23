#!/usr/bin/env python3

import aws_cdk as cdk
import os
from custom_nat import CustomNatInstance


app = cdk.App()

env = cdk.Environment(
    account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"]
)


CustomNatInstance(app, "CustomNatInstance", env=env)


app.synth()
