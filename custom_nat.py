import aws_cdk as cdk
from constructs import Construct
from aws_cdk import (
    aws_ec2 as ec2,
    aws_autoscaling as autoscaling,
    aws_lambda as lambda_,
    aws_iam as iam,
)
import typing
import cdk_iam_floyd as statement

import jsii


def is_outbound_allowed(direction: ec2.NatTrafficDirection) -> bool:
    return direction in [
        ec2.NatTrafficDirection.INBOUND_AND_OUTBOUND,
        ec2.NatTrafficDirection.OUTBOUND_ONLY,
    ]


def is_inbound_allowed(direction: ec2.NatTrafficDirection) -> bool:
    return direction in [ec2.NatTrafficDirection.INBOUND_AND_OUTBOUND]


@jsii.implements(ec2.IConnectable)
class NatInstanceAsgProvider(ec2.NatProvider):
    def __init__(
        self,
        instance_type: ec2.InstanceType,
        default_allowed_traffic: ec2.NatTrafficDirection = ec2.NatTrafficDirection.OUTBOUND_ONLY,
        eip_by_az: typing.Optional[dict[str, ec2.CfnEIP]] = None,
    ) -> None:
        super().__init__()
        self.instance_type = instance_type
        self.default_allowed_traffic = default_allowed_traffic
        self.eip_by_az = eip_by_az or {}
        self._connections: typing.Optional[ec2.Connections] = None
        self._security_group: typing.Optional[ec2.ISecurityGroup] = None
        self._gateways: dict[str, ec2.CfnNetworkInterface] = {}

    def configure_nat(  # type: ignore[misc]
        self, options: ec2.ConfigureNatOptions, /
    ) -> None:

        nat_subnets = options.nat_subnets
        private_subnets = options.private_subnets
        vpc = options.vpc
        default_direction = self.default_allowed_traffic

        machine_image = ec2.MachineImage.latest_amazon_linux(
            generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
        )
        # machine_image = NatInstanceImage()
        self._security_group = ec2.SecurityGroup(
            vpc,
            "NatSecurityGroup",
            vpc=vpc,
            description="Security Group for NAT instances",
            allow_all_outbound=is_outbound_allowed(default_direction),
        )
        self._connections = ec2.Connections(security_groups=[self._security_group])

        if is_inbound_allowed(default_direction):
            self.connections.allow_from_any_ipv4(ec2.Port.all_traffic())

        role = iam.Role(
            vpc, "NatRole", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        )

        for subnet in nat_subnets:

            az = subnet.subnet_availability_zone
            eni = ec2.CfnNetworkInterface(
                subnet,
                "NatEni",
                subnet_id=subnet.subnet_id,
                source_dest_check=False,
                group_set=[self._security_group.security_group_id],
            )
            eip = self.eip_by_az.get(az, ec2.CfnEIP(eni, "NatEIP", domain="vpc"))
            self.eip_by_az[az] = eip

            ec2.CfnEIPAssociation(
                eip,
                "EIPAssociation",
                allocation_id=eip.attr_allocation_id,
                network_interface_id=eni.attr_id,
            )

            # nat_asg = autoscaling.AutoScalingGroup(
            #     subnet,
            #     "NatAsg",
            #     vpc=vpc,
            #     instance_type=self.instance_type,
            #     machine_image=machine_image,
            #     min_capacity=1,
            #     vpc_subnets=ec2.SubnetSelection(
            #         subnets=[typing.cast(ec2.ISubnet, subnet)]
            #     ),
            #     security_group=self._security_group,
            #     role=typing.cast(iam.IRole, role),
            #     update_policy=autoscaling.UpdatePolicy.rolling_update(),
            # )
            nat_asg = ec2.Instance(
                subnet,
                "NatInstance",
                vpc=vpc,
                instance_type=self.instance_type,
                machine_image=machine_image,
                vpc_subnets=ec2.SubnetSelection(
                    subnets=[typing.cast(ec2.ISubnet, subnet)]
                ),
                security_group=self._security_group,
                role=typing.cast(iam.IRole, role),
            )

            self._gateways[subnet.subnet_availability_zone] = eni

            ec2.CfnNetworkInterfaceAttachment(
                nat_asg,
                "ENIattachment",
                network_interface_id=eni.attr_id,
                instance_id=nat_asg.instance_id,
                delete_on_termination=False,
                device_index="1",
            )
            # TODO: use a lifecycle hook instead
            # TODO: need to detach first if attached
            # nat_asg.add_user_data(
            #     "aws ec2 attach-network-interface --instance-id"
            #     + " `wget -q -O - http://169.254.169.254/latest/meta-data/instance-id`"
            #     + f" --network-interface-id {eni.attr_id}"
            #     + " --device-index 1"
            #     + f" --region {cdk.Stack.of(nat_asg).region}",
            # )
            nat_asg.add_user_data(
                # "sleep 5",
                "ifdown eth0",
                "sysctl -w net.ipv4.ip_forward=1",
                # "route del -net default netmask 0.0.0.0 dev eth0",
                # "route add -net default netmask 0.0.0.0 dev eth1",
                "iptables -t nat -I POSTROUTING -o eth1 -j MASQUERADE",
                "yum install iptables-services -y",
                "service iptables save",
                # "iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
                # "ifconfig eth0 down",
            )

            # nat_asg.add_to_role_policy(
            #     statement.Ec2()
            #     .to_attach_network_interface()
            #     .on_network_interface(
            #         network_interface_id=eni.attr_id,
            #         account=cdk.Stack.of(eni).account,
            #         region=cdk.Stack.of(eni).region,
            #     )
            #     .on_instance(
            #         instance_id="*",
            #         account=cdk.Stack.of(eni).account,
            #         region=cdk.Stack.of(eni).region,
            #     )
            # )

            nat_asg.add_to_role_policy(
                typing.cast(
                    statement.PolicyStatementWithResources,
                    statement.Ssmmessages().all_actions(),
                ).on_all_resources()
            )
            nat_asg.add_to_role_policy(
                statement.Ssm().to_update_instance_information().on_all_resources()
            )
            nat_asg.add_to_role_policy(
                typing.cast(
                    statement.PolicyStatementWithResources,
                    statement.Ec2messages().all_actions(),
                ).on_all_resources()
            )

            for subnet in private_subnets:
                self.configure_subnet(subnet)

    @property
    def security_group(self) -> ec2.ISecurityGroup:
        if self._security_group is None:
            raise ValueError(
                "Pass the NatInstanceAsgProvider to a Vpc before accessing 'security_group'"
            )
        else:
            return self._security_group

    @property
    def connections(self) -> ec2.Connections:
        if self._connections is None:
            raise ValueError(
                "Pass the NatInstanceAsgProvider to a Vpc before accessing 'security_group'"
            )
        else:
            return self._connections

    @property
    def configured_gateways(self) -> list[ec2.GatewayConfig]:
        return [
            ec2.GatewayConfig(az=az, gateway_id=eni.attr_id)
            for az, eni in self._gateways.items()
        ]

    def configure_subnet(self, subnet: ec2.PrivateSubnet) -> None:
        eni = self._gateways.get(
            subnet.subnet_availability_zone, list(self._gateways.values())[0]
        )
        subnet.add_route(
            "DefaultRoute",
            router_type=ec2.RouterType.NETWORK_INTERFACE,
            router_id=eni.attr_id,
            enables_internet_connectivity=True,
        )

        self.connections.allow_from(
            ec2.Peer.ipv4(subnet.ipv4_cidr_block), port_range=ec2.Port.all_traffic()
        )


class CustomNatInstance(cdk.Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        vpc = ec2.Vpc(
            self,
            "Vpc",
            nat_gateways=1,
            max_azs=99,
            subnet_configuration=typing.cast(
                typing.List[ec2.SubnetConfiguration],
                ec2.Vpc.DEFAULT_SUBNETS,
            ),
            nat_gateway_provider=NatInstanceAsgProvider(
                instance_type=ec2.InstanceType("t3.nano")
            ),
            enable_dns_hostnames=True,
            enable_dns_support=True,
        )

        lambda_.Function(
            self,
            "lambda",
            vpc=vpc,
            code=lambda_.Code.from_inline(
                """import json
import http.client
def handler(event, context):
    conn = http.client.HTTPSConnection("www.python.org")
    conn.request("GET", "/")
    r1 = conn.getresponse()
    print(r1.status, r1.reason)"""
            ),
            handler="index.handler",
            runtime=typing.cast(lambda_.Runtime, lambda_.Runtime.PYTHON_3_9),
            allow_all_outbound=True,
        )
