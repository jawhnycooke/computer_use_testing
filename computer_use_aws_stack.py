from aws_cdk import (
    Stack,
    aws_ecr_assets,
    aws_ecr,
    aws_ecs,
    aws_iam,
    aws_ec2,
    aws_logs,
    aws_kms,
    aws_servicediscovery,
    aws_route53resolver,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions as codepipeline_actions,
    aws_codebuild as codebuild,
    aws_codestarconnections as codestar,
    Duration,
    CfnOutput,
    RemovalPolicy,
    aws_cloudwatch,
    aws_budgets,
    Tags,
)
from constructs import Construct
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import os


class ComputerUseAwsStack(Stack):
    """
    AWS CDK Stack for deploying a secure computing environment with ECS Fargate.
    This stack creates a complete infrastructure including VPC, ECS cluster,
    security groups, and containerized services.
    """

    # Resource configuration constants
    CONTAINER_CPU = 1024 * 2
    CONTAINER_MEMORY = 1024 * 4
    LOG_RETENTION = aws_logs.RetentionDays.ONE_MONTH
    DEFAULT_REMOVAL_POLICY = RemovalPolicy.DESTROY
    MAX_SESSION_DURATION = Duration.hours(1)

    # Port mappings for various services
    PORTS = {"dcv": 8443, "flask": 5000, "streamlit": 8501}

    # CloudWatch Log group paths
    LOG_PATHS = {
        "vpc": "/aws/vpc/flowlogs",
        "container_insights": "/aws/ecs/containerinsights",
        "ecs_exec": "/aws/ecs/exec",
        "ecs_main": "/ecs/computer-use-aws",
    }

    # Add budget information
    BUDGET_AMOUNT = 1000  # Monthly budget in USD
    BUDGET_THRESHOLD_PERCENT = 80

    # Alert at 80% of budget
    COST_TAGS = {
        "Environment": "Sandbox",
        "Project": "ComputerUseAWS",
        "Owner": "DevOps",
        "CostCenter": "Engineering",
    }

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        """
        Initialize the stack and create all required AWS resources.

        Args:
            scope: The scope in which to define this construct
            construct_id: The scoped construct ID
            **kwargs: Additional arguments to pass to the parent Stack
        """
        super().__init__(scope, construct_id, **kwargs)

        # Initialize base resources
        self.encryption_key = self._create_kms_key()
        self.repository = self._create_ecr_repository()
        self.vpc = self._create_vpc()
        self.dns_firewall = self._create_dns_firewall()
        self.cluster = self._create_ecs_cluster()
        self.log_group = self._create_log_group("main", self.LOG_PATHS["ecs_main"])

        # Create roles
        self.execution_role = self._create_execution_role()
        self.orchestration_role = self._create_orchestration_role()

        # Create pipeline resources
        self.github_connection = self._create_github_connection()
        self.pipeline = self._create_pipeline()
        self.build_projects = self._create_build_projects()

        # Create task definitions and services
        self._create_environment_resources()
        self._create_orchestration_resources()

        # Add outputs
        self._add_stack_outputs()

        # Add stack tags
        self._add_stack_tags()

        self._create_cost_management()

    def get_resource_name(self, service: str, resource: str) -> str:
        """
        Generate consistent resource names across the stack.

        Args:
            service: Service identifier (e.g., 'ecs', 'iam')
            resource: Resource identifier (e.g., 'cluster', 'role')

        Returns:
            str: Formatted resource name
        """
        return f"computer-use-aws-{service}-{resource}-{self.stack_name.lower()}"

    def _get_kms_policy(self) -> aws_iam.PolicyDocument:
        """Create KMS key policy with additional permissions for CodeBuild and CodePipeline"""
        return aws_iam.PolicyDocument(
            statements=[
                # Existing permissions
                aws_iam.PolicyStatement(
                    actions=["kms:*"],
                    principals=[aws_iam.AccountRootPrincipal()],
                    resources=["*"],
                ),
                aws_iam.PolicyStatement(
                    actions=[
                        "kms:Encrypt*",
                        "kms:Decrypt*",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:Describe*",
                    ],
                    principals=[
                        aws_iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")
                    ],
                    resources=["*"],
                    conditions={
                        "ArnLike": {
                            "kms:EncryptionContext:aws:logs:arn": f"arn:aws:logs:{self.region}:{self.account}:*"
                        }
                    },
                ),
                # New permissions for CodeBuild and CodePipeline
                aws_iam.PolicyStatement(
                    actions=[
                        "kms:Encrypt*",
                        "kms:Decrypt*",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:Describe*",
                    ],
                    principals=[
                        aws_iam.ServicePrincipal("codebuild.amazonaws.com"),
                        aws_iam.ServicePrincipal("codepipeline.amazonaws.com"),
                    ],
                    resources=["*"],
                ),
            ]
        )

    def _create_flow_log_role(self, log_group_arn: str) -> aws_iam.Role:
        """Create IAM Role for VPC Flow Logs"""
        role = aws_iam.Role(
            self,
            "VPCFlowLogRole",
            assumed_by=aws_iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
            role_name=self.get_resource_name("iam", "vpc-flow-log"),
        )

        role.add_to_policy(
            aws_iam.PolicyStatement(
                actions=[
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogStreams",
                ],
                resources=[log_group_arn + ":*"],
            )
        )
        return role

    def _get_allowed_domains(self) -> List[str]:
        """Get list of allowed domains for DNS firewall"""
        return [
            # A2Z domains
            "a2z.com",
            "*.a2z.com",
            # Amazon/AWS domains
            "amazon.com",
            "*.amazon.com",
            "*.amazonaws.com",
            "*.awsstatic.com",
            "*.media-amazon.com",
            "*.ssl-images-amazon.com",
            "*.amazon-adsystem.com",
            "*.cloudfront.net",
            "aws.dev",
            "*.aws.dev",
            "repost.aws",
            "*.repost.aws",
            # Anthropic domains
            "anthropic.com",
            "*.anthropic.com",
            "claude.ai",
            "*.claude.ai",
            # GitHub domains
            "github.com",
            "*.github.com",
            "*.githubassets.com",
            "*.githubusercontent.com",
            # Google domains
            "google.com",
            "*.google.com",
            "*.googleapis.com",
            "*.gstatic.com",
            # Python and documentation domains
            "docs.python.org",
            "*.pypi.org",
            "*.pythonhosted.org",
            "readthedocs.org",
            "*.readthedocs.io",
            # Package management
            "cdn.jsdelivr.net",
            "npmjs.com",
            "*.npmjs.com",
            # Testing domains
            "example.com",
            "httpbin.org",
            # Internal domains
            "*.computer-use.local",
        ]

    def _get_firewall_rules(
        self,
        allowed_domains: aws_route53resolver.CfnFirewallDomainList,
        blocked_domains: aws_route53resolver.CfnFirewallDomainList,
    ) -> List[aws_route53resolver.CfnFirewallRuleGroup.FirewallRuleProperty]:
        """Get firewall rules for DNS firewall"""
        return [
            aws_route53resolver.CfnFirewallRuleGroup.FirewallRuleProperty(
                firewall_domain_list_id=allowed_domains.attr_id,
                action="ALLOW",
                priority=1000,
            ),
            aws_route53resolver.CfnFirewallRuleGroup.FirewallRuleProperty(
                firewall_domain_list_id=blocked_domains.attr_id,
                action="BLOCK",
                priority=2000,
                block_response="NODATA",
            ),
        ]

    def _create_execution_role(self) -> aws_iam.Role:
        """Create IAM role for ECS task execution"""
        role = aws_iam.Role(
            self,
            "EcsTaskExecutionRole",
            assumed_by=aws_iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            role_name=self.get_resource_name("iam", "execution-role"),
            max_session_duration=self.MAX_SESSION_DURATION,
            description="Role for Computer Use AWS ECS task execution",
        )

        # Add ECR permissions
        role.add_to_policy(
            aws_iam.PolicyStatement(
                actions=[
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                ],
                resources=[self.repository.repository_arn],
            )
        )

        # Add CloudWatch Logs permissions
        role.add_to_policy(
            aws_iam.PolicyStatement(
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=[
                    f"arn:aws:logs:{self.region}:{self.account}:log-group:{self.LOG_PATHS['ecs_main']}/{self.stack_name.lower()}:*"
                ],
            )
        )
        return role

    def _create_orchestration_role(self) -> aws_iam.Role:
        """Create IAM role for orchestration container with Bedrock permissions"""
        role = aws_iam.Role(
            self,
            "ComputerUseAwsOrchestrationTaskRole",
            assumed_by=aws_iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            role_name=self.get_resource_name("iam", "orchestration-role"),
            max_session_duration=self.MAX_SESSION_DURATION,
            description="Role for Computer Use AWS Orchestration ECS task",
            inline_policies={
                "BedrockModelAccess": aws_iam.PolicyDocument(
                    statements=[
                        aws_iam.PolicyStatement(
                            sid="AllowSpecificModels",
                            effect=aws_iam.Effect.ALLOW,
                            actions=[
                                "bedrock:InvokeModel",
                                "bedrock:InvokeModelWithResponseStream",
                            ],
                            resources=[
                                f"arn:aws:bedrock:{region}::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0"
                                for region in ["us-east-1", "us-east-2", "us-west-2"]
                            ]
                            + [
                                f"arn:aws:bedrock:{region}::foundation-model/us.anthropic.claude-3-5-sonnet-20241022-v2:0"
                                for region in ["us-east-1", "us-east-2", "us-west-2"]
                            ]
                            + [
                                f"arn:aws:bedrock:{region}:{self.account}:inference-profile/anthropic.claude-3-5-sonnet-20241022-v2:0"
                                for region in ["us-east-1", "us-east-2", "us-west-2"]
                            ]
                            + [
                                f"arn:aws:bedrock:{region}:{self.account}:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0"
                                for region in ["us-east-1", "us-east-2", "us-west-2"]
                            ],
                        ),
                        aws_iam.PolicyStatement(
                            effect=aws_iam.Effect.ALLOW,
                            actions=[
                                "bedrock:ListFoundationModels",
                                "bedrock:GetFoundationModel",
                            ],
                            resources=["*"],
                        ),
                    ]
                )
            },
        )
        return role

    def _add_security_group_rules(
        self, security_group: aws_ec2.SecurityGroup, ports: List[Tuple[int, str]]
    ) -> None:
        """Add ingress rules to a security group"""
        for port, description in ports:
            security_group.add_ingress_rule(
                peer=aws_ec2.Peer.any_ipv4(),
                connection=aws_ec2.Port.tcp(port),
                description=f"Allow public inbound traffic on port {port} for {description}",
            )

    def _create_log_group(self, name: str, prefix: str = None) -> aws_logs.LogGroup:
        """Create a CloudWatch log group with standard configuration"""
        log_path = prefix if prefix else self.LOG_PATHS["ecs_main"]
        return aws_logs.LogGroup(
            self,
            f"LogGroup{name}",
            log_group_name=f"{log_path}/{self.stack_name.lower()}/{name}",
            removal_policy=self.DEFAULT_REMOVAL_POLICY,
            retention=self.LOG_RETENTION,
            encryption_key=self.encryption_key,
        )

    def _create_kms_key(self) -> aws_kms.Key:
        """Create KMS key with required permissions"""
        key = aws_kms.Key(
            self,
            "ComputerUseAwsKey",
            enable_key_rotation=True,
            pending_window=Duration.days(7),
            removal_policy=self.DEFAULT_REMOVAL_POLICY,
            alias="computer-use-aws-key",
            policy=self._get_kms_policy(),
        )
        Tags.of(key).add("Service", "KMS")
        Tags.of(key).add("Environment", "Sandbox")
        return key

    def _create_ecr_repository(self) -> aws_ecr.Repository:
        """Create ECR repository"""
        repo = aws_ecr.Repository(
            self,
            "ComputerUseAwsRepository",
            repository_name=self.get_resource_name("ecr", "repo"),
            removal_policy=self.DEFAULT_REMOVAL_POLICY,
            image_scan_on_push=True,
            encryption=aws_ecr.RepositoryEncryption.KMS,
            encryption_key=self.encryption_key,
            image_tag_mutability=aws_ecr.TagMutability.MUTABLE,
        )
        Tags.of(repo).add("Service", "ECR")
        Tags.of(repo).add("Environment", "Sandbox")
        return repo

    def _create_github_connection(self) -> codestar.CfnConnection:
        """Create GitHub connection for CodePipeline"""
        return codestar.CfnConnection(
            self,
            "GitHubConnection",
            connection_name="ComputerUseDemoGitHub",
            provider_type="GitHub",
        )

    def _create_build_projects(self) -> Dict[str, codebuild.PipelineProject]:
        """Create CodeBuild projects for container builds"""
        build_projects = {}

        # Common build environment for ARM64
        build_env = codebuild.BuildEnvironment(
            build_image=codebuild.LinuxArmBuildImage.AMAZON_LINUX_2_STANDARD_3_0,
            privileged=True,
        )

        # Common environment variables
        env_vars = {
            "ECR_REPO_URI": codebuild.BuildEnvironmentVariable(
                value=self.repository.repository_uri
            ),
            "AWS_DEFAULT_REGION": codebuild.BuildEnvironmentVariable(value=self.region),
            "AWS_ACCOUNT_ID": codebuild.BuildEnvironmentVariable(value=self.account),
        }

        # Environment container build project
        build_projects["environment"] = codebuild.PipelineProject(
            self,
            "EnvironmentBuildProject",
            encryption_key=self.encryption_key,
            build_spec=codebuild.BuildSpec.from_object(
                {
                    "version": "0.2",
                    "phases": {
                        "pre_build": {
                            "commands": [
                                "echo Logging in to Amazon ECR...",
                                "aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com",
                            ]
                        },
                        "build": {
                            "commands": [
                                "echo Build started on `date`",
                                "cd computer_use_aws/environment_image",
                                "docker build -t $ECR_REPO_URI:$CODEBUILD_RESOLVED_SOURCE_VERSION .",
                                "docker tag $ECR_REPO_URI:$CODEBUILD_RESOLVED_SOURCE_VERSION $ECR_REPO_URI:environment-latest",
                            ]
                        },
                        "post_build": {
                            "commands": [
                                "echo Pushing Docker images...",
                                "docker push $ECR_REPO_URI:$CODEBUILD_RESOLVED_SOURCE_VERSION",
                                "docker push $ECR_REPO_URI:environment-latest",
                                "echo Writing image definitions...",
                                'printf \'{"ImageURI":"%s"}\' $ECR_REPO_URI:environment-latest > imageDefinitions.json',
                            ]
                        },
                    },
                    "artifacts": {"files": ["imageDefinitions.json"]},
                }
            ),
            environment=build_env,
            environment_variables=env_vars,
        )

        # Orchestration container build project
        build_projects["orchestration"] = codebuild.PipelineProject(
            self,
            "OrchestrationBuildProject",
            encryption_key=self.encryption_key,
            build_spec=codebuild.BuildSpec.from_object(
                {
                    "version": "0.2",
                    "phases": {
                        "pre_build": {
                            "commands": [
                                "echo Logging in to Amazon ECR...",
                                "aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com",
                            ]
                        },
                        "build": {
                            "commands": [
                                "echo Build started on `date`",
                                "cd computer_use_aws/orchestration_image",
                                "docker build -t $ECR_REPO_URI:$CODEBUILD_RESOLVED_SOURCE_VERSION .",
                                "docker tag $ECR_REPO_URI:$CODEBUILD_RESOLVED_SOURCE_VERSION $ECR_REPO_URI:orchestration-latest",
                            ]
                        },
                        "post_build": {
                            "commands": [
                                "echo Pushing Docker images...",
                                "docker push $ECR_REPO_URI:$CODEBUILD_RESOLVED_SOURCE_VERSION",
                                "docker push $ECR_REPO_URI:orchestration-latest",
                                "echo Writing image definitions...",
                                'printf \'{"ImageURI":"%s"}\' $ECR_REPO_URI:orchestration-latest > imageDefinitions.json',
                            ]
                        },
                    },
                    "artifacts": {"files": ["imageDefinitions.json"]},
                }
            ),
            environment=build_env,
            environment_variables=env_vars,
        )

        # Grant permissions to build projects
        for project in build_projects.values():
            self.repository.grant_pull_push(project)
            self.encryption_key.grant_encrypt_decrypt(project)

        return build_projects

    def _create_pipeline_role(self) -> aws_iam.Role:
        """Create IAM role for CodePipeline with ECS deployment permissions"""
        role = aws_iam.Role(
            self,
            "CodePipelineRole",
            assumed_by=aws_iam.ServicePrincipal("codepipeline.amazonaws.com"),
            role_name=self.get_resource_name("iam", "pipeline-role"),
            max_session_duration=self.MAX_SESSION_DURATION,
        )

        role.add_to_policy(
            aws_iam.PolicyStatement(
                actions=[
                    "ecs:DescribeServices",
                    "ecs:DescribeTaskDefinition",
                    "ecs:DescribeTasks",
                    "ecs:ListTasks",
                    "ecs:RegisterTaskDefinition",
                    "ecs:UpdateService",
                    "iam:PassRole",
                ],
                resources=["*"],
            )
        )

        # Add permissions for artifacts bucket
        role.add_to_policy(
            aws_iam.PolicyStatement(
                actions=[
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:GetBucketVersioning",
                    "s3:PutObject",
                ],
                resources=["*"],
            )
        )

        # Add KMS permissions
        role.add_to_policy(
            aws_iam.PolicyStatement(
                actions=[
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:Encrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                ],
                resources=[self.encryption_key.key_arn],
            )
        )
        return role

    def _create_pipeline(self) -> codepipeline.Pipeline:
        """Create CodePipeline for CI/CD"""
        pipeline = codepipeline.Pipeline(
            self,
            "ComputerUsePipeline",
            pipeline_name=self.get_resource_name("pipeline", "main"),
            role=self._create_pipeline_role(),  # Add the role here
        )

        # Source stage
        source_output = codepipeline.Artifact()
        source_action = codepipeline_actions.CodeStarConnectionsSourceAction(
            action_name="GitHub_Source",
            owner=str(os.getenv("GITHUB_REPO_USERNAME")),
            repo=str(os.getenv("GITHUB_REPO_NAME")),
            branch=str(os.getenv("GITHUB_BRANCH", "main")),
            connection_arn=self.github_connection.attr_connection_arn,
            output=source_output,
        )
        pipeline.add_stage(
            stage_name="Source",
            actions=[source_action],
        )

        # Build and deploy stages for each container
        for container_type in ["environment", "orchestration"]:
            # Build stage
            build_output = codepipeline.Artifact(f"{container_type}-build")
            build_action = codepipeline_actions.CodeBuildAction(
                action_name=f"Build_{container_type.capitalize()}",
                project=self.build_projects[container_type],
                input=source_output,
                outputs=[build_output],
            )
            pipeline.add_stage(
                stage_name=f"Build_{container_type.capitalize()}",
                actions=[build_action],
            )

            # Deploy stage
            deploy_action = codepipeline_actions.EcsDeployAction(
                action_name=f"Deploy_{container_type.capitalize()}",
                service=getattr(
                    self, f"{container_type}_service"
                ),  # Reference to the ECS service
                input=build_output,
            )
            pipeline.add_stage(
                stage_name=f"Deploy_{container_type.capitalize()}",
                actions=[deploy_action],
            )
        return pipeline

    def _create_vpc(self) -> aws_ec2.Vpc:
        """Create VPC with flow logs"""
        vpc_logs = self._create_log_group("vpc-flow", self.LOG_PATHS["vpc"])
        flow_log_role = self._create_flow_log_role(vpc_logs.log_group_arn)

        vpc = aws_ec2.Vpc(
            self,
            "ComputerUseAwsVPC",
            max_azs=2,
            restrict_default_security_group=True,
            flow_logs={
                "flowlog": aws_ec2.FlowLogOptions(
                    destination=aws_ec2.FlowLogDestination.to_cloud_watch_logs(
                        log_group=vpc_logs,
                        iam_role=flow_log_role,
                    ),
                    traffic_type=aws_ec2.FlowLogTrafficType.ALL,
                )
            },
        )
        Tags.of(vpc).add("Service", "VPC")
        Tags.of(vpc).add("Environment", "Sandbox")
        return vpc

    def _create_dns_firewall(self) -> aws_route53resolver.CfnFirewallRuleGroup:
        """Create DNS Firewall configuration"""
        allowed_domains = aws_route53resolver.CfnFirewallDomainList(
            self,
            "AllowedDomains",
            domains=self._get_allowed_domains(),
            name="computer-use-allowed-domains",
        )

        blocked_domains = aws_route53resolver.CfnFirewallDomainList(
            self,
            "BlockedDomains",
            domains=["*"],
            name="computer-use-blocked-domains",
        )

        rule_group = aws_route53resolver.CfnFirewallRuleGroup(
            self,
            "DnsFirewallRuleGroup",
            name="computer-use-dns-firewall",
            firewall_rules=self._get_firewall_rules(allowed_domains, blocked_domains),
        )

        aws_route53resolver.CfnFirewallRuleGroupAssociation(
            self,
            "FirewallAssociation",
            firewall_rule_group_id=rule_group.attr_id,
            priority=1000,
            vpc_id=self.vpc.vpc_id,
            name="computer-use-firewall-association",
        )
        return rule_group

    def _create_ecs_cluster(self) -> aws_ecs.Cluster:
        """Create ECS cluster"""
        cluster = aws_ecs.Cluster(
            self,
            "ComputerUseAwsCluster",
            cluster_name=self.get_resource_name("ecs", "cluster"),
            vpc=self.vpc,
            container_insights=True,
            default_cloud_map_namespace=aws_ecs.CloudMapNamespaceOptions(
                name="computer-use.local",
                type=aws_servicediscovery.NamespaceType.DNS_PRIVATE,
                vpc=self.vpc,
            ),
        )
        Tags.of(cluster).add("Service", "ECS")
        Tags.of(cluster).add("Environment", "Sandbox")
        return cluster

    def _create_task_definition(
        self, name: str, task_role: aws_iam.Role = None
    ) -> aws_ecs.FargateTaskDefinition:
        """Create a Fargate task definition with standard configuration"""
        task_def = aws_ecs.FargateTaskDefinition(
            self,
            f"{name}TaskDef",
            execution_role=self.execution_role,
            task_role=task_role,
            family=self.get_resource_name("ecs", name.lower()),
            cpu=self.CONTAINER_CPU,
            memory_limit_mib=self.CONTAINER_MEMORY,
            runtime_platform=aws_ecs.RuntimePlatform(
                operating_system_family=aws_ecs.OperatingSystemFamily.LINUX,
                cpu_architecture=aws_ecs.CpuArchitecture.ARM64,
            ),
        )
        Tags.of(task_def).add("Service", "ECS")
        Tags.of(task_def).add("Environment", "Sandbox")
        return task_def

    def _create_security_group(
        self, name: str, description: str
    ) -> aws_ec2.SecurityGroup:
        """Create a security group with standard configuration"""
        sg = aws_ec2.SecurityGroup(
            self,
            f"{name}SecurityGroup",
            vpc=self.vpc,
            allow_all_outbound=True,
            description=description,
            security_group_name=self.get_resource_name("sg", name.lower()),
        )
        Tags.of(sg).add("Service", "SecurityGroup")
        Tags.of(sg).add("Environment", "Sandbox")
        return sg

    def _create_fargate_service(
        self,
        name: str,
        task_definition: aws_ecs.FargateTaskDefinition,
        security_group: aws_ec2.SecurityGroup,
        cloudmap_name: str,
    ) -> aws_ecs.FargateService:
        """Create a Fargate service with standard configuration"""
        service = aws_ecs.FargateService(
            self,
            f"{name}Service",
            cluster=self.cluster,
            task_definition=task_definition,
            security_groups=[security_group],
            vpc_subnets=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PUBLIC),
            assign_public_ip=True,
            service_name=self.get_resource_name("service", name.lower()),
            desired_count=1,
            deployment_controller=aws_ecs.DeploymentController(
                type=aws_ecs.DeploymentControllerType.ECS
            ),
            min_healthy_percent=0,
            max_healthy_percent=100,
            enable_execute_command=False,
            cloud_map_options=aws_ecs.CloudMapOptions(
                name=cloudmap_name,
                dns_record_type=aws_servicediscovery.DnsRecordType.A,
                dns_ttl=Duration.seconds(60),
                cloud_map_namespace=self.cluster.default_cloud_map_namespace,
            ),
        )
        Tags.of(service).add("Service", "ECS")
        Tags.of(service).add("Environment", "Sandbox")

        # Store service reference in class attribute
        setattr(self, f"{name.lower()}_service", service)
        return service

    def _create_environment_resources(self):
        """
        Create ECS resources for the environment container including:
        - Fargate task definition
        - Security group with DCV and Flask ports
        - Container configuration with logging
        - ECS service with service discovery
        """
        task_def = self._create_task_definition("Environment")
        security_group = self._create_security_group(
            "Environment", "Security group for environment container"
        )

        # Add security group rules
        self._add_security_group_rules(
            security_group, [(self.PORTS["dcv"], "DCV"), (self.PORTS["flask"], "Flask")]
        )

        # Add container using ECR image instead of local build
        container = task_def.add_container(
            "EnvironmentContainer",
            image=aws_ecs.ContainerImage.from_ecr_repository(
                repository=self.repository, tag="environment-latest"
            ),
            logging=aws_ecs.LogDrivers.aws_logs(
                stream_prefix="ecs-environment",
                log_group=self.log_group,
            ),
            essential=True,
            readonly_root_filesystem=False,
            privileged=False,
        )

        # Add port mappings
        for port in [self.PORTS["dcv"], self.PORTS["flask"]]:
            container.add_port_mappings(
                aws_ecs.PortMapping(container_port=port, host_port=port)
            )

        # Create service
        self._create_fargate_service(
            "Environment", task_def, security_group, "environment"
        )

    def _create_orchestration_resources(self):
        """
        Create ECS resources for the orchestration container including:
        - Fargate task definition with Bedrock permissions
        - Security group with Streamlit port
        - Container configuration with logging
        - ECS service with service discovery
        """
        task_def = self._create_task_definition(
            "Orchestration", self.orchestration_role
        )
        security_group = self._create_security_group(
            "Orchestration", "Security group for orchestration container"
        )

        # Add security group rules
        self._add_security_group_rules(
            security_group, [(self.PORTS["streamlit"], "Streamlit")]
        )

        # Add container using ECR image instead of local build
        container = task_def.add_container(
            "OrchestrationContainer",
            image=aws_ecs.ContainerImage.from_ecr_repository(
                repository=self.repository, tag="orchestration-latest"
            ),
            logging=aws_ecs.LogDrivers.aws_logs(
                stream_prefix="ecs-orchestration",
                log_group=self.log_group,
            ),
            essential=True,
            readonly_root_filesystem=False,
            privileged=False,
        )

        # Add port mapping
        container.add_port_mappings(
            aws_ecs.PortMapping(
                container_port=self.PORTS["streamlit"],
                host_port=self.PORTS["streamlit"],
            )
        )

        # Create service
        self._create_fargate_service(
            "Orchestration", task_def, security_group, "orchestration"
        )

    def _create_cost_management(self) -> None:
        """
        Implements basic cost management including:
        - Cost allocation tags
        - Cost monitoring dashboard
        """
        # Create monthly budget
        self._create_monthly_budget()

        # Enable cost allocation tags
        self._enable_cost_allocation_tags()

        # Create cost monitoring dashboard
        self._create_cost_dashboard()

        # Create monthly budget

    def _create_monthly_budget(self) -> None:
        """
        Creates a monthly budget to track spending against threshold.
        No notifications are configured, just tracking.
        """
        aws_budgets.CfnBudget(
            self,
            "MonthlyBudget",
            budget=aws_budgets.CfnBudget.BudgetDataProperty(
                budget_limit=aws_budgets.CfnBudget.SpendProperty(
                    amount=self.BUDGET_AMOUNT, unit="USD"
                ),
                time_unit="MONTHLY",
                budget_type="COST",
                cost_filters={
                    "Service": [
                        "Amazon Elastic Container Service",
                        "AWS Key Management Service",
                        "Amazon ECR",
                    ]
                },
            ),
        )

    def _enable_cost_allocation_tags(self) -> None:
        """
        Applies standard cost allocation tags to all resources in the stack.
        These tags help track costs by different dimensions like environment,
        project, and cost center.
        """
        for key, value in self.COST_TAGS.items():
            Tags.of(self).add(key=key, value=value)

    def _create_cost_dashboard(self) -> None:
        """
        Creates a CloudWatch dashboard for cost monitoring.
        Displays key metrics like estimated charges and resource utilization.
        """
        dashboard = aws_cloudwatch.Dashboard(
            self,
            "CostDashboard",
            dashboard_name=self.get_resource_name("cw", "cost-dashboard"),
        )

        # Add widgets to track costs
        dashboard.add_widgets(
            aws_cloudwatch.TextWidget(
                markdown="# Cost Monitoring Dashboard", width=24, height=1
            ),
            aws_cloudwatch.GraphWidget(
                title="Estimated Monthly Charges",
                width=12,
                height=6,
                left=[
                    aws_cloudwatch.Metric(
                        namespace="AWS/Billing",
                        metric_name="EstimatedCharges",
                        statistic="Maximum",
                        period=Duration.hours(6),
                    )
                ],
            ),
            aws_cloudwatch.GraphWidget(
                title="ECS Service Utilization",
                width=12,
                height=6,
                left=[
                    self.cluster.metric_cpu_utilization(),
                    self.cluster.metric_memory_utilization(),
                ],
            ),
        )

    def _add_stack_outputs(self):
        """
        Add CloudFormation outputs including:
        - Stack name
        - ECR repository URI
        - Service discovery endpoints
        - Connection instructions
        - Cost management information
        - Pipeline information
        """
        # Stack Information Output
        CfnOutput(
            self,
            "StackInformation",
            value="\n".join(
                [
                    f"Stack Name: {self.stack_name}",
                    f"ECR Repository: {self.repository.repository_uri}",
                    f"Environment Service: environment.computer-use.local",
                    f"Orchestration Service: orchestration.computer-use.local",
                    "\nConnection Instructions:",
                    "Environment: https://<public-ip>:8443",
                    "Orchestration: http://<public-ip>:8501",
                    "Alternatively run the ./scripts/get_url.sh script to get the public IPs",
                ]
            ),
            description="Stack Resource Information",
        )

        # Cost Management Information Output
        CfnOutput(
            self,
            "CostManagementInfo",
            value="\n".join(
                [
                    f"Cost Dashboard: https://{self.region}.console.aws.amazon.com/cloudwatch/home#dashboards:",
                    f"Cost Tags: {', '.join(f'{k}={v}' for k, v in self.COST_TAGS.items())}",
                ]
            ),
            description="Cost Management Information",
        )

        # Pipeline Information Output
        CfnOutput(
            self,
            "PipelineInformation",
            value="\n".join(
                [
                    "\nPipeline Information:",
                    f"Pipeline Console: https://{self.region}.console.aws.amazon.com/codesuite/codepipeline/pipelines/{self.pipeline.pipeline_name}/view",
                    f"GitHub Connection ARN: {self.github_connection.attr_connection_arn}",
                    "\nRequired Environment Variables:",
                    "GITHUB_REPO_USERNAME",
                    "GITHUB_REPO_NAME",
                    "GITHUB_BRANCH",
                    "\nNote: Complete GitHub connection in AWS Console after deployment",
                ]
            ),
            description="Pipeline Information",
        )

    def _add_stack_tags(self):
        """
        Add standard tags to the stack for resource management and tracking:
        - Project name
        - Environment type
        - Creation date
        """
        Tags.of(self).add("Project", "AnthropicBedrockComputerUse")
        Tags.of(self).add("Environment", "Sandbox")
        Tags.of(self).add("CreatedDate", datetime.now().strftime("%Y-%m-%d"))
