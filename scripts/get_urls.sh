#!/bin/bash

# Function to print usage
print_usage() {
    echo "Usage: $0 [--profile <aws-profile>]"
    echo "  --profile : AWS profile to use (optional, defaults to 'default')"
    echo "Example: $0 --profile nyc"
}

# Default profile
PROFILE="default"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)
            if [ -z "$2" ]; then
                echo "Error: --profile requires a value"
                print_usage
                exit 1
            fi
            PROFILE="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option $1"
            print_usage
            exit 1
            ;;
    esac
done

# Print profile being used
echo "Using AWS Profile: $PROFILE"

# Stack configuration with proper case conversion
STACK_NAME="ComputerUseAwsStack"
STACK_NAME_LOWER=$(echo $STACK_NAME | tr '[:upper:]' '[:lower:]')
CLUSTER_NAME="computer-use-aws-ecs-cluster-${STACK_NAME_LOWER}"
ENV_SERVICE="computer-use-aws-service-environment-${STACK_NAME_LOWER}"
ORCH_SERVICE="computer-use-aws-service-orchestration-${STACK_NAME_LOWER}"

echo -e "\nChecking service status..."
aws ecs describe-services --cluster $CLUSTER_NAME --services $ENV_SERVICE $ORCH_SERVICE \
--query 'services[*].[serviceName,status,runningCount,desiredCount,events[0].message]' --output table \
--profile $PROFILE

echo -e "\nGetting Orchestration Service IP (Streamlit on port 8501)..."
ORCH_TASK=$(aws ecs list-tasks --cluster $CLUSTER_NAME --service-name $ORCH_SERVICE \
--query 'taskArns[0]' --output text --profile $PROFILE)
if [ ! -z "$ORCH_TASK" ] && [ "$ORCH_TASK" != "None" ]; then
    ORCH_ENI=$(aws ecs describe-tasks --cluster $CLUSTER_NAME --tasks $ORCH_TASK \
    --query 'tasks[0].attachments[0].details[?name==`networkInterfaceId`].value' --output text \
    --profile $PROFILE)
    ORCH_IP=$(aws ec2 describe-network-interfaces --network-interface-ids $ORCH_ENI \
    --query 'NetworkInterfaces[0].Association.PublicIp' --output text --profile $PROFILE)
    echo "Task ARN: $ORCH_TASK"
    echo "ENI: $ORCH_ENI"
    echo "IP Address: $ORCH_IP"
    echo "Orchestration Service URL: http://$ORCH_IP:8501"
else
    echo "No running tasks found for Orchestration Service"
fi

echo -e "\nGetting Environment Service IP (DCV on port 8443)..."
ENV_TASK=$(aws ecs list-tasks --cluster $CLUSTER_NAME --service-name $ENV_SERVICE \
--query 'taskArns[0]' --output text --profile $PROFILE)
if [ ! -z "$ENV_TASK" ] && [ "$ENV_TASK" != "None" ]; then
    ENV_ENI=$(aws ecs describe-tasks --cluster $CLUSTER_NAME --tasks $ENV_TASK \
    --query 'tasks[0].attachments[0].details[?name==`networkInterfaceId`].value' --output text \
    --profile $PROFILE)
    ENV_IP=$(aws ec2 describe-network-interfaces --network-interface-ids $ENV_ENI \
    --query 'NetworkInterfaces[0].Association.PublicIp' --output text --profile $PROFILE)
    echo "Task ARN: $ENV_TASK"
    echo "ENI: $ENV_ENI"
    echo "IP Address: $ENV_IP"
    echo "Environment Service URL: https://$ENV_IP:8443"
else
    echo "No running tasks found for Environment Service"
fi