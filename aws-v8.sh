#!/bin/bash

BLUE='\033[1;34m'
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 
echo_blue() { echo -e "${BLUE}$1${NC}"; }
echo_red() { echo -e "${RED}$1${NC}"; }
echo_green() { echo -e "${GREEN}$1${NC}"; }
echo_yellow() { echo -e "${YELLOW}$1${NC}"; }

AWS_PROFILE=""

# Function to show the help message
show_help() {

    echo "Usage: $0 [options]"
    echo
    echo "Options:"
	echo -e "  --profile <name>            Specify AWS profile"
    echo "  -i, --imdsv2                Check if EC2 instances have IMDSv2 enabled"
    echo -e "  -s, --s3-security           Check S3 buckets for versioning, logging, and secure transport"
    echo -e "  -p, --iam-policies          Check IAM policies for privilege escalation vulnerabilities $(echo_red "Manual review is required")"
    echo "  -r, --assume-pass-role      Check IAM policies for iam:PassRole and sts:AssumeRole permissions"
    echo "  -k, --kms-keys              Check KMS key rotation status"
    echo "  -m, --secrets-manager       Check Secrets Manager secrets and their rotation status"
    echo "  -y, --iam-key-rotation      Check IAM key rotation"
    echo "  -u, --iam-key-usage         Check for unused IAM keys"
    echo -e "  -c, --cloudtrail-encryption Check if CloudTrail logs are encrypted with KMS"
    echo -e "  -l, --sensitiveInfo_lambda  Check for Hardcoded sensitive information in Lambda  $(echo_red "Manual review is required")"
    echo -e "  -e, --ec2_userdata          Check for sensitive information in EC2 instances user data  $(echo_red "Manual review is required")"
    echo "  -sg1, --secGroups1          To check if Egress and Ingress are allowed on all ports and to all IPs"
    echo "  -sg2, --secGroups2          To check if any unused security groups are being used or not"
    echo -e "  -lb, --loadbalancer         To check if load balancer allows cleartext communication"
    echo -e "  -sm, --secrets              To check if secrets manager parameter store has securestring or not"
	echo -e " -cl, --consoleLink        To generate AWS console link"
	echo -e " -pu, --pacu               To run Pacu modules automatically, please ensure aws cli v2 and Pacu is installed. $(echo_red "Manual review is required of the generated output")"
    echo -e " -ct, --cloudtool          To run Scoutsuite, Prowler, Cloudfox, Cloudsplaining $(echo_red "Manual review is required of the generated output")"
	echo -e "$(echo_red "Please make sure that Pacu, ScoutSuite, Cloudfox, Cloudsplaining, Prowler are installed or are added in your PATH env variable")"
	echo -e "  -h, --help                  Display help message"
    echo -e "                   Please install Scrot and jq utility using: sudo apt install jq scrot -y"
    echo
	echo $(echo_yellow "When copy-pasting list of affected items, please limit it to 5-6. As including lot of items might result in bad console output/screenshot")
	echo
    echo "Examples:"
    echo "  $0 --profile yourProfileName --imdsv2 --s3-security"
	echo "  $0 --profile is not required for "
    echo "  $0 --help"
}

# Function to check if IMDSv2 is enabled on EC2 instances
#The enabled should be displayed in green color and NOT enabled ones should be displayed in red color
check_imdsv2() {
    clear

    # Color helpers
    echo_blue()   { echo -e "\e[34m$1\e[0m"; }
    echo_red()    { echo -e "\e[31m$1\e[0m"; }
    echo_green()  { echo -e "\e[32m$1\e[0m"; }
    echo_yellow() { echo -e "\e[33m$1\e[0m"; }

    echo "Do you want to run the IMDSv2 status check on all instances or selective instances?"
    echo "1. All instances"
    echo "2. Selective instances"
    read -p "Please enter your choice (1 or 2): " choice

    identity_info=$(aws sts get-caller-identity --query "{Account:Account, Arn:Arn}" --profile "$AWS_PROFILE" --output json)
    account_id=$(echo $identity_info | jq -r .Account)
    arn=$(echo $identity_info | jq -r .Arn)
    region=$(aws configure get region --profile "$AWS_PROFILE")

    echo_blue "ARN: $arn"
    echo "Instance IMDSv2 status check:" | tee imds.txt

    if [ "$choice" == "1" ]; then
        instances=$(aws ec2 describe-instances \
            --query "Reservations[].Instances[].InstanceId" \
            --profile "$AWS_PROFILE" --output text)

    elif [ "$choice" == "2" ]; then
        echo "Enter instance ID(s) or instance name(s), one per line. Press Ctrl+D when done:"
        mapfile -t instance_input_array

        if [ ${#instance_input_array[@]} -eq 0 ]; then
            echo_red "No input provided. Exiting..."
            return 1
        fi

        instances=""
        for input in "${instance_input_array[@]}"; do
            if [[ "$input" =~ ^i-[a-zA-Z0-9]+$ ]]; then
                instances+="$input "
            else
                instance_id=$(aws ec2 describe-instances \
                    --filters "Name=tag:Name,Values=$input" \
                    --query "Reservations[].Instances[].InstanceId" \
                    --profile "$AWS_PROFILE" --output text)

                if [ -z "$instance_id" ]; then
                    echo_red "Instance name '$input' not found."
                else
                    instances+="$instance_id "
                fi
            fi
        done

    else
        echo "Invalid choice! Exiting script."
        return 1
    fi

    for instance_id in $instances; do
        instance_arn="arn:aws:ec2:$region:$account_id:instance/$instance_id"

        aws_command="aws ec2 describe-instances --instance-id $instance_id --query \"Reservations[].Instances[].MetadataOptions.HttpTokens\" --profile \"$AWS_PROFILE\" --output text"
        imds_state=$(eval $aws_command)

        echo_yellow "Executed: $aws_command" | tee -a imds.txt
        echo "Instance ARN: $instance_arn" | tee -a imds.txt

        if [ "$imds_state" == "required" ]; then
            echo_green "✅ IMDSv2 is enabled on instance $instance_id (ARN: $instance_arn)" | tee -a imds.txt
        else
            echo_red "❌ IMDSv2 is NOT enabled on instance $instance_id (ARN: $instance_arn)" | tee -a imds.txt
        fi
    done

    echo_green "Screenshot taken using Scrot"
    scrot -u -f "IMDSv2_Status.png"
}


################################################################################################
# Function to check S3 security
check_s3_security() {
    clear
    echo "Do you want to check security settings for all buckets or selected buckets?"
    echo "1. All buckets"
    echo "2. Selective buckets"
    read -p "Please enter your choice (1 or 2): " choice

    identity_info=$(aws sts get-caller-identity --query "{Account:Account, Arn:Arn}" --profile "$AWS_PROFILE" --output json)
    account_id=$(echo $identity_info | jq -r .Account)
    arn=$(echo $identity_info | jq -r .Arn)
    echo_blue "ARN: $arn"

    echo "S3 Bucket security status check:" | tee s3_security.txt

    if [ "$choice" == "1" ]; then
        buckets=$(aws s3api list-buckets --query "Buckets[].Name" --profile "$AWS_PROFILE" --output text)

        if echo "$buckets" | grep -q "Access Denied"; then
            echo_red "Access Denied while listing buckets. Exiting script."
            exit 1
        fi
        # Convert string to array
        read -r -a buckets <<< "$buckets"

    elif [ "$choice" == "2" ]; then
        echo "Enter bucket name(s), one per line. Press Ctrl+D when done:"
        mapfile -t buckets

        if [ ${#buckets[@]} -eq 0 ]; then
            echo_red "No bucket names provided. Exiting script."
            exit 1
        fi

    else
        echo "Invalid choice! Exiting script."
        exit 1
    fi

    for bucket in "${buckets[@]}"; do
        bucket_arn="arn:aws:s3:::$bucket"

        echo "Checking bucket: $bucket (ARN: $bucket_arn)" | tee -a s3_security.txt

        aws_command_versioning="aws s3api get-bucket-versioning --profile \"$AWS_PROFILE\" --bucket \"$bucket\" --query \"Status\" --output text"
        versioning=$(eval "$aws_command_versioning")

        if [ $? -ne 0 ]; then
            echo_red  "Access Denied or error occurred while checking versioning for bucket $bucket. Exiting script."
            exit 1
        fi

        echo_yellow "Executed: $aws_command_versioning" | tee -a s3_security.txt
        if [ "$versioning" != "Enabled" ]; then
            echo_red "Versioning is NOT enabled on bucket $bucket (ARN: $bucket_arn)" | tee -a s3_security.txt
        else
            echo_green "Versioning is enabled on bucket $bucket (ARN: $bucket_arn)" | tee -a s3_security.txt
        fi

        aws_command_logging="aws s3api get-bucket-logging --profile \"$AWS_PROFILE\" --bucket \"$bucket\" --query \"LoggingEnabled\" --output text"
        logging=$(eval "$aws_command_logging")

        if [ $? -ne 0 ]; then
            echo_red  "Access Denied or error occurred while checking logging for bucket $bucket. Exiting script."
            exit 1
        fi

        echo_yellow "Executed: $aws_command_logging" | tee -a s3_security.txt
        if [ "$logging" == "None" ]; then
            echo_red "Logging is NOT enabled on bucket $bucket (ARN: $bucket_arn)" | tee -a s3_security.txt
        else
            echo_green "Logging is enabled on bucket $bucket (ARN: $bucket_arn)" | tee -a s3_security.txt
        fi

        aws_command_ssl_check="aws s3api get-bucket-policy --profile \"$AWS_PROFILE\" --bucket \"$bucket\" --query \"Policy\" --output text | grep -oP '\"aws:SecureTransport\":\"\K\w+' "
        ssl_check=$(eval "$aws_command_ssl_check")

        if [ $? -ne 0 ]; then
            echo_red  "Access Denied or error occurred while checking SSL enforcement for bucket $bucket. Exiting script."
            exit 1
        fi

        echo_yellow "Executed: $aws_command_ssl_check" | tee -a s3_security.txt
        if [ "$ssl_check" == "false" ]; then
            echo_green "Secure transport (SSL) is enforced on bucket $bucket (ARN: $bucket_arn)" | tee -a s3_security.txt

        else
            echo_red "Secure transport (SSL) is NOT enforced on bucket $bucket (ARN: $bucket_arn)" | tee -a s3_security.txt
        fi

        echo "------------------------------------" | tee -a s3_security.txt
    done

    echo_green "Screenshot taken using Scrot"
    scrot -u -f "S3_bucket_security_Status.png"
}


##############################################################################################

# Function to check IAM policies
check_iam_policies() {
    clear

    # Color helpers
    echo_blue()   { echo -e "\e[34m$1\e[0m"; }
    echo_red()    { echo -e "\e[31m$1\e[0m"; }
    echo_green()  { echo -e "\e[32m$1\e[0m"; }
    echo_yellow() { echo -e "\e[33m$1\e[0m"; }

    echo "Do you want to check IAM policies for:"
    echo "1. All policies"
    echo "2. Selected policies"
    read -p "Please enter your choice (1 or 2): " choice

    echo "Executing: aws sts get-caller-identity --profile \"$AWS_PROFILE\" --query \"{Account:Account, Arn:Arn}\" --output json"
    identity_info=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query "{Account:Account, Arn:Arn}" --output json)
    account_id=$(echo $identity_info | jq -r .Account)
    arn=$(echo $identity_info | jq -r .Arn)

    echo_blue "ARN: $arn"
    echo "IAM policies security check:" | tee iam_policies.txt

    if [ "$choice" == "1" ]; then
        echo "Executing: aws iam list-policies --profile \"$AWS_PROFILE\" --scope Local --query \"Policies[].Arn\" --output text"
        policies=$(aws iam list-policies --profile "$AWS_PROFILE" --scope Local --query "Policies[].Arn" --output text)
        echo "Retrieved policies." | tee -a iam_policies.txt

        for policy_arn in $policies; do
            echo "Executing: aws iam list-policy-versions --profile \"$AWS_PROFILE\" --policy-arn $policy_arn --query \"Versions[0].VersionId\" --output text"
            version_id=$(aws iam list-policy-versions --profile "$AWS_PROFILE" --policy-arn $policy_arn --query "Versions[0].VersionId" --output text)

            if [[ ! $version_id =~ ^v[0-9]+ ]]; then
                echo_red "❌ Invalid version_id format for policy $policy_arn: $version_id" | tee -a iam_policies.txt
                continue
            fi

            aws_command_policy_document="aws iam get-policy-version --profile \"$AWS_PROFILE\" --policy-arn $policy_arn --version-id $version_id --query \"PolicyVersion.Document\" --output json"
            echo_yellow "Executed: $aws_command_policy_document" | tee -a iam_policies.txt
            policy_document=$(eval $aws_command_policy_document)

            echo "Policy Document for $policy_arn:" | tee -a iam_policies.txt
            echo "$policy_document" | tee -a iam_policies.txt
            echo "----------------------------------" | tee -a iam_policies.txt
        done

    elif [ "$choice" == "2" ]; then
        echo "Enter the names of the IAM policies to check (one per line). Press Ctrl+D when done:"
        mapfile -t selected_policy_names

        if [ ${#selected_policy_names[@]} -eq 0 ]; then
            echo_red "❌ No policy names entered. Exiting..." | tee -a iam_policies.txt
            return 1
        fi

        echo -e "Enter the IAM Actions you want to search for (one per line). Press Ctrl+D when done:"
        mapfile -t actions_to_search

        if [ ${#actions_to_search[@]} -eq 0 ]; then
            echo_red "❌ No IAM actions entered. Exiting..." | tee -a iam_policies.txt
            return 1
        fi

        echo "Checking IAM policies for specified actions..." > iam_policies.txt
        action_found=false

        for policy_name in "${selected_policy_names[@]}"; do
            echo "Executing: aws iam list-policies --scope Local --profile \"$AWS_PROFILE\" --query \"Policies[?PolicyName=='$policy_name'].Arn\" --output text"
            policy_arn=$(aws iam list-policies --scope Local --profile "$AWS_PROFILE" \
                --query "Policies[?PolicyName=='$policy_name'].Arn" --output text)

            if [ -z "$policy_arn" ]; then
                echo_red "❌ Policy with name '$policy_name' not found." | tee -a iam_policies.txt
                continue
            fi

            echo "🔎 Policy Name: $policy_name" | tee -a iam_policies.txt
            echo "Policy ARN: $policy_arn" | tee -a iam_policies.txt

            echo "Executing: aws iam list-policy-versions --profile \"$AWS_PROFILE\" --policy-arn $policy_arn --query \"Versions[0].VersionId\" --output text"
            version_id=$(aws iam list-policy-versions --profile "$AWS_PROFILE" --policy-arn $policy_arn \
                --query "Versions[0].VersionId" --output text)

            if [[ ! $version_id =~ ^v[0-9]+ ]]; then
                echo_red "❌ Invalid version_id format for policy $policy_name: $version_id" | tee -a iam_policies.txt
                continue
            fi

            aws_command_policy_document="aws iam get-policy-version --profile \"$AWS_PROFILE\" --policy-arn $policy_arn --version-id $version_id --query \"PolicyVersion.Document\" --output json"
            echo_yellow "Executed: $aws_command_policy_document" | tee -a iam_policies.txt
            policy_document=$(eval $aws_command_policy_document)

            echo_yellow "🔍 Checking for potentially risky IAM Actions..." | tee -a iam_policies.txt

            for action_to_search in "${actions_to_search[@]}"; do
                matching_lines=$(echo "$policy_document" | grep -i -A 10 -B 5 -e "$action_to_search" -e "Resource")

                if [[ -z "$matching_lines" ]]; then
                    echo_red "❌ The IAM Action '$action_to_search' NOT found in policy $policy_name." | tee -a iam_policies.txt
                else
                    echo_green "✅ Found IAM Action '$action_to_search' in policy $policy_name:" | tee -a iam_policies.txt
                    echo "$matching_lines" | tee -a iam_policies.txt
                    action_found=true
                fi
            done

            echo "----------------------------------" | tee -a iam_policies.txt
        done

        if [ "$action_found" = false ]; then
            echo_red "❌ None of the specified IAM Actions were found in any of the selected policies." | tee -a iam_policies.txt
        fi
    else
        echo_red "❌ Invalid choice! Exiting script."
        exit 1
    fi

    echo_green "📸 Screenshot taken using Scrot"
    scrot -u -f "IAM_Policies.png"
}

################################################################################################
# Function to check PassRole and AssumeRole
check_assume_pass_role() {
    clear
	    # Color helpers
    echo_blue()   { echo -e "\e[34m$1\e[0m"; }
    echo_red()    { echo -e "\e[31m$1\e[0m"; }
    echo_green()  { echo -e "\e[32m$1\e[0m"; }
    echo_yellow() { echo -e "\e[33m$1\e[0m"; }

    echo "Do you want to check IAM policies for:"
    echo "1. All policies"
    echo "2. Selected policies"
    read -p "Please enter your choice (1 or 2): " choice

    echo "Which permission(s) do you want to check for?"
    echo "1. iam:PassRole"
    echo "2. sts:AssumeRole"
    echo "3. Both"
    read -p "Enter your choice (1, 2, or 3): " permission_choice

    check_passrole=false
    check_assumerole=false

    case "$permission_choice" in
        1)
            check_passrole=true
            ;;
        2)
            check_assumerole=true
            ;;
        3)
            check_passrole=true
            check_assumerole=true
            ;;
        *)
            echo "❌ Invalid permission choice. Exiting..."
            return 1
            ;;
    esac

    # Show AWS CLI command for sts get-caller-identity
    echo "Executing: aws sts get-caller-identity --profile \"$AWS_PROFILE\" --query \"{Account:Account, Arn:Arn}\" --output json"
    identity_info=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query "{Account:Account, Arn:Arn}" --output json)
    account_id=$(echo "$identity_info" | jq -r .Account)
    arn=$(echo "$identity_info" | jq -r .Arn)
    echo_blue "ARN: $arn"

    echo "Checking policies for selected permissions..." | tee iam_passrole_assumerole.txt

    if [ "$choice" == "1" ]; then
        echo "Checking all policies..." | tee -a iam_passrole_assumerole.txt
        # Show AWS CLI command for listing policies
        echo_blue "Executing: aws iam list-policies --scope Local --profile \"$AWS_PROFILE\" --query \"Policies[].Arn\" --output text"
        policy_arns=$(aws iam list-policies --scope Local --profile "$AWS_PROFILE" --query "Policies[].Arn" --output text)
    elif [ "$choice" == "2" ]; then
        echo "Enter the names of the IAM policies to check (one per line). Press Ctrl+D when done:"
        mapfile -t selected_policy_names
        if [ ${#selected_policy_names[@]} -eq 0 ]; then
            echo "❌ No policy names entered. Exiting..." | tee -a iam_passrole_assumerole.txt
            return 1
        fi

        policy_arns=""
        for policy_name in "${selected_policy_names[@]}"; do
            # Show AWS CLI command for fetching policy ARN
            echo_blue "Executing: aws iam list-policies --profile \"$AWS_PROFILE\" --scope Local --query \"Policies[?PolicyName=='$policy_name'].Arn\" --output text"
            arn=$(aws iam list-policies --profile "$AWS_PROFILE" --scope Local --query "Policies[?PolicyName=='$policy_name'].Arn" --output text)
            if [ -z "$arn" ]; then
                echo_yellow "❌ Policy with name '$policy_name' not found." | tee -a iam_passrole_assumerole.txt
            else
                policy_arns+="$arn "
            fi
        done
    else
        echo "❌ Invalid choice! Exiting script."
        return 1
    fi

    for policy_arn in $policy_arns; do
        # Show AWS CLI command for listing policy versions
        echo_blue "Executing: aws iam list-policy-versions --policy-arn \"$policy_arn\" --profile \"$AWS_PROFILE\" --query \"Versions[?IsDefaultVersion==\`true\`].VersionId | [0]\" --output text"
        version_id=$(aws iam list-policy-versions \
            --policy-arn "$policy_arn" \
            --profile "$AWS_PROFILE" \
            --query "Versions[?IsDefaultVersion==\`true\`].VersionId | [0]" \
            --output text)

        if [[ -z "$version_id" || "$version_id" == "None" ]]; then
            echo_yellow "❌ Skipping policy $policy_arn: couldn't get default version." | tee -a iam_passrole_assumerole.txt
            continue
        fi

        # Show AWS CLI command for fetching the policy document
        echo_blue "Executing: aws iam get-policy-version --profile \"$AWS_PROFILE\" --policy-arn \"$policy_arn\" --version-id \"$version_id\" --query \"PolicyVersion.Document\" --output json"
        policy_document=$(aws iam get-policy-version \
            --profile "$AWS_PROFILE" \
            --policy-arn "$policy_arn" \
            --version-id "$version_id" \
            --query "PolicyVersion.Document" \
            --output json)

        echo_yellow "Policy Document for $policy_arn:" >> iam_passrole_assumerole.txt
        echo "$policy_document" >> iam_passrole_assumerole.txt

        # Check for iam:PassRole permission
        if $check_passrole && echo "$policy_document" | grep -q 'iam:PassRole' && echo "$policy_document" | grep -q 'Resource": "*"'; then
            echo_red "❌ Policy $policy_arn grants iam:PassRole on all resources" >> iam_passrole_assumerole.txt
            echo_red "\nHighlighted Context for iam:PassRole in $policy_arn:\n" >> iam_passrole_assumerole.txt
            echo "$policy_document" | grep --color=always -A 35 -B 5 -e "iam:PassRole"
        else
            echo_green "✅ No wide iam:PassRole permissions found in $policy_arn." >> iam_passrole_assumerole.txt
        fi

        # Check for sts:AssumeRole permission
        if $check_assumerole && echo "$policy_document" | grep -q 'sts:AssumeRole' && echo "$policy_document" | grep -q 'Resource": "*"'; then
            echo_red "❌ Policy $policy_arn grants sts:AssumeRole on all resources" >> iam_passrole_assumerole.txt
            echo_red "\nHighlighted Context for sts:AssumeRole in $policy_arn:\n" >> iam_passrole_assumerole.txt
            echo "$policy_document" | grep --color=always -A 35 -B 5 -e "sts:AssumeRole"
        else
            echo_green "✅ No wide sts:AssumeRole permissions found in $policy_arn." >> iam_passrole_assumerole.txt
        fi
    done

    echo_green "📸 Screenshot taken using Scrot"
    scrot -u -f "IAM_PassRole_AssumeRole.png"
}


################################################################################################
# Function to check KMS key rotation status
check_kms_keys() {
    clear
    echo "Do you want to check KMS key rotation status for:"
    echo "1. All keys"
    echo "2. Selective keys"
    read -p "Please enter your choice (1 or 2): " choice
    identity_info=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query "{Account:Account, Arn:Arn}" --output json)
    account_id=$(echo $identity_info | jq -r .Account)
    arn=$(echo $identity_info | jq -r .Arn)
    echo_blue "ARN: $arn"
    echo "Listing KMS key rotation status:" | tee kms_key_rotation.txt

    if [ "$choice" == "1" ]; then
        echo "Listing all KMS keys and checking rotation status..." > kms_key_rotation.txt
        aws_command_list_keys="aws kms list-keys --profile "$AWS_PROFILE" --query \"Keys[]\" --output text"
        KEY_IDS=$(eval $aws_command_list_keys)
        echo_yellow "Executed: $aws_command_list_keys" | tee -a kms_key_rotation.txt
        
        if [ -z "$KEY_IDS" ]; then
            echo_yellow "❌ No KMS keys found." | tee -a kms_key_rotation.txt
        else
            for KEY_ID in $KEY_IDS; do
                aws_command_get_arn="aws kms describe-key --profile "$AWS_PROFILE" --key-id \"$KEY_ID\" --query \"KeyMetadata.Arn\" --output text"
                KEY_ARN=$(eval $aws_command_get_arn)
                echo_yellow "Executed: $aws_command_get_arn" | tee -a kms_key_rotation.txt
                aws_command_rotation_status="aws kms get-key-rotation-status --profile "$AWS_PROFILE"  --key-id \"$KEY_ID\" --query \"KeyRotationEnabled\" --output text"
                KEY_ROTATION_STATUS=$(eval $aws_command_rotation_status)
                echo_yellow "Executed: $aws_command_rotation_status" | tee -a kms_key_rotation.txt
                if [ "$KEY_ROTATION_STATUS" == "True" ]; then
                    echo_green "✅ Key rotation is ENABLED for KMS key: $KEY_ARN" | tee -a kms_key_rotation.txt
                else
                    echo_red "❌ Key rotation is DISABLED for KMS key: $KEY_ARN" | tee -a kms_key_rotation.txt
                fi
            done
        fi
    elif [ "$choice" == "2" ]; then
        echo "Enter the KMS key IDs to check (one per line). Press Ctrl+D when done:"
        mapfile -t selected_key_ids

        if [ ${#selected_key_ids[@]} -eq 0 ]; then
            echo "❌ No KMS key IDs entered. Exiting..." | tee kms_key_rotation.txt
            return 1
        fi

        echo "Checking rotation status for selected KMS keys..." > kms_key_rotation.txt

        for KEY_ID in "${selected_key_ids[@]}"; do
            aws_command_get_arn="aws kms describe-key --profile "$AWS_PROFILE" --key-id \"$KEY_ID\" --query \"KeyMetadata.Arn\" --output text"
            KEY_ARN=$(eval $aws_command_get_arn)
            echo_yellow "Executed: $aws_command_get_arn" | tee -a kms_key_rotation.txt
            aws_command_rotation_status="aws kms get-key-rotation-status --profile "$AWS_PROFILE" --key-id \"$KEY_ID\" --query \"KeyRotationEnabled\" --output text"
            KEY_ROTATION_STATUS=$(eval $aws_command_rotation_status)
            echo_yellow "Executed: $aws_command_rotation_status" | tee -a kms_key_rotation.txt
            if [ "$KEY_ROTATION_STATUS" == "True" ]; then
                echo_green "✅ Key rotation is ENABLED for KMS key: $KEY_ARN" | tee -a kms_key_rotation.txt
            else
                echo_red "❌ Key rotation is DISABLED for KMS key: $KEY_ARN" | tee -a kms_key_rotation.txt
            fi
        done
    else
        echo "❌ Invalid choice! Exiting script."
        exit 1
    fi

    echo_green "📸 Screenshot taken using Scrot"
    scrot -u -f "IAM_KMS_Key_Rotation.png"
}

# Function to check Secrets Manager secrets and their rotation status
check_secrets_manager() {
    clear
    echo "Do you want to check Secrets Manager secret rotation status for:"
    echo "1. All secrets"
    echo "2. Selective secrets"
    read -p "Please enter your choice (1 or 2): " choice
    identity_info=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query "{Account:Account, Arn:Arn}" --output json)
    account_id=$(echo $identity_info | jq -r .Account)
    arn=$(echo $identity_info | jq -r .Arn)
    echo_blue "ARN: $arn"
    echo "Listing Secrets Manager secret rotation status:" | tee secrets_manager_rotation.txt

    if [ "$choice" == "1" ]; then
        echo "Listing all Secrets Manager secrets and checking rotation status..." > secrets_manager_rotation.txt
        aws_command_list_secrets="aws secretsmanager list-secrets --profile "$AWS_PROFILE" --query \"SecretList[].Name\" --output text"
        SECRET_NAMES=$(eval $aws_command_list_secrets)
        echo_yellow "Executed: $aws_command_list_secrets" | tee -a secrets_manager_rotation.txt

        if [ -z "$SECRET_NAMES" ]; then
            echo "❌ No Secrets Manager secrets found." | tee -a secrets_manager_rotation.txt
        else
            for SECRET_NAME in $SECRET_NAMES; do
                aws_command_rotation_status="aws secretsmanager describe-secret --profile "$AWS_PROFILE" --secret-id \"$SECRET_NAME\" --query \"RotationEnabled\" --output text"
                SECRET_ROTATION_STATUS=$(eval $aws_command_rotation_status)
                echo_yellow "Executed: $aws_command_rotation_status" | tee -a secrets_manager_rotation.txt

                if [ "$SECRET_ROTATION_STATUS" == "True" ]; then
                    echo_green "✅ Rotation is ENABLED for secret: $SECRET_NAME" | tee -a secrets_manager_rotation.txt
                else
                    echo_red "❌ Rotation is DISABLED for secret: $SECRET_NAME" | tee -a secrets_manager_rotation.txt
                fi
            done
        fi
    elif [ "$choice" == "2" ]; then
        echo "Enter the names of the Secrets Manager secrets to check (one per line). Press Ctrl+D when done:"
        mapfile -t selected_secret_names

        if [ ${#selected_secret_names[@]} -eq 0 ]; then
            echo "❌ No secret names entered. Exiting..." | tee secrets_manager_rotation.txt
            return 1
        fi

        echo "Checking rotation status for selected Secrets Manager secrets..." > secrets_manager_rotation.txt

        for SECRET_NAME in "${selected_secret_names[@]}"; do
            aws_command_rotation_status="aws secretsmanager describe-secret --profile "$AWS_PROFILE" --secret-id \"$SECRET_NAME\" --query \"RotationEnabled\" --output text"
            SECRET_ROTATION_STATUS=$(eval $aws_command_rotation_status)
            echo_yellow "Executed: $aws_command_rotation_status" | tee -a secrets_manager_rotation.txt

            if [ "$SECRET_ROTATION_STATUS" == "True" ]; then
                echo_green "✅ Rotation is ENABLED for secret: $SECRET_NAME" | tee -a secrets_manager_rotation.txt
            else
                echo_red "❌ Rotation is DISABLED for secret: $SECRET_NAME" | tee -a secrets_manager_rotation.txt
            fi
        done
    else
        echo "❌ Invalid choice! Exiting script."
        exit 1
    fi

    echo_green "📸 Screenshot taken using Scrot"
    scrot -u -f "SecretsManager_SecretRotation.png"
}



# Function to check IAM key rotation
check_iam_key_rotation() {
    clear
    echo "Do you want to check IAM key rotation for:"
    echo "1. All users"
    echo "2. Selected users"
    read -p "Please enter your choice (1 or 2): " choice

    identity_info=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query "{Account:Account, Arn:Arn}" --output json)
    account_id=$(echo $identity_info | jq -r .Account)
    arn=$(echo $identity_info | jq -r .Arn)
    echo_blue "ARN: $arn"
    echo "Checking IAM Key Rotation..." > iam_key_rotation.txt

    current_date=$(date +%s)

    if [ "$choice" == "1" ]; then
        aws_command_list_users="aws iam list-users --profile \"$AWS_PROFILE\" --query \"Users[].[UserName]\" --output text"
        IAM_USERS=$(eval $aws_command_list_users)
        echo_yellow "Executed: $aws_command_list_users" | tee -a iam_key_rotation.txt

        if [ -z "$IAM_USERS" ]; then
            echo "❌ No IAM users found." | tee -a iam_key_rotation.txt
        else
            for username in $IAM_USERS; do
                aws_command_list_keys="aws iam list-access-keys --profile \"$AWS_PROFILE\" --user-name $username --query \"AccessKeyMetadata[].[UserName,AccessKeyId,CreateDate]\" --output text"
                IAM_KEYS=$(eval $aws_command_list_keys)
                echo_yellow "Executed: $aws_command_list_keys for user $username" | tee -a iam_key_rotation.txt

                while IFS=$'\t' read -r user_name access_key_id create_date; do
                    echo "Processing access key for user $user_name, AccessKeyId: $access_key_id, CreateDate: $create_date" | tee -a iam_key_rotation.txt

                    aws_command_user_arn="aws iam get-user --profile \"$AWS_PROFILE\" --user-name $user_name --query \"User.Arn\" --output text"
                    user_arn=$(eval $aws_command_user_arn)
                    echo_yellow "Executed: $aws_command_user_arn for user $user_name" | tee -a iam_key_rotation.txt

                    key_creation_timestamp=$(date -d "$create_date" +%s)
                    echo_green "CreateDate parsed as timestamp: $key_creation_timestamp" | tee -a iam_key_rotation.txt

                    days_since_creation=$(( (current_date - key_creation_timestamp) / 86400 ))
                    echo_green "Days since creation: $days_since_creation" | tee -a iam_key_rotation.txt

                    if [ "$days_since_creation" -gt 365 ]; then
                        echo_red "⚠️ Warning: IAM Key for user $user_name (Key: $access_key_id, User ARN: $user_arn) has not been rotated for more than 365 days." | tee -a iam_key_rotation.txt
                    fi
                done <<< "$IAM_KEYS"
            done
        fi

    elif [ "$choice" == "2" ]; then
        echo "Enter IAM usernames or AccessKey IDs to check (one per line). Press Ctrl+D when done:"
        mapfile -t selected_entries

        if [ ${#selected_entries[@]} -eq 0 ]; then
            echo "❌ No input provided. Exiting..." | tee iam_key_rotation.txt
            return 1
        fi

        echo "Checking IAM key rotation for selected inputs..." > iam_key_rotation.txt

        for input in "${selected_entries[@]}"; do
            if [[ "$input" =~ ^AKIA[0-9A-Z]{16}$ ]]; then
                # Input is an AccessKey ID
                echo_yellow "Detected AccessKey ID: $input" | tee -a iam_key_rotation.txt

                aws_command_lookup_user="aws iam get-access-key-last-used --access-key-id $input --profile \"$AWS_PROFILE\" --query \"UserName\" --output text"
                username=$(eval $aws_command_lookup_user)
                echo_yellow "Executed: $aws_command_lookup_user, Found username: $username" | tee -a iam_key_rotation.txt

                if [ "$username" == "None" ] || [ -z "$username" ]; then
                    echo_red "❌ Could not find a user for AccessKey: $input" | tee -a iam_key_rotation.txt
                    continue
                fi
            else
                # Input is a username
                username=$input
                echo_yellow "Detected Username: $username" | tee -a iam_key_rotation.txt
            fi

            aws_command_list_keys="aws iam list-access-keys --profile \"$AWS_PROFILE\" --user-name $username --query \"AccessKeyMetadata[].[UserName,AccessKeyId,CreateDate]\" --output text"
            IAM_KEYS=$(eval $aws_command_list_keys)
            echo_yellow "Executed: $aws_command_list_keys for user $username" | tee -a iam_key_rotation.txt

            while IFS=$'\t' read -r user_name access_key_id create_date; do
                echo "Processing access key for user $user_name, AccessKeyId: $access_key_id, CreateDate: $create_date" | tee -a iam_key_rotation.txt

                aws_command_user_arn="aws iam get-user --profile \"$AWS_PROFILE\" --user-name $user_name --query \"User.Arn\" --output text"
                user_arn=$(eval $aws_command_user_arn)
                echo_yellow "Executed: $aws_command_user_arn for user $user_name" | tee -a iam_key_rotation.txt

                key_creation_timestamp=$(date -d "$create_date" +%s)
                echo_green "CreateDate parsed as timestamp: $key_creation_timestamp" | tee -a iam_key_rotation.txt

                days_since_creation=$(( (current_date - key_creation_timestamp) / 86400 ))
                echo_green "Days since creation: $days_since_creation" | tee -a iam_key_rotation.txt

                if [ "$days_since_creation" -gt 365 ]; then
                    echo_red "⚠️ Warning: IAM Key for user $user_name (Key: $access_key_id, User ARN: $user_arn) has not been rotated for more than 365 days." | tee -a iam_key_rotation.txt
                fi
            done <<< "$IAM_KEYS"
        done
    else
        echo "❌ Invalid choice! Exiting script."
        exit 1
    fi

    echo_green "📸 Screenshot taken using Scrot"
    scrot -u -f "IAM_Key_rotation.png"
}



# Function to check for unused IAM keys #need to print ARN
check_iam_key_usage() {
    clear
    echo "Do you want to check IAM key usage for:"
    echo "1. All users"
    echo "2. Selected users (username or AccessKeyId)"
    read -p "Please enter your choice (1 or 2): " choice

    identity_info=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query "{Account:Account, Arn:Arn}" --output json)
    account_id=$(echo "$identity_info" | jq -r .Account)
    arn=$(echo "$identity_info" | jq -r .Arn)
    echo_blue "ARN: $arn"

    echo "Checking IAM Key Usage..." > iam_key_usage.txt
    current_date=$(date +%s)

    if [ "$choice" == "1" ]; then
        aws_command_list_users="aws iam list-users --profile \"$AWS_PROFILE\" --query \"Users[].[UserName]\" --output text"
        IAM_USERS=$(eval $aws_command_list_users)
        echo_yellow "Executed: $aws_command_list_users" | tee -a iam_key_usage.txt

        if [ -z "$IAM_USERS" ]; then
            echo "❌ No IAM users found." | tee -a iam_key_usage.txt
        else
            for username in $IAM_USERS; do
                aws_command_list_keys="aws iam list-access-keys --profile \"$AWS_PROFILE\" --user-name $username --query \"AccessKeyMetadata[].[UserName,AccessKeyId,Status]\" --output text"
                IAM_KEYS=$(eval $aws_command_list_keys)
                echo_yellow "Executed: $aws_command_list_keys for user $username" | tee -a iam_key_usage.txt

                if [ -z "$IAM_KEYS" ]; then
                    echo "❌ No IAM keys found for user $username." | tee -a iam_key_usage.txt
                    continue
                fi

                while IFS=$'\t' read -r user_name access_key_id status; do
                    if [ -z "$access_key_id" ]; then continue; fi

                    echo "🔑 Access Key Status for $access_key_id: $status" | tee -a iam_key_usage.txt

                    aws_command_last_used="aws iam get-access-key-last-used --profile \"$AWS_PROFILE\" --access-key-id \"$access_key_id\" --query \"AccessKeyLastUsed.LastUsedDate\" --output text"
                    last_used=$(eval $aws_command_last_used)
                    echo_yellow "Executed: $aws_command_last_used for key $access_key_id" | tee -a iam_key_usage.txt
                    echo_yellow "Last used date for key $access_key_id: $last_used" | tee -a iam_key_usage.txt

                    if [ "$last_used" == "None" ]; then
                        echo_red "⚠️ Warning: IAM Key for user $user_name (Key: $access_key_id) has not been used." | tee -a iam_key_usage.txt
                    else
                        last_used_timestamp=$(date -d "$last_used" +%s 2>/dev/null)
                        if [ $? -ne 0 ]; then
                            echo "❌ Error: Invalid last used date format for key $access_key_id. Last used: $last_used" | tee -a iam_key_usage.txt
                            continue
                        fi

                        days_since_last_used=$(( (current_date - last_used_timestamp) / 86400 ))
                        echo_yellow "Days since last used for key $access_key_id: $days_since_last_used" | tee -a iam_key_usage.txt

                        if [ "$days_since_last_used" -ge 90 ]; then
                            echo_red "⚠️ Warning: IAM Key for user $user_name (Key: $access_key_id) has not been used for $days_since_last_used days." | tee -a iam_key_usage.txt
                        fi
                    fi
                done <<< "$IAM_KEYS"
            done
        fi

    elif [ "$choice" == "2" ]; then
        echo "Enter IAM usernames or AccessKey IDs to check (one per line). Press Ctrl+D when done:"
        mapfile -t selected_inputs

        if [ ${#selected_inputs[@]} -eq 0 ]; then
            echo "❌ No input provided. Exiting..." | tee iam_key_usage.txt
            return 1
        fi

        echo "Checking IAM key usage for selected inputs..." > iam_key_usage.txt

        for input in "${selected_inputs[@]}"; do
            if [[ "$input" =~ ^AKIA[0-9A-Z]{16}$ ]]; then
                echo_yellow "Detected AccessKey ID: $input" | tee -a iam_key_usage.txt
                aws_command_lookup_user="aws iam get-access-key-last-used --access-key-id $input --profile \"$AWS_PROFILE\" --query \"UserName\" --output text"
                username=$(eval $aws_command_lookup_user)
                echo_yellow "Executed: $aws_command_lookup_user, Found username: $username" | tee -a iam_key_usage.txt

                if [ "$username" == "None" ] || [ -z "$username" ]; then
                    echo_red "❌ Could not find a user for AccessKey: $input" | tee -a iam_key_usage.txt
                    continue
                fi
            else
                username=$input
                echo_yellow "Detected Username: $username" | tee -a iam_key_usage.txt
            fi

            aws_command_list_keys="aws iam list-access-keys --profile \"$AWS_PROFILE\" --user-name $username --query \"AccessKeyMetadata[].[UserName,AccessKeyId,Status]\" --output text"
            IAM_KEYS=$(eval $aws_command_list_keys)
            echo_yellow "Executed: $aws_command_list_keys for user $username" | tee -a iam_key_usage.txt

            if [ -z "$IAM_KEYS" ]; then
                echo "❌ No IAM keys found for user $username." | tee -a iam_key_usage.txt
                continue
            fi

            while IFS=$'\t' read -r user_name access_key_id status; do
                if [ -z "$access_key_id" ]; then continue; fi

                echo "🔑 Access Key Status for $access_key_id: $status" | tee -a iam_key_usage.txt

                aws_command_last_used="aws iam get-access-key-last-used --profile \"$AWS_PROFILE\" --access-key-id \"$access_key_id\" --query \"AccessKeyLastUsed.LastUsedDate\" --output text"
                last_used=$(eval $aws_command_last_used)
                echo_yellow "Executed: $aws_command_last_used for key $access_key_id" | tee -a iam_key_usage.txt
                echo_yellow "Last used date for key $access_key_id: $last_used" | tee -a iam_key_usage.txt

                if [ "$last_used" == "None" ]; then
                    echo_red "⚠️ Warning: IAM Key for user $user_name (Key: $access_key_id) has not been used." | tee -a iam_key_usage.txt
                else
                    last_used_timestamp=$(date -d "$last_used" +%s 2>/dev/null)
                    if [ $? -ne 0 ]; then
                        echo "❌ Error: Invalid last used date format for key $access_key_id. Last used: $last_used" | tee -a iam_key_usage.txt
                        continue
                    fi

                    days_since_last_used=$(( (current_date - last_used_timestamp) / 86400 ))
                    echo_yellow "Days since last used for key $access_key_id: $days_since_last_used" | tee -a iam_key_usage.txt

                    if [ "$days_since_last_used" -ge 90 ]; then
                        echo_red "⚠️ Warning: IAM Key for user $user_name (Key: $access_key_id) has not been used for $days_since_last_used days." | tee -a iam_key_usage.txt
                    fi
                fi
            done <<< "$IAM_KEYS"
        done
    else
        echo "❌ Invalid choice! Exiting script."
        exit 1
    fi

    echo_green "📸 Screenshot taken using Scrot"
    scrot -u -f "IAM_Dormant_Access_keys.png"
}




# Function to check CloudTrail encryption with KMS
check_cloudtrail_encryption() {
    clear
    echo "Do you want to check CloudTrail log encryption for:"
    echo "1. All trails"
    echo "2. Selected trails"
    read -p "Please enter your choice (1 or 2): " choice
    identity_info=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query "{Account:Account, Arn:Arn}" --output json)
    account_id=$(echo $identity_info | jq -r .Account)
    arn=$(echo $identity_info | jq -r .Arn)
    echo_blue "ARN: $arn"
    echo "Checking if CloudTrail logs are encrypted with KMS..." > cloudtrail_encryption.txt

    if [ "$choice" == "1" ]; then
        aws_command_describe_trails="aws cloudtrail describe-trails --profile "$AWS_PROFILE" --query \"trailList[].TrailARN\" --output text"
        trails=$(eval $aws_command_describe_trails)
        echo_yellow "Executed: $aws_command_describe_trails" | tee -a cloudtrail_encryption.txt

        if [ -z "$trails" ]; then
            echo "❌ No CloudTrail logs found." | tee -a cloudtrail_encryption.txt
        else
            for trail in $trails; do
                trail_name=$(echo "$trail" | awk -F'/' '{print $NF}')
                aws_command_get_trail="aws cloudtrail get-trail --profile "$AWS_PROFILE" --name \"$trail_name\" --query \"Trail.KmsKeyId\" --output text"
                kms_key_id=$(eval $aws_command_get_trail)
                echo_yellow "Executed: $aws_command_get_trail" | tee -a cloudtrail_encryption.txt

                if [ "$kms_key_id" != "None" ] && [ -n "$kms_key_id" ]; then
                    echo_green "✅ CloudTrail logs for trail $trail are encrypted with KMS key: $kms_key_id" | tee -a cloudtrail_encryption.txt
                else
                    echo_red "❌ CloudTrail logs for trail $trail are NOT encrypted with KMS" | tee -a cloudtrail_encryption.txt
                fi
            done
        fi
    elif [ "$choice" == "2" ]; then
        echo "Enter the names of the CloudTrail trails to check (one per line). Press Ctrl+D when done:"
        mapfile -t selected_trail_names

        if [ ${#selected_trail_names[@]} -eq 0 ]; then
            echo "❌ No trail names entered. Exiting..." | tee cloudtrail_encryption.txt
            return 1
        fi

        echo "Checking CloudTrail log encryption for selected trails..." > cloudtrail_encryption.txt

        for trail_name in "${selected_trail_names[@]}"; do
            aws_command_get_trail="aws cloudtrail get-trail --profile "$AWS_PROFILE" --name \"$trail_name\" --query \"Trail.KmsKeyId\" --output text"
            kms_key_id=$(eval $aws_command_get_trail)
            echo_yellow "Executed: $aws_command_get_trail" | tee -a cloudtrail_encryption.txt

            if [ "$kms_key_id" != "None" ] && [ -n "$kms_key_id" ]; then
                echo_green "✅ CloudTrail logs for trail $trail_name are encrypted with KMS key: $kms_key_id" | tee -a cloudtrail_encryption.txt
            else
                echo_red "❌ CloudTrail logs for trail $trail_name are NOT encrypted with KMS" | tee -a cloudtrail_encryption.txt
            fi
        done
    else
        echo "❌ Invalid choice! Exiting script."
        exit 1
    fi

    echo_green "📸 Screenshot taken using Scrot"
    scrot -u -f "IAM_CloudtrailLog_Encryption.png"
}



#sensitive info in lambda env variables..
check_sensitiveInfo_lambda() {
    clear
    echo "Do you want to check for sensitive information in:"
    echo "1. All Lambda functions"
    echo "2. Specific Lambda functions"
    read -p "Please enter your choice (1 or 2): " choice
    identity_info=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query "{Account:Account, Arn:Arn}" --output json)
    account_id=$(echo $identity_info | jq -r .Account)
    arn=$(echo $identity_info | jq -r .Arn)
    echo_blue "ARN: $arn"
    echo "Checking if Lambda functions have sensitive information..." > lambda_sensitive_info.txt

    if [ "$choice" == "1" ]; then
        aws_command_list_functions="aws lambda list-functions --profile "$AWS_PROFILE" --query \"Functions[].FunctionName\" --output text"
        lambda_list=$(eval $aws_command_list_functions)
        echo_yellow "Executed: $aws_command_list_functions" | tee -a lambda_sensitive_info.txt

        if [ -z "$lambda_list" ]; then
            echo "❌ No Lambda functions found." | tee -a lambda_sensitive_info.txt
        else
            for function in $lambda_list; do
                echo "Fetching ARN and environment variables for Lambda function: $function" | tee -a lambda_sensitive_info.txt
                aws_command_get_function_config="aws lambda get-function-configuration --profile "$AWS_PROFILE" --function-name \"$function\" --query \"{FunctionArn: FunctionArn, EnvironmentVariables: Environment.Variables}\" --output json"
                function_config=$(eval $aws_command_get_function_config)
                echo_yellow "Executed: $aws_command_get_function_config" | tee -a lambda_sensitive_info.txt
                arn=$(echo "$function_config" | jq -r '.FunctionArn')
                env_vars=$(echo "$function_config" | jq -r '.EnvironmentVariables')

                echo "Lambda ARN: $arn" | tee -a lambda_sensitive_info.txt

                if [[ "$env_vars" != "null" && "$env_vars" != "{}" ]]; then
                    echo_yellow "⚠️ Please review the environment variables for $function: $env_vars" | tee -a lambda_sensitive_info.txt
                else
                    echo_green "✅ No environment variables found for Lambda function: $function" | tee -a lambda_sensitive_info.txt
                fi

                echo "---------------------------------------------" | tee -a lambda_sensitive_info.txt
            done
        fi
    elif [ "$choice" == "2" ]; then
        echo "Enter the names of the Lambda functions to check (one per line). Press Ctrl+D when done:"
        mapfile -t selected_lambda_functions

        if [ ${#selected_lambda_functions[@]} -eq 0 ]; then
            echo "❌ No function names entered. Exiting..." | tee lambda_sensitive_info.txt
            return 1
        fi

        echo "Checking Lambda functions for sensitive information..." > lambda_sensitive_info.txt

        for function in "${selected_lambda_functions[@]}"; do
            echo "Fetching ARN and environment variables for Lambda function: $function" | tee -a lambda_sensitive_info.txt
            aws_command_get_function_config="aws lambda get-function-configuration --profile "$AWS_PROFILE" --function-name \"$function\" --query \"{FunctionArn: FunctionArn, EnvironmentVariables: Environment.Variables}\" --output json"
            function_config=$(eval $aws_command_get_function_config)
            echo_yellow "Executed: $aws_command_get_function_config" | tee -a lambda_sensitive_info.txt
            arn=$(echo "$function_config" | jq -r '.FunctionArn')
            env_vars=$(echo "$function_config" | jq -r '.EnvironmentVariables')

            echo "Lambda ARN: $arn" | tee -a lambda_sensitive_info.txt

            if [[ "$env_vars" != "null" && "$env_vars" != "{}" ]]; then
                echo_yellow "⚠️ Please review the environment variables for $function: $env_vars" | tee -a lambda_sensitive_info.txt
            else
                echo_green "✅ No environment variables found for Lambda function: $function" | tee -a lambda_sensitive_info.txt
            fi

            echo "---------------------------------------------" | tee -a lambda_sensitive_info.txt
        done
    else
        echo "❌ Invalid choice! Exiting script."
        exit 1
    fi

    echo_green "📸 Screenshot taken using Scrot"
    scrot -u -f "SensitiveInfo_Lambda.png"
}


# sensitive info in ec2 instance user data
check_ec2_user_data() {
    clear
    echo "Do you want to check EC2 user data for:"
    echo "1. All running EC2 instances"
    echo "2. Specific EC2 instances (Instance ID or Name)"
    read -p "Please enter your choice (1 or 2): " choice
    identity_info=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query "{Account:Account, Arn:Arn}" --output json)
    account_id=$(echo "$identity_info" | jq -r .Account)
    arn=$(echo "$identity_info" | jq -r .Arn)
    echo_blue "ARN: $arn"
    echo "Checking user data for EC2 instances..." > ec2_user_data.txt
    echo "Checking current role..." | tee -a ec2_user_data.txt
    aws_checkrole="aws sts get-caller-identity"
    checkrole=$(eval $aws_checkrole) >> ec2_user_data.txt

    if [ "$choice" == "1" ]; then
        aws_command_list_instances="aws ec2 describe-instances --profile \"$AWS_PROFILE\" --query \"Reservations[].Instances[].[InstanceId,State.Name]\" --filters \"Name=instance-state-name,Values=running\" --output text"
        instance_ids=$(eval "$aws_command_list_instances")
        echo_yellow "Executed: $aws_command_list_instances" | tee -a ec2_user_data.txt

        if [ -z "$instance_ids" ]; then
            echo "❌ No running EC2 instances found." | tee -a ec2_user_data.txt
        else
            for instance in $instance_ids; do
                instance_id=$(echo "$instance" | awk '{print $1}')
                fetch_user_data "$instance_id"
            done
        fi
    elif [ "$choice" == "2" ]; then
        echo "Paste EC2 Instance IDs or Names (one per line). Press Ctrl+D when done:"
        mapfile -t inputs

        if [ ${#inputs[@]} -eq 0 ]; then
            echo "❌ No input provided. Exiting..." | tee ec2_user_data.txt
            return 1
        fi

        echo "Resolving instance names/IDs..." >> ec2_user_data.txt
        selected_instance_ids=()

        for input in "${inputs[@]}"; do
            if [[ "$input" =~ ^i-[a-z0-9]+$ ]]; then
                selected_instance_ids+=("$input")
            else
                resolved_ids=$(aws ec2 describe-instances \
                    --profile "$AWS_PROFILE" \
                    --filters "Name=tag:Name,Values=$input" \
                    --query "Reservations[].Instances[].InstanceId" \
                    --output text)
                if [ -z "$resolved_ids" ]; then
                    echo_red "❌ Could not find EC2 instance with Name tag: $input" | tee -a ec2_user_data.txt
                else
                    for id in $resolved_ids; do
                        selected_instance_ids+=("$id")
                    done
                fi
            fi
        done

        for instance_id in "${selected_instance_ids[@]}"; do
            fetch_user_data "$instance_id"
        done
    else
        echo "❌ Invalid choice! Exiting script."
        exit 1
    fi

    echo_green "📸 Screenshot taken using Scrot"
    scrot -u -f "EC2_UserData_Check.png"
}

fetch_user_data() {
    local instance_id="$1"

    # Get the "Name" tag for the instance
    instance_name=$(aws ec2 describe-instances \
        --profile "$AWS_PROFILE" \
        --instance-ids "$instance_id" \
        --query "Reservations[0].Instances[0].Tags[?Key=='Name'].Value" \
        --output text)

    if [ -z "$instance_name" ]; then
        instance_name="(No Name)"
    fi

    echo "Fetching user data for instance: $instance_id [$instance_name]" | tee -a ec2_user_data.txt
    aws_command_get_user_data="aws ec2 describe-instance-attribute --profile \"$AWS_PROFILE\" --instance-id \"$instance_id\" --attribute userData --query \"UserData.Value\" --output text"
    user_data=$(eval "$aws_command_get_user_data")
    echo_yellow "Executed: $aws_command_get_user_data" | tee -a ec2_user_data.txt

    if [ "$user_data" != "None" ]; then
        decoded_user_data=$(echo "$user_data" | base64 --decode)
        echo_yellow "⚠️ Please review the user data for instance $instance_id [$instance_name]: $decoded_user_data" | tee -a ec2_user_data.txt
    else
        echo_green "✅ No User Data found for instance $instance_id [$instance_name]." | tee -a ec2_user_data.txt
    fi

    echo "---------------------------------------------" | tee -a ec2_user_data.txt

}



#Security group misconfiguration - egress & ingress Check
check_sg_ingress_egress() {
    clear
    # ===== Color Config =====
    BLUE='\033[1;34m'
    RED='\033[1;31m'
    GREEN='\033[1;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
    
    # ===== Output Functions =====
    echo_blue() { echo -e "${BLUE}$1${NC}"; }
    echo_red() { echo -e "${RED}$1${NC}"; }
    echo_green() { echo -e "${GREEN}$1${NC}"; }
    echo_yellow() { echo -e "${YELLOW}$1${NC}"; }
    
    # ===== AWS Region =====
    region="ap-southeast-1"
    
    # ===== Output Files =====
    timestamp=$(date +%Y%m%d_%H%M%S)
    output_file_csv="security_groups_egress_ingress_check_${timestamp}.csv"
    output_file_txt="security_groups_egress_ingress_check_${timestamp}.txt"
    
    # ===== CSV Header =====
    csv_output="SecurityGroupName,SecurityGroupArn,Protocol,FromPort,ToPort,CIDR,RuleType,Status"
    
    # ===== Intro Message =====
    echo_yellow "Checking security groups for ingress and egress to 0.0.0.0/0 or ::/0 (all ports/protocols)..." | tee "$output_file_txt"
    
    # ===== Get AWS Identity =====
    echo "📌 Executing: aws sts get-caller-identity --region $region" | tee -a "$output_file_txt"
    identity_info=$(aws sts get-caller-identity --region "$region" --output json)
    account_id=$(echo "$identity_info" | jq -r .Account)
    caller_arn=$(echo "$identity_info" | jq -r .Arn)
    echo_blue "🔐 Account ARN: $caller_arn" | tee -a "$output_file_txt"
    
    # ===== User Choice =====
    echo -e "\nChoose an option:"
    echo "1. Check ALL security groups"
    echo "2. Paste specific Security Group IDs or Names (one per line)"
    read -rp "Enter your choice (1 or 2): " choice
    
    selected_sgs=()
    
    if [[ "$choice" == "1" ]]; then
        echo_blue "\n🔍 Fetching all Security Groups..." | tee -a "$output_file_txt"
        echo_yellow "📌 Running: aws ec2 describe-security-groups --query 'SecurityGroups[].GroupId' --output text --region $region" | tee -a "$output_file_txt"
        mapfile -t selected_sgs < <(aws ec2 describe-security-groups --region "$region" --query 'SecurityGroups[].GroupId' --output text)
    elif [[ "$choice" == "2" ]]; then
        echo -e "\nPaste the Security Group IDs or Names (one per line), then press Ctrl+D when done:"
        while IFS= read -r line; do
            trimmed=$(echo "$line" | xargs)
            [[ -z "$trimmed" ]] && continue
    
            if [[ "$trimmed" == sg-* ]]; then
                selected_sgs+=("$trimmed")
            else
                echo_yellow "📌 Resolving name: $trimmed via aws ec2 describe-security-groups --filters Name=group-name,Values=$trimmed" | tee -a "$output_file_txt"
                sg_id=$(aws ec2 describe-security-groups --region "$region" --filters "Name=group-name,Values=$trimmed" --query "SecurityGroups[0].GroupId" --output text 2>/dev/null)
                if [[ "$sg_id" != "None" && -n "$sg_id" ]]; then
                    selected_sgs+=("$sg_id")
                else
                    echo_yellow "⚠️ Could not resolve Security Group name: $trimmed" | tee -a "$output_file_txt"
                fi
            fi
        done < <(cat)
    else
        echo_red "Invalid choice. Exiting." | tee -a "$output_file_txt"
        exit 1
    fi
    
    # ===== Check Each Security Group (Ingress & Egress) =====
    for sg_id in "${selected_sgs[@]}"; do
        [[ -z "$sg_id" ]] && continue
    
        sg_info=$(aws ec2 describe-security-groups --group-id "$sg_id" --region "$region" 2>&1)
        if [[ $? -ne 0 ]]; then
            echo_yellow "⚠️ $sg_id does not exist!" | tee -a "$output_file_txt"
            csv_output+=$'\n'"NA,NA,NA,NA,NA,Security Group Not Found, NA"
            continue
        fi
    
        sg_name=$(echo "$sg_info" | jq -r '.SecurityGroups[0].GroupName')
        arn="arn:aws:ec2:$region:$account_id:security-group/$sg_id"
        
        echo_blue "\n🔎 Checking Security Group: $sg_name ($arn)" | tee -a "$output_file_txt"
        echo_yellow "📌 Running: aws ec2 describe-security-groups --group-id $sg_id --region $region" | tee -a "$output_file_txt"
    
        # Check egress rules
        egress_count=$(echo "$sg_info" | jq '.SecurityGroups[].IpPermissionsEgress | length')
        if [[ "$egress_count" -eq 0 ]]; then
            echo_yellow "⚠️ $sg_name has no egress rules" | tee -a "$output_file_txt"
            csv_output+=$'\n'"$sg_name,$arn,NA,NA,NA,No Egress Rules found, NA"
        else
            mapfile -t egress_rules < <(echo "$sg_info" | jq -c '.SecurityGroups[].IpPermissionsEgress[]')
            for rule in "${egress_rules[@]}"; do
                from_port=$(echo "$rule" | jq -r '.FromPort // 0')
                to_port=$(echo "$rule" | jq -r '.ToPort // 65535')
                ip_protocol=$(echo "$rule" | jq -r 'if .IpProtocol == "-1" then "all" else .IpProtocol end')
                ipv4_cidrs=$(echo "$rule" | jq -r '.IpRanges[]?.CidrIp')
                ipv6_cidrs=$(echo "$rule" | jq -r '.Ipv6Ranges[]?.CidrIpv6')
    
                for cidr in $ipv4_cidrs $ipv6_cidrs; do
                    if [[ "$cidr" == "0.0.0.0/0" || "$cidr" == "::/0" ]]; then
                        echo_red "❌ $sg_name ($arn) | Egress | $ip_protocol | $from_port-$to_port | $cidr" | tee -a "$output_file_txt"
                        csv_output+=$'\n'"$sg_name,$arn,$ip_protocol,$from_port,$to_port,$cidr,Egress,Open"
                    else
                        echo_green " ✅ $sg_name ($arn) | Egress | $ip_protocol | $from_port-$to_port | $cidr" | tee -a "$output_file_txt"
                        csv_output+=$'\n'"$sg_name,$arn,$ip_protocol,$from_port,$to_port,$cidr,Egress,Closed"
                    fi
                done
            done
        fi
    
        # Check ingress rules
        ingress_count=$(echo "$sg_info" | jq '.SecurityGroups[].IpPermissions | length')
        if [[ "$ingress_count" -eq 0 ]]; then
            echo_yellow "⚠️ $sg_name has no ingress rules" | tee -a "$output_file_txt"
            csv_output+=$'\n'"$sg_name,$arn,NA,NA,NA,Ingress No Rules found"
        else
            mapfile -t ingress_rules < <(echo "$sg_info" | jq -c '.SecurityGroups[].IpPermissions[]')
            for rule in "${ingress_rules[@]}"; do
                from_port=$(echo "$rule" | jq -r '.FromPort // 0')
                to_port=$(echo "$rule" | jq -r '.ToPort // 65535')
                ip_protocol=$(echo "$rule" | jq -r 'if .IpProtocol == "-1" then "all" else .IpProtocol end')
                ipv4_cidrs=$(echo "$rule" | jq -r '.IpRanges[]?.CidrIp')
                ipv6_cidrs=$(echo "$rule" | jq -r '.Ipv6Ranges[]?.CidrIpv6')
    
                for cidr in $ipv4_cidrs $ipv6_cidrs; do
                    if [[ "$cidr" == "0.0.0.0/0" || "$cidr" == "::/0" ]]; then
                        echo_red "❌ $sg_name ($arn) | Ingress | $ip_protocol | $from_port-$to_port | $cidr" | tee -a "$output_file_txt"
                        csv_output+=$'\n'"$sg_name,$arn,$ip_protocol,$from_port,$to_port,$cidr,Ingress,Open"
                    else
                        echo_green " ✅ $sg_name ($arn) | Ingress | $ip_protocol | $from_port-$to_port | $cidr" | tee -a "$output_file_txt"
                        csv_output+=$'\n'"$sg_name,$arn,$ip_protocol,$from_port,$to_port,$cidr,Ingress,Closed"
                    fi
                done
            done
        fi
    done
    echo "📸 Screenshot taken using Scrot"
    scrot -u -f "SecurityGroup_egress_ingress.png"
    # ===== Save Output Files =====
    echo "$csv_output" > "$output_file_csv"
    echo_blue "\n📁 CSV output saved to: $output_file_csv" | tee -a "$output_file_txt"
    echo_blue "📝 Text log saved to: $output_file_txt"
}
#Security group misconfiguration - check unused sec groups
check_sg_unused() {
    clear
    output_file="unused_security_groups.txt"
    echo "Do you want to check Security Groups by:"
    echo "1. Security Group ID"
    echo "2. Security Group Name"
    read -p "Please enter your choice (1 or 2): " choice

    echo "Executing: aws sts get-caller-identity --profile \"$AWS_PROFILE\" --query \"{Account:Account, Arn:Arn}\" --output json"
    identity_info=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query "{Account:Account, Arn:Arn}" --output json)
    account_id=$(echo "$identity_info" | jq -r .Account)
    arn=$(echo "$identity_info" | jq -r .Arn)
    echo_blue "ARN: $arn" | tee -a "$output_file"

    echo "Checking for unused security groups..." | tee "$output_file"

    echo "Executing: aws ec2 describe-security-groups --profile \"$AWS_PROFILE\" --query \"SecurityGroups[].[GroupId,GroupName]\" --output text"
    sg_ids=$(aws ec2 describe-security-groups --profile "$AWS_PROFILE" \
             --query "SecurityGroups[].[GroupId,GroupName]" --output text)
    echo "Retrieved list of all security groups." | tee -a "$output_file"

    echo "Executing: aws ec2 describe-instances --profile \"$AWS_PROFILE\" --query \"Reservations[].Instances[].SecurityGroups[].GroupId\" --output text"
    echo "Executing: aws ec2 describe-network-interfaces --profile \"$AWS_PROFILE\" --query \"NetworkInterfaces[].Groups[].GroupId\" --output text"
    used_sg_ids=$( (aws ec2 describe-instances --profile "$AWS_PROFILE" \
                        --query "Reservations[].Instances[].SecurityGroups[].GroupId" --output text
                    aws ec2 describe-network-interfaces --profile "$AWS_PROFILE" \
                        --query "NetworkInterfaces[].Groups[].GroupId" --output text) | sort -u)
    echo "Retrieved list of used security groups." | tee -a "$output_file"

    if [ "$choice" == "1" ]; then
        echo "Enter the Security Group IDs to check (one per line). Press Ctrl+D when done:"
        mapfile -t selected_sgs

        if [ ${#selected_sgs[@]} -eq 0 ]; then
            echo "No Security Group IDs entered. Exiting..." | tee -a "$output_file"
            return 1
        fi

        for sg_id in "${selected_sgs[@]}"; do
            echo "Checking Security Group ID: $sg_id" | tee -a "$output_file"

            if ! echo "$used_sg_ids" | grep -qw "$sg_id"; then
                echo_yellow "❌ Security group $sg_id is UNUSED." | tee -a "$output_file"
            else
                echo_green "✅ Security group $sg_id is in use." | tee -a "$output_file"
            fi
            echo "---------------------------------------------" | tee -a "$output_file"
        done

    elif [ "$choice" == "2" ]; then
        echo "Enter the Security Group Names to check (one per line). Press Ctrl+D when done:"
        mapfile -t selected_sg_names

        if [ ${#selected_sg_names[@]} -eq 0 ]; then
            echo "No Security Group Names entered. Exiting..." | tee -a "$output_file"
            return 1
        fi

        for sg_name in "${selected_sg_names[@]}"; do
            echo "Checking Security Group Name: $sg_name" | tee -a "$output_file"
            echo "Searching for Group ID using awk..."
            sg_id=$(echo "$sg_ids" | awk -v name="$sg_name" '$2 == name {print $1}')

            if [ -z "$sg_id" ]; then
                echo_yellow "⚠️ Security Group with name $sg_name not found." | tee -a "$output_file"
                continue
            fi

            if ! echo "$used_sg_ids" | grep -qw "$sg_id"; then
                echo_red "❌ Security group $sg_name ($sg_id) is UNUSED." | tee -a "$output_file"
            else
                echo_green "✅ Security group $sg_name ($sg_id) is in use." | tee -a "$output_file"
            fi
            echo "---------------------------------------------" | tee -a "$output_file"
        done

    else
        echo "Invalid choice! Exiting script."
        exit 1
    fi

    echo "Check completed. Results saved in $output_file."
    echo "📸 Screenshot taken using Scrot"
    scrot -u -f "SecurityGroup_Misconfiguration_UnusedGroups.png"
}


#to check if load balacers allow cleartext communication
check_lb() {
    clear
    output_file="load_balancers_http_check.txt"
    echo "Do you want to check Load Balancers by:"
    echo "1. Load Balancer ARN"
    echo "2. Load Balancer Name"
    read -p "Please enter your choice (1 or 2): " choice
    identity_info=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query "{Account:Account, Arn:Arn}" --output json)
    account_id=$(echo $identity_info | jq -r .Account)
    arn=$(echo $identity_info | jq -r .Arn) | tee -a $output_file
    echo_blue "ARN: $arn"
    echo "Checking for Load Balancers allowing cleartext (HTTP) communication..." > $output_file
    
    aws_command_lb_arns="aws elbv2 describe-load-balancers --profile \"$AWS_PROFILE\" --query \"LoadBalancers[].[LoadBalancerArn, LoadBalancerName]\" --output text"
    lb_arns=$(eval $aws_command_lb_arns)
    echo_yellow "Executed: $aws_command_lb_arns" | tee -a $output_file
    
    if [ "$choice" == "1" ]; then
        echo "Enter the Load Balancer ARNs to check (one per line). Press Ctrl+D when done:"
        mapfile -t selected_lb_arns

        if [ ${#selected_lb_arns[@]} -eq 0 ]; then
            echo "❌ No Load Balancer ARNs entered. Exiting..." | tee $output_file
            return 1
        fi

        for lb_arn in "${selected_lb_arns[@]}"; do
            check_single_lb "$lb_arn"
        done

    elif [ "$choice" == "2" ]; then
        echo "Enter the Load Balancer Names to check (one per line). Press Ctrl+D when done:"
        mapfile -t selected_lb_names

        if [ ${#selected_lb_names[@]} -eq 0 ]; then
            echo "❌ No Load Balancer Names entered. Exiting..." | tee $output_file
            return 1
        fi

        for lb_name in "${selected_lb_names[@]}"; do
            lb_arn=$(echo "$lb_arns" | grep -w "$lb_name" | awk '{print $1}')
            
            if [ -z "$lb_arn" ]; then
                echo "❌ Load Balancer with name $lb_name not found." | tee -a $output_file
                continue
            fi
            
            check_single_lb "$lb_arn" "$lb_name"
        done
    else
        echo "❌ Invalid choice! Exiting script." | tee $output_file
        exit 1
    fi

    echo "✔️ Check completed. Results saved in $output_file."
    echo_green "📸 Screenshot taken using Scrot"
    scrot -u -f "LoadBalancer_Cleartext_HTTP_Communication.png"
}

check_single_lb() {
    lb_arn="$1"
    lb_name="${2:-$lb_arn}"

    echo "Checking Load Balancer: $lb_name (ARN: $lb_arn)" | tee -a $output_file
    listeners=$(aws elbv2 describe-listeners --profile "$AWS_PROFILE" --load-balancer-arn "$lb_arn" --query "Listeners[].[ListenerArn, Port, Protocol]" --output text)
    
    echo "Listeners for Load Balancer $lb_name:" | tee -a $output_file
    echo "$listeners" | while read -r listener_arn port protocol; do
        echo_yellow "Port: $port, Protocol: $protocol" | tee -a $output_file
        
        if [[ "$port" == "80" && "$protocol" == "HTTP" ]]; then
            echo "🔍 Checking listener rules for port 80..." | tee -a $output_file
            rules=$(aws elbv2 describe-rules --profile "$AWS_PROFILE" --listener-arn "$listener_arn" --query "Rules[*].Actions[*].RedirectConfig" --output json)
            
            if echo "$rules" | jq -e '.[][] | select(.Protocol == "HTTPS")' > /dev/null; then
                echo_green "✅ HTTP on port 80 is redirected to HTTPS" | tee -a $output_file
            else
                echo_red "❌ Load Balancer $lb_name allows cleartext HTTP traffic on port 80 WITHOUT regrp_type" | tee -a $output_file
            fi
        fi
    done

    echo "---------------------------------------------" | tee -a $output_file
}


#check if "securestring" is being used or not in ssm and secrets manager.. if not being used, then its ok to report as the secrets will be in plaintext
check_secrets() {
    clear
    echo "Do you want to check SecureString status for:"
    echo "1. All secrets (SSM + Secrets Manager)"
    echo "2. Selected secrets/parameters only"
    read -p "Please enter your choice (1 or 2): " choice

    identity_info=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query "{Account:Account, Arn:Arn}" --output json)
    account_id=$(echo "$identity_info" | jq -r .Account)
    arn=$(echo "$identity_info" | jq -r .Arn)
    echo_blue "ARN: $arn"
    echo "Checking SecureString status in SSM Parameter Store and AWS Secrets Manager..." > securestrings_and_secrets.txt

    if [ "$choice" == "1" ]; then
        # Check all SSM parameters
        aws_command_ssm_parameters="aws ssm describe-parameters --profile \"$AWS_PROFILE\" --query \"Parameters[].Name\" --output text"
        parameters=$(eval $aws_command_ssm_parameters)
        echo_yellow "Executed: $aws_command_ssm_parameters" | tee -a securestrings_and_secrets.txt

        echo "SSM Parameter Store SecureString Check:" | tee -a securestrings_and_secrets.txt
        for parameter in $parameters; do
            aws_command_get_param="aws ssm get-parameter --name \"$parameter\" --profile \"$AWS_PROFILE\" --query \"Parameter.Type\" --output text"
            param_type=$(eval $aws_command_get_param)
            echo_yellow "Executed: $aws_command_get_param" | tee -a securestrings_and_secrets.txt

            if [ "$param_type" == "SecureString" ]; then
                echo_green "✅ SSM Parameter $parameter is of type SecureString" | tee -a securestrings_and_secrets.txt
            else
                echo_red "❌ SSM Parameter $parameter is NOT SecureString, please report" | tee -a securestrings_and_secrets.txt
            fi
        done

        # Check all Secrets Manager secrets
        aws_command_secrets="aws secretsmanager list-secrets --profile \"$AWS_PROFILE\" --query \"SecretList[].Name\" --output text"
        secrets=$(eval $aws_command_secrets)
        echo_yellow "Executed: $aws_command_secrets" | tee -a securestrings_and_secrets.txt

        echo "Secrets Manager SecureString Check:" | tee -a securestrings_and_secrets.txt
        for secret in $secrets; do
            aws_command_describe_secret="aws secretsmanager describe-secret --profile \"$AWS_PROFILE\" --secret-id \"$secret\" --query \"SecretString\" --output text"
            secret_value=$(eval $aws_command_describe_secret)
            echo_yellow "Executed: $aws_command_describe_secret" | tee -a securestrings_and_secrets.txt

            if [ "$secret_value" != "None" ]; then
                echo_green "✅ Secret $secret is a SecureString (SecretString is present)" | tee -a securestrings_and_secrets.txt
            else
                echo_red "❌ Secret $secret is NOT a SecureString (SecretString not found), please report" | tee -a securestrings_and_secrets.txt
            fi
        done

    elif [ "$choice" == "2" ]; then
        echo "Enter names of SSM parameters or Secrets Manager secrets to check (one per line). Press Ctrl+D when done:"
        mapfile -t selected_items

        if [ ${#selected_items[@]} -eq 0 ]; then
            echo "❌ No names entered. Exiting..." | tee -a securestrings_and_secrets.txt
            return 1
        fi

        echo "Checking SecureString status for selected inputs..." > securestrings_and_secrets.txt

        for item in "${selected_items[@]}"; do
            echo_yellow "Checking if $item exists in SSM..." | tee -a securestrings_and_secrets.txt
            aws_command_check_ssm="aws ssm get-parameter --name \"$item\" --profile \"$AWS_PROFILE\" --query \"Parameter.Type\" --output text 2>/dev/null"
            param_type=$(eval $aws_command_check_ssm)

            if [ $? -eq 0 ]; then
                echo_yellow "Executed: $aws_command_check_ssm" | tee -a securestrings_and_secrets.txt
                if [ "$param_type" == "SecureString" ]; then
                    echo_green "✅ SSM Parameter $item is of type SecureString" | tee -a securestrings_and_secrets.txt
                else
                    echo_red "❌ SSM Parameter $item is NOT SecureString, please report" | tee -a securestrings_and_secrets.txt
                fi
                continue
            fi

            echo_yellow "Checking if $item exists in Secrets Manager..." | tee -a securestrings_and_secrets.txt
            aws_command_check_secret="aws secretsmanager describe-secret --profile \"$AWS_PROFILE\" --secret-id \"$item\" --query \"SecretString\" --output text 2>/dev/null"
            secret_value=$(eval $aws_command_check_secret)

            if [ $? -eq 0 ]; then
                echo_yellow "Executed: $aws_command_check_secret" | tee -a securestrings_and_secrets.txt
                if [ "$secret_value" != "None" ]; then
                    echo_green "✅ Secret $item is a SecureString (SecretString is present)" | tee -a securestrings_and_secrets.txt
                else
                    echo_red "❌ Secret $item is NOT a SecureString (SecretString not found), please report" | tee -a securestrings_and_secrets.txt
                fi
            else
                echo_red "❌ $item not found in either SSM or Secrets Manager" | tee -a securestrings_and_secrets.txt
            fi
        done

    else
        echo "❌ Invalid choice! Exiting script."
        exit 1
    fi

    echo_green "✔️ Screenshot taken using Scrot"
    scrot -u -f "Secrets_Check_SecureString.png"
}


#Code to generate aws console link instead of using Pacu
aws_console() {
    clear
    echo "🔐 Choose input method:"
    echo "1. Load from AWS credentials profile"
    echo "2. Enter credentials manually"
    read -p "👉 Enter choice [1 or 2]: " choice

    if [ "$choice" == "1" ]; then
        if [ -z "$AWS_PROFILE" ]; then
            echo_red "❌ --profile not provided. Please run the script with --profile <name>."
            exit 1
        fi
    
        echo_blue "🔍 Loading credentials from profile: $AWS_PROFILE"
        ACCESS_KEY_ID=$(aws configure get aws_access_key_id --profile "$AWS_PROFILE")
        SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key --profile "$AWS_PROFILE")
        SESSION_TOKEN=$(aws configure get aws_session_token --profile "$AWS_PROFILE")
    else
        echo "📝 Enter AWS credentials:"
        read -p "🔑 AWS Access Key ID: " ACCESS_KEY_ID
        read -p "🔐 AWS Secret Access Key: " SECRET_ACCESS_KEY
        read -p "🪪 AWS Session Token: " SESSION_TOKEN
    fi
    
    if [ -z "$ACCESS_KEY_ID" ] || [ -z "$SECRET_ACCESS_KEY" ] || [ -z "$SESSION_TOKEN" ]; then
        echo_yellow "❌ Missing credentials. Exiting."
        exit 1
    fi
    
    echo_blue "🛠️  Generating session JSON..."
    SESSION_JSON=$(jq -n --arg sessionId "$ACCESS_KEY_ID" --arg sessionKey "$SECRET_ACCESS_KEY" --arg sessionToken "$SESSION_TOKEN" \
      '{sessionId: $sessionId, sessionKey: $sessionKey, sessionToken: $sessionToken}')
    
    echo_blue "🌐 Requesting AWS sign-in token..."
    SIGNIN_TOKEN=$(curl -s -G --data-urlencode "Action=getSigninToken" --data-urlencode "Session=$SESSION_JSON" \
      "https://signin.aws.amazon.com/federation" | jq -r .SigninToken)
    
    URL="https://signin.aws.amazon.com/federation?Action=login&Issuer=CLI&Destination=https://console.aws.amazon.com/&SigninToken=$SIGNIN_TOKEN"
    
    echo ""
    echo_blue "✅ AWS Console Federation URL generated!"
    echo_green "🌐 Use the below URL in your web browser:"
    echo "$URL"
}

#Code to run Pacu modules
run_pacu() {
    clear

    if [ -z "$AWS_PROFILE" ]; then
        echo_red "❌ --profile is required for Pacu. Please specify it with --profile <name>."
        exit 1
    fi

    PROFILES=$(aws configure list-profiles)
    if ! echo "$AWS_PROFILES" | grep -q "^$AWS_PROFILE$"; then
        echo_red "❌ Profile '$AWS_PROFILE' not found. Please check with 'aws configure list-profiles'."
        exit 1
    fi

    read -p "🌐 Enter AWS region (default: ap-southeast-1): " REGION
    REGION=${REGION:-ap-southeast-1}

    SESSION_NAME="${AWS_PROFILE}-session"
    echo_blue "🔧 Creating new Pacu session: $SESSION_NAME"
    pacu --new-session "$SESSION_NAME"

    echo_blue "🔑 Importing credentials from profile: $AWS_PROFILE"
    pacu --import-keys "$AWS_PROFILE" --session "$SESSION_NAME"

    MODULES=(
        iam__enum_permissions
        iam__enum_users_roles_policies_groups
        iam__enum_roles
        iam__enum_users
        iam__privesc_scan
        iam__get_credential_report
		ec2__enum
        ebs__enum_snapshots_unauth
        acm__enum
        apigateway__enum
        cloudformation__download_data
        codebuild__enum
        dynamodb__enum
        ebs__enum_volumes_snapshots
        ec2__download_userdata
        ecr__enum
        ecs__enum
        ecs__enum_task_def
        eks__enum
        glue__enum
        lambda__enum
        lightsail__enum
        organizations__enum
        rds__enum
        rds__enum_snapshots
        route53__enum
        sns__enum
        systemsmanager__download_parameters
        transfer_family__enum
        secrets__enum
    )

    for MODULE in "${MODULES[@]}"; do
        echo_blue "⚙️ Running module: $MODULE"
		echo_red "Be in a lookput for any prompts where you might have to do Y/N"
		#mkdir -p "$HOME/.local/share/pacu/$SESSION_NAME/downloads/ssm_parameters"
		###uncomment the above line if Pacu gives an error like: FileNotFoundError: [Errno 2] No such file or directory: '/home/kali/.local/share/pacu/default-session/downloads/ssm_parameters/ap-southeast-1.txt'
                #change your path if required.
        pacu --module-name "$MODULE" --set-regions "$REGION" --exec --session "$SESSION_NAME"
    done

    echo_green "🎉 All Pacu modules executed. Review the session logs for details."
}

cloud_tools(){
    clear
    #Tool Availability Check
    #check_tool() {
    #  if ! command -v "$1" &>/dev/null; then
    #    echo_red "❌ $1 is not installed or not in PATH. Please install it first."
    #    exit 1
    #  fi
    #}
    echo_red "Please make sure that ScoutSuite, Cloudfox, Cloudsplaining, Prowler are installed or are added in your PATH env variable"
    #ScoutSuite
    run_scoutsuite() {
      echo_blue "🔍 Running ScoutSuite..."
      #check_tool "scoutsuite"
      export AWS_PROFILE="$AWS_PROFILE"
      scout aws --no-browser
      if [ $? -ne 0 ]; then
        echo_red "❌ ScoutSuite failed."
        exit 1
      fi
      echo_green "✅ ScoutSuite complete!"
    }
    
    #Prowler
    run_prowler() {
      echo_blue "🔍 Running Prowler..."
      #check_tool "prowler"
      export AWS_PROFILE="$AWS_PROFILE"
      prowler -M csv,json,html -p "$AWS_PROFILE" -S
      if [ $? -ne 0 ]; then
        echo_red "❌ Prowler failed."
        exit 1
      fi
      echo_green "✅ Prowler reports (CSV, JSON, HTML) saved in current directory! Please review the output."
    }
    
    #CloudFox
    run_cloudfox() {
      echo_blue "🔍 Running CloudFox..."
      #check_tool "cloudfox"
      export AWS_PROFILE="$AWS_PROFILE"
      cloudfox aws --profile "$AWS_PROFILE" --output current-dir
      if [ $? -ne 0 ]; then
        echo_red "❌ CloudFox failed."
        exit 1
      fi
      echo_green "✅ CloudFox complete! Please review the output"
    }
    
    #CloudSplaining
    run_cloudsplaining() {
      echo_blue "🔍 Running CloudSplaining..."
      #check_tool "cloudsplaining"
      export AWS_PROFILE="$AWS_PROFILE"
    
      IAM_JSON="iam-data-$AWS_PROFILE.json"
      OUTPUT_DIR="cloudsplaining-report-$AWS_PROFILE"
    
      echo_blue "📥 Downloading IAM policies..."
      cloudsplaining download --profile "$AWS_PROFILE" --output "$IAM_JSON"
      if [ $? -ne 0 ]; then
        echo_red "❌ Failed to download IAM data."
        exit 1
      fi
    
      echo_blue "🔎 Scanning IAM policies..."
      cloudsplaining scan -i "$IAM_JSON" --output "$OUTPUT_DIR"
      if [ $? -ne 0 ]; then
        echo_red "❌ CloudSplaining scan failed."
        exit 1
      fi
    
      echo_green "✅ CloudSplaining complete!"
      echo "📁 Please review the results saved in: $OUTPUT_DIR/"
    }
	run_scoutsuite
    run_prowler
    run_cloudfox
    run_cloudsplaining
}

#main
main() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
	    case "$1" in
            --profile)
                shift
                AWS_PROFILE="$1"
                ;;
            -i|--imdsv2)
                check_imdsv2
                ;;
            -s|--s3-security)
                check_s3_security
                ;;
            -p|--iam-policies)
                check_iam_policies
                ;;
            -r|--assume-pass-role)
                check_assume_pass_role
                ;;
            -k|--kms-keys)
                check_kms_keys
                ;;
            -m|--secrets-manager)
                check_secrets_manager
                ;;
            -y|--iam-key-rotation)
                check_iam_key_rotation
                ;;
            -u|--iam-key-usage)
                check_iam_key_usage
                ;;
            -c|--cloudtrail-encryption)
                check_cloudtrail_encryption
                ;;
			-l|--sensitiveInfo_lambda)
			    check_sensitiveInfo_lambda
				;;
			-e|--ec2_userdata)
			    check_ec2_user_data
				;;
			-sg1|--secGroups1)
			    check_sg_ingress_egress
				;;
			-sg2|--secGroups2)
			    check_sg_unused
				;;
			-lb|--loadbalancer)
                check_lb
				;;
			-sm|--secrets)
			    check_secrets
				;;
		    -cl|--consoleLink)
			    aws_console
				;;
			-pu|--pacu)
			    run_pacu
				;;
			-ct|--cloudtool)
			    cloud_tools
				;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done
}

main "$@"
