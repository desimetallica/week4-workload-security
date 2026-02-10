import boto3
from botocore.exceptions import ClientError
import sys

PROFILE = "bob"
REGION = "eu-south-1"  # change if needed


def session():
    return boto3.Session(profile_name=PROFILE, region_name=REGION)


def ec2_recon(sess):
    print("[*] EC2 reconnaissance")
    ec2 = sess.client("ec2")

    try:
        # Equivalent AWS CLI: aws ec2 describe-vpcs
        vpcs = ec2.describe_vpcs()["Vpcs"]
        print(f"    [+] VPCs: {len(vpcs)} found")
        for vpc in vpcs:
            print(f"        - VPC ID: {vpc.get('VpcId')}, CIDR: {vpc.get('CidrBlock')}, State: {vpc.get('State')}")

        # Equivalent AWS CLI: aws ec2 describe-security-groups
        # Security Groups (firewall rules)
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        print(f"    [+] Security Groups: {len(sgs)} found (firewall rules)")
        for sg in sgs:
            print(f"        - SG ID: {sg.get('GroupId')}, Name: {sg.get('GroupName')}, VPC: {sg.get('VpcId')}")
            # Ingress rules
            for rule in sg.get('IpPermissions', []):
                proto = rule.get('IpProtocol')
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                ip_ranges = ', '.join([ip.get('CidrIp', '') for ip in rule.get('IpRanges', [])])
                print(f"            [Ingress] Protocol: {proto}, Ports: {from_port}-{to_port}, CIDRs: {ip_ranges}")
            # Egress rules
            for rule in sg.get('IpPermissionsEgress', []):
                proto = rule.get('IpProtocol')
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                ip_ranges = ', '.join([ip.get('CidrIp', '') for ip in rule.get('IpRanges', [])])
                print(f"            [Egress] Protocol: {proto}, Ports: {from_port}-{to_port}, CIDRs: {ip_ranges}")

        # Equivalent AWS CLI: aws ec2 describe-network-acls
        # Network ACLs (stateless firewall)
        acls = ec2.describe_network_acls()["NetworkAcls"]
        print(f"    [+] Network ACLs: {len(acls)} found")
        for acl in acls:
            print(f"        - ACL ID: {acl.get('NetworkAclId')}, VPC: {acl.get('VpcId')}, IsDefault: {acl.get('IsDefault')}")
            for entry in acl.get('Entries', []):
                rule_type = 'Egress' if entry.get('Egress') else 'Ingress'
                action = entry.get('RuleAction')
                proto = entry.get('Protocol')
                cidr = entry.get('CidrBlock')
                port_range = entry.get('PortRange', {})
                from_port = port_range.get('From')
                to_port = port_range.get('To')
                print(f"            [{rule_type}] Rule #{entry.get('RuleNumber')}: {action}, Protocol: {proto}, Ports: {from_port}-{to_port}, CIDR: {cidr}")
    except ClientError as e:
        print(f"[!] EC2 error: {e.response['Error']['Code']}")


def s3_recon(sess):
    print("[*] S3 reconnaissance")
    s3 = sess.client("s3")

    try:
        # Equivalent AWS CLI: aws s3api list-buckets
        buckets = s3.list_buckets()["Buckets"]
        for b in buckets:
            name = b["Name"]
            print(f"    [+] Bucket: {name}")

            # List a few objects
            try:
                # Equivalent AWS CLI: aws s3api list-objects-v2 --bucket <bucket-name> --max-keys 5
                s3.list_objects_v2(Bucket=name, MaxKeys=5)
            except ClientError:
                pass

            # Get bucket ACL
            try:
                # Equivalent AWS CLI: aws s3api get-bucket-acl --bucket <bucket-name>
                acl = s3.get_bucket_acl(Bucket=name)
                grants = acl.get('Grants', [])
                for g in grants:
                    grantee = g.get('Grantee', {})
                    perm = g.get('Permission')
                    print(f"        - ACL: {grantee.get('Type')} {grantee.get('URI', grantee.get('ID', ''))} => {perm}")
            except ClientError:
                pass

            # Get bucket policy
            try:
                # Equivalent AWS CLI: aws s3api get-bucket-policy --bucket <bucket-name>
                policy = s3.get_bucket_policy(Bucket=name)
                print(f"        - Policy: {policy['Policy'][:100]}... (truncated)")
            except ClientError:
                print(f"        - No bucket policy or access denied.")

            # Get bucket encryption
            try:
                # Equivalent AWS CLI: aws s3api get-bucket-encryption --bucket <bucket-name>
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                for rule in rules:
                    algo = rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')
                    print(f"        - Encryption: {algo}")
            except ClientError:
                print(f"        - No encryption or access denied.")

            # Get public access block
            try:
                # Equivalent AWS CLI: aws s3api get-public-access-block --bucket <bucket-name>
                pab = s3.get_public_access_block(Bucket=name)
                pab_cfg = pab.get('PublicAccessBlockConfiguration', {})
                print(f"        - Public Access Block: {pab_cfg}")
            except ClientError:
                print(f"        - No public access block or access denied.")

    except ClientError as e:
        print(f"[!] S3 error: {e.response['Error']['Code']}")


def dynamodb_recon(sess):
    print("[*] DynamoDB reconnaissance")
    ddb = sess.client("dynamodb")

    try:
        # Equivalent AWS CLI: aws dynamodb list-tables
        tables = ddb.list_tables()["TableNames"]
        for t in tables:
            print(f"    [+] Table: {t}")
            try:
                # Equivalent AWS CLI: aws dynamodb describe-table --table-name <table>
                ddb.describe_table(TableName=t)
                # Equivalent AWS CLI: aws dynamodb scan --table-name <table> --limit 1
                ddb.scan(TableName=t, Limit=1)
            except ClientError:
                pass

    except ClientError as e:
        print(f"[!] DynamoDB error: {e.response['Error']['Code']}")


def lambda_recon(sess):
    print("[*] Lambda reconnaissance")
    lam = sess.client("lambda")

    try:
        # Equivalent AWS CLI: aws lambda list-functions
        funcs = lam.list_functions()["Functions"]
        for f in funcs:
            name = f["FunctionName"]
            print(f"    [+] Lambda: {name}")

            try:
                # Equivalent AWS CLI: aws lambda get-function --function-name <name>
                lam.get_function(FunctionName=name)
            except ClientError:
                pass

            try:
                # Equivalent AWS CLI: aws lambda invoke --function-name <name> --invocation-type DryRun outfile.txt
                lam.invoke(FunctionName=name, InvocationType="DryRun")
            except ClientError:
                pass

    except ClientError as e:
        print(f"[!] Lambda error: {e.response['Error']['Code']}")


def main():
    print(f"[*] Starting AWS recon using profile '{PROFILE}'")
    sess = session()

    ec2_recon(sess)
    s3_recon(sess)
    dynamodb_recon(sess)
    lambda_recon(sess)

    print("[*] Recon complete")


if __name__ == "__main__":
    main()
