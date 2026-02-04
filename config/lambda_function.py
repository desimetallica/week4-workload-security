import boto3

def lambda_handler(event, context):
    iam = boto3.client('iam')
    iam.attach_user_policy(
        UserName="bob",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )
    return {'statusCode': 200, 'body': 'Policy attached successfully'}