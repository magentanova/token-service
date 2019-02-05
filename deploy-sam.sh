cd sam-app
sam build --use-container 
aws s3 mb s3://rentalated-lambda-functions
sam package \
    --output-template-file packaged.yaml \
    --s3-bucket rentalated-lambda-functions
sam deploy \
    --template-file packaged.yaml \
    --stack-name sam-app \
    --capabilities CAPABILITY_IAM \
    --region us-east-2