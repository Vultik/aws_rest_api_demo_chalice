# aws_rest_api_demo_chalice

Copyright (c) 2021, programmingwithalex

## General Info

Deploy a `AWS lambda` function zip package as an `AWS API Gateway` that connects to a `AWS dynamodb`. The `dynamodb` database is publicly accessible.

No `AWS VPC` is used in this tutorial as it requires a `VPC Endpoint` in order to access the `dynamodb` tables from the `AWS lambda` function and a `VPC` can't be assigned to a `dynamodb` table. Instead the use of a `VPC` will be omitted until a later video series that uses an `AWS RDS Postgres` database instead of the `dynamodb` tables. `VPC` assignment for the `chalice` app can be automated via the `chalice` configuration files.

## Need to Do

* [Issue #1810](https://github.com/aws/chalice/issues/1810) - customize AuthResponse message when `jwt` token is expired
  * currently response is `"Message": "User is not authorized to access this resource"` for all unauthorized requests

## Chalice Commands

* `chalice local --port=8001` - run locally for testing
* `chalice deploy --stage dev`
* `chalice delete --stage dev`

---

## Chalice Settings

### Custom Route53 Domain

To deploy with custom domain name (`Route53` or otherwise) an additional step is needed after `chalice deploy` by following [the AWS instructions here](https://aws.amazon.com/blogs/developer/configuring-custom-domain-names-with-aws-chalice/) to create the `Route53` A record. A sample using powershell:

```powershell
aws route53 change-resource-record-sets --hosted-zone-id Z0*******49 --change-batch `
'{
  \"Changes\": [
    {
      \"Action\": \"CREATE\",
      \"ResourceRecordSet\": {
        \"Name\": \"chalice-dev.programmingwithalex.com\",
        \"Type\": \"A\",
        \"AliasTarget\": {
          \"DNSName\": \"d-0****f.execute-api.us-east-1.amazonaws.com\",
          \"HostedZoneId\": \"Z1********\",
          \"EvaluateTargetHealth\": false
        }
      }
    }
  ]
}'
```

### Secrets

Secrets that have to be used in `chalice` application are accessed using **AWS Secrets Manager**. Secrets include:

* `JWT_SECRET_KEY`

Secrets that are only needed for authentication for the CD pipeline are stored as secrets in the GitHub repo:

* `AWS_ACCESS_KEY_ID`
* `AWS_SECRET_ACCESS_KEY`

### Restrict Access to API

* **`jwt` tokens** - authorization token is returned on login and is used for accessing any additional endpoints
  * token expires after 30 minutes

* **IP Address** - To [allow only specific IP addresses to access API Gateway](https://aws.amazon.com/premiumsupport/knowledge-center/api-gateway-resource-policy-access/), a `Resource Policy` must be created for the API. This is done in `chalice` via the `api_gateway_policy_file` flag that points to a json file with the `Resource Policy` definition. The json file is located in the `.chalice` directory.

### Configurations

#### IAM Role

Resource access for role assigned to `lambda` function is defined in `.chalice\policy-dev.json`. The role has access to the following resources:

* `dyanmodb` tables for users and todos
* `secrets manager` for `JWT_SECRET_KEY`
* `logs` for AWS

#### API Configurations

Specification for the API and stage-specific settings are found in `.chalice\config.json`.

---

## HTTP Requests

1. POST request to /login with username and password. Receive authorization token.
2. Make GET request with header: [Authorization]

## Sample Deployment Commands

```powershell
chalice local --port=8001
chalice deploy --stage dev
chalice deploy --stage prod
chalice delete --stage dev
chalice delete --stage prod
```

## Continuous Deployment (CD) Pipeline

Manual GitHub Action that will deploy application to AWS. Found in `.github\workflows\chalice-deploy.yml`.

## Reference Guides

1. [AWS chalice workshop](https://github.com/aws-samples/chalice-workshop)

2. [Chalice `config.json` parameters](https://aws.github.io/chalice/topics/configfile)

3. [Structuring project files](https://aws.github.io/chalice/topics/packaging.html)

## Feature Comparison to Zappa

### Pros

* developed by AWS team
* supports local testing with native `chalice` command
* more stables deployments
* built-in lambda function authenticator with `jwt` tokens

### Cons

* no `docker` container support for deployment to AWS lambda, only zip packages
  * forces using layers for non-native python packages (ex: `pandas`)
* deployment with custom domain (`Rout53` or otherwise) requires manual creation of `Route53` A record
  * no native `chalice` command
