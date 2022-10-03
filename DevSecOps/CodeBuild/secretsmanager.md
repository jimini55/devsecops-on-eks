# AWS SecretsManager Examples

## Soanrqube Credentials

```
version: 0.2

env:
  secrets-manager:
    SONAR_URL: "SonarQube:sonarqube_url"
    SONAR_TOKEN: "SonarQube:sonarqube_token"
phases:
  install:
    runtime-versions:
      java: corretto17
  
  pre_build:
      commands:
      # Environment & Parameter Sourcing   
      - echo pre_build stage
      - SONAR_PROJECT_NAME=${repositoryName}.${BranchName}
      - echo Sonar Project key info - $SONAR_PROJECT_NAME
```

## Slack webhook
```
client = boto3.client('secretsmanager')
secretdict = json.loads(client.get_secret_value( SecretId='SonarQube' ).get('SecretString'))
webhook_url = secretdict['slack_webhook']
```

