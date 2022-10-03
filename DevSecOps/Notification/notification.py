import json, boto3,requests
import logging

logger = logging.getLogger()
#logger.setLevel(logging.DEBUG)
logger.setLevel(logging.INFO)

#Function에서 지원되는 source:detail-type 을 사전 정의
AWSSupportEvents = ['aws.codecommit:CodeCommit Repository State Change', 'aws.codebuild:CodeBuild Build State Change', 'aws.ecr:ECR Image Scan', 'aws.codepipeline:CodePipeline Action Execution State Change']


#AWS Event정보
def getCodeCommitDetails(originsnsMsg,event_region):
    
    event_repositoryName = originsnsMsg["repositoryName"]
    event_refname = originsnsMsg["referenceFullName"]
    
    retDict = { "imogi" : ":pencil2:" }
    retDict["url"] = \
        "https://"+ event_region + ".console.aws.amazon.com/codesuite/codecommit/repositories/" \
        + event_repositoryName + "/browse/" + event_refname + "?region=" + event_region
    retDict["msg"] =  \
             "*CodeCommit 레파지토리 브랜치가 변경 되었습니다. ( 이벤트 : " + originsnsMsg["event"] + ")*\n" + \
             "Repository: " + originsnsMsg["repositoryName"] + "\n" + \
             "Branch: " + originsnsMsg["referenceName"] + "\n" + \
             "commitId: " + originsnsMsg["commitId"] + "\n"
             
    logger.info("이벤트상세 : %s ",retDict["msg"]  )
    return retDict
    
#AWS Event정보
def getCodePipelineDetails(originsnsMsg,event_region):
    
    event_pipelineName = originsnsMsg["pipeline"]
    event_executionID = originsnsMsg["execution-id"]
    event_state = originsnsMsg["state"]
    event_type = originsnsMsg["type"]
    
    # if event_type == "Approval":
    #     return None
    
    retDict = { "imogi" : ":pencil2:" }
    # https://ap-northeast-2.console.aws.amazon.com/codesuite/codepipeline/pipelines/eks-tf-plan/view?region=ap-northeast-2
    # https://ap-northeast-2.console.aws.amazon.com/codesuite/codepipeline/pipelines/eks-tf-plan/executions/2c26a7ce-d88d-4451-9d9f-6c7a969712cd/timeline?region=ap-northeast-2
    # retDict["url"] = \
    #     "https://"+ event_region + ".console.aws.amazon.com/codesuite/codepipeline/pipelines/" \
    #     + event_pipelineName + "/view?region=" + event_region
    retDict["url"] = \
        "https://"+ event_region + ".console.aws.amazon.com/codesuite/codepipeline/pipelines/" \
        + event_pipelineName + "/executions/" + event_executionID + "?region=" + event_region
    retDict["msg"] =  \
         "*CodePipeline Approval 상태가 변경되었습니다. ( state : " + event_state + ")*\n" + \
         "pipeline: " + event_pipelineName + "\n" + \
         "State: " + event_state + "\n" + \
         "executionID: " + event_executionID + "\n"
         
    logger.info("이벤트상세 : %s ",retDict["msg"]  )
    return retDict

#AWS Event정보-CodeBuild
def getCodebuildDetails (originsnsMsg,event_region):
    
    event_projectName = originsnsMsg["project-name"]
    event_build = originsnsMsg["build-id"].split("/")[1]
    
    
    retDict = { "imogi" : ":mega:" }
    retDict["url"] = \
            "https://"+ event_region + ".console.aws.amazon.com/codesuite/codebuild/projects/" \
            + event_projectName + "/build/" + event_build + "?region=" + event_region
    retDict["msg"] =  \
             "*CodeBuild 상태가 변경 되었습니다. ( 상태 : " + originsnsMsg["build-status"] + ")*\n" + \
             "CodeBuild Project Name: " + originsnsMsg["project-name"] + "\n"
    
    logger.info("이벤트상세 : %s ", retDict["msg"]  )
    return retDict


#AWS Event정보-ECR Scan
def getECRScanDetails (originsnsMsg,event_region):
    
    event_repositoryname = originsnsMsg["repository-name"]
    event_scanstatus = originsnsMsg["scan-status"]
    event_imagedigest = originsnsMsg["image-digest"]
    event_imagetags = originsnsMsg["image-tags"][0]
    event_imageId={ 'imageDigest': event_imagedigest, 'imageTag': event_imagetags }
    
    #ECR Privavte Image only ( Public인 경우는 ecr-public임.)
    ecrclient = boto3.client('ecr')
    response = ecrclient.describe_repositories( repositoryNames=[event_repositoryname] )
    
    event_accountid = response["repositories"][0]["registryId"]
    #print(response["repositories"][0]["repositoryUri"])
    #print(response["repositories"][0]["repositoryArn"])

    respscan= ecrclient.describe_image_scan_findings( repositoryName=event_repositoryname, imageId=event_imageId )
    event_finding = str(respscan["imageScanFindings"]['findingSeverityCounts'])

    
    if event_scanstatus == "COMPLETE":
        retDict = { "imogi" : ":white_check_mark:" }
    else:
        retDict = { "imogi" : ":warning:" }
    retDict["url"] = \
            "https://"+ event_region + ".console.aws.amazon.com/ecr/repositories/private/" \
            + event_accountid + "/" \
            + event_repositoryname + "/image/" + event_imagedigest + "/scan-results/?region=" + event_region
    retDict["msg"] =  \
             "*ECR Code Scan 결과 상태 : " + event_scanstatus + "*\n" + \
             "Image Repository: " + event_repositoryname + "\n" + \
             "Image digest: " + event_imagedigest + "\n" + \
             "Image Tag: " + event_imagetags + "\n" + \
             "Finding severity counts: *"+ event_finding + "*\n"         # MEDIUM: 12, LOW: 2

    logger.info("이벤트상세 : %s ", retDict["msg"]  )
    return retDict
    

#AWS Event정보-Sonarqube
def getSonarqubeDetails (originsnsMsg):
    
    retDict = { "imogi" : ":information_source:" }
    retDict["url"] = originsnsMsg["sonarlink"]
    retDict["msg"] = "*" + originsnsMsg["Result"] + "*\n"
    
    logger.info("이벤트상세 : %s ", retDict["msg"]  )
    return retDict
    
    
def unsupportedDetails():
    retDict = { "imogi" : ":warning:" }
    retDict["url"] = "https://console.aws.com"
    retDict["msg"] = "* 해당 이벤트는 지원 되지 않습니다.*\n"
    
    logger.info("이벤트상세 : %s ", retDict["msg"]  )
    return retDict
  
#AWS Code Series 및 Custom Event를 처리
def lambda_handler(event, context): 
    
    # Slack 주소
    secretclient = boto3.client('secretsmanager')
    secretdict = json.loads(secretclient.get_secret_value( SecretId='SonarQube' ).get('SecretString'))
    webhook_url = secretdict['slack_webhook']
    event_imogi = ":information_source:"
    
    # AWS Event와 Custom Event의 동시 적용
    try:
        print("AWS Events Try")
        eventMsg = event['Records'][0]['Sns']['Message']
        snsMsg = json.loads(eventMsg)
    except Exception:
        print("AWS Events Message")
        eventMsg = json.dumps(event['Records'][0]['Sns']['Message'])
        snsMsg = json.loads(eventMsg)
    
    logger.info (snsMsg)
    event_source = snsMsg["source"]
    event_detailtype = snsMsg["detail-type"]
    eventCheckStr = event_source + ":" + event_detailtype

    #환경변수확인 Flag
    logger.debug("====================================================================")
    logger.debug("Start of Local Env Variables")
    all_variables = dir()
    for name in all_variables:
        if not name.startswith('__'):
            logger.debug("%s : %s ", name, eval(name))  
            #print(name , type(eval(name)) , eval(name))  
    logger.debug("End of Local Env Variables")
        
        
    logger.info("====================================================================")
    logger.info("이벤트정보 : %s , %s ",event_source , event_detailtype  )

    
    #Detail Event 정보 추출
    if (eventCheckStr in AWSSupportEvents):
        #AWS 공식 이벤트 처리
        event_account = snsMsg["account"]
        event_region = snsMsg["region"]
        event_resource = snsMsg["resources"]
        
        event_header = event_detailtype + " | " + event_region + " | " + event_account
        logger.info("이벤트제목 : %s",event_header  )
        
        #Detail Event 정보 추출
        if event_source == "aws.codecommit":
            event_detailDict = getCodeCommitDetails (snsMsg["detail"],event_region)
        elif event_source ==  "aws.codebuild":
            event_detailDict = getCodebuildDetails (snsMsg["detail"],event_region)
        elif event_source ==  "aws.ecr" and event_detailtype == "ECR Image Scan":
            event_detailDict = getECRScanDetails (snsMsg["detail"],event_region)  
        elif event_source == "aws.codepipeline":
            event_detailDict = getCodePipelineDetails (snsMsg["detail"], event_region)
            if event_detailDict == None:
                return None
            
    
    #Custom Event정보
    else:
        if event_detailtype == "Sonarqube Scan":
            event_header = "Sonarqube Scan 결과 "
            event_detailDict = getSonarqubeDetails (snsMsg)   
        else:
            event_header = "이벤트 미지원 "
            event_detailDict = unsupportedDetails() 
            logger.info()
    

    slack_data = slack_data = {
    "blocks": [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": event_detailDict["imogi"] +" <"+ event_detailDict["url"] + "|" + event_header + ".>"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text":  event_detailDict["msg"]
            }
        }
      ]
    }

    response = requests.post(
        webhook_url, data=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )
    if response.status_code != 200:
        raise ValueError(
            'Request to slack returned an error %s, the response is:\n%s'
            % (response.status_code, response.text)
    )