#!/bin/bash
image_tag=$1 
repository_name=$2
# Wait until scan is completed
aws ecr wait image-scan-complete --repository-name "$repository_name"  --image-id imageTag="$image_tag"
if [ $(echo $?) -eq 0 ]; then
    scan_results=$(aws ecr describe-image-scan-findings --repository-name "$repository_name" --image-id imageTag="$image_tag"| jq '.imageScanFindings.findingSeverityCounts')
    critical=$(echo $scan_results | jq '.CRITICAL')
    high=$(echo $scan_results | jq '.HIGH')
    if [ "$critical" != null ] || [ "$high" != null ]; then
        echo "Docker image contains vulnerabilities at CRITICAL or HIGH level"
        echo $scan_results
        # If the pushed image has CRITICAL or HIGH findings, you may add deleting process. (Optional)
        # aws ecr batch-delete-image --repository-name "$repository_name" --image-ids imageTag="$image_tag"
        # exit 1
      fi
fi