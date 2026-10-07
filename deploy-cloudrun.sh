#!/bin/bash
# Cloud Run deployment script for the Intune (Microsoft Graph) API simulator.
# Usage: bash deploy-cloudrun.sh
# Demo day: MIN_INSTANCES=1 bash deploy-cloudrun.sh  (avoids a cold start that would reset the fleet)
#
# Service access (who can invoke the Cloud Run service) is NOT configured by this script:
# set it manually according to your GCP project policy. XSIAM must be able to reach the URL.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ -f .env ]; then
  set -a; . ./.env; set +a
fi

PROJECT_ID=${GCP_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}
REGION="${GCP_REGION:-europe-west1}"
SERVICE_NAME="${CLOUD_RUN_SERVICE:-intune-simulator}"
REPO_NAME="intune-simulator"
MIN_INSTANCES="${MIN_INSTANCES:-0}"

SIM_TENANT_ID="${SIM_TENANT_ID:-00000000-0000-0000-0000-000000000000}"
SIM_CLIENT_ID="${SIM_CLIENT_ID:-11111111-1111-1111-1111-111111111111}"
SIM_CLIENT_SECRET="${SIM_CLIENT_SECRET:-change-me-intune-simulator-secret}"
PATCH_DURATION_SECONDS="${PATCH_DURATION_SECONDS:-150}"

echo -e "${GREEN}=== Cloud Run deployment - Intune Simulator ===${NC}\n"
echo -e "${YELLOW}Project:${NC} $PROJECT_ID"
echo -e "${YELLOW}Region:${NC}  $REGION"
echo -e "${YELLOW}Service:${NC} $SERVICE_NAME"
echo ""

echo -e "${YELLOW}[1/5] Enabling APIs...${NC}"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com --project=$PROJECT_ID
echo -e "${GREEN}OK - APIs enabled${NC}\n"

echo -e "${YELLOW}[2/5] Configuring Artifact Registry...${NC}"
REPO_EXISTS=$(gcloud artifacts repositories list --location=$REGION --project=$PROJECT_ID --filter="name:$REPO_NAME" --format="value(name)" 2>/dev/null)
if [ -z "$REPO_EXISTS" ]; then
  gcloud artifacts repositories create $REPO_NAME --repository-format=docker --location=$REGION --project=$PROJECT_ID --description="Intune simulator images" --quiet
  echo -e "${GREEN}OK - Repository created${NC}"
else
  echo -e "${GREEN}OK - Repository already exists${NC}"
fi
echo ""

echo -e "${YELLOW}[3/5] Checking Dockerfile...${NC}"
[ -f "deployment/Dockerfile" ] || { echo -e "${RED}ERROR: Dockerfile not found${NC}"; exit 1; }
echo -e "${GREEN}OK${NC}\n"

echo -e "${YELLOW}[4/5] Building Docker image...${NC}"
gcloud builds submit --config cloudbuild.yaml --project=$PROJECT_ID --substitutions=_REGION=$REGION
IMAGE_PATH="${REGION}-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/intune-simulator:latest"
echo -e "${GREEN}OK - Image built: $IMAGE_PATH${NC}\n"

echo -e "${YELLOW}[5/5] Deploying to Cloud Run...${NC}"
# max-instances 1: the simulated fleet lives in memory and must not be split across instances
gcloud run deploy $SERVICE_NAME \
  --image $IMAGE_PATH --platform managed --region $REGION --project=$PROJECT_ID \
  --memory 512Mi --cpu 1 --timeout 300 \
  --min-instances $MIN_INSTANCES --max-instances 1 \
  --set-env-vars "SIM_TENANT_ID=${SIM_TENANT_ID},SIM_CLIENT_ID=${SIM_CLIENT_ID},SIM_CLIENT_SECRET=${SIM_CLIENT_SECRET},PATCH_DURATION_SECONDS=${PATCH_DURATION_SECONDS},DEBUG=False"

SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region $REGION --project=$PROJECT_ID --format 'value(status.url)')

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}Deployment successful!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${YELLOW}Service URL:${NC} ${GREEN}$SERVICE_URL${NC}"
echo -e "${YELLOW}Console:${NC}     ${GREEN}$SERVICE_URL/console${NC}"
echo -e "${YELLOW}Reminder:${NC}    configure service access manually (XSIAM must reach this URL)."
echo ""
echo "1. Health: curl $SERVICE_URL/health"
echo ""
echo -e "${YELLOW}XSIAM configuration (integration 'Intune (Demo)'):${NC}"
echo "   Server URL:         $SERVICE_URL"
echo "   Tenant ID:          ${SIM_TENANT_ID}"
echo "   Application ID:     ${SIM_CLIENT_ID}"
echo "   Application Secret: (SIM_CLIENT_SECRET)"
echo ""
