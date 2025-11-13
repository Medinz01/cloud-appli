Cloud Deployer: A Secure, Multi-Tenant PaaS for Automated AWS Deployments

1. Abstract

A high-level summary of the entire project.

Problem: The high complexity and steep learning curve of modern cloud (IaaS) deployment for individual developers.

Gap: The trade-off between the simplicity of PaaS (e.g., Heroku) and the power/cost-efficiency of IaaS (e.g., AWS).

Solution: This project, "Cloud Deployer," a web-based "Control Plane" that provides a simple UI to securely orchestrate the automated containerization and deployment of applications (the "Data Plane") into a user's own AWS account.

Core Technologies: Next.js (Frontend), Node.js (Backend), MySQL, Docker, Terraform, and AWS (IAM, ECS, Fargate).

Result: A functional prototype capable of taking a user's source code and, with zero cloud expertise required from the user, deploying it as a scalable, load-balanced application with a public URL.

2. Introduction

Set the stage for the reader.

2.1. The Problem with Modern Cloud Deployment: Detail the "wall of complexity" developers face (VPCs, IAM, security, container orchestration).

2.2. Existing Solutions (PaaS vs. IaaS):

PaaS (e.g., Heroku, Vercel): Pros (ease of use) and Cons (high cost, vendor lock-in, lack of control).

IaaS (e.g., AWS, GCP): Pros (power, flexibility, cost) and Cons (high complexity, security risks).

2.3. Our Proposed Solution: A Hybrid PaaS:

Introduce the "Cloud Deployer" concept: a platform that provides the easy user experience of a PaaS but deploys all resources directly into the user's own AWS account.

Benefits: Full user ownership, cost transparency, and no vendor lock-in.

2.4. Project Objectives & Scope:

Objective 1: Securely manage multiple user accounts (multi-tenancy).

Objective 2: Automate the containerization of a user's web application.

Objective 3: Use Infrastructure as Code (Terraform) to provision all necessary AWS resources.

Objective 4: Provide a clean, simple web interface for the entire process.

3. System Architecture & Design

The high-level blueprint of the system.

3.1. The Control Plane vs. The Data Plane: This is the most important architectural concept.

Control Plane: Our application (Frontend, Backend, Database). Its job is to orchestrate.

Data Plane: The user's AWS account. This is where their deployed resources (VPC, ALB, containers) live.

3.2. Core Security Model: The IAM Cross-Account Role

Explain why we chose this: Why it's superior and more secure than asking users for their Secret Access Keys.

Trust Policy: How the user's role "trusts" our backend's IAM user.

Permissions Policy: The "leash" defining what our backend is allowed to do.

3.3. The Onboarding Workflow (The "Handshake"):

Diagram the flow: User registers -> Clicks "Launch Stack" -> Redirected to AWS -> Creates CloudDeployerRole (from our S3 template) -> Copies ARN -> Saves ARN in our database.

3.4. The Deployment Workflow (The Core Logic):

High-level diagram: User clicks "Deploy" -> Backend assumes role -> Creates ECR repo -> Builds & Pushes Docker image -> Runs terraform apply -> Returns URL.

4. Implementation Details

The "how-to" section with specific technical details.

4.1. The Control Plane: Our Application

Frontend: Next.js, AuthContext.js (JWT management), file upload UI.

Backend: Node.js/Express.js, API endpoints (/api/register, /api/login, /api/deployments).

Database: MySQL schema (users table, deployments table).

4.2. The Secure Bridge: Assuming the Role

Detail the sts:AssumeRole call using @aws-sdk/client-sts.

Explain how the temporary credentials from this call are used to power all subsequent AWS actions.

4.3. The Deployment Engine

Step 1: Workspace Preparation: Using multer, fs-extra, and extract-zip.

Step 2: Automated Containerization:

The getDockerfileContent function (dynamically creating a Dockerfile).

The runCommandStream function to execute docker build and docker push.

Step 3: Infrastructure as Code (IaC):

The tf-ecs-fargate-webapp Terraform module explained (VPC, Subnets, ALB, ECS, Fargate, VPC Endpoints).

The runTerraformCommand function to execute terraform apply and terraform destroy.

Step 4: State Management:

Saving the deployment (app_url, tf_workspace_path) to the deployments table.

4.4. The Destroy Workflow

Explaining the DELETE /api/deployments/:appName endpoint.

How it retrieves the tf_workspace_path from the database and runs terraform destroy.

5. Results & Challenges

What happened, and what did we learn?

5.1. Successful Deployment:

Show the final success log from your backend terminal (the one with the URL).

Include screenshots of the user's AWS account:

The ECR repository with the pushed image.

The ECS cluster with the service in a RUNNING state.

The EC2 Load Balancer with a public DNS name.

The running application in a web browser.

5.2. Key Challenges & Debugging: This is a critical section.

Challenge 1: IAM Permissions: The iterative debugging of the CloudDeployerRole (e.g., missing ecr:CreateRepository, ec2:DescribeVpcAttribute). This demonstrates the "least privilege" principle.

Challenge 2: The Service-Linked Role: The AWSServiceRoleForECS error, and the solution to make the Terraform module idempotent (null_resource with aws iam create-service-linked-role).

Challenge 3: Environment Mismatches: The node:18 vs. node:20 Docker build failure.

Challenge 4: Failed Deploy Cleanup: The "VPC is in use" problem and the required manual deletion order (ECS Service -> ALB -> Endpoints -> VPC).

Challenge 5: Local Windows Environment: The Access is denied errors, fixed by running the backend as an Administrator.

6. Conclusion & Future Work

6.1. Conclusion: Summarize the project. We successfully built a functional, end-to-end, multi-tenant PaaS that automates the deployment of containerized applications into a user's own AWS account, solving the core problem of balancing simplicity with power and ownership.

6.2. Future Work: What's next?

Real-time Frontend Logs: Streaming the docker and terraform output to the user's browser using WebSockets.

Dashboard & State: A proper dashboard page that lists all active deployments from the deployments table, with "Destroy" buttons for each.

More Frameworks: Add support for other app types (Go, Ruby, plain Dockerfile).

Database Provisioning: Allow users to check a box to also deploy a managed RDS database with their application.

Custom Domains: Add a feature to link a custom domain to the deployed ALB.

Git Integration: Deploying directly from a Git repository instead of a .zip file.

7. Appendices

Appendix A: Full Source Code for server.js

Appendix B: Full Source Code for ecs.tf

Appendix C: Full Source Code for cross-account-role.yml

Appendix D: Database Schema (SQL CREATE TABLE statements)