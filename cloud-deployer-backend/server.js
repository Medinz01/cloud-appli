// 1. Import Dependencies
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();
const jose = require('jose');
const multer = require('multer');
const fs = require('fs-extra');
const path = require('path');
const extract = require('extract-zip');
const { spawn } = require('child_process');
const { STSClient, AssumeRoleCommand } = require('@aws-sdk/client-sts');
const { ECRClient, CreateRepositoryCommand, DescribeRepositoriesCommand } = require('@aws-sdk/client-ecr');

// 2. Initialize App & Middleware
const app = express();
const PORT = process.env.PORT || 8080;
app.use(cors({ origin: 'http://localhost:3000' }));
app.use(express.json());

// 3. Database, JWT, Multer Config
const dbPool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'cloud_deployer'
});

if (!process.env.JWT_SECRET_KEY || process.env.JWT_SECRET_KEY.length < 32) {
    throw new Error('JWT_SECRET_KEY is not set in .env or is too short (min 32 chars).');
}
const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET_KEY);
const JWT_ALG = 'HS256';

const upload = multer({ dest: path.join(__dirname, 'uploads') });

// --- HELPER FUNCTIONS ---

const protectRoute = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ message: 'Unauthorized: No token provided.' });
        
        const { payload } = await jose.jwtVerify(token, JWT_SECRET, {
            algorithms: [JWT_ALG]
        });
        req.user = payload;
        next();
    } catch (error) {
        console.error("Token verification failed:", error.message);
        return res.status(401).json({ message: 'Unauthorized: Invalid token.' });
    }
};

const runCommandStream = (command, options) => {
    return new Promise((resolve, reject) => {
        console.log(`\n--- Running command: ${command} ---\n`);
        const child = spawn(command, { ...options, shell: true });
        child.stdout.on('data', (data) => process.stdout.write(data.toString()));
        child.stderr.on('data', (data) => process.stderr.write(data.toString()));
        child.on('close', (code) => {
            if (code !== 0) {
                console.error(`\n--- Command failed with exit code: ${code} ---\n`);
                return reject(new Error(`Command failed: ${command}`));
            }
            console.log(`\n--- Command finished successfully ---\n`);
            resolve();
        });
        child.on('error', (err) => {
            console.error(`\n--- Failed to start command: ${command} ---\n`, err);
            reject(err);
        });
    });
};

const runTerraformCommand = (command, workspacePath, variables, awsEnv) => {
    return new Promise((resolve, reject) => {
        const varArgs = Object.entries(variables).map(([key, value]) => `-var=${key}=${value}`);
        // Only use -json for apply, not for destroy
        const args = (command === 'apply') 
            ? [command, '-auto-approve', '-json', ...varArgs]
            : [command, '-auto-approve', ...varArgs];
        
        const terraform = spawn('terraform', args, { cwd: workspacePath, env: { ...process.env, ...awsEnv } });

        let output = '';
        terraform.stdout.on('data', (data) => {
            // Log to console in real-time
            process.stdout.write(data.toString());
            // Store for parsing
            output += data.toString();
        });
        terraform.stderr.on('data', (data) => process.stderr.write(data.toString()));

        terraform.on('close', (code) => {
            if (code !== 0) return reject(new Error(`Terraform ${command} failed.`));
            if (command === 'destroy') return resolve();

            // --- THIS IS THE FIX ---
            // Find the JSON output line with "@type": "outputs"
            // --- parse structured logs for outputs, with fallback ---
            const outputLines = output.split(/\r?\n/).filter(l => l.trim() !== '');
            let foundOutputs = null;

            for (const line of outputLines.reverse()) {
            try {
                const jsonLine = JSON.parse(line);
                const evtType = jsonLine.type || jsonLine['@type']; // handle both
                if (evtType === 'outputs' && jsonLine.outputs) {
                foundOutputs = jsonLine.outputs;
                break;
                }
            } catch (_) { /* ignore non-JSON lines */ }
            }

            if (foundOutputs) {
            return resolve(foundOutputs);
            }

            // Fallback: run `terraform output -json` which is the most reliable way
            const tfOutput = spawn('terraform', ['output', '-json'], { cwd: workspacePath, env: { ...process.env, ...awsEnv } });
            let buf = '';
            tfOutput.stdout.on('data', (d) => { buf += d.toString(); });
            tfOutput.stderr.on('data', (d) => process.stderr.write(d.toString()));
            tfOutput.on('close', (code2) => {
            if (code2 !== 0) return reject(new Error("Could not parse Terraform outputs."));
            try {
                const outputsJson = JSON.parse(buf);
                return resolve(outputsJson);
            } catch (e) {
                return reject(new Error("Could not parse Terraform outputs."));
            }
            });
        });
    });
};

const getDockerfileContent = (appType) => {
    if (appType === 'nextjs') {
        return `
# Build Stage
FROM node:20-alpine AS builder 
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Production Stage
FROM node:20-alpine AS runner 
WORKDIR /app
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs
COPY --from=builder /app/package*.json ./
RUN npm install --omit=dev
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
USER nextjs
EXPOSE 3000
CMD ["npm", "start"]
        `;
    }
    if (appType === 'python-flask') {
        return `
# Build Stage
FROM python:3.9-slim-bullseye AS builder
WORKDIR /app
RUN useradd --create-home appuser
USER appuser
RUN python -m venv /home/appuser/venv
ENV PATH="/home/appuser/venv/bin:$PATH"
COPY --chown=appuser:appuser requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production Stage
FROM python:3.9-slim-bullseye AS runner
WORKDIR /app
RUN useradd --create-home appuser
USER appuser
ENV PATH="/home/appuser/venv/bin:$PATH"
COPY --from=builder /home/appuser/venv /home/appuser/venv
COPY --chown=appuser:appuser app.py .
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
        `;
    }
    throw new Error('Unsupported application type.');
};

const findProjectRoot = async (workspaceDir, appType) => {
    const rootIdentifier = appType === 'nextjs' ? 'package.json' : 'requirements.txt';
    const entries = await fs.readdir(workspaceDir, { withFileTypes: true });

    for (const entry of entries) {
        if (entry.isDirectory()) {
            const potentialRoot = path.join(workspaceDir, entry.name);
            try {
                const files = await fs.readdir(potentialRoot);
                if (files.includes(rootIdentifier)) {
                    return potentialRoot;
                }
            } catch (e) {
                console.warn(`Could not read directory ${potentialRoot}, skipping.`);
            }
        }
    }
    
    if (entries.some(entry => entry.name === rootIdentifier)) {
      return workspaceDir;
    }

    throw new Error(`Could not find project root containing '${rootIdentifier}'.`);
};

// --- API ENDPOINTS ---

app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Email and password are required.' });
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        await dbPool.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, passwordHash]);
        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Email already exists.' });
        res.status(500).json({ message: 'An error occurred during registration.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const [rows] = await dbPool.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = rows[0];
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        const token = await new jose.SignJWT({ userId: user.id, email: user.email })
            .setProtectedHeader({ alg: JWT_ALG }).setIssuedAt().setExpirationTime('2h').sign(JWT_SECRET);
        res.status(200).json({ message: 'Login successful!', token });
    } catch (error) {
        res.status(500).json({ message: 'An error occurred during login.' });
    }
});

app.post('/api/account/connect-aws', protectRoute, async (req, res) => {
    const { roleArn } = req.body;
    const { userId } = req.user;
    await dbPool.execute('UPDATE users SET aws_role_arn = ? WHERE id = ?', [roleArn, userId]);
    res.status(200).json({ message: 'AWS account connected successfully!' });
});

app.post('/api/deployments', protectRoute, upload.single('projectFile'), async (req, res) => {
    const { appName, appType } = req.body;
    const containerPort = appType === 'nextjs' ? 3000 : 8080;
    const projectFile = req.file;
    const user = req.user;
    
    const deploymentId = `${Date.now()}-${appName}`;
    const workspaceDir = path.join(__dirname, 'deployments', deploymentId);
    const tfWorkspaceDir = path.join(__dirname, 'tf_workspaces', deploymentId);
    let projectRoot;

    try {
        console.log(`[${appName}] 1. Preparing workspace...`);
        await fs.ensureDir(workspaceDir);
        await extract(projectFile.path, { dir: workspaceDir });
        projectRoot = await findProjectRoot(workspaceDir, appType);
        const dockerfileContent = getDockerfileContent(appType);
        await fs.writeFile(path.join(projectRoot, 'Dockerfile'), dockerfileContent);

        console.log(`[${appName}] 2. Assuming user's AWS role...`);
        const [rows] = await dbPool.execute('SELECT aws_role_arn FROM users WHERE id = ?', [user.userId]);
        const userRoleArn = rows[0]?.aws_role_arn;
        if (!userRoleArn) throw new Error("User's AWS account is not connected.");
        
        const stsClient = new STSClient({ region: process.env.AWS_REGION });
        const { Credentials } = await stsClient.send(new AssumeRoleCommand({ RoleArn: userRoleArn, RoleSessionName: `CloudDeployerSession-${deploymentId}` }));
        const awsEnvVars = {
            AWS_ACCESS_KEY_ID: Credentials.AccessKeyId,
            AWS_SECRET_ACCESS_KEY: Credentials.SecretAccessKey,
            AWS_SESSION_TOKEN: Credentials.SessionToken,
        };

        console.log(`[${appName}] 3. Containerizing application...`);
        const region = process.env.AWS_REGION;
        const accountId = userRoleArn.split(':')[4];
        const ecrRepoUri = `${accountId}.dkr.ecr.${region}.amazonaws.com/${appName}`;
        
        const userEcrClient = new ECRClient({ region, credentials: { accessKeyId: Credentials.AccessKeyId, secretAccessKey: Credentials.SecretAccessKey, sessionToken: Credentials.SessionToken } });
        try {
            await userEcrClient.send(new DescribeRepositoriesCommand({ repositoryNames: [appName] }));
        } catch (e) {
            if (e.name === 'RepositoryNotFoundException') await userEcrClient.send(new CreateRepositoryCommand({ repositoryName: appName }));
            else throw e;
        }

        const dockerLoginCmd = `aws ecr get-login-password --region ${region} | docker login --username AWS --password-stdin ${accountId}.dkr.ecr.${region}.amazonaws.com`;
        await runCommandStream(dockerLoginCmd, { cwd: projectRoot, env: { ...process.env, ...awsEnvVars } });
        await runCommandStream(`docker build -t ${ecrRepoUri}:latest .`, { cwd: projectRoot });
        await runCommandStream(`docker push ${ecrRepoUri}:latest`, { cwd: projectRoot });
        console.log(`   - Image pushed to ${ecrRepoUri}:latest`);

        console.log(`[${appName}] 4. Deploying infrastructure with Terraform...`);
        const terraformModulePath = path.resolve(__dirname, '..', 'tf-ecs-fargate-webapp');
        await fs.copy(terraformModulePath, tfWorkspaceDir);
        await runCommandStream('terraform init', { cwd: tfWorkspaceDir, env: { ...process.env, ...awsEnvVars } });

        
        const variables = {
            aws_region: region,
            app_name: appName,
            docker_image: `${ecrRepoUri}:latest`,
            container_port: containerPort,
            cpu: 256,
            memory: 512
        };
        const outputs = await runTerraformCommand('apply', tfWorkspaceDir, variables, awsEnvVars);
        const appUrl = outputs.app_url.value;
        console.log(`   - Terraform deployment complete! URL: ${appUrl}`);

        await dbPool.execute(
            'INSERT INTO deployments (user_id, app_name, tf_workspace_path, app_url) VALUES (?, ?, ?, ?)',
            [user.userId, appName, tfWorkspaceDir, appUrl]
        );
        
        res.status(200).json({ message: `Deployment successful!`, url: appUrl });

    } catch (error) {
        console.error(`[${appName}] Deployment error:`, error.message);
        if (tfWorkspaceDir) await fs.remove(tfWorkspaceDir);
        res.status(500).json({ message: error.message || 'An error occurred during deployment.' });
    } finally {
        if (workspaceDir) await fs.remove(workspaceDir);
        if (projectFile) await fs.remove(projectFile.path);
        console.log(`- Code workspace for [${appName}] cleaned up.`);
    }
});

app.delete('/api/deployments/:appName', protectRoute, async (req, res) => {
    const { appName } = req.params;
    const user = req.user;

    try {
        console.log(`--- [${appName}] DESTROY START ---`);
        
        const [rows] = await dbPool.execute('SELECT * FROM deployments WHERE user_id = ? AND app_name = ?', [user.userId, appName]);
        const deployment = rows[0];
        if (!deployment) return res.status(404).json({ message: 'Deployment not found.' });

        console.log(`1. Assuming user's AWS role...`);
        const [userRows] = await dbPool.execute('SELECT aws_role_arn FROM users WHERE id = ?', [user.userId]);
        const userRoleArn = userRows[0]?.aws_role_arn;
        if (!userRoleArn) throw new Error("User's AWS account is not connected.");
        
        const stsClient = new STSClient({ region: process.env.AWS_REGION });
        const { Credentials } = await stsClient.send(new AssumeRoleCommand({ RoleArn: userRoleArn, RoleSessionName: `CloudDeployerDestroy-${appName}` }));
        const awsEnvVars = {
            AWS_ACCESS_KEY_ID: Credentials.AccessKeyId,
            AWS_SECRET_ACCESS_KEY: Credentials.SecretAccessKey,
            AWS_SESSION_TOKEN: Credentials.SessionToken,
        };

        console.log(`2. Destroying infrastructure for [${appName}]...`);
        const variables = { 
            aws_region: process.env.AWS_REGION,
            app_name: appName,
            docker_image: "temp",
            container_port: 80,
            cpu: 256,
            memory: 512
        };
        await runTerraformCommand('destroy', deployment.tf_workspace_path, variables, awsEnvVars);
        console.log(`   - Infrastructure for [${appName}] destroyed.`);

        await dbPool.execute('DELETE FROM deployments WHERE id = ?', [deployment.id]);
        await fs.remove(deployment.tf_workspace_path);
        console.log(`- Database record and workspace for [${appName}] cleaned up.`);

        res.status(200).json({ message: `Successfully destroyed deployment: ${appName}` });

    } catch (error) {
        console.error(`[${appName}] Destroy error:`, error.message);
        res.status(500).json({ message: error.message || 'An error occurred during destroy.' });
    }
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});