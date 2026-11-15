#!/usr/bin/env node
// AWS SDK for JavaScript v3: check whether an image tag already exists in ECR.
// Lets a pipeline skip rebuilding an image that was already built for this commit.
//
//   npm i @aws-sdk/client-ecr
//   node ecr_image_exists.mjs <repository> <tag>
//
// Writes `exists=true|false` to $GITHUB_OUTPUT.
import { ECRClient, DescribeImagesCommand } from "@aws-sdk/client-ecr";
import { appendFileSync } from "node:fs";

const [repositoryName, imageTag] = process.argv.slice(2);
if (!repositoryName || !imageTag) {
  console.error("usage: ecr_image_exists.mjs <repository> <tag>");
  process.exit(2);
}

const client = new ECRClient({}); // region & credentials come from the environment (OIDC)
let exists = false;
try {
  const res = await client.send(new DescribeImagesCommand({ repositoryName, imageIds: [{ imageTag }] }));
  exists = (res.imageDetails ?? []).length > 0;
} catch (err) {
  if (err.name !== "ImageNotFoundException") throw err;
}

console.log(`${repositoryName}:${imageTag} exists=${exists}`);
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `exists=${exists}\n`);
