import * as process from "process";
import * as fs from "fs/promises";
import * as core from "@actions/core";
import { generateIssues, parseResults } from "./report-generator.js";
import { IssueOption, IssueResponse, ReportDict } from "./interface.js";
import { GitHub } from "./github.js";
import { Inputs } from "./inputs.js";

function abort(message: string, error?: Error): never {
  console.error(`Error: ${message}`);
  if (error) {
    console.error(error); // Optionally log the error object itself
  }
  process.exit(1);
}

async function main() {
  // Read inputs from environment variables
  const inputs = new Inputs();

  // Initialize GitHub client with the provided token
  const github = new GitHub(inputs.token);

  // Initialise arrays to store created, updated and closed issues
  const issuesCreated: IssueResponse[] = [];
  const issuesUpdated: { issueNumber: number }[] = [];
  const issuesClosed: IssueResponse[] = [];

  try {
    // Create GitHub labels if createLabels is true and the labels dont already exist
    if (inputs.issue.createLabels) {
      const labelsToCreate = [...inputs.issue.labels];
      if (inputs.issue.enableFixLabel) {
        labelsToCreate.push(inputs.issue.fixLabel!);
      }
      for (const label of labelsToCreate) {
        if (inputs.dryRun) {
          core.info(`[Dry Run] Would create label: ${label}`);
        } else {
          await github.createLabelIfMissing(label);
        }
      }
    }

    // Read Trivy report from file and parse it into a ReportDict object
    const trivyRaw = await fs.readFile(inputs.issue.filename, "utf-8");
    const reportData = JSON.parse(trivyRaw) as ReportDict; // Data is now defined here.

    // Fetch existing Trivy issues from GitHub and filter out duplicates using a Set
    const existingIssues = await github.getTrivyIssues(inputs.issue.labels);

    const reports = parseResults(reportData, existingIssues);

    if (reports === null && existingIssues.length > 0) {
      core.info(
        "No reports found but open issues were found. Closing existing issues.",
      );
      for (const issue of existingIssues) {
        if (inputs.dryRun) {
          core.info(
            `[Dry Run] Would close issue: ${issue.number} - ${issue.title}`,
          );
        } else {
          issuesClosed.push(await github.closeIssue(issue.number));
        }
      }
      return;
    } else if (reports === null) {
      core.info("No reports to create issues for");
      return;
    }

    // Generate GitHub issues from the parsed report data
    const issues = generateIssues(reports);

    // Create GitHub issues from the parsed report data, excluding duplicates if found in existing issues
    for (const issue of issues) {
      //check if issue exists
      const existingIssue = existingIssues.find(
        (existingIssue) =>
          existingIssue.title.toLowerCase() === issue.title.toLowerCase(),
      );
      if (existingIssue) {
        // Issue exists, check if we need to update it (e.g., if a fix is now available)
        if (
          (issue.hasFix &&
            !existingIssue.labels.includes(inputs.issue.fixLabel!)) ||
          issue.body !== existingIssue.body
        ) {
          // Update the issue
          const updateIssueOption: IssueOption & { hasFix?: boolean } = {
            title: issue.title,
            body: issue.body,
            labels: inputs.issue.labels, // Use the labels from inputs
            assignees: inputs.issue.assignees,
            projectId: inputs.issue.projectId,
            enableFixLabel: inputs.issue.enableFixLabel,
            fixLabel: inputs.issue.fixLabel,
            hasFix: issue.hasFix,
          };

          if (inputs.dryRun) {
            console.log(
              `[Dry Run] Would update issue #${existingIssue.number} with:`,
              updateIssueOption,
            );
          } else {
            issuesUpdated.push(
              await github.updateIssue(existingIssue.number, updateIssueOption),
            );
          }
        }
      } else {
        // Issue doesn't exist, create it
        const issueOption = {
          title: issue.title,
          body: issue.body,
          ...inputs.issue,
          hasFix: issue.hasFix,
        };
        if (inputs.dryRun) {
          core.info(`[Dry Run] Would create issue with: ${issueOption}`);
        } else {
          issuesUpdated.push(await github.createIssue(issueOption));
        }
      }
    }

    // Set the created and updated issues as outputs
    core.setOutput("issues-created", JSON.stringify(issuesCreated));
    core.setOutput("issues-updated", JSON.stringify(issuesUpdated));
    core.setOutput("issues-closed", JSON.stringify(issuesClosed));
  } catch (error) {
    if (error instanceof Error) {
      abort(`Error: ${error.message}`, error);
    } else {
      abort(`Error: An unknown error occurred. ${error}`);
    }
  }
}

main();
