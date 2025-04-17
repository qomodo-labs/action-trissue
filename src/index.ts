import * as process from 'process'
import * as fs from 'fs/promises'
import * as core from '@actions/core'
import { generateIssues, parseResults } from './report-generator.js'
import {
  IssueOption,
  IssueResponse,
  ReportDict,
  TrivyIssue
} from './interface.js' // Added TrivyIssue
import { GitHub } from './github.js'
import { Inputs } from './inputs.js'
import { Issue } from './dataclass.js' // Added Issue import

function abort(message: string, error?: Error): never {
  console.error(`Error: ${message}`)
  if (error) {
    console.error(error) // Optionally log the error object itself
  }
  process.exit(1)
}

async function main() {
  // Read inputs from environment variables
  const inputs = new Inputs()

  // Initialize GitHub client with the provided token
  const github = new GitHub(inputs.token)

  // Initialise arrays to store created, updated and closed issues
  const issuesCreated: IssueResponse[] = []
  // Updated issues need the IssueResponse format too if we want title/url
  const issuesUpdated: IssueResponse[] = []
  const issuesClosed: IssueResponse[] = []
  let fixableVulnerabilityExists = false // Initialize the new output flag

  try {
    // Create GitHub labels if createLabels is true and the labels dont already exist
    if (inputs.issue.createLabels) {
      const labelsToCreate = [...inputs.issue.labels]
      if (inputs.issue.enableFixLabel && inputs.issue.fixLabel) {
        // Check if fixLabel exists
        labelsToCreate.push(inputs.issue.fixLabel)
      }
      for (const label of labelsToCreate) {
        if (inputs.dryRun) {
          core.info(`[Dry Run] Would create label: ${label}`)
        } else {
          await github.createLabelIfMissing(label)
        }
      }
    }

    // Read Trivy report from file and parse it into a ReportDict object
    const trivyRaw = await fs.readFile(inputs.issue.filename, 'utf-8')
    const reportData = JSON.parse(trivyRaw) as ReportDict // Data is now defined here.

    // Fetch existing Trivy issues from GitHub
    const existingTrivyIssues: TrivyIssue[] = await github.getTrivyIssues(
      inputs.issue.labels
    ) // Renamed variable

    const reports = parseResults(reportData, existingTrivyIssues)

    // --- Logic to close stale issues ---
    const reportIssueTitles = new Set(
      reports?.map((r) =>
        `${r.vulnerabilities[0].VulnerabilityID}: ${r.package_type} package ${r.package}`.toLowerCase()
      ) || []
    )

    for (const existingIssue of existingTrivyIssues) {
      // Close open issues that are no longer in the report
      if (
        existingIssue.state === 'open' &&
        !reportIssueTitles.has(existingIssue.title.toLowerCase())
      ) {
        if (inputs.dryRun) {
          core.info(
            `[Dry Run] Would close stale issue: #${existingIssue.number} - ${existingIssue.title}`
          )
        } else {
          core.info(
            `Closing stale issue: #${existingIssue.number} - ${existingIssue.title}`
          )
          issuesClosed.push(await github.closeIssue(existingIssue.number))
        }
      }
      // Check if any existing open issue has a fix label (relevant for the fixable_vulnerability output)
      if (
        existingIssue.state === 'open' &&
        inputs.issue.enableFixLabel &&
        inputs.issue.fixLabel &&
        existingIssue.labels.includes(inputs.issue.fixLabel)
      ) {
        fixableVulnerabilityExists = true
      }
    }

    if (reports === null) {
      core.info('No new vulnerabilities found in the report.')
      // Existing issues closing logic is handled above
    } else {
      // Generate GitHub issues from the parsed report data
      const issuesToProcess: Issue[] = generateIssues(reports) // Renamed variable

      // Check for fixable vulnerabilities among the new/updated issues
      if (!fixableVulnerabilityExists) {
        // Only check if not already found in existing issues
        fixableVulnerabilityExists = issuesToProcess.some(
          (issue) => issue.hasFix
        )
      }

      // Create/Update GitHub issues
      for (const issue of issuesToProcess) {
        // Use renamed variable
        const existingIssue = existingTrivyIssues.find(
          // Use renamed variable
          (ei) => ei.title.toLowerCase() === issue.title.toLowerCase()
        )
        const issueOptionBase: IssueOption & { hasFix: boolean } = {
          title: issue.title,
          body: issue.body,
          labels: inputs.issue.labels, // Use the labels from inputs
          assignees: inputs.issue.assignees,
          projectId: inputs.issue.projectId,
          enableFixLabel: inputs.issue.enableFixLabel,
          fixLabel: inputs.issue.fixLabel,
          hasFix: issue.hasFix
        }

        if (existingIssue) {
          // Issue exists, check if we need to update it
          const needsUpdate =
            (issue.hasFix &&
              inputs.issue.enableFixLabel &&
              inputs.issue.fixLabel &&
              !existingIssue.labels.includes(inputs.issue.fixLabel)) || // Add fix label if needed
            (!issue.hasFix &&
              inputs.issue.enableFixLabel &&
              inputs.issue.fixLabel &&
              existingIssue.labels.includes(inputs.issue.fixLabel)) || // Remove fix label if needed
            issue.body !== existingIssue.body // Body changed

          if (needsUpdate && existingIssue.state === 'open') {
            if (inputs.dryRun) {
              console.log(
                `[Dry Run] Would update issue #${existingIssue.number} ('${issue.title}')` // Removed options dump
              )
            } else {
              core.info(
                `Updating issue #${existingIssue.number} ('${issue.title}')`
              )
              issuesUpdated.push(
                await github.updateIssue(existingIssue.number, issueOptionBase)
              )
            }
          } else if (existingIssue.state === 'closed') {
            // Issue is closed, but vulnerability still exists, reopen it
            if (inputs.dryRun) {
              core.info(
                `[Dry Run] Would reopen issue #${existingIssue.number} ('${issue.title}')`
              )
            } else {
              core.info(
                `Reopening issue #${existingIssue.number} ('${issue.title}')`
              )
              // Reopening should likely be tracked under 'updated' or a separate 'reopened' list
              // Using 'updated' for now as per original logic tendency
              issuesUpdated.push(await github.reopenIssue(existingIssue.number))
            }
          } else {
            core.info(
              `No update needed for issue #${existingIssue.number} ('${issue.title}')`
            )
          }
        } else if (inputs.dryRun) {
          core.info(`[Dry Run] Would create issue with title: ${issue.title}`) // Simplified log
        } else {
          core.info(`Creating issue with title: ${issue.title}`)
          issuesCreated.push(await github.createIssue(issueOptionBase))
        }
      }
    }

    // --- Set Outputs ---
    core.setOutput(
      'fixable_vulnerability',
      fixableVulnerabilityExists.toString()
    ) // Set the new output
    core.setOutput('created_issues', JSON.stringify(issuesCreated)) // Use the correct variable name and format
    core.setOutput('closed_issues', JSON.stringify(issuesClosed)) // Use the correct variable name and format
    // Keep the updated issues output as well, might be useful
    core.setOutput('updated_issues', JSON.stringify(issuesUpdated))
  } catch (error) {
    if (error instanceof Error) {
      abort(`Error: ${error.message}`, error)
    } else {
      abort(`Error: An unknown error occurred. ${error}`)
    }
  }
}

main()
