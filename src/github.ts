import * as github from '@actions/github'
import { Octokit } from '@octokit/rest'
import { IssueOption, IssueResponse, TrivyIssue } from './interface.js'
import { RequestError } from '@octokit/request-error'
import * as core from '@actions/core'

export class GitHub {
  client: Octokit

  constructor(token: string) {
    this.client = new Octokit({ auth: token })
  }

  async getTrivyIssues(labels: string[] | undefined): Promise<TrivyIssue[]> {
    try {
      if (!labels) {
        return []
      }

      const { data: trivyIssues } = await this.client.issues.listForRepo({
        ...github.context.repo,
        labels: labels.join(','),
        state: 'all'
      })

      return trivyIssues
        .filter((issue) => issue.title && issue.body)
        .map((issue) => ({
          number: issue.number,
          title: issue.title,
          body: issue.body!,
          state: issue.state,
          labels: issue.labels
            .map((label) =>
              typeof label === 'string' ? label : (label.name ?? '')
            )
            .filter(Boolean),
          html_url: issue.html_url ?? ''
        }))
    } catch (err) {
      throw new Error(`Failed to fetch issues: ${err}`)
    }
  }

  async createIssue(
    options: IssueOption & { hasFix?: boolean }
  ): Promise<IssueResponse> {
    try {
      let labels = [...options.labels]
      if (options.enableFixLabel && options.hasFix) {
        labels.push(options.fixLabel!)
      }
      const { data: issue } = await this.client.issues.create({
        ...github.context.repo,
        ...options,
        labels: labels
      })
      const issueResponse: IssueResponse = {
        issueNumber: issue.number,
        htmlUrl: issue.html_url
      }

      core.info(
        `Created issue: ${issue.html_url} (Issue Number: ${issue.number})`
      )

      return issueResponse
    } catch (err) {
      throw new Error(`Failed to create issue: ${err}`)
    }
  }
  async updateIssue(
    issueNumber: number,
    options: IssueOption & { hasFix?: boolean }
  ): Promise<IssueResponse> {
    try {
      let labels = [...options.labels]
      if (options.enableFixLabel && options.hasFix) {
        labels.push(options.fixLabel!)
      }
      core.info(`Updating issue ${issueNumber} with: ${options} ${labels}`)

      const { data: issue } = await this.client.issues.update({
        ...github.context.repo,
        issue_number: issueNumber,
        ...options,
        labels: labels
      })

      return {
        issueNumber: issue.number,
        htmlUrl: issue.html_url ?? '' // Use nullish coalescing in case html_url is undefined
      }
    } catch (err) {
      throw new Error(`Failed to update issue: ${err}`)
    }
  }
  async closeIssue(issueNumber: number): Promise<IssueResponse> {
    try {
      const { data: issue } = await this.client.issues.update({
        ...github.context.repo,
        issue_number: issueNumber,
        state: 'closed'
      })

      core.info(`Closed issue #${issueNumber}`)

      return {
        issueNumber: issue.number,
        htmlUrl: issue.html_url ?? '' // Use nullish coalescing in case html_url is undefined
      }
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(
          `Failed to close issue #${issueNumber}: ${error.message}`
        )
      } else {
        throw new Error(
          `Failed to close issue #${issueNumber}: An unknown error occurred.`
        )
      }
    }
  }
  async createLabelIfMissing(label: string): Promise<void> {
    try {
      await this.client.issues.getLabel({
        ...github.context.repo,
        name: label
      })
      core.info(`Label "${label}" already exists.`)
    } catch (error: unknown) {
      if (error instanceof RequestError) {
        // Use RequestError (or the appropriate Octokit error type)
        if (error.status === 404) {
          core.info(`Label "${label}" does not exist. Creating it...`)
          await this.client.issues.createLabel({
            ...github.context.repo,
            name: label
          })
          core.info(`Label "${label}" created successfully.`)
        } else {
          throw new Error(
            `Error checking or creating label "${label}": ${error.message}`
          )
        }
      } else if (error instanceof Error) {
        // Handle other standard JavaScript errors
        throw new Error(
          `Error checking or creating label "${label}": ${error.message}`
        )
      } else {
        // Handle cases where error is not an Error instance
        throw new Error(
          `Error checking or creating label "${label}": An unknown error occurred.`
        )
      }
    }
  }
}
