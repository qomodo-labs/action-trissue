import * as github from '@actions/github'
import { Octokit } from '@octokit/rest'
import { IssueOption, IssueResponse, TrivyIssue } from './interface.js'
import * as core from '@actions/core'

interface RequestErrorLike {
  status: number
  message: string
}

function isRequestError(error: unknown): error is RequestErrorLike {
  if (typeof error === 'object' && error !== null) {
    const err = error as Record<string, unknown>
    return typeof err.status === 'number' && typeof err.message === 'string'
  }
  return false
}

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

  private async handleIssueOperation(
    operation: 'create' | 'update' | 'reopen' | 'close',
    issueNumber: number | null,
    options?: IssueOption & { hasFix: boolean }
  ): Promise<IssueResponse> {
    try {
      let data
      const params: any = { ...github.context.repo }

      if (operation === 'create') {
        const labels = [...(options?.labels || [])]
        if (options?.enableFixLabel && options?.hasFix) {
          labels.push(options.fixLabel!)
        }
        params.title = options?.title
        params.body = options?.body
        params.labels = labels
        params.assignees = options?.assignees
        data = (await this.client.issues.create(params)).data
      } else {
        params.issue_number = issueNumber!
        params.state = operation === 'close' ? 'closed' : 'open'

        if (operation === 'update' && options) {
          const labels = [...(options.labels || [])]
          if (options.enableFixLabel && options.hasFix) {
            labels.push(options.fixLabel!)
          }
          params.title = options.title
          params.body = options.body
          params.labels = labels
          params.assignees = options.assignees
        }

        data = (await this.client.issues.update(params)).data
      }

      const actionVerb =
        operation === 'create'
          ? 'Created'
          : operation === 'update'
            ? 'Updated'
            : operation === 'reopen'
              ? 'Reopened'
              : 'Closed'
      core.info(
        `${actionVerb} issue: ${data.html_url} (Issue Number: ${data.number})`
      )

      return {
        issueNumber: data.number,
        htmlUrl: data.html_url ?? ''
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'An unknown error occurred.'
      throw new Error(
        `Failed to ${operation} issue${issueNumber ? ` #${issueNumber}` : ''}: ${errorMessage}`
      )
    }
  }

  async createIssue(
    options: IssueOption & { hasFix: boolean }
  ): Promise<IssueResponse> {
    return this.handleIssueOperation('create', null, options)
  }
  async updateIssue(
    issueNumber: number,
    options: IssueOption & { hasFix: boolean }
  ): Promise<IssueResponse> {
    return this.handleIssueOperation('update', issueNumber, options)
  }
  async closeIssue(issueNumber: number): Promise<IssueResponse> {
    return this.handleIssueOperation('close', issueNumber)
  }
  async reopenIssue(issueNumber: number): Promise<IssueResponse> {
    return this.handleIssueOperation('reopen', issueNumber)
  }
  async createLabelIfMissing(label: string): Promise<void> {
    try {
      await this.client.issues.getLabel({
        ...github.context.repo,
        name: label
      })
      core.info(`Label "${label}" already exists.`)
    } catch (error: unknown) {
      // Check if it's a 404 error
      if (isRequestError(error) && error.status === 404) {
        core.info(`Label "${label}" does not exist. Creating it...`)
        // Generate a random hex color
        const randomColor = Math.floor(Math.random() * 16777215)
          .toString(16)
          .padStart(6, '0')

        try {
          await this.client.issues.createLabel({
            ...github.context.repo,
            name: label,
            color: randomColor // GitHub requires a color when creating a label
          })
          core.info(`Label "${label}" created successfully.`)
        } catch (createError: unknown) {
          if (isRequestError(createError)) {
            core.error(
              `Failed to create label "${label}": ${createError.message}`
            )
            throw new Error(
              `Failed to create label "${label}": ${createError.message}`
            )
          }
          throw createError
        }
      } else {
        core.error(`Unexpected error while checking label "${label}": ${error}`)
        throw new Error(`Error checking or creating label "${label}": ${error}`)
      }
    }
  }
}
