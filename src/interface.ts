export interface VulnerabilityDict {
  VulnerabilityID: string
  PkgName: string
  InstalledVersion: string
  FixedVersion?: string
  Title: string
  Description: string
  Severity: string
  PrimaryURL: string
  References: string[]
}

export interface ResultDict {
  Type: string
  Target: string
  Vulnerabilities: VulnerabilityDict[]
}

export interface ReportDict {
  Results: ResultDict
}

export interface IssueInputs {
  filename: string
  labels: string[]
  assignees?: string[]
  projectId?: string
  createLabels: boolean
  enableFixLabel: boolean
  fixLabel?: string
}

export interface IssueOption {
  title: string
  body: string
  labels: string[]
  assignees?: string[]
  projectId?: string
  enableFixLabel: boolean
  fixLabel?: string
}

export interface IssueResponse {
  issueNumber: number
  title: string // Add this line
  htmlUrl: string
}

export interface TrivyIssue {
  number: number
  title: string
  body: string
  state: string
  labels: string[]
  html_url: string
}
