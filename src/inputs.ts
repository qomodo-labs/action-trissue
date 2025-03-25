import * as core from "@actions/core";
import { IssueInputs } from "./interface.js";

export class Inputs {
  token: string;
  issue: IssueInputs;
  dryRun: boolean;

  constructor() {
    this.token = core.getInput("token", { required: true });

    this.issue = {
      filename: core.getInput("filename", { required: true }),
      labels: core.getInput("labels").replace(/\s+/g, "").split(","),
      assignees: core.getInput("assignees").replace(/\s+/g, "").split(","),
      projectId: core.getInput("project-id"),
      createLabels:
        core.getInput("create-labels").toLowerCase() === "true" || true,
      enableFixLabel:
        core.getInput("enable-fix-label").toLowerCase() === "true" || true,
      fixLabel: core.getInput("fix-label") || "fix-available",
    };
    this.dryRun = core.getInput("dry-run").toLowerCase() === "true" || false; // Initialize dryRun
  }
}
