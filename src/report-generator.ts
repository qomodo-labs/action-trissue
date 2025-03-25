import { Issue, Report } from "./dataclass.js";
import { ReportDict, TrivyIssue } from "./interface.js";

export function parseResults(
  data: ReportDict,
  existing_issues: TrivyIssue[],
): Report[] | null {
  /**
   * Parses Trivy result structure and creates a report per vulnerability.
   * Return null if no Results found.
   *
   * @param data The report data parsed from the JSON file.
   * @param existing_issues List of GitHub issues used to exclude already reported vulnerabilities.
   */
  try {
    const results = data.Results;

    if (!Array.isArray(results)) {
      throw new TypeError(
        `The JSON entry .Results is not a list, got: ${typeof results}`,
      );
    }

    const reports: Report[] = [];

    // Create a Set of existing issue identifiers for efficient lookup.
    // Updated identifier now includes VulnerabilityID.
    const existingIssueSet = new Set<string>();
    for (const issue of existing_issues) {
      existingIssueSet.add(issue.title.toLowerCase());
    }

    for (let idx = 0; idx < results.length; idx++) {
      const result = results[idx];

      if (
        typeof result !== "object" ||
        result === null ||
        Array.isArray(result)
      ) {
        throw new TypeError(
          `The JSON entry .Results[${idx}] is not a dictionary, got: ${typeof result}`,
        );
      }

      if (!("Vulnerabilities" in result)) {
        continue;
      }

      const package_type = result["Type"];
      const vulnerabilities = result["Vulnerabilities"];

      if (!Array.isArray(vulnerabilities)) {
        throw new TypeError(
          `The JSON entry .Results[${idx}].Vulnerabilities is not a list, got: ${typeof vulnerabilities}`,
        );
      }

      for (const vulnerability of vulnerabilities) {
        const package_name = vulnerability["PkgName"];
        const package_version = vulnerability["InstalledVersion"];
        const package_fixed_version = vulnerability["FixedVersion"];
        const pkg = `${package_name}-${package_version}`;
        // Include VulnerabilityID in the identifier to ensure uniqueness per vulnerability.
        const issueIdentifier = `${package_name.toLowerCase()} ${package_version.toLowerCase()} ${vulnerability.VulnerabilityID.toLowerCase()}`;

        if (existingIssueSet.has(issueIdentifier)) {
          continue;
        }

        const report_id = `${package_name}-${package_version}-${vulnerability.VulnerabilityID}`;

        // Each vulnerability gets its own report.
        const report: Report = {
          id: report_id,
          package: pkg,
          package_name: package_name,
          package_version: package_version,
          package_fixed_version: package_fixed_version,
          package_type: package_type,
          target: result["Target"],
          vulnerabilities: [vulnerability],
        };

        reports.push(report);
      }
    }

    return reports;
  } catch (e) {
    console.error("Error during parseResults:", e);
    return null;
  }
}

export function generateIssues(reports: Report[]): Issue[] {
  /**
   * Iterates all reports (each representing a vulnerability) and renders them into GitHub issues.
   */
  const issues: Issue[] = [];
  for (const report of reports) {
    // Since each report only has one vulnerability, grab it.
    const vulnerability = report.vulnerabilities[0];

    const issue_title = `${vulnerability.VulnerabilityID}: ${report.package_type} package ${report.package}`;

    let issue_body = `## Title\n${vulnerability.Title}\n`;
    issue_body += `## Description\n${vulnerability.Description}\n`;
    issue_body += `## Severity\n**${vulnerability.Severity}**\n`;
    issue_body += `## Fixed in Version\n**${report.package_fixed_version || "No known fix at this time"}**\n\n`;
    issue_body += `## Primary URL\n${vulnerability.PrimaryURL}\n`;
    issue_body += `## Additional Information\n`;
    issue_body += `**Vulnerability ID:** ${vulnerability.VulnerabilityID}}\n`;
    issue_body += `**Package Name:** ${report.package_name}\n`;
    issue_body += `**Package Version:** ${report.package_version}\n`;
    const reference_items = vulnerability.References.map(
      (reference: string) => `- ${reference}`,
    ).join("\n");
    issue_body += `## References\n${reference_items}\n\n`;

    issues.push({
      id: report.id,
      report: report,
      title: issue_title,
      body: issue_body,
      hasFix: report.package_fixed_version !== undefined,
    });
  }
  return issues;
}
