import { VulnerabilityDict } from "./interface.js";

export class Vulnerability {
  vulnerability_id: string;
  title: string;
  pkg_name: string;
  installed_version: string;
  fixed_version?: string;
  description: string;
  severity: string;
  url: string;
  references: string[];

  constructor(
    vulnerability_id: string,
    title: string,
    pkg_name: string,
    installed_version: string,
    fixed_version: string,
    description: string,
    severity: string,
    url: string,
    references: string[],
  ) {
    this.vulnerability_id = vulnerability_id;
    this.title = title;
    this.pkg_name = pkg_name;
    this.installed_version = installed_version;
    this.fixed_version = fixed_version;
    this.description = description;
    this.severity = severity;
    this.url = url;
    this.references = references;
  }
}

export class Report {
  id: string;
  package: string;
  package_name: string;
  package_version: string;
  package_fixed_version?: string;
  package_type: string;
  target: string;
  vulnerabilities: VulnerabilityDict[];

  constructor(
    id: string,
    pkg: string,
    package_name: string,
    package_version: string,
    package_type: string,
    target: string,
    vulnerabilities: VulnerabilityDict[],
    package_fixed_version?: string,
  ) {
    this.id = id;
    this.package = pkg;
    this.package_name = package_name;
    this.package_version = package_version;
    this.package_fixed_version = package_fixed_version;
    this.package_type = package_type;
    this.target = target;
    this.vulnerabilities = vulnerabilities;
  }
}

export class Issue {
  id: string;
  report: Report;
  title: string;
  body: string;
  hasFix: boolean;

  constructor(
    id: string,
    report: Report,
    title: string,
    body: string,
    hasFix: boolean,
  ) {
    this.id = id;
    this.report = report;
    this.title = title;
    this.body = body;
    this.hasFix = hasFix;
  }
}
