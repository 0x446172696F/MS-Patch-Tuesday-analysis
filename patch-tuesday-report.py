import requests
import xml.etree.ElementTree as ET
import csv
import sys
import os
sys.stdout.reconfigure(encoding="utf-8")

# Define the API URL for December 2024 Patch Tuesday release
url = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun"

# Define headers (if authentication is required, include tokens or API keys here)
headers = {
    "Accept": "application/xml"
}

# Target release date
target_date = "2026-06-09"

# Where to write the generated report files
output_dir = os.path.dirname(os.path.abspath(__file__))
html_path = os.path.join(output_dir, f"patch-tuesday-{target_date}.html")
csv_path = os.path.join(output_dir, f"patch-tuesday-{target_date}.csv")

# Make the GET request
try:
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Raise an error for HTTP status codes 4xx/5xx

    # Parse the XML response
    root = ET.fromstring(response.text)

    # Define the namespaces used in the XML document
    namespaces = {
        'cvrf': 'http://www.icasi.org/CVRF/schema/cvrf/1.1',
        'vuln': 'http://www.icasi.org/CVRF/schema/vuln/1.1',
        'prod': 'http://www.icasi.org/CVRF/schema/prod/1.1',
        'cvssv2': 'https://scap.nist.gov/schema/cvss-v2/1.0',
        'cpe-lang': 'http://cpe.mitre.org/language/2.0'
    }

    # Extract all product information to create a mapping of ProductID to Product Name
    product_mapping = {}
    products = root.findall(".//prod:Branch//prod:FullProductName", namespaces=namespaces)

    for product in products:
        product_id = product.attrib.get('ProductID')
        product_name = product.text.strip() if product.text else "Unknown Product"
        product_mapping[product_id] = product_name

    # Extract vulnerabilities
    vulnerabilities = root.findall(".//vuln:Vulnerability", namespaces=namespaces)

    if not vulnerabilities:
        print("No vulnerabilities found!")
        exit()

    # Initialize a counter for CVEs
    cve_count = 0

    # List to hold processed vulnerabilities
    processed_vulnerabilities = []

    for vuln in vulnerabilities:
        # Find all <vuln:Revision> elements within this vulnerability
        revisions = vuln.findall(".//vuln:RevisionHistory/vuln:Revision", namespaces=namespaces)

        # Find the release date
        release_date = "N/A"
        for revision in revisions:
            description_elem = revision.find(".//cvrf:Description", namespaces=namespaces)
            if description_elem is not None and "Information published" in description_elem.text:
                date_elem = revision.find(".//cvrf:Date", namespaces=namespaces)
                if date_elem is not None:
                    release_date = date_elem.text.split("T")[0]
                    break

        if release_date != target_date:
            continue

        # CVE ID
        cve_elem = vuln.find(".//vuln:CVE", namespaces=namespaces)
        cve = cve_elem.text if cve_elem is not None else "N/A"

        # Increment the CVE count
        cve_count += 1

        # Title
        title_elem = vuln.find(".//vuln:Title", namespaces=namespaces)
        title = title_elem.text if title_elem is not None else "No Title"

        # Exploitation Status and Public Disclosure
        exploitation_status_elem = vuln.findall(".//vuln:Threat[@Type='Exploit Status']/vuln:Description", namespaces=namespaces)
        exploitation_status = exploitation_status_elem[0].text if exploitation_status_elem else "Unknown"

        # Parse the specific status from the exploitation status string
        status_parts = exploitation_status.split(";")
        latest_status = next(
            (part.split(":")[1] for part in status_parts if "Latest Software Release" in part),
            "Unknown"
        )
        publicly_disclosed = next(
            (part.split(":")[1] for part in status_parts if "Publicly Disclosed" in part),
            "No"
        )

        # Severity
        severity_elem = vuln.findall(".//vuln:Threat[@Type='Severity']/vuln:Description", namespaces=namespaces)
        severity = severity_elem[0].text if severity_elem else "N/A"

        # CVSS Base Score
        cvss_score_elem = vuln.find(".//vuln:CVSSScoreSets/vuln:ScoreSet/vuln:BaseScore", namespaces=namespaces)
        cvss_score = float(cvss_score_elem.text) if cvss_score_elem is not None else 0.0

        # FAQ Notes
        faq_notes = vuln.findall(".//vuln:Notes/vuln:Note[@Title='FAQ']", namespaces=namespaces)
        faq = "\n".join(
            "".join(note.itertext()).strip()
            for note in faq_notes
        ) if faq_notes else "No FAQ available"

        # Executive Summary (the vulnerability's "Description" note, not always present)
        exec_summary_notes = vuln.findall(".//vuln:Notes/vuln:Note[@Type='Description']", namespaces=namespaces)
        executive_summary = "\n".join(
            "".join(note.itertext()).strip()
            for note in exec_summary_notes
        ) if exec_summary_notes else ""

        # CWE Details
        cwe_elem = vuln.find(".//vuln:CWE", namespaces=namespaces)
        if cwe_elem is not None:
            cwe_id = cwe_elem.get("ID", "N/A")
            cwe_description = cwe_elem.text if cwe_elem.text else "No Description"
        else:
            cwe_id = "N/A"
            cwe_description = "N/A"

        # Products: Map ProductIDs to Product Names
        product_ids = vuln.findall(".//vuln:ProductStatuses/vuln:Status/vuln:ProductID", namespaces=namespaces)
        products = ", ".join([product_mapping.get(pid.text, "Unknown Product") for pid in product_ids]) if product_ids else "N/A"

        # Impact
        impact_elem = vuln.findall(".//vuln:Threat[@Type='Impact']/vuln:Description", namespaces=namespaces)
        impact = impact_elem[0].text if impact_elem else "Unknown"

        # Add to the list of processed vulnerabilities
        processed_vulnerabilities.append({
            "cve": cve,
            "title": title,
            "release_date": release_date,
            "latest_status": latest_status,
            "publicly_disclosed": publicly_disclosed,
            "severity": severity,
            "cvss_score": cvss_score,
            "faq": faq,
            "executive_summary": executive_summary,
            "cwe_id": cwe_id,
            "cwe_description": cwe_description,
            "products": products,
            "impact": impact
        })

    # Define sorting priorities
    def sort_priority(vuln):
        priority = 0
        # Prioritize according to the criteria:
        if vuln["latest_status"] == "Exploitation Detected":
            priority = 1
        elif vuln["publicly_disclosed"] == "Yes":
            priority = 2
        elif vuln["latest_status"] == "Exploitation More Likely":
            priority = 3
        elif vuln["severity"] == "Critical":
            priority = 4
        elif vuln["cvss_score"] >= 8.0:
            priority = 5
        return priority

    # Filter vulnerabilities with CVSS score < 8, except for the prioritized cases
    filtered_vulnerabilities = [
        vuln for vuln in processed_vulnerabilities
        if (vuln["severity"] == "Critical" or vuln["cvss_score"] >= 8.0 or vuln["latest_status"] in ["Exploitation Detected", "Exploitation More Likely"] or vuln["publicly_disclosed"] == "Yes")
    ]

    # Within a priority tier, Critical severity should rank above Important (and other severities)
    def severity_rank(vuln):
        return 0 if vuln["severity"] == "Critical" else 1

    # Sort vulnerabilities by priority, then severity (Critical first), then by CVSS score (high to low)
    sorted_vulnerabilities = sorted(filtered_vulnerabilities, key=lambda v: (sort_priority(v), severity_rank(v), -v["cvss_score"]))

    # Build the HTML report in memory
    html_parts = []
    html_parts.append("<html><head><meta charset='utf-8'><title>Patch Tuesday Report</title></head><body>")
    html_parts.append(f"<h1>Vulnerabilities with release date {target_date}:</h1><br>")

    # Total CVE count
    html_parts.append(f"<p><strong>Total CVEs with release date {target_date}:</strong> {cve_count}</p>")

    # Counters for the exploitation statuses
    exploitation_detected_count = sum(1 for vuln in processed_vulnerabilities if vuln["latest_status"] == "Exploitation Detected")
    publicly_disclosed_count = sum(1 for vuln in processed_vulnerabilities if vuln["publicly_disclosed"] == "Yes")
    exploitation_more_likely_count = sum(1 for vuln in processed_vulnerabilities if vuln["latest_status"] == "Exploitation More Likely")
    critical_count = sum(1 for vuln in processed_vulnerabilities if vuln["severity"] == "Critical")

    html_parts.append(f"<p><strong>Total Exploited in the wild:</strong> {exploitation_detected_count}</p>")
    html_parts.append(f"<p><strong>Total Publicly Disclosed:</strong> {publicly_disclosed_count}</p>")
    html_parts.append(f"<p><strong>Total Exploitation More Likely:</strong> {exploitation_more_likely_count}</p>")
    html_parts.append(f"<p><strong>Total Critical:</strong> {critical_count}</p>")
    html_parts.append(f"<p><strong>Total vulnerabilities matching selection criteria:</strong> {len(sorted_vulnerabilities)}</p>")

    html_parts.append("<h2>Short summary</h2><br>")
    for vuln in sorted_vulnerabilities:
        html_parts.append(f"<b>{vuln['cve']} ({vuln['cvss_score']}) - {vuln['title']}</b><br>")
        html_parts.append(f"<b>Publicly disclosed:</b> {vuln['publicly_disclosed']} - <b>Exploitation status:</b> {vuln['latest_status']} <br>")
        html_parts.append(f"{vuln['cwe_id']}: {vuln['cwe_description']} <br>")
        if vuln['executive_summary']:
            html_parts.append(f"<strong>Executive Summary:</strong> {vuln['executive_summary']}<br>")
        html_parts.append(f"{vuln['faq']}<br>")
        html_parts.append("-" * 50 + " </p>")

    html_parts.append("<h2>Summary</h2><br>")
    for vuln in sorted_vulnerabilities:
        html_parts.append(f"<h2>{vuln['cve']} <br></h2>")
        html_parts.append(f" <strong><p>Title: </strong> {vuln['title']} </p>")
        html_parts.append(f" <strong><p>Release Date: </strong> {vuln['release_date']} </p>")
        html_parts.append(f" <strong><p>Publicly Disclosed: </strong> {vuln['publicly_disclosed']} </p>")
        html_parts.append(f" <strong><p>Exploitation Status: </strong> {vuln['latest_status']} </p>")
        html_parts.append(f" <strong><p>Severity: </strong> {vuln['severity']} <p>")
        html_parts.append(f" <strong><p>CVSS Score: </strong> {vuln['cvss_score']} <p>")
        html_parts.append(f" <strong><p>CWE ID: </strong> {vuln['cwe_id']}: {vuln['cwe_description']} </p>")
        html_parts.append(f" <strong><p>Impacted Products: </strong></p><p> {vuln['products']} </p>")
        html_parts.append(f" <strong><p>Impact: </strong> {vuln['impact']} <//p>")
        if vuln['executive_summary']:
            html_parts.append(f" <strong><p>Executive Summary: </strong></p><p> {vuln['executive_summary']} </p>")
        html_parts.append(f" <strong><p>FAQ: </strong></p><p> {vuln['faq']} </p>")
        html_parts.append("-" * 50 + " </p>")

    # HTML Table Generation
    html_parts.append(f"<p><strong>Total vulnerabilities matching selection criteria:</strong> {len(sorted_vulnerabilities)}</p>")
    html_parts.append("<h2>Table</h2><br>")
    table_html = "<table border='1'><thead><tr><th>CVE ID</th><th>Title</th><th>Publicly Disclosed</th><th>Exploitation Status</th><th>Severity</th><th>CVSS Score</th><th>Impacted Products</th><th>Impact</th></tr></thead><tbody>"
    for vuln in sorted_vulnerabilities:
        table_html += f"""
            <tr>
                <td>{vuln['cve']}</td>
                <td>{vuln['title']}</td>
                <td>{vuln['publicly_disclosed']}</td>
                <td>{vuln['latest_status']}</td>
                <td>{vuln['severity']}</td>
                <td>{vuln['cvss_score']}</td>
                <td>{vuln['products']}</td>
                <td>{vuln['impact']}</td>
            </tr>
        """
    table_html += "</tbody></table>"
    html_parts.append(table_html)
    html_parts.append("</body></html>")

    # Write the HTML report to disk
    with open(html_path, "w", encoding="utf-8") as html_file:
        html_file.write("\n".join(html_parts))

    # Write the sorted table to a CSV file (opens directly in Excel)
    csv_columns = ["CVE ID", "Title", "Publicly Disclosed", "Exploitation Status", "Severity", "CVSS Score", "Impacted Products", "Impact"]
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(csv_columns)
        for vuln in sorted_vulnerabilities:
            writer.writerow([
                vuln['cve'],
                vuln['title'],
                vuln['publicly_disclosed'],
                vuln['latest_status'],
                vuln['severity'],
                vuln['cvss_score'],
                vuln['products'],
                vuln['impact']
            ])

    print(f"Total CVEs with release date {target_date}: {cve_count}")
    print(f"HTML report written to: {html_path}")
    print(f"CSV report written to: {csv_path}")

except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
