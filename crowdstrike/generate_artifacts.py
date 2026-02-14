import json
import csv
import urllib.request
import re
import os

URL = "https://lolrmm.io/api/rmm_tools.json"


def get_data():
    try:
        req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as url:
            data = json.loads(url.read().decode())
        return data
    except Exception as e:
        print(f"Error fetching data: {e}")
        return []


def is_hash(s):
    # Simple regex for md5, sha1, sha256
    s = s.strip()
    if re.match(r"^[a-fA-F0-9]{32}$", s):
        return True
    if re.match(r"^[a-fA-F0-9]{40}$", s):
        return True
    if re.match(r"^[a-fA-F0-9]{64}$", s):
        return True
    return False


def main():
    print(f"Fetching data from {URL}...")
    data = get_data()

    if not data:
        print("No data found.")
        return

    file_artifacts = []  # (Artifact, Type, Tool)
    domain_artifacts = []  # (Artifact, Type, Tool)

    for tool in data:
        name = tool.get("Name")
        details = tool.get("Details") or {}
        artifacts = tool.get("Artifacts") or {}

        # Domains
        # From Network
        for net in artifacts.get("Network") or []:
            for domain in net.get("Domains") or []:
                domain = domain.strip()
                if domain:
                    domain_artifacts.append((domain, "domain", name))

        # Files and Hashes
        # From PEMetadata
        for pe in details.get("PEMetadata") or []:
            if isinstance(pe, dict):
                fname = pe.get("Filename")
                if fname:
                    file_artifacts.append((fname, "filename", name))
            elif isinstance(pe, str):
                file_artifacts.append((pe, "filename", name))

        # From InstallationPaths
        for path in details.get("InstallationPaths") or []:
            path = path.strip()
            if not path:
                continue

            # Check if hash
            if is_hash(path):
                file_artifacts.append((path, "hash", name))
            else:
                # Extract filename if it's a path
                if "\\" in path or "/" in path:
                    fname = os.path.basename(path.replace("\\", "/"))
                    # filtering out potential directory wildcards or non-files if needed
                    # but usually basename is good enough for "filename" type
                    if fname and fname != "*" and "?" not in fname:
                        file_artifacts.append((fname, "filename", name))
                else:
                    if path != "*" and "?" not in path:
                        file_artifacts.append((path, "filename", name))

    # Deduplicate
    file_artifacts = sorted(list(set(file_artifacts)))
    domain_artifacts = sorted(list(set(domain_artifacts)))

    # Write RMM_Artifacts.csv
    print(f"Writing {len(file_artifacts)} artifacts to RMM_Artifacts.csv...")
    with open("RMM_Artifacts.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Artifact", "Type", "Tool"])
        writer.writerows(file_artifacts)

    # Write RMM_Domain_Artifacts.csv
    print(f"Writing {len(domain_artifacts)} artifacts to RMM_Domain_Artifacts.csv...")
    with open("RMM_Domain_Artifacts.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Artifact", "Type", "Tool"])
        writer.writerows(domain_artifacts)

    print("Done.")


if __name__ == "__main__":
    main()
