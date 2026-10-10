import sys
import json
import requests

def check_vulnerability(pkg_name, version):
    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version.lstrip("^~"),
        "package": {
            "name": pkg_name,
            "ecosystem": "npm"
        }
    }
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("vulns", [])
    except Exception:
        return []
    return []

def main():
    if len(sys.argv) < 2:
        print(json.dumps([]))
        sys.exit(0)

    file_path = sys.argv[1]
    results = []

    try:
        with open(file_path, 'r') as f:
            manifest = json.load(f)
            deps = manifest.get("dependencies", {})

            for pkg, ver in deps.items():
                vulns = check_vulnerability(pkg, ver)
                if vulns:
                    results.append({
                        "package": pkg,
                        "version": ver,
                        "cveCount": len(vulns),
                        "details": [v.get("id", "Unknown") for v in vulns[:3]]
                    })
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    print(json.dumps(results))

if __name__ == "__main__":
    main()