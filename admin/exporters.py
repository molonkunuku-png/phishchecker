import csv
import io


def export_json(items):
    import json
    return json.dumps(items, indent=2)


def export_csv(items):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['url', 'domain', 'risk', 'score', 'mode'])
    writer.writeheader()
    for item in items:
        writer.writerow({k: item.get(k, '') for k in ['url', 'domain', 'risk', 'score', 'mode']})
    return output.getvalue()
