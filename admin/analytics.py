def compute_stats(items):
    total = len(items)
    high = sum(1 for i in items if (i.get('risk') or '').lower() == 'high')
    suspicious = sum(1 for i in items if (i.get('risk') or '').lower() == 'suspicious')
    clean = sum(1 for i in items if (i.get('risk') or '').lower() == 'clean')
    return {
        'total': total,
        'high': high,
        'suspicious': suspicious,
        'clean': clean,
        'summary': f"{high} / {suspicious} / {clean}",
    }
