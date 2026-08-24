from app import scans


def apply_filters(risk, q, sort):
    items = list(scans)
    if risk:
        items = [x for x in items if (x.get('risk') or '').lower() == risk]
    if q:
        q = q.lower()
        items = [x for x in items if q in (x.get('domain') or '').lower() or q in (x.get('url') or '').lower()]
    if sort == 'oldest':
        items.reverse()
    return items
