"""
Minimal OData support for the queries a playbook actually sends:
  $filter=deviceName eq 'BSNS-WIN-ALICE'
  $filter=startswith(deviceName,'BSNS-WIN')
  $filter=operatingSystem eq 'Windows' and complianceState eq 'noncompliant'
  $select=id,deviceName   $top=10
String comparisons are case-insensitive, like Graph.
"""
import re

from flask import request

_EQ = re.compile(r"^\s*(\w+)\s+(eq|ne)\s+(?:'((?:[^']|'')*)'|(true|false|null|[\w.-]+))\s*$", re.IGNORECASE)
_STARTS = re.compile(r"^\s*startswith\(\s*(\w+)\s*,\s*'((?:[^']|'')*)'\s*\)\s*$", re.IGNORECASE)


class ODataError(ValueError):
    pass


def _norm(v):
    return str(v).lower() if v is not None else None


def _clause(text):
    m = _EQ.match(text)
    if m:
        field, op, quoted, bare = m.groups()
        value = quoted.replace("''", "'") if quoted is not None else bare
        if value is not None and value.lower() == 'null':
            value = None
        if op.lower() == 'eq':
            return lambda o: _norm(o.get(field)) == _norm(value)
        return lambda o: _norm(o.get(field)) != _norm(value)
    m = _STARTS.match(text)
    if m:
        field, prefix = m.group(1), m.group(2).replace("''", "'").lower()
        return lambda o: str(o.get(field) or '').lower().startswith(prefix)
    raise ODataError(f"Invalid filter clause: {text.strip()}")


def apply(items):
    """Apply $filter / $top / $select from the current request to a list of dicts."""
    flt = request.args.get('$filter')
    if flt:
        preds = [_clause(part) for part in re.split(r'\s+and\s+', flt, flags=re.IGNORECASE)]
        items = [o for o in items if all(p(o) for p in preds)]
    top = request.args.get('$top')
    if top:
        try:
            items = items[:int(top)]
        except ValueError:
            raise ODataError(f'Invalid $top value: {top}')
    select = request.args.get('$select')
    if select:
        fields = [f.strip() for f in select.split(',') if f.strip()]
        items = [{k: o.get(k) for k in fields if k in o} for o in items]
    return items
