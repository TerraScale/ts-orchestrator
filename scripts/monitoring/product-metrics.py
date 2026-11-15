import re
import sys
from pathlib import Path

UNITS = {"s": "seconds", "ms": "milliseconds", "By": "bytes", "1": "ratio"}
CREATE = re.compile(r"\.Create(Counter|Histogram|Gauge|UpDownCounter|ObservableCounter|ObservableGauge|ObservableUpDownCounter)\s*(?:<[^>()]+>)?\(\s*\"([^\"]+)\"")
STRING = re.compile(r'\s*(?:unit\s*:\s*)?"((?:[^"\\]|\\.)*)"')


def arguments(text, start):
    depth, current, result, index = 0, start, [], start
    while index < len(text):
        character = text[index]
        if character == '"':
            index = text.index('"', index + 1)
            while text[index - 1] == "\\":
                index = text.index('"', index + 1)
        elif character in "([{":
            depth += 1
        elif character in ")]}":
            if depth == 0:
                result.append(text[current:index])
                return result
            depth -= 1
        elif character == "," and depth == 0:
            result.append(text[current:index])
            current = index + 1
        index += 1
    return result


def unit(kind, rest):
    positional = [argument for argument in rest if not re.match(r"\s*(description|tags|advice)\s*:", argument)]
    if kind.startswith("Observable") and positional:
        positional = positional[1:]
    for argument in positional:
        match = STRING.fullmatch(argument.strip() and argument)
        if match:
            return match.group(1)
        return None
    return None


def names(kind, name, symbol):
    base = name.replace(".", "_").replace("-", "_")
    if symbol and not symbol.startswith("{") and UNITS.get(symbol, symbol) and not (symbol == "1" and kind in ("Counter", "ObservableCounter", "Histogram")):
        suffix = UNITS.get(symbol)
        if suffix and not base.endswith("_" + suffix):
            base += "_" + suffix
    if kind in ("Counter", "ObservableCounter"):
        return [base if base.endswith("_total") else base + "_total"]
    if kind == "Histogram":
        return [base + "_bucket", base + "_sum", base + "_count"]
    return [base]


def catalog(product):
    found = set()
    for project in ("src/TerraBase", "src/TerraScale.Authentication"):
        for path in sorted((product / project).rglob("*.cs")):
            text = path.read_text()
            for match in CREATE.finditer(text):
                kind, name = match.groups()
                rest = arguments(text, match.end())
                rest = rest[1:] if rest and rest[0].strip() == "" else rest
                found.update(names(kind, name, unit(kind, rest)))
    return sorted(found)


product, production, target = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
live = {name for name in production.read_text().split() if name.startswith(("terrabase_", "ts_auth_"))}
rendered = "".join(name + "\n" for name in sorted(set(catalog(product)) | live))
if len(sys.argv) == 5 and sys.argv[4] == "--check":
    if target.read_text() != rendered:
        sys.exit(f"{target} differs from the instruments in {product} and {production}; regenerate it")
else:
    target.write_text(rendered)
