"""Embed the primary implementation's assets verbatim, without runtime paths."""
import pathlib
import sys

root, output = map(pathlib.Path, sys.argv[1:])
sources = {
    "default_rules": root / "internal/classify/defaults.json",
    "conformance": root / "testdata/conformance/classification.json",
    "index_html": root / "internal/dashboard/web/index.html",
    "app_js": root / "internal/dashboard/web/app.js",
    "style_css": root / "internal/dashboard/web/style.css",
}
output.parent.mkdir(parents=True, exist_ok=True)
with output.open("w") as stream:
    stream.write("#pragma once\n#include <string_view>\nnamespace embedded {\n")
    for name, path in sources.items():
        data = path.read_bytes()
        stream.write(f"inline constexpr unsigned char {name}_data[] = {{")
        stream.write(",".join(map(str, data)))
        stream.write("};\n")
        stream.write(
            f"inline const std::string_view {name}"
            f"(reinterpret_cast<const char*>({name}_data), sizeof({name}_data));\n"
        )
    stream.write("}\n")
