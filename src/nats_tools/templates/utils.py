import typing as t
from pathlib import Path

import jinja2


def load_template_from_path(template: t.Union[str, Path]) -> jinja2.Template:
    """Load a jinja2 template from path."""
    filepath = Path(template).absolute()
    if not filepath.exists():
        raise FileNotFoundError(filepath.as_posix())
    loader = jinja2.FileSystemLoader(filepath.parent)
    environment = jinja2.Environment(loader=loader)
    return environment.get_template(filepath.name)


def load_template_from_name(template: str) -> jinja2.Template:
    """Load a jinja2 template from name."""
    loader = jinja2.FileSystemLoader(Path(__file__).parent.joinpath("data"))
    environment = jinja2.Environment(loader=loader)
    return environment.get_template(template)
