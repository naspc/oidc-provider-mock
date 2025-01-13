# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import sys
from pathlib import Path

# Allow autodoc to import modules
sys.path.insert(0, str(Path("..", "src").resolve()))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "oidc-provider-mock"
copyright = "2025, Thomas Scholtes"
author = "Thomas Scholtes"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "myst_parser",
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "flask": ("https://flask.palletsprojects.com/en/stable/", None),
}

html_theme = "furo"
templates_path = ["_templates"]
html_title = "OIDC Provider Mock"
html_sidebars = {
    "**": [
        "sidebar/brand.html",
        "sidebar/scroll-start.html",
        # "sidebar/search.html",
        "sidebar/navigation.html",
        # "sidebar/ethical-ads.html",
        "sidebar_bottom.html",
        "sidebar/scroll-end.html",
        "sidebar/variant-selector.html",
    ]
}
