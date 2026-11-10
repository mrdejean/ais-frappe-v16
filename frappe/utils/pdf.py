# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# License: MIT. See LICENSE
import base64
import contextlib
import io
import mimetypes
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

import frappe
from frappe import _
from frappe.core.doctype.file.utils import find_file_by_url
from frappe.utils import cstr
from frappe.utils.data import get_url
from frappe.utils.jinja_globals import is_rtl

if TYPE_CHECKING:
	import cssutils
	from bs4 import BeautifulSoup
	from pypdf import PdfWriter


def pdf_header_html(soup, head, content, styles, html_id, css, path=None):
	if not path:
		path = "templates/print_formats/pdf_header_footer.html"
	return frappe.render_template(
		path,
		{
			"head": head,
			"content": content,
			"styles": styles,
			"html_id": html_id,
			"css": css,
			"lang": frappe.local.lang,
			"layout_direction": "rtl" if is_rtl() else "ltr",
		},
	)


def pdf_body_html(template, args, **kwargs):
	try:
		return template.render(args, filters={"len": len})
	except Exception as e:
		# Guess line number ?
		frappe.throw(
			_("Error in print format on line {0}: {1}").format(
				_guess_template_error_line_number(template), str(e)
			),
			exc=frappe.PrintFormatError,
			title=_("Print Format Error"),
		)


def _guess_template_error_line_number(template) -> int | None:
	"""Guess line on which exception occurred from current traceback."""
	with contextlib.suppress(Exception):
		import sys
		import traceback

		_, _, tb = sys.exc_info()

		for frame in reversed(traceback.extract_tb(tb)):
			if template.filename in frame.filename:
				return frame.lineno


def pdf_footer_html(soup, head, content, styles, html_id, css, path=None):
	return pdf_header_html(
		soup=soup, head=head, content=content, styles=styles, html_id=html_id, css=css, path=path
	)


def get_pdf(
	html,
	options=None,
	output: PdfWriter | None = None,
	smart_shrinking: bool = False,
	*,
	print_format: str | None = None,
):
	"""Render legacy/direct HTML through guarded Chromium.

	The original positional API, PdfWriter accumulation and final-byte password
	behavior are retained. Transport, filesystem and scripting switches specific
	to the removed renderer are rejected. Other registered print engines keep
	their existing hooks; this function always uses Chromium.
	"""
	from pypdf import PdfReader, PdfWriter

	if not isinstance(html, str):
		raise frappe.ValidationError("PDF HTML must be a string")
	if output is not None and not isinstance(output, PdfWriter):
		raise frappe.ValidationError("PDF output must be a PdfWriter")
	render_options = _chrome_options(options, smart_shrinking)
	password = render_options.pop("password", None)
	from bs4 import BeautifulSoup

	# The guarded Browser resolves relative resources against the configured
	# canonical site and enforces File permission. Do not expand URLs from the
	# incoming request Host or inline files by path before that origin check.
	soup = BeautifulSoup(html, "html5lib")
	toggle_visible_pdf(soup)
	rendered = _render_chrome_pdf(print_format, str(soup), render_options)
	if not isinstance(rendered, bytes):
		raise frappe.ValidationError("Chromium did not return PDF bytes")
	reader = PdfReader(io.BytesIO(rendered))
	if output is not None:
		output.append_pages_from_reader(reader)
		return output

	writer = PdfWriter()
	writer.append_pages_from_reader(reader)
	if password is not None:
		writer.encrypt(password)
	return get_file_data_from_writer(writer)


def _chrome_options(options, smart_shrinking=False):
	"""Copy the bounded legacy option surface and force the HTML-render policy."""
	if options is not None and not isinstance(options, dict):
		raise frappe.ValidationError("PDF options must be a dictionary")
	result = dict(options or {})
	allowed = {
		"page-size",
		"page-width",
		"page-height",
		"orientation",
		"margin-top",
		"margin-bottom",
		"margin-left",
		"margin-right",
		"header-spacing",
		"page-ranges",
		"password",
		"fit-height",
		"header-includes-top-margin",
		"generate-tagged-pdf",
		"generate-outline",
		"shrink-to-fit",
		"block-external-requests",
		"disable-javascript",
		"disable-local-file-access",
		"disable-smart-shrinking",
		"print-media-type",
		"background",
		"images",
		"quiet",
		"encoding",
		"no-outline",
	}
	unsupported = set(result) - allowed
	if unsupported:
		raise frappe.ValidationError(
			"Unsupported PDF options for Chromium: " + ", ".join(sorted(map(str, unsupported)))
		)
	if result.get("encoding") not in (None, "", "utf-8", "UTF-8"):
		raise frappe.ValidationError("Chromium PDF HTML must use UTF-8")
	password = result.get("password")
	if password is not None and not isinstance(password, str):
		raise frappe.ValidationError("PDF password must be a string")
	for flag in (
		"fit-height",
		"header-includes-top-margin",
		"generate-tagged-pdf",
		"generate-outline",
		"shrink-to-fit",
	):
		if flag in result and not isinstance(result[flag], bool):
			raise frappe.ValidationError(f"PDF option {flag} must be a boolean")
	orientation = result.get("orientation")
	if orientation is not None and (
		not isinstance(orientation, str) or orientation.lower() not in ("portrait", "landscape")
	):
		raise frappe.ValidationError("PDF orientation must be Portrait or Landscape")
	if "header-spacing" in result:
		import math
		import re

		from frappe.utils.print_utils import convert_uom, parse_float_and_unit

		spacing = result["header-spacing"]
		if (
			isinstance(spacing, bool)
			or not isinstance(spacing, str | int | float)
			or (
				isinstance(spacing, str)
				and not re.fullmatch(r"[+-]?\d+(?:\.\d+)?(?:px|mm|cm|in)?", spacing.strip())
			)
			or (isinstance(spacing, int | float) and not math.isfinite(spacing))
		):
			raise frappe.ValidationError("PDF header-spacing must be a finite length")
		parsed = parse_float_and_unit(spacing.strip() if isinstance(spacing, str) else spacing)
		if not parsed:
			raise frappe.ValidationError("PDF header-spacing must be a length")
		result["header-spacing"] = convert_uom(parsed["value"], parsed["unit"], "px", only_number=True)
	disable_shrinking = "disable-smart-shrinking" in result
	# Chromium already uses print media, UTF-8, backgrounds and images. No
	# renderer command-line switches or temporary-file options are passed on.
	for option in (
		"print-media-type",
		"background",
		"images",
		"quiet",
		"encoding",
		"no-outline",
		"disable-smart-shrinking",
	):
		result.pop(option, None)
	result["shrink-to-fit"] = (
		False if disable_shrinking else bool(smart_shrinking or result.get("shrink-to-fit"))
	)
	result.update(
		{
			"block-external-requests": True,
			"disable-javascript": True,
			"disable-local-file-access": True,
		}
	)
	return result


def measure_time(func):
	import time

	def wrapper(*args, **kwargs):
		start_time = time.time()
		result = func(*args, **kwargs)
		end_time = time.time()
		print(f"Function {func.__name__} took {end_time - start_time:.4f} seconds")
		return result

	return wrapper


def encrypt_pdf(content: bytes, password: str) -> bytes:
	from pypdf import PdfReader, PdfWriter

	writer = PdfWriter(clone_from=PdfReader(io.BytesIO(content)))
	writer.encrypt(password)
	stream = io.BytesIO()
	writer.write(stream)
	return stream.getvalue()


def get_chrome_pdf(print_format, html, options, output, pdf_generator=None):
	"""Built-in Chrome hook with the same guarded writer/password contract."""
	if pdf_generator != "chrome":
		return
	return get_pdf(html, options, output, print_format=print_format)


@measure_time
def _render_chrome_pdf(print_format, html, options):
	"""Render bytes internally; get_pdf owns final accumulation/encryption."""
	from frappe.utils.pdf_generator.browser import Browser
	from frappe.utils.pdf_generator.chrome_pdf_generator import ChromePDFGenerator
	from frappe.utils.pdf_generator.pdf_merge import PDFTransformer

	# scrubbing url to expand url is not required as we have set url.
	# also, planning to remove network requests anyway 🤞
	generator = ChromePDFGenerator()
	browser = None
	try:
		browser = Browser(generator, print_format, html, options)
		transformer = PDFTransformer(browser)
		# transforms and merges header, footer into body pdf and returns merged pdf
		return transformer.transform_pdf()
	finally:
		generator._close_browser()


def get_plutoprint_pdf(print_format, html, options, output, pdf_generator=None):
	from frappe.utils.pdf_generator.pdf_merge import PDFTransformer
	from frappe.utils.pdf_generator.pluto import PlutoBrowser, plutoprint_can_render

	if pdf_generator != "PlutoPrint":
		return
	options = options or {}
	if options.get("page-ranges") or not plutoprint_can_render(html):
		return get_chrome_pdf(print_format, html, options, output, pdf_generator="chrome")
	return PDFTransformer(PlutoBrowser(print_format, html, options)).transform_pdf(output=output)


def get_file_data_from_writer(writer_obj):
	# https://docs.python.org/3/library/io.html
	stream = io.BytesIO()
	writer_obj.write(stream)

	# Change the stream position to start of the stream
	stream.seek(0)

	# Read up to size bytes from the object and return them
	return stream.read()


def get_print_format_styles(soup: BeautifulSoup) -> list[cssutils.css.Property]:
	"""
	Get styles purely on class 'print-format'.
	Valid:
	1) .print-format { ... }
	2) .print-format, p { ... } | p, .print-format { ... }

	Invalid (applied on child elements):
	1) .print-format p { ... } | .print-format > p { ... }
	2) .print-format #abc { ... }

	Returns:
	[cssutils.css.Property(name='margin-top', value='50mm', priority=''), ...]
	"""
	import cssutils

	cssutils.log.setLog(frappe.logger("cssutils"))

	stylesheet = ""
	style_tags = soup.find_all("style")

	# Prepare a css stylesheet from all the style tags' contents
	for style_tag in style_tags:
		stylesheet += cstr(style_tag.string)

	# Use css parser to tokenize the classes and their styles
	parsed_sheet = cssutils.CSSParser(fetcher=lambda url: (None, "")).parseString(stylesheet)

	# Get all styles that are only for .print-format
	valid_styles = []
	for rule in parsed_sheet:
		if not isinstance(rule, cssutils.css.CSSStyleRule):
			continue

		# Allow only .print-format { ... } and .print-format, p { ... }
		# Disallow .print-format p { ... } and .print-format > p { ... }
		if ".print-format" in [x.strip() for x in rule.selectorText.split(",")]:
			valid_styles.extend(entry for entry in rule.style)

	return valid_styles


def inline_private_images(html) -> str:
	from bs4 import BeautifulSoup

	soup = BeautifulSoup(html, "html.parser")
	for img in soup.find_all("img"):
		if b64 := _get_base64_image(img["src"]):
			img["src"] = b64
	return str(soup)


def _get_base64_image(src):
	"""Return base64 version of image if user has permission to view it"""
	try:
		parsed_url = urlparse(src)
		path = parsed_url.path
		query = parse_qs(parsed_url.query)
		mime_type = mimetypes.guess_type(path)[0]
		if mime_type is None or not mime_type.startswith("image/"):
			return
		filename = (query.get("fid") and query["fid"][0]) or None
		file = find_file_by_url(path, name=filename)
		if not file or not file.is_private:
			return

		b64_encoded_image = base64.b64encode(file.get_content()).decode()
		return f"data:{mime_type};base64,{b64_encoded_image}"
	except Exception:
		frappe.logger("pdf").error("Failed to convert inline images to base64", exc_info=True)


def toggle_visible_pdf(soup):
	for tag in soup.find_all(attrs={"class": "visible-pdf"}):
		# remove visible-pdf class to unhide
		tag.attrs["class"].remove("visible-pdf")

	for tag in soup.find_all(attrs={"class": "hidden-pdf"}):
		# remove tag from html
		tag.extract()


@frappe.whitelist()
def is_wkhtmltopdf_valid():
	"""Compatibility read: this framework candidate has no wkhtmltopdf engine."""
	return False


def get_wkhtmltopdf_version():
	"""Compatibility read for integrations that inspected the retired engine."""
	return "0"


def pdf_contains_js(file_content: bytes):
	"""
	Check if a PDF file contains JavaScript.

	Args:
		file_content (bytes): The content of the PDF file.

	Returns:
		bool: True if the PDF contains JavaScript, False otherwise and also if the file is encrypted.
	"""
	from io import BytesIO

	from pypdf import PdfReader, errors
	from pypdf.generic import IndirectObject

	reader = PdfReader(BytesIO(file_content))

	def has_javascript(obj, seen=None):
		if seen is None:
			seen = set()
		if isinstance(obj, IndirectObject):
			key = (obj.idnum, obj.generation)
			if key in seen:
				return False
			seen.add(key)
			obj = obj.get_object()
		if isinstance(obj, dict):
			for key, value in obj.items():
				if key == "/Parent":
					continue
				if key in ("/JS", "/JavaScript"):
					return True
				if has_javascript(value, seen):
					return True
		elif isinstance(obj, list):
			for item in obj:
				if has_javascript(item, seen):
					return True
		return False

	root = reader.trailer.get("/Root", {})

	try:
		if has_javascript(root):
			return True

		for page in reader.pages:
			if has_javascript(page):
				return True
	except errors.FileNotDecryptedError:
		# resolving any indirect object (root, page, or otherwise) requires
		# decryption; an encrypted file we can't decrypt is treated as not
		# containing JS, same as an unreadable/undecryptable file always was
		pass

	return False


def get_host_url():
	if frappe.request:
		return frappe.request.host_url
	else:
		return get_url() + "/"
