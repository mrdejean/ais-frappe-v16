"""Isolated regression evidence for the unsupported AIS pdfkit-free prototype.

These tests render with the actual configured Chrome binary. They do not send
mail, print to a device, or establish hosted compatibility or AIS acceptance.
"""

import importlib.util
import io
import os
import tempfile
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from PIL import Image
from pypdf import PdfReader, PdfWriter
from werkzeug.wrappers import Request

import frappe
from frappe.tests import IntegrationTestCase
from frappe.utils import pdf as pdfgen


def _reader(content):
	if not isinstance(content, bytes) or not content.startswith(b"%PDF-"):
		raise AssertionError("The real renderer did not return PDF bytes")
	return PdfReader(io.BytesIO(content))


def _text(reader):
	return "\n".join(page.extract_text() or "" for page in reader.pages)


def _image_count(reader):
	return sum(len(page.images) for page in reader.pages)


def declining_pdf_hook(**kwargs):
	"""A registered test hook which intentionally does not handle this engine."""
	return None


@contextmanager
def _request_counter():
	"""Observe only a disposable loopback server; no real external host is probed."""
	requests = []

	class Handler(BaseHTTPRequestHandler):
		def do_GET(self):
			requests.append(self.path)
			self.send_response(200)
			self.send_header("Content-Type", "text/plain")
			self.end_headers()
			self.wfile.write(b"AIS FORBIDDEN NETWORK RESPONSE")

		def log_message(self, *args):
			pass

	server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
	thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
	thread.start()
	try:
		yield f"http://127.0.0.1:{server.server_port}", requests
	finally:
		server.shutdown()
		server.server_close()
		thread.join(timeout=2)


class TestAisPdfkitFree(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		if os.environ.get("AIS_PDFKIT_FREE_PROTOTYPE") != "Yes" or not frappe.local.site.startswith("test_"):
			raise RuntimeError(
				"PDF prototype regression requires explicit opt-in and a disposable test_ site"
			)
		self.previous_user = frappe.session.user
		frappe.set_user("Administrator")
		self.addCleanup(frappe.set_user, self.previous_user)
		self.marker = f"AISPDF{frappe.generate_hash(length=10)}"

	@contextmanager
	def _response(self):
		previous = frappe.local.response
		frappe.local.response = frappe._dict()
		try:
			yield frappe.local.response
		finally:
			frappe.local.response = previous

	def _delete(self, doc):
		with self.set_user("Administrator"):
			if frappe.db.exists(doc.doctype, doc.name):
				doc.delete(ignore_permissions=True)

	def _user(self):
		doc = frappe.get_doc(
			{
				"doctype": "User",
				"email": f"ais-pdf-{frappe.generate_hash(length=12)}@test.invalid",
				"first_name": "Synthetic PDF reader",
				"send_welcome_email": 0,
				"user_type": "Website User",
			}
		).insert(ignore_permissions=True)
		self.addCleanup(self._delete, doc)
		return doc.name

	def _image(self, private=False):
		stream = io.BytesIO()
		image = Image.new("RGB", (32, 32), (215, 35, 35))
		image.putpixel((0, 0), (0, 0, 255))
		image.save(stream, format="PNG")
		doc = frappe.get_doc(
			{
				"doctype": "File",
				"file_name": f"{self.marker}-{frappe.generate_hash(length=6)}.png",
				"content": stream.getvalue(),
				"is_private": int(private),
			}
		).insert(ignore_permissions=True)
		self.addCleanup(self._delete, doc)
		# The creation object retains flags.ignore_permissions=True. Permission
		# checks must use a fresh read, as the production URL resolver does.
		return frappe.get_doc("File", doc.name)

	def _todo_and_format(self):
		todo = frappe.get_doc({"doctype": "ToDo", "description": self.marker}).insert()
		print_format = frappe.get_doc(
			{
				"doctype": "Print Format",
				"name": f"AIS PDF prototype {frappe.generate_hash(length=10)}",
				"doc_type": "ToDo",
				"standard": "No",
				"custom_format": 1,
				"print_format_type": "Jinja",
				"pdf_generator": "chrome",
				"html": '<div class="print-format"><p>{{ doc.description }}</p></div>',
			}
		).insert(ignore_permissions=True)
		self.addCleanup(self._delete, todo)
		self.addCleanup(self._delete, print_format)
		return todo, print_format

	def test_pdfkit_is_absent_and_raw_html_really_renders(self):
		self.assertIsNone(importlib.util.find_spec("pdfkit"))
		reader = _reader(pdfgen.get_pdf(f"<p>{self.marker}</p>"))
		self.assertEqual(len(reader.pages), 1)
		self.assertIn(self.marker, _text(reader))
		self.assertFalse(pdfgen.pdf_contains_js(pdfgen.get_pdf("<p>Clean PDF</p>")))

	def test_trusted_root_matches_chromium_navigation_and_only_same_origin_resources(self):
		from concurrent.futures import Future
		from unittest.mock import MagicMock

		from frappe.utils.pdf_generator import page as page_module

		for configured, expected in (
			("https://PDF.Example:443", "https://pdf.example/"),
			("https://pdf.example/", "https://pdf.example/"),
			("http://PDF.Example:80", "http://pdf.example/"),
			("http://pdf.example:8000", "http://pdf.example:8000/"),
			("https://b\u00fccher.example", "https://xn--bcher-kva.example/"),
			("http://[::1]:80", "http://[::1]/"),
		):
			with (
				self.subTest(configured=configured),
				patch.object(frappe.utils, "get_url", return_value=configured) as get_url,
			):
				self.assertEqual(page_module.get_trusted_site_url(), expected)
				get_url.assert_called_once_with(allow_header_override=False)

		# Use the actual interception callbacks: the initial stub must catch every
		# request, deny unexpected navigation and complete only for Chromium's '/'.
		page = page_module.Page.__new__(page_module.Page)
		page.block_external_requests = True
		page.trusted_site_url = "https://pdf.example/"
		page.session_id, page.target_id, page.frame_id = "session", "target", "frame"
		page.session = MagicMock()
		page.send = MagicMock()
		future = Future()
		page.session.loop.create_future.return_value = future
		fulfill = page.intercept_request_and_fulfill(page.trusted_site_url)
		page.send.assert_called_once_with("Fetch.enable", {"patterns": [{"urlPattern": "*"}]})
		callback = page.session.start_listener.call_args.args[1]
		callback(
			future,
			{"params": {"requestId": "unexpected", "request": {"url": "https://pdf.example/api/method/x"}}},
		)
		self.assertFalse(future.done())
		page.send.assert_called_with(
			"Fetch.failRequest",
			{"requestId": "unexpected", "errorReason": "AccessDenied"},
			return_future=True,
		)
		callback(future, {"params": {"requestId": "root", "request": {"url": page.trusted_site_url}}})
		self.assertEqual(future.result(timeout=0), "root")
		fulfill()
		page.send.assert_called_with(
			"Fetch.fulfillRequest", {"requestId": "root", "responseCode": 200}, return_future=True
		)
		page.session.wait_for_event.assert_called_once_with(future)
		self.assertFalse(hasattr(page, "_guarded_stub_future"))
		with patch.object(page_module, "read_guarded_local_resource") as reader:
			callback(
				future,
				{
					"params": {
						"requestId": "before-handoff",
						"request": {"url": "https://pdf.example/files/safe.png"},
					}
				},
			)
			reader.assert_not_called()
			page.send.assert_called_with(
				"Fetch.failRequest",
				{"requestId": "before-handoff", "errorReason": "AccessDenied"},
				return_future=True,
			)

		page.intercept_request_for_local_resources()
		page.session.start_listener.assert_called_once()
		page.session.remove_listener.assert_not_called()
		self.assertEqual([call.args[0] for call in page.send.call_args_list].count("Fetch.enable"), 1)
		with patch.object(
			page_module, "read_guarded_local_resource", return_value=("c2FmZQ==", "image/png")
		) as reader:
			callback(
				future,
				{
					"params": {
						"requestId": "asset",
						"request": {"url": "https://PDF.Example:443/files/safe.png"},
					}
				},
			)
			reader.assert_called_once_with("https://PDF.Example:443/files/safe.png")
			self.assertEqual(page.send.call_args.args[0], "Fetch.fulfillRequest")
			reader.reset_mock()
			callback(
				future,
				{
					"params": {
						"requestId": "spoof",
						"request": {"url": "https://pdf.example.attacker.invalid/files/safe.png"},
					}
				},
			)
			reader.assert_not_called()
			page.send.assert_called_with(
				"Fetch.failRequest", {"requestId": "spoof", "errorReason": "AccessDenied"}, return_future=True
			)
		commands = [call.args[0] for call in page.send.call_args_list]
		self.assertNotIn("Fetch.continueRequest", commands)
		self.assertNotIn("Fetch.disable", commands)

	def test_output_writer_appends_once_and_preserves_existing_pages(self):
		writer = PdfWriter()
		writer.add_blank_page(width=72, height=72)
		result = pdfgen.get_pdf(f"<p>{self.marker}</p>", output=writer)
		self.assertIs(result, writer)
		self.assertEqual(len(writer.pages), 2)
		self.assertEqual(float(writer.pages[0].mediabox.width), 72)
		self.assertIn(self.marker, writer.pages[1].extract_text())

	def test_password_encrypts_final_bytes(self):
		content = pdfgen.get_pdf(f"<p>{self.marker}</p>", options={"password": "synthetic-only"})
		reader = _reader(content)
		self.assertTrue(reader.is_encrypted)
		self.assertTrue(reader.decrypt("synthetic-only"))
		self.assertIn(self.marker, _text(reader))

	def test_custom_dimensions_orientation_and_page_range(self):
		reader = _reader(
			pdfgen.get_pdf(
				f"<p>{self.marker}</p>",
				options={"page-size": "Custom", "page-width": "80mm", "page-height": "120mm"},
			)
		)
		self.assertAlmostEqual(float(reader.pages[0].mediabox.width), 80 / 25.4 * 72, delta=3)
		self.assertAlmostEqual(float(reader.pages[0].mediabox.height), 120 / 25.4 * 72, delta=3)
		landscape = _reader(pdfgen.get_pdf("<p>Landscape</p>", options={"orientation": "Landscape"}))
		self.assertGreater(landscape.pages[0].mediabox.width, landscape.pages[0].mediabox.height)
		pages = '<p>AISFIRST</p><p style="page-break-before:always">AISSECOND</p><p style="page-break-before:always">AISTHIRD</p>'
		selected = _reader(pdfgen.get_pdf(pages, options={"page-ranges": "2"}))
		self.assertEqual(len(selected.pages), 1)
		self.assertIn("AISSECOND", _text(selected))
		self.assertNotIn("AISFIRST", _text(selected))
		self.assertNotIn("AISTHIRD", _text(selected))

	def test_static_header_and_dynamic_page_footer_render_on_each_page(self):
		content = (
			"<style>.print-format { header-spacing: 5mm; }</style>"
			'<div id="header-html"><b>AISHEADER</b></div>'
			'<p>AISBODYONE</p><p style="page-break-before:always">AISBODYTWO</p>'
			'<div id="footer-html">Page <span class="page"></span> of <span class="topage"></span></div>'
		)
		reader = _reader(pdfgen.get_pdf(content))
		self.assertEqual(len(reader.pages), 2)
		for number, page in enumerate(reader.pages, start=1):
			text = page.extract_text()
			self.assertIn("AISHEADER", text)
			self.assertIn(f"Page {number} of 2", text)

	def test_report_renders_landscape_and_wide_content_is_scaled_inside_page(self):
		from frappe.utils.print_format import report_to_pdf

		html = '<div style="width:1400px;display:flex;justify-content:space-between"><span>AISLEFTEDGE</span><span>AISRIGHTEDGE</span></div>'
		with self._response() as response:
			report_to_pdf(html, orientation="Landscape")
			reader = _reader(response.filecontent)
			self.assertEqual(response.type, "pdf")
			self.assertGreater(reader.pages[0].mediabox.width, reader.pages[0].mediabox.height)
			positions = []

			def record(text, cm, tm, *_):
				if "AISRIGHTEDGE" in text:
					positions.append(tm[4] * cm[0] + tm[5] * cm[2] + cm[4])

			reader.pages[0].extract_text(visitor_text=record)
			self.assertTrue(positions, "The right edge of the wide report was not rendered")
			for x in positions:
				self.assertGreaterEqual(x, 0)
				self.assertLess(x, float(reader.pages[0].mediabox.right) - 10)

	def test_normal_document_print_and_raw_html_attachment(self):
		todo, print_format = self._todo_and_format()
		with self.change_settings("Print Settings", pdf_generator="chrome", send_print_as_pdf=1):
			printed = frappe.get_print("ToDo", todo.name, print_format=print_format.name, as_pdf=True)
			self.assertIn(self.marker, _text(_reader(printed)))
			encrypted = _reader(
				frappe.get_print(
					"ToDo", todo.name, print_format=print_format.name, as_pdf=True, password="print-only"
				)
			)
			self.assertTrue(encrypted.is_encrypted)
			self.assertTrue(encrypted.decrypt("print-only"))
			self.assertIn(self.marker, _text(encrypted))
			empty_password = _reader(
				frappe.get_print("ToDo", todo.name, print_format=print_format.name, as_pdf=True, password="")
			)
			self.assertTrue(empty_password.is_encrypted)
			self.assertTrue(empty_password.decrypt(""))
			self.assertIn(self.marker, _text(empty_password))
			attached = frappe.attach_print("ToDo", todo.name, print_format=print_format.name)
			self.assertTrue(attached["fname"].endswith(".pdf"))
			self.assertIn(self.marker, _text(_reader(attached["fcontent"])))
			raw = frappe.attach_print("ToDo", todo.name, html=f"<p>{self.marker} RAWATTACHMENT</p>")
			self.assertIn("RAWATTACHMENT", _text(_reader(raw["fcontent"])))
		self.assertFalse(frappe.local.flags.ignore_print_permissions)

	def test_email_pdf_attachment_assembles_mime_without_sending(self):
		from frappe.email.email_body import EMail

		mail = EMail(
			sender="pdf-sender@test.invalid",
			recipients=["pdf-recipient@test.invalid"],
			subject="Synthetic PDF fixture",
			email_account=frappe._dict(default_sender="pdf-sender@test.invalid"),
		)
		mail.add_pdf_attachment("synthetic.pdf", f"<p>{self.marker} EMAILATTACHMENT</p>")
		attachments = [part for part in mail.msg_root.walk() if part.get_filename() == "synthetic.pdf"]
		self.assertEqual(len(attachments), 1)
		self.assertIn("EMAILATTACHMENT", _text(_reader(attachments[0].get_payload(decode=True))))

	def test_auto_email_report_builds_actual_pdf_without_sending(self):
		# The built-in report supplies real data; only build content, never call send().
		report = frappe.get_doc(
			{
				"doctype": "Auto Email Report",
				"name": self.marker,
				"report": "Permitted Documents For User",
				"report_type": "Script Report",
				"user": "Administrator",
				"enabled": 0,
				"format": "PDF",
				"no_of_rows": 5,
				"filters": frappe.as_json({"user": "Administrator", "doctype": "DocType"}),
			}
		)
		reader = _reader(report.get_report_content())
		self.assertGreaterEqual(len(reader.pages), 1)
		self.assertIn(self.marker, _text(reader))

	def test_missing_or_declining_custom_hook_never_falls_back_to_chrome(self):
		todo, print_format = self._todo_and_format()
		for hooks in ([], ["frappe.tests.test_ais_pdfkit_free.declining_pdf_hook"]):
			with (
				self.subTest(hooks=hooks),
				self.patch_hooks({"pdf_generator": hooks}),
				patch.object(frappe.local, "form_dict", frappe._dict()),
				patch.object(pdfgen, "get_pdf", side_effect=AssertionError("Unexpected Chrome fallback")),
				self.assertRaises(frappe.ValidationError),
			):
				frappe.get_print(
					"ToDo",
					todo.name,
					print_format=print_format.name,
					as_pdf=True,
					pdf_generator="unhandled-custom-engine",
				)

	def test_bulk_print_merges_two_actual_document_pdfs(self):
		from frappe.utils.print_format import _download_multi_pdf

		first, print_format = self._todo_and_format()
		second = frappe.get_doc({"doctype": "ToDo", "description": f"{self.marker} SECOND"}).insert()
		self.addCleanup(self._delete, second)
		with self.change_settings("Print Settings", pdf_generator="chrome"), self._response() as response:
			_download_multi_pdf("ToDo", frappe.as_json([first.name, second.name]), format=print_format.name)
			reader = _reader(response.filecontent)
			self.assertEqual(len(reader.pages), 2)
			self.assertIn(self.marker, _text(reader))
			self.assertIn("SECOND", _text(reader))

	def test_page_scripts_event_handlers_and_javascript_links_do_not_survive(self):
		html = (
			f"<p>{self.marker}</p>"
			'<script>document.body.append("AISJAVASCRIPTRAN")</script>'
			"<body onload=\"document.body.append('AISEVENTRAN')\">"
			"<a href=\"javascript:document.write('AISLINKRAN')\">Harmless link label</a>"
			"</body>"
		)
		pdf = pdfgen.get_pdf(html)
		reader = _reader(pdf)
		self.assertIn(self.marker, _text(reader))
		for marker in ("AISJAVASCRIPTRAN", "AISEVENTRAN", "AISLINKRAN"):
			self.assertNotIn(marker, _text(reader))
		self.assertFalse(pdfgen.pdf_contains_js(pdf))
		for page in reader.pages:
			for annotation in page.get("/Annots", []):
				action = annotation.get_object().get("/A", {})
				self.assertFalse(str(action.get("/URI", "")).lower().startswith(("javascript:", "vbscript:")))

	def test_external_loopback_imports_frames_and_file_urls_never_fetch(self):
		with _request_counter() as (external, requests), tempfile.TemporaryDirectory() as directory:
			secret = Path(directory) / "synthetic-secret.txt"
			secret.write_text("AISLOCALFILESECRET", encoding="utf-8")
			html = (
				f'<p>{self.marker}</p><style>@import url("{external}/import.css");'
				f'.probe{{background:url("{external}/background.png")}}</style>'
				f'<div class="probe">Safe body</div><img src="{external}/image.png">'
				f'<iframe src="{external}/frame"></iframe><object data="{secret.as_uri()}"></object>'
				f'<iframe src="{secret.as_uri()}"></iframe>'
			)
			text = _text(_reader(pdfgen.get_pdf(html)))
			self.assertIn(self.marker, text)
			self.assertNotIn("AISLOCALFILESECRET", text)
			self.assertNotIn("AIS FORBIDDEN NETWORK RESPONSE", text)
			self.assertEqual(requests, [])

	def test_same_site_public_asset_still_renders_with_poisoned_request_host(self):
		file = self._image()
		with _request_counter() as (external, requests):
			request = Request.from_values(base_url=external)
			with patch.object(frappe.local, "request", request, create=True):
				reader = _reader(pdfgen.get_pdf(f'<p>{self.marker}</p><img src="{file.file_url}">'))
			self.assertIn(self.marker, _text(reader))
			self.assertGreater(_image_count(reader), 0)
			self.assertEqual(requests, [])

	def test_private_image_requires_real_non_admin_file_permission(self):
		import hashlib
		import json

		from frappe.core.doctype.file.utils import find_file_by_url

		def pixels(image):
			rgb = image.convert("RGB")
			return (rgb.width, rgb.height, hashlib.sha256(rgb.tobytes()).hexdigest())

		def image_signatures(reader):
			return sorted(pixels(image.image) for page in reader.pages for image in page.images)

		pdfs = {}
		diagnostics = {}

		def write_evidence():
			directory = (
				Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
				/ "ais-pdf-regression-evidence"
				/ self.marker
			)
			directory.mkdir(parents=True, exist_ok=True)
			for label, content in pdfs.items():
				(directory / f"{label}.pdf").write_bytes(content)
			(directory / "image-identities.json").write_text(
				json.dumps(diagnostics, indent=2), encoding="utf-8"
			)
			print(f"AIS_PRIVATE_IMAGE_DIAGNOSTICS: {directory}")

		owner = self._user()
		other = self._user()
		with self.set_user(owner):
			file = self._image(private=True)
			self.assertNotEqual(frappe.session.user, "Administrator")
			self.assertEqual(file.owner, owner)
			self.assertTrue(file.is_private)
			self.assertTrue(file.file_url.startswith("/private/files/"))
			self.assertFalse(file.attached_to_doctype)
			self.assertFalse(file.attached_to_name)
			self.assertFalse(file.flags.ignore_permissions)
			file.check_permission("read")
			self.assertTrue(file.is_downloadable())
			self.assertEqual(find_file_by_url(file.file_url, name=file.name).name, file.name)
			protected_pixels = pixels(Image.open(io.BytesIO(file.get_content(encodings=[]))))
			protected_path = os.path.realpath(file.get_full_path())
			missing_url = f"/private/files/ais-missing-{frappe.generate_hash(length=20)}.png"
			self.assertFalse(frappe.db.exists("File", {"file_url": missing_url}))
			real_read_file = frappe.read_file

			def render(url):
				protected_reads = []

				def observe_read(path, *args, **kwargs):
					if (
						isinstance(path, str | bytes | os.PathLike)
						and os.path.realpath(os.fsdecode(path)) == protected_path
					):
						protected_reads.append(frappe.session.user)
					return real_read_file(path, *args, **kwargs)

				with patch.object(frappe, "read_file", side_effect=observe_read):
					# The only difference between protected/control HTML is the URL.
					content = pdfgen.get_pdf(f'<p>{self.marker}</p><img width="32" height="32" src="{url}">')
				return content, protected_reads

			pdfs["owner-allowed"], owner_reads = render(file.file_url)
			pdfs["owner-missing-control"], owner_control_reads = render(missing_url)
			write_evidence()
			allowed = _reader(pdfs["owner-allowed"])
			allowed_signatures = image_signatures(allowed)
			owner_control_signatures = image_signatures(_reader(pdfs["owner-missing-control"]))
			diagnostics["owner"] = {
				"protected_pixels": protected_pixels,
				"allowed_images": allowed_signatures,
				"missing_control_images": owner_control_signatures,
				"protected_path_reads": len(owner_reads),
				"reads_attributed_to_owner": all(user == owner for user in owner_reads),
			}
			print("AIS_PRIVATE_IMAGE_IDENTITIES: " + json.dumps(diagnostics["owner"], sort_keys=True))
			write_evidence()
			try:
				self.assertIn(self.marker, _text(allowed))
				self.assertIn(protected_pixels, allowed_signatures)
				self.assertNotIn(protected_pixels, owner_control_signatures)
				self.assertNotEqual(allowed_signatures, owner_control_signatures)
				self.assertTrue(owner_reads, "Authorized rendering must actually read the protected file")
				self.assertTrue(all(user == owner for user in owner_reads))
				self.assertEqual(owner_control_reads, [])
			except AssertionError:
				write_evidence()
				raise
		for label, user in (("guest", "Guest"), ("unrelated-user", other)):
			with self.subTest(user=user), self.set_user(user):
				fresh = frappe.get_doc("File", file.name)
				self.assertFalse(fresh.flags.ignore_permissions)
				self.assertFalse(fresh.has_permission("read"))
				self.assertFalse(fresh.is_downloadable())
				self.assertIsNone(find_file_by_url(file.file_url, name=file.name))
				self.assertIsNone(find_file_by_url(file.file_url))
				pdfs[f"{label}-denied"], denied_reads = render(file.file_url)
				pdfs[f"{label}-missing-control"], control_reads = render(missing_url)
				write_evidence()
				denied = _reader(pdfs[f"{label}-denied"])
				control = _reader(pdfs[f"{label}-missing-control"])
				denied_signatures = image_signatures(denied)
				control_signatures = image_signatures(control)
				diagnostics[label] = {
					"denied_images": denied_signatures,
					"missing_control_images": control_signatures,
					"protected_path_reads": len(denied_reads),
					"control_protected_path_reads": len(control_reads),
				}
				print(
					"AIS_PRIVATE_IMAGE_IDENTITIES: " + json.dumps({label: diagnostics[label]}, sort_keys=True)
				)
				write_evidence()
				try:
					self.assertIn(self.marker, _text(denied))
					self.assertIn(self.marker, _text(control))
					self.assertNotIn(protected_pixels, denied_signatures)
					self.assertNotIn(protected_pixels, control_signatures)
					self.assertEqual(denied_signatures, control_signatures, diagnostics[label])
					self.assertEqual(denied_reads, [], "Unauthorized render read protected bytes")
					self.assertEqual(control_reads, [])
				except AssertionError:
					write_evidence()
					raise

	def test_renderer_migration_preserves_inherited_and_nonlegacy_choices(self):
		from frappe.patches.v16_0 import ais_inventory_and_switch_legacy_pdf_renderers as migration

		for site in ("PlutoPrint", "Typst", "WeasyPrint", "custom-hook"):
			with self.subTest(site=site):
				self.assertEqual(migration.format_replacement(""), "")
				self.assertEqual(migration.configured_generator("", site), site)
				self.assertEqual(migration.replacement(site), site)
				self.assertEqual(migration.format_replacement(site), site)
		for site in (None, "", "wkhtmltopdf"):
			self.assertEqual(migration.replacement(site), "chrome")
		self.assertEqual(migration.format_replacement("wkhtmltopdf"), "chrome")
		setter = frappe._dict(
			doc_type="Print Format", property="options", value="\nwkhtmltopdf\nchrome\ncustom-hook\nTypst"
		)
		self.assertEqual(migration.setter_replacement(setter), "\nchrome\ncustom-hook\nTypst")
		setter.update(property="default", value="")
		self.assertEqual(migration.setter_replacement(setter), "")

	def test_renderer_migration_retains_original_inventory_before_switch_and_is_idempotent(self):
		from frappe.patches.v16_0 import ais_inventory_and_switch_legacy_pdf_renderers as migration

		_, print_format = self._todo_and_format()
		previous = frappe.db.get_single_value("Print Settings", "pdf_generator")
		self.addCleanup(frappe.db.set_single_value, "Print Settings", "pdf_generator", previous)
		# Simulate pre-migration persisted values without weakening the new validator.
		frappe.db.set_single_value("Print Settings", "pdf_generator", "wkhtmltopdf")
		frappe.db.set_value("Print Format", print_format.name, "pdf_generator", "wkhtmltopdf")
		marker = f"AIS_PDF_INVENTORY_TEST_{frappe.generate_hash(length=12)}"
		with patch.object(migration, "INVENTORY_MARKER", marker):
			migration.execute()
			filters = {"data": ("like", f"%{marker}%")}
			first = frappe.get_all(
				"Version", filters=filters, fields=["name", "ref_doctype", "docname", "data"]
			)
			self.assertTrue(first)
			stored = next(
				row for row in first if row.ref_doctype == "Print Format" and row.docname == print_format.name
			)
			facts = frappe.parse_json(stored.data)[marker]
			self.assertEqual(facts["stored_pdf_generator"], "wkhtmltopdf")
			self.assertEqual(facts["target_pdf_generator"], "chrome")
			self.assertFalse(facts["compatibility_verified"])
			self.assertEqual(frappe.db.get_single_value("Print Settings", "pdf_generator"), "chrome")
			self.assertEqual(
				frappe.db.get_value("Print Format", print_format.name, "pdf_generator"), "chrome"
			)
			migration.execute()
			second = frappe.get_all(
				"Version", filters=filters, fields=["name", "ref_doctype", "docname", "data"]
			)
			self.assertEqual({row.name: row.data for row in first}, {row.name: row.data for row in second})

	def test_legacy_script_network_and_file_path_options_fail_closed(self):
		for key, value in (
			("enable-local-file-access", ""),
			("run-script", "document.body.append('AISOPTIONRAN')"),
			("javascript-delay", "1000"),
			("cookie-jar", "/tmp/ais-pdf-cookie-jar"),
			("header-html", "/tmp/ais-pdf-header.html"),
			("proxy", "http://127.0.0.1:9"),
		):
			with self.subTest(option=key), self.assertRaises(frappe.ValidationError):
				pdfgen.get_pdf(
					"<p>Must reject unsupported legacy transport options</p>", options={key: value}
				)
