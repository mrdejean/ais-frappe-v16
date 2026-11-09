import base64
import mimetypes
import os
import re
import time
import urllib

from bs4 import BeautifulSoup

import frappe
from frappe.core.doctype.file.utils import find_file_by_url
from frappe.utils.pdf import get_host_url

"""
CDP commands documentation can be found here.
https://chromedevtools.github.io/devtools-protocol/
"""


def resource_origin(url: str) -> tuple[str, str, int] | None:
	"""Compare parsed HTTP origins, never a request-controlled URL prefix."""
	try:
		parsed = urllib.parse.urlsplit(url)
		if parsed.scheme not in ("http", "https") or not parsed.hostname:
			return None
		if parsed.username is not None or parsed.password is not None:
			return None
		default_port = 443 if parsed.scheme == "https" else 80
		return (
			parsed.scheme,
			parsed.hostname.encode("idna").decode("ascii").lower(),
			parsed.port if parsed.port is not None else default_port,
		)
	except (TypeError, ValueError, UnicodeError):
		return None


def get_trusted_site_url() -> str:
	"""The initialized site's configured origin, independent of Host/forwarded headers.

	Guarded pages never fetch this origin over the network: it only identifies the
	local public/private files that the current Frappe principal can read.
	"""
	if not getattr(frappe.local, "site", None):
		raise ValueError("Guarded PDF rendering requires an initialized site")
	url = frappe.utils.get_url(allow_header_override=False)
	parsed = urllib.parse.urlsplit(url)
	origin = resource_origin(url)
	if not origin or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
		raise ValueError("Guarded PDF rendering requires a configured HTTP site origin")
	scheme, hostname, port = origin
	authority = f"[{hostname}]" if ":" in hostname else hostname
	if port != (443 if scheme == "https" else 80):
		authority += f":{port}"
	# Chromium canonicalizes a root navigation to '/'. The initial Fetch stub
	# must use this exact URL, not an origin string with an empty path.
	return urllib.parse.urlunsplit((scheme, authority, "/", "", ""))


def sanitize_guarded_html(html: str, site_url: str) -> str:
	"""Remove executable markup and install a restrictive resource policy.

	CDP also disables page JavaScript and denies every request which cannot be
	fulfilled locally. The CSP covers schemes (notably file:) which may never
	produce a Fetch interception event. Trusted pagination runs explicitly via CDP.
	"""
	soup = BeautifulSoup(html, "html5lib")
	for tag in soup.find_all([
		"script", "iframe", "frame", "frameset", "object", "embed", "base",
		"animate", "animatemotion", "animatetransform", "set",
	]):
		tag.decompose()
	for tag in soup.find_all("meta"):
		if str(tag.get("http-equiv", "")).lower() in ("refresh", "content-security-policy"):
			tag.decompose()
	for tag in soup.find_all(True):
		for attribute in list(tag.attrs):
			if attribute.lower().startswith("on") or attribute.lower() in ("srcdoc", "ping"):
				del tag.attrs[attribute]
			elif attribute.lower() in ("href", "src", "xlink:href", "action", "formaction", "poster", "data"):
				value = re.sub(r"[\x00-\x20\x7f-\x9f]", "", str(tag.attrs[attribute])).lower()
				if value.startswith(("javascript:", "vbscript:", "file:", "blob:")) or (
					attribute.lower() in ("href", "xlink:href") and value.startswith("data:")
				):
					del tag.attrs[attribute]
	policy = (
		"default-src 'none'; script-src 'none'; "
		# The document was stub-navigated to the trusted configured origin.
		# 'self' also works for valid site URLs (e.g. test_ais.localhost) whose
		# host cannot appear in CSP's narrower host-source grammar.
		"style-src 'unsafe-inline' 'self'; img-src data: 'self'; font-src data: 'self'; "
		"connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
	)
	meta = soup.new_tag("meta", attrs={"http-equiv": "Content-Security-Policy", "content": policy})
	soup.head.insert(0, meta)
	return str(soup)


def read_guarded_local_resource(url: str) -> tuple[str, str | None] | None:
	"""Resolve only canonical public assets or principal-authorized private files.

	Unlike the upstream reader, resolve asset symlinks against trusted app public
	roots too. Bench asset symlinks are required for normal framework CSS/fonts;
	a symlink to any other bench/system file is not an asset.
	"""
	parsed = urllib.parse.urlsplit(url)
	path = urllib.parse.unquote(parsed.path)
	if "\\" in path or "\x00" in path or any(part in (".", "..") for part in path.split("/")):
		return None
	clean_path = path.lstrip("/")
	if not clean_path:
		return None
	if clean_path.startswith("assets/"):
		asset_root = os.path.realpath(os.path.join(frappe.utils.get_bench_path(), "sites", "assets"))
		final_path = os.path.realpath(os.path.join(asset_root, clean_path.removeprefix("assets/")))
		roots = [asset_root]
		for app in frappe.get_installed_apps():
			roots.append(os.path.realpath(frappe.get_app_path(app, "public")))
		if not any(os.path.commonpath([final_path, root]) == root for root in roots):
			return None
		if os.path.isfile(final_path) and (content := frappe.read_file(final_path, as_base64=True)):
			return content, mimetypes.guess_type(final_path)[0]
		return None
	# The established reader performs File permission checks and confines real
	# paths to the current site's public or private/files directory.
	if resource := read_local_resource(url):
		content, content_type = resource
		return content, content_type or mimetypes.guess_type(path)[0]
	return None


def read_local_resource(url: str) -> tuple[str, str | None] | None:
	"""Return the base64 body and Content-Type of a site URL the session user may
	read from disk, else None."""
	import os

	parsed = urllib.parse.urlparse(url)
	clean_path = urllib.parse.unquote(parsed.path).lstrip("/")
	query_params = urllib.parse.parse_qs(parsed.query)

	bench_sites = os.path.abspath(os.path.join(frappe.utils.get_bench_path(), "sites"))
	asset_path = os.path.abspath(os.path.join(bench_sites, "assets"))
	site_public_root = os.path.realpath(frappe.utils.get_site_path("public"))
	site_private_files_root = os.path.realpath(frappe.utils.get_site_path("private/files"))

	if clean_path.startswith("assets/"):
		final_system_path = os.path.abspath(os.path.join(bench_sites, clean_path))
		is_safe = os.path.commonpath([final_system_path, asset_path]) == asset_path
	elif clean_path.startswith("private/files/"):
		can_read = False
		if frappe.session.user == "Administrator":
			can_read = True
		elif frappe.session.user != "Guest":
			fid: str | None = query_params.get("fid", [None])[0]
			if find_file_by_url("/" + clean_path, name=fid):
				can_read = True

		file_path = clean_path.removeprefix("private/files/")
		final_system_path = os.path.realpath(os.path.join(site_private_files_root, file_path))
		is_safe = can_read and (
			os.path.commonpath([final_system_path, site_private_files_root]) == site_private_files_root
		)
	else:
		# Covers files/, builder_assets/, etc... under public root.
		final_system_path = os.path.realpath(os.path.join(site_public_root, clean_path))
		is_safe = os.path.commonpath([final_system_path, site_public_root]) == site_public_root

	if is_safe and os.path.isfile(final_system_path):
		if content := frappe.read_file(final_system_path, as_base64=True):
			return content, "image/svg+xml" if clean_path.endswith(".svg") else None
	elif clean_path:
		frappe.log_error(
			title="Attempted Unauthorized File Access in PDF Generator",
			message=f"Blocked access to: {clean_path} \nResolved Path to: {final_system_path}",
		)
	return None


class Page:
	# Preserve the original unguarded behavior for callers/tests which create a
	# Page without __init__; guarded construction always overrides this value.
	block_external_requests = False

	def __init__(self, session, browser_context_id, page_type, block_external_requests=False):
		self.session = session
		self.block_external_requests = block_external_requests
		self.trusted_site_url = get_trusted_site_url() if block_external_requests else None
		result, error = self.session.send(
			"Target.createTarget", {"url": "", "browserContextId": browser_context_id}
		)
		if error:
			frappe.log_error(title="Error creating new page:", message=f"{error}")

		self.target_id = result["targetId"]
		self.type = page_type
		result, error = self.session.send(
			"Target.attachToTarget", {"targetId": self.target_id, "flatten": True}
		)
		if error:
			raise RuntimeError(f"Error attaching to target: {error}")
		self.session_id = result["sessionId"]
		self.send("Page.enable")
		self.frame_id = None
		self.get_frame_id_on_demand()
		self.set_media_emulation("print")
		if self.block_external_requests:
			self.send("Emulation.setScriptExecutionDisabled", {"value": True})
		else:
			self.set_cookies()

	# TODO: make send to return future and don't wait for it by default.
	def send(self, method, params=None, return_future=False):
		if params is None:
			params = {}
		return self.session.send(method, params, self.session_id, return_future)

	def get_frame_id_on_demand(self):
		if self.frame_id:
			return self.frame_id
		try:
			result, error = self.send("Page.getFrameTree")
			if error:
				raise RuntimeError(f"Error fetching frameId: {error}")
			frame_tree = result["frameTree"]
			frame = frame_tree["frame"]
			self.frame_id = frame["id"]
			return self.frame_id
		except Exception:
			frappe.log_error(title="Error fetching frameId:", message=f"{frappe.get_traceback()}")
			raise

	def _ensure_frame_id(self):
		if not self.frame_id:
			self.get_frame_id_on_demand()
		return self.frame_id

	def set_media_emulation(self, media_type: str = "print"):
		"""Set media emulation for the page."""
		return self.send("Emulation.setEmulatedMedia", {"media": media_type})

	def set_cookies(self):
		if frappe.session and frappe.session.sid and hasattr(frappe.local, "request"):
			domain = frappe.utils.get_host_name().split(":", 1)[0]
			cookie = {
				"name": "sid",
				"value": frappe.session.sid,
				"domain": domain,
				"sameSite": "Strict",
			}
			_result, error = self.send("Network.enable")
			if error:
				raise RuntimeError(f"Error enabling network: {error}")
			_result, error = self.send("Network.setCookie", cookie)
			if error:
				raise RuntimeError(f"Error setting cookie: {error}")
			_result, error = self.send("Network.disable")
			if error:
				raise RuntimeError(f"Error disabling network: {error}")

	def intercept_request_and_fulfill(self, url_pattern):
		"""Starts intercepting network requests for the given target_id and URL pattern."""
		if self.block_external_requests:
			# Install one deny-by-default handler before navigating. Keep it
			# active through the empty-root/content handoff and all later loads.
			self._guarded_stub_future = self.session.loop.create_future()
			self._guarded_resources_enabled = False
			self.intercept_request_for_local_resources()

			def fulfill_guarded_root():
				self.session.wait_for_event(self._guarded_stub_future)
				request_id = self._guarded_stub_future.result()
				self.send(
					"Fetch.fulfillRequest",
					{"requestId": request_id, "responseCode": 200},
					return_future=True,
				)
				del self._guarded_stub_future

			return fulfill_guarded_root
		data = {}

		def on_request_paused_event(future, response):
			"""Callback for when a request is paused (intercepted)."""
			params = response.get("params")
			if params and params.get("requestId"):
				data["request_id"] = params["requestId"]
				if not future.done():
					future.set_result(data["request_id"])

		# Start listening for requestPaused event
		event = self.session.start_listener(
			"Fetch.requestPaused", on_request_paused_event, self.session_id, self.target_id, self.frame_id
		)

		# Enable request interception for the specified URL pattern
		self.send("Fetch.enable", {"patterns": [{"urlPattern": url_pattern}]})

		def intercept_and_fulfill():
			self.session.wait_for_event(event)
			self.send(
				"Fetch.fulfillRequest",
				{"requestId": event[1].result(), "responseCode": 200},
				return_future=True,
			)
			self.session.remove_listener("Fetch.requestPaused", event)

		return intercept_and_fulfill

	def intercept_request_for_local_resources(self, url_pattern="*"):
		"""Starts intercepting network requests for the given target_id and URL pattern."""
		if self.block_external_requests and getattr(self, "_guarded_fetch_installed", False):
			# The same handler now permits only authorized local file reads.
			# Fetch is never disabled and there is no listenerless interval.
			self._guarded_resources_enabled = True
			return
		data = {}

		def on_request_paused_event(future, response):
			"""Callback for when a request is paused (intercepted)."""
			params = response.get("params")
			if params and params.get("requestId"):
				data["request_id"] = params["requestId"]
				url = params["request"]["url"]
				if self.block_external_requests:
					stub = getattr(self, "_guarded_stub_future", None)
					if stub is not None and not stub.done() and url == self.trusted_site_url:
						stub.set_result(data["request_id"])
						return
					resource = None
					if (
						getattr(self, "_guarded_resources_enabled", False)
						and resource_origin(url) == resource_origin(self.trusted_site_url)
					):
						resource = read_guarded_local_resource(url)
					if resource:
						content, content_type = resource
						self.send(
							"Fetch.fulfillRequest",
							{
								"requestId": data["request_id"],
								"responseCode": 200,
								"responseHeaders": [{"name": "Content-Type", "value": content_type}]
								if content_type else [],
								"body": content,
							},
							return_future=True,
						)
					else:
						self.send(
							"Fetch.failRequest",
							{"requestId": data["request_id"], "errorReason": "AccessDenied"},
							return_future=True,
						)
					return

				if isinstance(url, str) and url.startswith(get_host_url()):
					if resource := read_local_resource(url):
						content, content_type = resource
						self.send(
							"Fetch.fulfillRequest",
							{
								"requestId": data["request_id"],
								"responseCode": 200,
								"responseHeaders": [{"name": "Content-Type", "value": content_type}]
								if content_type
								else [],
								"body": content,
							},
							return_future=True,
						)
						return
					elif urllib.parse.urlparse(url).path.lstrip("/"):
						self.send(
							"Fetch.failRequest",
							{"requestId": data["request_id"], "errorReason": "AccessDenied"},
							return_future=True,
						)
						return
				self.send(
					"Fetch.continueRequest",
					{"requestId": data["request_id"]},
					return_future=True,
				)

		# Start listening for requestPaused event
		self.session.start_listener(
			"Fetch.requestPaused", on_request_paused_event, self.session_id, self.target_id, self.frame_id
		)
		if self.block_external_requests:
			self._guarded_fetch_installed = True

		# Enable request interception for the specified URL pattern
		pattern = "*" if self.block_external_requests else url_pattern
		self.send("Fetch.enable", {"patterns": [{"urlPattern": pattern}]})

	def set_tab_url(self, url):
		"""Navigate to a URL and fulfill the request with status code 200."""
		if self.block_external_requests and url != self.trusted_site_url:
			raise ValueError("Guarded PDF pages require the configured site origin")

		# Intercept and fulfill request with 200 status code
		wait_and_fulfill = self.intercept_request_and_fulfill(url)
		# Now, navigate after intercepting the request
		wait_start = self.wait_for_load(wait_for="load")
		page_navigate = self.send("Page.navigate", {"url": url}, return_future=True)
		wait_and_fulfill()

		def wait_for_navigate():
			self.session.wait_for_event(page_navigate, 3)
			wait_start()

		self.wait_for_navigate = wait_for_navigate

	def navigate(self, url, wait_for=None):
		"""Really load a URL and wait for render (vs set_tab_url's empty-body stub)."""
		if self.block_external_requests:
			raise ValueError("Guarded PDF pages do not navigate to network URLs")
		wait_start = self.wait_for_load(wait_for=wait_for or ["load", "DOMContentLoaded", "networkIdle"])
		_result, error = self.send("Page.navigate", {"url": url})
		if error:
			raise RuntimeError(f"Error navigating to URL: {error}")
		wait_start()

	def evaluate(self, expression, await_promise=False):
		self.send("Runtime.enable")
		result, error = self.send(
			"Runtime.evaluate", {"expression": expression, "awaitPromise": await_promise}
		)
		if error:
			# retry if error in 500ms for 3 times (just safe guard as i had few edge cases where it failed).
			# waiting for network is still slower than this.
			for _i in range(3):
				print(f"Error evaluating expression: {error}. Retrying in 500ms")
				time.sleep(0.5)
				result, error = self.send(
					"Runtime.evaluate", {"expression": expression, "awaitPromise": await_promise}
				)
				if not error:
					break
			raise RuntimeError(f"Error evaluating expression: {error}")

		self.send("Runtime.disable")
		return result

	# set wait_for to networkIdle if pdf is not rendering correctly.
	# if you face header Height to be incorrect as some external script is changing elements.
	# networkIdle is most stable option but make it a lot slower so avoiding for now. enable if not stable
	def set_content(self, html, wait_for=None):
		if self.block_external_requests:
			html = sanitize_guarded_html(html, self.trusted_site_url)
		if not wait_for:
			wait_for = ["load", "DOMContentLoaded"]
		self.intercept_request_for_local_resources()
		wait_start = self.wait_for_load(wait_for=wait_for)
		self.send("Page.setDocumentContent", {"frameId": self._ensure_frame_id(), "html": html})
		self.wait_for_set_content = wait_start

	def wait_for_load(self, wait_for, timeout=60):
		self.send("Page.setLifecycleEventsEnabled", {"enabled": True})
		status = {}
		if isinstance(wait_for, str):
			status[wait_for] = False
		if isinstance(wait_for, list):
			for event in wait_for:
				status[event] = False

		def on_lifecycle_event(future, response):
			params = response.get("params", {})
			if params.get("name") in status.keys():
				status[params.get("name")] = True
				if all(status.values()):
					if not future.done():
						future.set_result(response)

		event = self.session.start_listener(
			"Page.lifecycleEvent", on_lifecycle_event, self.session_id, self.target_id, self.frame_id
		)

		def start_wait():
			self.session.wait_for_event(event, timeout)
			self.session.remove_listener("Page.lifecycleEvent", event)

		return start_wait

	def get_element_height(self, selector="body"):
		if not self.is_print_designer:
			selector = ".wrapper"

		js = f"""(function() {{
			var wrapper = document.querySelector('{selector}');
			if (!wrapper) return 0;
			var h = wrapper.getBoundingClientRect().height;
			if (h > 0) return Math.ceil(h);
			var top = wrapper.getBoundingClientRect().top;
			var maxBottom = top;
			var nodes = wrapper.querySelectorAll('*');
			for (var i = 0; i < nodes.length; i++) {{
				var pos = window.getComputedStyle(nodes[i]).position;
				if (pos === 'absolute' || pos === 'fixed') continue;
				var b = nodes[i].getBoundingClientRect().bottom;
				if (b > maxBottom) maxBottom = b;
			}}
			return Math.ceil(maxBottom - top);
		}})()"""
		try:
			result = self.evaluate(js)
			height = result.get("result", {}).get("value", 0) or 0
		except Exception:
			try:
				self.send("DOM.enable")
				doc_result, _err = self.send("DOM.getDocument")
				doc_node_id = doc_result["root"]["nodeId"]
				result, _err = self.send("DOM.querySelector", {"nodeId": doc_node_id, "selector": selector})
				node_id = result["nodeId"]
				result, _err = self.send("DOM.getBoxModel", {"nodeId": node_id})
				height = result["model"]["height"]
			finally:
				self.send("DOM.disable")
		return height

	def add_page_size_css(self):
		width = str(self.options["paperWidth"]) + "in"
		height = str(self.options["paperHeight"]) + "in"
		marginLeft = str(self.options["marginLeft"]) + "in"
		marginRight = str(self.options["marginRight"]) + "in"
		marginTop = str(self.options["marginTop"]) + "in"
		marginBottom = str(self.options["marginBottom"]) + "in"

		# Enable DOM and CSS agents
		result, error = self.send("DOM.enable")
		if error:
			raise RuntimeError(f"Error enabling DOM: {error}")

		result, error = self.send("CSS.enable")
		if error:
			raise RuntimeError(f"Error enabling CSS: {error}")

		# Create a new stylesheet
		result, error = self.send("CSS.createStyleSheet", {"frameId": self._ensure_frame_id()})
		if error:
			raise RuntimeError(f"Error creating stylesheet: {error}")

		style_sheet_id = result["styleSheetId"]

		# Define the CSS rule for the page size
		css_rule = f"""
			@page {{
				size: {width} {height};
				margin: {marginTop} {marginRight} {marginBottom} {marginLeft};
			}}
		"""

		# Apply the CSS rule to the created stylesheet
		result, error = self.send("CSS.setStyleSheetText", {"styleSheetId": style_sheet_id, "text": css_rule})

		if error:
			raise RuntimeError(f"Error setting stylesheet text: {error}")

		self.send("CSS.disable")
		self.send("DOM.disable")

	def set_device_metrics(self, width=1280, height=720, scale_factor=1):
		"""Override viewport size for deterministic screenshot dimensions (default 1280x720)."""
		_result, error = self.send(
			"Emulation.setDeviceMetricsOverride",
			{"width": width, "height": height, "deviceScaleFactor": scale_factor, "mobile": False},
		)
		if error:
			raise RuntimeError(f"Error setting device metrics: {error}")

	def get_content_height(self):
		result = self.evaluate(
			"""(() => {
				const style = document.createElement("style");
				style.textContent = "html, body, .print-format { height: auto !important; min-height: 0 !important; }";
				document.head.appendChild(style);
				return document.documentElement.scrollHeight;
			})()"""
		)
		return (result or {}).get("result", {}).get("value") or 0

	def capture_screenshot(self, image_format="jpeg", quality=30):
		"""Screenshot the current viewport; returns raw image bytes."""
		params = {"format": image_format, "captureBeyondViewport": False}
		if image_format in ("jpeg", "webp"):  # quality is only valid for lossy formats
			params["quality"] = quality
		result, error = self.send("Page.captureScreenshot", params)
		if error:
			raise RuntimeError(f"Error capturing screenshot: {error}")
		return base64.b64decode(result["data"])

	def generate_pdf(self, wait_for_pdf=True, raw=False):
		self.add_page_size_css()
		if not wait_for_pdf:
			self.wait_for_pdf = self.send("Page.printToPDF", self.options, return_future=True)
			return

		result, error = self.send("Page.printToPDF", self.options)
		if error:
			raise RuntimeError(f"Error generating PDF: {error}")
		if "stream" not in result:
			raise ValueError("Stream handle not returned from Page.printToPDF")
		return self.get_pdf_from_stream(result["stream"], raw)

	def get_pdf_stream_id(self):
		self.session.wait_for_event(self.wait_for_pdf)
		response_future = self.wait_for_pdf.result()
		self.session.wait_for_event(response_future, timeout=30)
		if not response_future.done() or response_future.cancelled():
			raise RuntimeError("Timed out waiting for the Page.printToPDF response")
		response = response_future.result()
		return response["result"]["stream"]

	def get_pdf_from_stream(self, stream_id, raw=False):
		from io import BytesIO

		from pypdf import PdfReader

		chunks = []
		offset = 0
		while True:
			chunk_result, error = self.send(
				"IO.read", {"handle": stream_id, "offset": offset, "size": 1024 * 1024}
			)
			if error:
				raise RuntimeError(f"Error reading PDF chunk: {error}")
			chunk_data = chunk_result["data"]
			# we don't use base64Encode option but added check anyway as it is one of the valid options.
			if chunk_result.get("base64Encoded", False):
				chunk_data = base64.b64decode(chunk_data)
			chunks.append(chunk_data)
			offset += len(chunk_data)
			if chunk_result.get("eof", False):
				break

		pdf_data = b"".join(chunks)
		chunks.clear()
		_result, error = self.send("IO.close", {"handle": stream_id})
		if error:
			raise RuntimeError(f"Error closing PDF stream: {error}")

		if raw:
			return pdf_data

		return PdfReader(BytesIO(pdf_data))

	def close(self):
		self.send("Fetch.disable")
		_result, error = self.send("Target.closeTarget", {"targetId": self.target_id})
		if error:
			raise RuntimeError(f"Error closing target: {error}")
