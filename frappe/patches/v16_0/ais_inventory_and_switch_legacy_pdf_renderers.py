"""Inventory legacy renderer choices before an isolated v16 Chrome substitution.

This patch changes renderer selection only. It does not establish that retained
HTML, custom formats, letterheads or legal/business output are Chrome-compatible.
The Version records retain identifiers and settings, never HTML or document data.
"""

import frappe

INVENTORY_MARKER = "AIS_V16_PDF_RENDERER_MIGRATION_V1"
FRAMEWORK_BASE = "3d1284c5fdb52207a516a49bbf2fd186cb43b3ab"
LEGACY_CHOICES = (None, "", "wkhtmltopdf")


def replacement(value):
	return "chrome" if value in LEGACY_CHOICES else value


def format_replacement(value):
	# Blank is an intentional inheritance setting, including for non-Chrome site defaults.
	return "chrome" if value == "wkhtmltopdf" else value


def configured_generator(format_value, site_value):
	# This records configuration selection, not successful rendering or beta-layout compatibility.
	return format_value or site_value or "wkhtmltopdf"


def setter_replacement(row):
	if row.property == "options":
		return options_without_wkhtmltopdf(row.value)
	if row.doc_type == "Print Format":
		return format_replacement(row.value)
	return replacement(row.value)


def options_without_wkhtmltopdf(value):
	options = [option for option in (value or "").split("\n") if option != "wkhtmltopdf"]
	if "chrome" not in options:
		options.append("chrome")
	return "\n".join(options)


def retain_inventory(doctype, name, facts):
	"""One protected inventory entry per record; repeat execution retains the first."""
	if frappe.db.exists(
		"Version",
		{
			"ref_doctype": doctype,
			"docname": name,
			"data": ("like", f"%{INVENTORY_MARKER}%"),
		},
	):
		return
	frappe.get_doc(
		{
			"doctype": "Version",
			"ref_doctype": doctype,
			"docname": name,
			"data": frappe.as_json(
				{
					INVENTORY_MARKER: {
						"framework_base": FRAMEWORK_BASE,
						"inventory_schema": 1,
						"compatibility_verified": False,
						"review_scope": "Renderer selection only; custom HTML, letterheads and legal/business output require separate review.",
						**facts,
					}
				}
			),
		}
	).insert(ignore_permissions=True)


def execute():
	settings = frappe.db.get_single_value("Print Settings", "pdf_generator")
	formats = frappe.get_all(
		"Print Format",
		fields=[
			"name",
			"pdf_generator",
			"standard",
			"custom_format",
			"raw_printing",
			"disabled",
			"print_format_builder_beta",
		],
		order_by="name",
	)
	setters = frappe.get_all(
		"Property Setter",
		filters={
			"doc_type": ("in", ["Print Settings", "Print Format"]),
			"field_name": "pdf_generator",
			"property": ("in", ["options", "default"]),
		},
		fields=["name", "doc_type", "field_name", "property", "value"],
		order_by="name",
	)

	# Retain the complete selection inventory before modifying any setting. A patch
	# failure rolls these records and the setting writes back in the same migration.
	retain_inventory(
		"Print Settings",
		"Print Settings",
		{
			"stored_pdf_generator": settings,
			"target_pdf_generator": replacement(settings),
			"renderer_changed": settings in LEGACY_CHOICES,
			"format_count": len(formats),
			"explicit_wkhtml_format_count": sum(row.pdf_generator == "wkhtmltopdf" for row in formats),
			"inherited_format_count": sum(not row.pdf_generator for row in formats),
		},
	)
	for row in formats:
		retain_inventory(
			"Print Format",
			row.name,
			{
				"stored_pdf_generator": row.pdf_generator,
				"target_pdf_generator": format_replacement(row.pdf_generator),
				"stored_renderer_changed": row.pdf_generator == "wkhtmltopdf",
				"configured_generator_before": configured_generator(row.pdf_generator, settings),
				"configured_generator_after": configured_generator(
					format_replacement(row.pdf_generator), replacement(settings)
				),
				"inherits_site_generator": not bool(row.pdf_generator),
				"selection_requires_format_resolution": bool(row.print_format_builder_beta),
				"standard": row.standard,
				"custom_format": row.custom_format,
				"raw_printing": row.raw_printing,
				"disabled": row.disabled,
				"print_format_builder_beta": row.print_format_builder_beta,
			},
		)
	for row in setters:
		target = setter_replacement(row)
		retain_inventory(
			"Property Setter",
			row.name,
			{
				"doc_type": row.doc_type,
				"field_name": row.field_name,
				"property": row.property,
				"stored_value": row.value,
				"target_value": target,
			},
		)

	if settings in LEGACY_CHOICES:
		frappe.db.set_single_value("Print Settings", "pdf_generator", "chrome")
	for row in formats:
		if row.pdf_generator == "wkhtmltopdf":
			frappe.db.set_value("Print Format", row.name, "pdf_generator", "chrome", update_modified=False)
	for row in setters:
		target = setter_replacement(row)
		if row.value != target:
			frappe.db.set_value("Property Setter", row.name, "value", target, update_modified=False)

	frappe.clear_cache(doctype="Print Settings")
	frappe.clear_cache(doctype="Print Format")
