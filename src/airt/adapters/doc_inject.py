"""Document injection adapter for testing RAG pipeline vulnerabilities.

Creates poisoned PDF and DOCX files with hidden payloads that influence AI
responses when the documents are ingested into a Retrieval-Augmented Generation
system.
"""

from __future__ import annotations

import datetime
import io
import zipfile
from enum import Enum
from pathlib import Path
from typing import Callable


# ---------------------------------------------------------------------------
# Injection methods
# ---------------------------------------------------------------------------

class InjectionMethod(str, Enum):
    # PDF methods
    PDF_WHITE_ON_WHITE = "pdf-white-on-white"  # White text on white background
    PDF_TINY_FONT = "pdf-tiny-font"            # 1pt font text
    PDF_METADATA = "pdf-metadata"              # Payload in PDF metadata fields
    PDF_ANNOTATION = "pdf-annotation"          # Hidden annotation

    # DOCX methods
    DOCX_HIDDEN_TEXT = "docx-hidden-text"      # vanish property in XML
    DOCX_WHITE_TEXT = "docx-white-text"         # White colored text
    DOCX_COMMENT = "docx-comment"              # Document comment
    DOCX_METADATA = "docx-metadata"            # Core properties


def list_methods() -> list[str]:
    """Return available injection method names."""
    return [m.value for m in InjectionMethod]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def craft_document(
    visible_text: str,
    payload: str,
    output_path: str | Path,
    *,
    method: InjectionMethod | str = InjectionMethod.PDF_WHITE_ON_WHITE,
) -> Path:
    """Create a document with a hidden injection payload.

    Args:
        visible_text: The visible/legitimate content.
        payload: The injection payload to hide.
        output_path: Where to save the file.
        method: Injection method to use.

    Returns:
        Path to the created file.

    Raises:
        ValueError: If *method* is not a recognised injection method.
    """
    if isinstance(method, str):
        try:
            method = InjectionMethod(method)
        except ValueError:
            raise ValueError(
                f"Unknown injection method {method!r}. "
                f"Available: {list_methods()}"
            ) from None

    crafter: Callable[[str, str, Path], Path] = _CRAFTERS[method]
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    return crafter(visible_text, payload, out)


# ---------------------------------------------------------------------------
# PDF helpers (fpdf2)
# ---------------------------------------------------------------------------

def _get_fpdf():
    """Import and return the FPDF class, raising a clear error if missing."""
    try:
        from fpdf import FPDF  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            "fpdf2 is required for PDF document injection. "
            "Install it with:  pip install fpdf2"
        ) from None
    return FPDF


def _sanitize_for_core_font(text: str) -> str:
    """Replace characters unsupported by PDF core fonts (latin-1 range)."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _new_pdf_with_visible(visible: str):
    """Create a new FPDF document with visible text already rendered.

    Returns ``(pdf, FPDF_class)`` with the cursor positioned below the
    visible text and *x* reset to the left margin.
    """
    FPDF = _get_fpdf()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(0, 10, _sanitize_for_core_font(visible))
    # multi_cell may leave x at end-of-line; reset to left margin.
    pdf.set_x(pdf.l_margin)
    return pdf


def _craft_pdf_white_on_white(visible: str, payload: str, path: Path) -> Path:
    pdf = _new_pdf_with_visible(visible)

    # Hidden payload: white text on the default white background
    pdf.set_text_color(255, 255, 255)
    pdf.multi_cell(0, 10, _sanitize_for_core_font(payload))

    pdf.output(str(path))
    return path


def _craft_pdf_tiny_font(visible: str, payload: str, path: Path) -> Path:
    pdf = _new_pdf_with_visible(visible)

    # Hidden payload: 1-point font
    pdf.set_font("Helvetica", size=1)
    pdf.multi_cell(0, 1, _sanitize_for_core_font(payload))

    pdf.output(str(path))
    return path


def _craft_pdf_metadata(visible: str, payload: str, path: Path) -> Path:
    FPDF = _get_fpdf()
    pdf = FPDF()
    pdf.set_title(payload)
    pdf.set_subject(payload)
    pdf.set_author(payload)
    pdf.set_creator(payload)
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    pdf.multi_cell(0, 10, _sanitize_for_core_font(visible))
    pdf.output(str(path))
    return path


def _craft_pdf_annotation(visible: str, payload: str, path: Path) -> Path:
    pdf = _new_pdf_with_visible(visible)

    # Add a text annotation (invisible sticky-note style)
    pdf.text_annotation(
        x=10,
        y=pdf.get_y() + 5,
        text=payload,
    )

    pdf.output(str(path))
    return path


# ---------------------------------------------------------------------------
# DOCX helpers (zipfile + raw XML)
# ---------------------------------------------------------------------------

_CONTENT_TYPES_XML = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
{extra_overrides}
</Types>
"""

_RELS_XML = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
</Relationships>
"""

_WORD_RELS_XML = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
{extra_rels}
</Relationships>
"""

_DOCUMENT_XML_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:body>
{paragraphs}
  </w:body>
</w:document>
"""


def _xml_escape(text: str) -> str:
    """Minimal XML escaping."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _plain_paragraph(text: str) -> str:
    """Generate a simple <w:p> element with plain text."""
    escaped = _xml_escape(text)
    return (
        "    <w:p><w:r><w:t xml:space=\"preserve\">"
        f"{escaped}"
        "</w:t></w:r></w:p>"
    )


def _write_minimal_docx(
    path: Path,
    paragraphs_xml: str,
    *,
    extra_parts: dict[str, str] | None = None,
    extra_content_type_overrides: str = "",
    extra_word_rels: str = "",
) -> Path:
    """Write a minimal but valid DOCX archive."""
    doc_xml = _DOCUMENT_XML_TEMPLATE.format(paragraphs=paragraphs_xml)
    ct_xml = _CONTENT_TYPES_XML.format(extra_overrides=extra_content_type_overrides)
    word_rels = _WORD_RELS_XML.format(extra_rels=extra_word_rels)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", ct_xml)
        zf.writestr("_rels/.rels", _RELS_XML)
        zf.writestr("word/document.xml", doc_xml)
        zf.writestr("word/_rels/document.xml.rels", word_rels)
        if extra_parts:
            for part_name, part_content in extra_parts.items():
                zf.writestr(part_name, part_content)

    path.write_bytes(buf.getvalue())
    return path


def _craft_docx_hidden_text(visible: str, payload: str, path: Path) -> Path:
    visible_p = _plain_paragraph(visible)
    escaped_payload = _xml_escape(payload)
    hidden_p = (
        '    <w:p><w:r>'
        '<w:rPr><w:vanish/></w:rPr>'
        f'<w:t xml:space="preserve">{escaped_payload}</w:t>'
        '</w:r></w:p>'
    )
    return _write_minimal_docx(path, visible_p + "\n" + hidden_p)


def _craft_docx_white_text(visible: str, payload: str, path: Path) -> Path:
    visible_p = _plain_paragraph(visible)
    escaped_payload = _xml_escape(payload)
    white_p = (
        '    <w:p><w:r>'
        '<w:rPr><w:color w:val="FFFFFF"/></w:rPr>'
        f'<w:t xml:space="preserve">{escaped_payload}</w:t>'
        '</w:r></w:p>'
    )
    return _write_minimal_docx(path, visible_p + "\n" + white_p)


def _craft_docx_comment(visible: str, payload: str, path: Path) -> Path:
    visible_p = _plain_paragraph(visible)
    escaped_payload = _xml_escape(payload)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    comment_xml = f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:comment w:id="1" w:author="Author" w:date="{now}">
    <w:p><w:r><w:t xml:space="preserve">{escaped_payload}</w:t></w:r></w:p>
  </w:comment>
</w:comments>
"""

    # The visible paragraph references the comment
    commented_p = (
        '    <w:p>'
        '<w:commentRangeStart w:id="1"/>'
        f'<w:r><w:t xml:space="preserve">{_xml_escape(visible)}</w:t></w:r>'
        '<w:commentRangeEnd w:id="1"/>'
        '<w:r><w:rPr><w:rStyle w:val="CommentReference"/></w:rPr>'
        '<w:commentReference w:id="1"/></w:r>'
        '</w:p>'
    )

    extra_overrides = (
        '  <Override PartName="/word/comments.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument'
        '.wordprocessingml.comments+xml"/>'
    )
    extra_rels = (
        '  <Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" '
        'Target="comments.xml"/>'
    )

    return _write_minimal_docx(
        path,
        commented_p,
        extra_parts={"word/comments.xml": comment_xml},
        extra_content_type_overrides=extra_overrides,
        extra_word_rels=extra_rels,
    )


def _craft_docx_metadata(visible: str, payload: str, path: Path) -> Path:
    visible_p = _plain_paragraph(visible)
    escaped_payload = _xml_escape(payload)

    core_xml = f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties
    xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    xmlns:dcterms="http://purl.org/dc/terms/">
  <dc:title>{escaped_payload}</dc:title>
  <dc:subject>{escaped_payload}</dc:subject>
  <dc:creator>{escaped_payload}</dc:creator>
  <dc:description>{escaped_payload}</dc:description>
</cp:coreProperties>
"""

    # Need a relationship to core.xml in the package-level .rels
    rels_with_core = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"
    Target="docProps/core.xml"/>
</Relationships>
"""

    ct_override = (
        '  <Override PartName="/docProps/core.xml" '
        'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
    )

    # Build manually to inject custom _rels/.rels
    doc_xml = _DOCUMENT_XML_TEMPLATE.format(paragraphs=visible_p)
    ct_xml = _CONTENT_TYPES_XML.format(extra_overrides=ct_override)
    word_rels = _WORD_RELS_XML.format(extra_rels="")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", ct_xml)
        zf.writestr("_rels/.rels", rels_with_core)
        zf.writestr("word/document.xml", doc_xml)
        zf.writestr("word/_rels/document.xml.rels", word_rels)
        zf.writestr("docProps/core.xml", core_xml)

    path.write_bytes(buf.getvalue())
    return path


# ---------------------------------------------------------------------------
# Method dispatch table
# ---------------------------------------------------------------------------

_CRAFTERS: dict[InjectionMethod, Callable[[str, str, Path], Path]] = {
    InjectionMethod.PDF_WHITE_ON_WHITE: _craft_pdf_white_on_white,
    InjectionMethod.PDF_TINY_FONT: _craft_pdf_tiny_font,
    InjectionMethod.PDF_METADATA: _craft_pdf_metadata,
    InjectionMethod.PDF_ANNOTATION: _craft_pdf_annotation,
    InjectionMethod.DOCX_HIDDEN_TEXT: _craft_docx_hidden_text,
    InjectionMethod.DOCX_WHITE_TEXT: _craft_docx_white_text,
    InjectionMethod.DOCX_COMMENT: _craft_docx_comment,
    InjectionMethod.DOCX_METADATA: _craft_docx_metadata,
}
