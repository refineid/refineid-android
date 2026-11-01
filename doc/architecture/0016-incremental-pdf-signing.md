# ADR 0016: Bounded incremental PDF signing

Status: Superseded by [ADR 0046](0046-document-signing-on-core.md)

Date: 2026-08-15

## Context

A detached PAdES CMS value must be inserted without changing any byte already
covered by its digest. The PDF layer therefore needs to reserve a bounded
signature container, calculate the final byte ranges before card access, and
append all form and page changes as an incremental revision. Existing form
arrays may be direct or indirect, and a later signature must retain every
earlier revision.

PDF has several cross-reference representations and a broad object grammar.
Silently guessing at an unsupported representation could produce a document
that appears signed while readers reconstruct a different object graph.

## Decision

The Android writer accepts unencrypted PDFs whose revision chain uses classic
cross-reference tables, cross-reference streams, or hybrid tables with
`/XRefStm`. Its byte-oriented index validates each section, generation, object
offset, trailer link, dictionary boundary, page-tree depth, and cycle before
planning an update. It resolves both direct objects and generation-zero objects
stored in object streams.

Structural streams may be unfiltered or use one `FlateDecode` filter, including
the equivalent singleton filter and decode-parameter arrays. Inflation is
limited to 64 MiB. PNG predictors 10 through 15 are decoded for one-color,
eight-bit rows. Other filters, predictors, color counts, and component widths
fail with a typed unsupported-encoding result; malformed structures fail as
unreadable. Encrypted documents remain explicitly refused.

The writer copies the input verbatim and appends:

1. one signature or document-timestamp dictionary with a fixed-width
   `/ByteRange` and zero-filled hexadecimal `/Contents` reservation;
2. one invisible combined signature-field and widget object;
3. revised page, AcroForm, field-array, and annotation-array objects as needed;
4. a cross-reference section whose `/Prev` points to the prior one.

The appended section follows the newest source representation: a classic table
or hybrid section remains a table, while a cross-reference stream remains a
stream. The writer does not rewrite or convert the source revision.

Existing object generations are retained. New object numbers are allocated
above both the declared size and every claimed cross-reference entry. Direct
and indirect `/Fields` and `/Annots` arrays are updated without duplicating an
existing reference, and signature flags preserve existing bits. A second
signature receives a new field and follows the previous cross-reference chain.

The signature reservation is 49,152 bytes and the timestamp reservation is
16,384 bytes. Both limits are named document-profile constants. The four byte
ranges use fixed ten-digit fields and exclude exactly the opening delimiter,
reserved hexadecimal content, and closing delimiter. Filling uppercase DER
hex returns a new byte array, cannot move a byte, and refuses oversized values.

Signature reasons and locations are length-bounded, validated UTF-16, and
encoded as UTF-16BE hexadecimal strings. Signing dates are UTC PDF dates with
four-digit years. This keeps holder-visible metadata from becoming PDF syntax.

## Verification

Unit tests cover exact preservation of the original revision, byte-range and
digest equality before and after filling, field and page linkage, direct and
indirect form arrays, retained signature flags, repeated signing, previous-xref
linkage, distinct field names, signature versus timestamp dictionaries,
Unicode metadata, syntax-shaped metadata, malformed surrogate pairs, excessive
length, and dates outside the PDF year range.

Cross-reference tests cover direct and compressed objects, all five PNG row
filters, singleton filter and decode-parameter arrays, hybrid precedence,
retained DSS revisions, malformed field widths, and unsupported encodings. An
optional interoperability test asks qpdf to convert a synthetic classic file to
an object-stream PDF, signs it, and requires the result to pass
`qpdf --check` without repair warnings. `pdfinfo` and Poppler rendering provide
independent inspection of the resulting revision. Fixtures contain only
synthetic data and no valid private signature.

## Consequences

Modern unencrypted PDFs can now reach the deterministic CMS boundary without
changing signed bytes. Encrypted documents, additional stream filters and
predictor shapes, visible appearances, and holder-facing orchestration remain
outside this layer.
