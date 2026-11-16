// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

@file:Suppress(
    "MagicNumber",
    "ComplexMethod",
    "NestedBlockDepth",
    "LoopWithTooManyJumpStatements",
)

package fi.refineid.android.asic

import org.w3c.dom.Attr
import org.w3c.dom.Element
import org.w3c.dom.Node
import java.io.ByteArrayOutputStream

/**
 * Exclusive XML Canonicalization 1.0 (W3C Recommendation 18 July 2002,
 * http://www.w3.org/2001/10/xml-exc-c14n#).
 *
 * Renders an element and its descendants into canonical XML octets:
 * - Empty elements are never self-closed: `<tag></tag>`
 * - Namespace declarations and attributes are lexicographically sorted
 * - Only visibly utilized namespaces are declared (unless in inclusive prefix list)
 * - Comment nodes are omitted
 * - Attribute and text values are escaped per XML-c14n rules
 */
internal object XmlCanonicalizer {
    private const val XMLNS_URI = "http://www.w3.org/2000/xmlns/"
    private const val XML_PREFIX = "xml"

    data class NamespaceBinding(
        val prefix: String,
        val uri: String,
    )

    /**
     * Canonicalizes [element] using Exclusive XML Canonicalization 1.0 without comments.
     */
    fun canonicalize(
        element: Element,
        inclusivePrefixes: Set<String> = emptySet(),
    ): ByteArray {
        val out = ByteArrayOutputStream()
        val inScopeAncestors = inScopeNamespaces(element)
        val renderedStack = mutableListOf<NamespaceBinding>()
        renderElement(element, inclusivePrefixes, inScopeAncestors, renderedStack, out)
        return out.toByteArray()
    }

    private fun renderElement(
        element: Element,
        inclusivePrefixes: Set<String>,
        parentScope: List<NamespaceBinding>,
        renderedStack: MutableList<NamespaceBinding>,
        out: ByteArrayOutputStream,
    ) {
        val currentScope = currentElementScope(element, parentScope)
        val candidatePrefixes = candidatePrefixes(element, inclusivePrefixes)
        val declarationsToRender = declarationsToRender(candidatePrefixes, currentScope, renderedStack)

        val prefix = element.prefix
        val localName = element.localName ?: element.tagName
        val qualifiedName = if (!prefix.isNullOrEmpty()) "$prefix:$localName" else localName

        out.write('<'.code)
        out.write(qualifiedName.toByteArray(Charsets.UTF_8))

        // Render namespace declarations sorted: default namespace first, then by prefix
        for (decl in declarationsToRender) {
            out.write(' '.code)
            if (decl.prefix.isEmpty()) {
                out.write("xmlns=\"".toByteArray(Charsets.UTF_8))
            } else {
                out.write("xmlns:${decl.prefix}=\"".toByteArray(Charsets.UTF_8))
            }
            writeEscapedAttribute(decl.uri, out)
            out.write('"'.code)
        }

        // Render non-namespace attributes sorted: namespace URI first, then localName
        val regularAttrs = regularAttributes(element)
        val sortedAttrs =
            regularAttrs.sortedWith { a, b ->
                val nsA = a.namespaceURI ?: ""
                val nsB = b.namespaceURI ?: ""
                val nsCmp = nsA.compareTo(nsB)
                if (nsCmp != 0) {
                    nsCmp
                } else {
                    val nameA = a.localName ?: a.name
                    val nameB = b.localName ?: b.name
                    nameA.compareTo(nameB)
                }
            }

        for (attr in sortedAttrs) {
            out.write(' '.code)
            val attrPrefix = attr.prefix
            val attrLocal = attr.localName ?: attr.name
            val attrQName = if (!attrPrefix.isNullOrEmpty()) "$attrPrefix:$attrLocal" else attrLocal
            out.write(attrQName.toByteArray(Charsets.UTF_8))
            out.write("=\"".toByteArray(Charsets.UTF_8))
            writeEscapedAttribute(attr.value, out)
            out.write('"'.code)
        }

        out.write('>'.code)

        val depth = renderedStack.size
        renderedStack.addAll(declarationsToRender)

        val children = element.childNodes
        for (i in 0 until children.length) {
            val child = children.item(i)
            renderNode(child, inclusivePrefixes, currentScope, renderedStack, out)
        }

        out.write("</".toByteArray(Charsets.UTF_8))
        out.write(qualifiedName.toByteArray(Charsets.UTF_8))
        out.write('>'.code)

        while (renderedStack.size > depth) {
            renderedStack.removeAt(renderedStack.size - 1)
        }
    }

    private fun renderNode(
        node: Node,
        inclusivePrefixes: Set<String>,
        parentScope: List<NamespaceBinding>,
        renderedStack: MutableList<NamespaceBinding>,
        out: ByteArrayOutputStream,
    ) {
        when (node.nodeType) {
            Node.ELEMENT_NODE -> {
                renderElement(node as Element, inclusivePrefixes, parentScope, renderedStack, out)
            }

            Node.TEXT_NODE, Node.CDATA_SECTION_NODE -> {
                writeEscapedText(node.nodeValue ?: "", out)
            }

            Node.PROCESSING_INSTRUCTION_NODE -> {
                out.write("<?".toByteArray(Charsets.UTF_8))
                out.write(node.nodeName.toByteArray(Charsets.UTF_8))
                val data = node.nodeValue
                if (!data.isNullOrEmpty()) {
                    out.write(' '.code)
                    out.write(data.toByteArray(Charsets.UTF_8))
                }
                out.write("?>".toByteArray(Charsets.UTF_8))
            }
            // Node.COMMENT_NODE is omitted in c14n without comments
        }
    }

    private fun candidatePrefixes(
        element: Element,
        inclusivePrefixes: Set<String>,
    ): Set<String> {
        val candidates = mutableSetOf<String>()
        val elemPrefix = element.prefix ?: ""
        candidates.add(elemPrefix)

        val attrs = regularAttributes(element)
        for (attr in attrs) {
            val attrPrefix = attr.prefix
            if (!attrPrefix.isNullOrEmpty()) {
                candidates.add(attrPrefix)
            }
        }

        for (inc in inclusivePrefixes) {
            candidates.add(inc)
        }

        candidates.remove(XML_PREFIX)
        return candidates
    }

    private fun declarationsToRender(
        candidatePrefixes: Set<String>,
        scope: List<NamespaceBinding>,
        rendered: List<NamespaceBinding>,
    ): List<NamespaceBinding> {
        val toRender = mutableListOf<NamespaceBinding>()
        for (prefix in candidatePrefixes) {
            val uri = scope.firstOrNull { it.prefix == prefix }?.uri ?: ""
            val inEffect = rendered.lastOrNull { it.prefix == prefix }?.uri ?: ""
            if (uri != inEffect) {
                // If prefix is empty and uri is empty, but parent had non-empty default, emit xmlns=""
                if (prefix.isNotEmpty() || uri.isNotEmpty() || inEffect.isNotEmpty()) {
                    toRender.add(NamespaceBinding(prefix, uri))
                }
            }
        }
        return toRender.sortedWith { a, b ->
            when {
                a.prefix.isEmpty() && b.prefix.isNotEmpty() -> -1
                a.prefix.isNotEmpty() && b.prefix.isEmpty() -> 1
                else -> a.prefix.compareTo(b.prefix)
            }
        }
    }

    private fun inScopeNamespaces(element: Element): List<NamespaceBinding> {
        val scope = mutableListOf<NamespaceBinding>()
        var current: Node? = element.parentNode
        while (current != null) {
            if (current is Element) {
                val decls = namespaceDeclarations(current)
                for (d in decls) {
                    if (scope.none { it.prefix == d.prefix }) {
                        scope.add(d)
                    }
                }
            }
            current = current.parentNode
        }
        return scope
    }

    private fun currentElementScope(
        element: Element,
        parentScope: List<NamespaceBinding>,
    ): List<NamespaceBinding> {
        val scope = parentScope.toMutableList()
        val decls = namespaceDeclarations(element)
        for (d in decls) {
            val idx = scope.indexOfFirst { it.prefix == d.prefix }
            if (idx >= 0) {
                scope[idx] = d
            } else {
                scope.add(d)
            }
        }
        return scope
    }

    private fun namespaceDeclarations(element: Element): List<NamespaceBinding> {
        val list = mutableListOf<NamespaceBinding>()
        val attrs = element.attributes ?: return list
        for (i in 0 until attrs.length) {
            val attr = attrs.item(i) as? Attr ?: continue
            if (isNamespaceDeclaration(attr)) {
                val prefix = namespacePrefix(attr)
                list.add(NamespaceBinding(prefix, attr.value))
            }
        }
        return list
    }

    private fun regularAttributes(element: Element): List<Attr> {
        val list = mutableListOf<Attr>()
        val attrs = element.attributes ?: return list
        for (i in 0 until attrs.length) {
            val attr = attrs.item(i) as? Attr ?: continue
            if (!isNamespaceDeclaration(attr)) {
                list.add(attr)
            }
        }
        return list
    }

    private fun isNamespaceDeclaration(attr: Attr): Boolean {
        val name = attr.name
        val prefix = attr.prefix
        return name == "xmlns" ||
            prefix == "xmlns" ||
            name.startsWith("xmlns:") ||
            attr.namespaceURI == XMLNS_URI
    }

    private fun namespacePrefix(attr: Attr): String {
        val prefix = attr.prefix
        val name = attr.name
        return when {
            prefix == "xmlns" -> attr.localName ?: name.removePrefix("xmlns:")
            name.startsWith("xmlns:") -> name.removePrefix("xmlns:")
            else -> "" // Default namespace xmlns="..."
        }
    }

    private fun writeEscapedAttribute(
        value: String,
        out: ByteArrayOutputStream,
    ) {
        for (ch in value) {
            when (ch) {
                '&' -> out.write("&amp;".toByteArray(Charsets.UTF_8))
                '<' -> out.write("&lt;".toByteArray(Charsets.UTF_8))
                '"' -> out.write("&quot;".toByteArray(Charsets.UTF_8))
                '\t' -> out.write("&#x9;".toByteArray(Charsets.UTF_8))
                '\n' -> out.write("&#xA;".toByteArray(Charsets.UTF_8))
                '\r' -> out.write("&#xD;".toByteArray(Charsets.UTF_8))
                else -> out.write(ch.toString().toByteArray(Charsets.UTF_8))
            }
        }
    }

    private fun writeEscapedText(
        value: String,
        out: ByteArrayOutputStream,
    ) {
        for (ch in value) {
            when (ch) {
                '&' -> out.write("&amp;".toByteArray(Charsets.UTF_8))
                '<' -> out.write("&lt;".toByteArray(Charsets.UTF_8))
                '>' -> out.write("&gt;".toByteArray(Charsets.UTF_8))
                '\r' -> out.write("&#xD;".toByteArray(Charsets.UTF_8))
                else -> out.write(ch.toString().toByteArray(Charsets.UTF_8))
            }
        }
    }
}
