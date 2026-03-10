import { useState, useEffect, useCallback, useRef } from "react";
import { marked } from "marked";
import { getDocsTree, getDocContent, type DocEntry } from "../api";

interface DocSection {
  label: string;
  items: DocEntry[];
}

/** Resolve a relative link against the current doc's directory. */
function resolveDocLink(href: string, currentPath: string): string | null {
  // Skip external links, anchors, images, etc.
  if (!href || href.startsWith("http") || href.startsWith("#") || href.startsWith("mailto:")) {
    return null;
  }

  // Get the directory of the current doc.
  const dir = currentPath.includes("/")
    ? currentPath.substring(0, currentPath.lastIndexOf("/"))
    : "";

  // Build absolute path from relative.
  const parts = (dir ? dir + "/" + href : href).split("/");
  const resolved: string[] = [];
  for (const p of parts) {
    if (p === "." || p === "") continue;
    if (p === "..") {
      resolved.pop();
    } else {
      resolved.push(p);
    }
  }

  let docPath = resolved.join("/");

  // Strip anchor fragments for path lookup.
  const hashIdx = docPath.indexOf("#");
  if (hashIdx !== -1) {
    docPath = docPath.substring(0, hashIdx);
  }

  return docPath || null;
}

/** Rewrite relative .md links in rendered HTML to use data-doc-path attributes. */
function rewriteDocLinks(html: string, currentPath: string): string {
  return html.replace(
    /<a\s+href="([^"]*)"([^>]*)>/g,
    (match, href: string, rest: string) => {
      const resolved = resolveDocLink(href, currentPath);
      if (resolved === null) {
        // External link or anchor — open in new tab if external.
        if (href.startsWith("http")) {
          return `<a href="${href}" target="_blank" rel="noopener noreferrer"${rest}>`;
        }
        return match;
      }
      return `<a href="#" data-doc-path="${resolved}"${rest}>`;
    },
  );
}

/** Convert MkDocs admonition blocks (!!!&nbsp;type "title") to HTML before marked processes them. */
function convertAdmonitions(md: string): string {
  const lines = md.split("\n");
  const out: string[] = [];
  let i = 0;

  while (i < lines.length) {
    const match = lines[i].match(/^(\s*)!!!\s+(\w+)\s*(?:"([^"]*)")?/);
    if (!match) {
      out.push(lines[i]);
      i++;
      continue;
    }

    const baseIndent = match[1].length;
    const type = match[2]; // warning, tip, note, example, bug, etc.
    const title = match[3] || type.charAt(0).toUpperCase() + type.slice(1);

    // Collect indented body lines (at least baseIndent+4 spaces).
    const bodyLines: string[] = [];
    i++;
    // Skip one optional blank line right after the !!!.
    if (i < lines.length && lines[i].trim() === "") i++;
    while (i < lines.length) {
      const line = lines[i];
      if (line.trim() === "") {
        bodyLines.push("");
        i++;
        continue;
      }
      // Count leading spaces.
      const stripped = line.replace(/^\s*/, "");
      const indent = line.length - stripped.length;
      if (indent > baseIndent) {
        // Remove the extra indentation (baseIndent + 4).
        bodyLines.push(line.substring(Math.min(indent, baseIndent + 4)));
        i++;
      } else {
        break;
      }
    }

    // Trim trailing blank lines.
    while (bodyLines.length > 0 && bodyLines[bodyLines.length - 1].trim() === "") {
      bodyLines.pop();
    }

    // Recursively convert any nested admonitions.
    const bodyMd = convertAdmonitions(bodyLines.join("\n"));
    out.push(`<div class="admonition admonition-${type}">`);
    out.push(`<p class="admonition-title">${title}</p>`);
    out.push("");
    out.push(bodyMd);
    out.push("");
    out.push("</div>");
    out.push("");
  }

  return out.join("\n");
}

function buildSections(docs: DocEntry[]): DocSection[] {
  const groups: Record<string, DocEntry[]> = {};
  const order: string[] = [];

  for (const doc of docs) {
    const parts = doc.path.split("/");
    const section = parts.length > 1 ? parts.slice(0, -1).join("/") : "";
    if (!groups[section]) {
      groups[section] = [];
      order.push(section);
    }
    groups[section].push(doc);
  }

  const labelMap: Record<string, string> = {
    "": "Overview",
    about: "About",
    ref: "Reference",
    "ref/integration": "Integrations",
    setup: "Setup",
    "setup/install": "Installation",
    usage: "Usage",
    "usage/connect": "Connect",
  };

  return order.map((key) => ({
    label: labelMap[key] || key,
    items: groups[key],
  }));
}

export function DocsPage() {
  const [sections, setSections] = useState<DocSection[]>([]);
  const [knownPaths, setKnownPaths] = useState<Set<string>>(new Set());
  const [activePath, setActivePath] = useState("");
  const [html, setHtml] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadingContent, setLoadingContent] = useState(false);
  const contentRef = useRef<HTMLDivElement>(null);

  // Sync activePath → URL hash.
  const navigate = useCallback((path: string) => {
    setActivePath(path);
    window.history.replaceState(null, "", `#${path}`);
  }, []);

  useEffect(() => {
    getDocsTree()
      .then((tree) => {
        setSections(buildSections(tree));
        const paths = new Set(tree.map((d) => d.path));
        setKnownPaths(paths);
        // Restore from URL hash, or fall back to index.
        const hash = window.location.hash.replace(/^#/, "");
        if (hash && paths.has(hash)) {
          setActivePath(hash);
        } else {
          const idx = tree.find((d) => d.path === "index.md");
          const initial = idx ? idx.path : tree[0]?.path || "";
          setActivePath(initial);
          if (initial) window.history.replaceState(null, "", `#${initial}`);
        }
      })
      .finally(() => setLoading(false));
  }, []);

  const loadDoc = useCallback(
    async (path: string) => {
      if (!path) return;
      setActivePath(path);
      setLoadingContent(true);
      try {
        const md = await getDocContent(path);
        // Strip YAML frontmatter, convert MkDocs admonitions, then render markdown.
        const stripped = md.replace(/^---[\s\S]*?---\n*/, "");
        const preprocessed = convertAdmonitions(stripped);
        let rendered = await marked.parse(preprocessed, { gfm: true, breaks: false });
        // Inject copy button into code blocks, with position class based on line count.
        const clipIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
        const checkIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
        rendered = rendered.replace(/<pre><code([^>]*)>([\s\S]*?)<\/code><\/pre>/g, (_m, attrs: string, code: string) => {
          const isMultiline = (code.match(/\n/g) || []).length > 1;
          const posClass = isMultiline ? "code-copy-bottom" : "code-copy-inline";
          return `<pre class="${posClass}"><button class="code-copy-btn" type="button" title="Copy to clipboard" data-clip-icon='${clipIcon}' data-check-icon='${checkIcon}'>${clipIcon}</button><code${attrs}>${code}</code></pre>`;
        });
        setHtml(rewriteDocLinks(rendered, path));
      } catch {
        setHtml("<p>Failed to load document.</p>");
      } finally {
        setLoadingContent(false);
      }
    },
    [],
  );

  useEffect(() => {
    if (activePath) loadDoc(activePath);
  }, [activePath, loadDoc]);

  // Intercept clicks on doc-internal links and copy buttons.
  useEffect(() => {
    const el = contentRef.current;
    if (!el) return;
    function handleClick(e: MouseEvent) {
      // Copy button on code blocks.
      const copyBtn = (e.target as Element).closest(".code-copy-btn") as HTMLButtonElement | null;
      if (copyBtn) {
        e.preventDefault();
        const pre = copyBtn.closest("pre");
        const code = pre?.querySelector("code");
        if (code) {
          navigator.clipboard.writeText(code.textContent || "").then(() => {
            const checkIcon = copyBtn.getAttribute("data-check-icon") || "✓";
            const clipIcon = copyBtn.getAttribute("data-clip-icon") || "";
            copyBtn.innerHTML = checkIcon;
            setTimeout(() => { copyBtn.innerHTML = clipIcon; }, 1500);
          });
        }
        return;
      }
      // Doc-internal links.
      const anchor = (e.target as Element).closest("a[data-doc-path]") as HTMLAnchorElement | null;
      if (!anchor) return;
      e.preventDefault();
      const docPath = anchor.getAttribute("data-doc-path");
      if (docPath && knownPaths.has(docPath)) {
        navigate(docPath);
        contentRef.current?.scrollTo(0, 0);
      }
    }
    el.addEventListener("click", handleClick);
    return () => el.removeEventListener("click", handleClick);
  }, [html, knownPaths]);

  if (loading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", padding: "4rem" }}>
        <span className="spinner" />
      </div>
    );
  }

  return (
    <div style={{ display: "flex", gap: "1.5rem", minHeight: "calc(100vh - 140px)" }}>
      {/* Left sidebar */}
      <nav
        style={{
          width: 220,
          flexShrink: 0,
          borderRight: "1px solid var(--color-border)",
          paddingRight: "1rem",
          overflowY: "auto",
          maxHeight: "calc(100vh - 140px)",
          position: "sticky",
          top: "1.5rem",
        }}
      >
        {sections.map((section) => (
          <div key={section.label} style={{ marginBottom: "1rem" }}>
            <div
              style={{
                fontSize: "0.6875rem",
                fontWeight: 600,
                textTransform: "uppercase",
                letterSpacing: "0.04em",
                color: "var(--color-text-tertiary)",
                marginBottom: "0.375rem",
                padding: "0 0.5rem",
              }}
            >
              {section.label}
            </div>
            {section.items.map((item) => (
              <button
                key={item.path}
                onClick={() => navigate(item.path)}
                style={{
                  display: "block",
                  width: "100%",
                  textAlign: "left",
                  padding: "0.3rem 0.5rem",
                  borderRadius: "var(--radius)",
                  border: "none",
                  background:
                    item.path === activePath
                      ? "var(--color-primary-subtle)"
                      : "transparent",
                  color:
                    item.path === activePath
                      ? "var(--color-primary)"
                      : "var(--color-text-secondary)",
                  fontSize: "0.8125rem",
                  cursor: "pointer",
                  transition: "all 150ms",
                }}
                onMouseEnter={(e) => {
                  if (item.path !== activePath)
                    e.currentTarget.style.background = "var(--color-surface-2)";
                }}
                onMouseLeave={(e) => {
                  if (item.path !== activePath)
                    e.currentTarget.style.background = "transparent";
                }}
              >
                {item.title}
              </button>
            ))}
          </div>
        ))}
      </nav>

      {/* Content area */}
      <article
        ref={contentRef}
        style={{
          flex: 1,
          minWidth: 0,
          maxWidth: 800,
        }}
      >
        {loadingContent ? (
          <div style={{ display: "flex", justifyContent: "center", padding: "2rem" }}>
            <span className="spinner" />
          </div>
        ) : (
          <div
            className="docs-content"
            dangerouslySetInnerHTML={{ __html: html }}
          />
        )}
      </article>
    </div>
  );
}
