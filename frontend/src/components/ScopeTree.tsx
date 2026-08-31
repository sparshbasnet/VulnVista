import { useState } from "react";
import type { DiscoveredPath } from "../types";

/**
 * Renders the discovered paths as a collapsible tree with tri-state checkboxes
 * so the operator can pick which paths are in-scope before scanning. Selection
 * is tracked as the set of in-scope `path` strings; toggling a branch toggles
 * every discovered page beneath it.
 */

interface TreeNode {
  name: string;
  fullPath: string;
  isPage: boolean;
  meta?: DiscoveredPath;
  children: Map<string, TreeNode>;
}

function newNode(name: string, fullPath: string): TreeNode {
  return { name, fullPath, isPage: false, children: new Map() };
}

function buildTree(paths: DiscoveredPath[]): TreeNode {
  const root = newNode("/", "/");
  for (const entry of paths) {
    const segments = entry.path.split("/").filter(Boolean);
    if (segments.length === 0) {
      root.isPage = true;
      root.meta = entry;
      continue;
    }
    let node = root;
    let acc = "";
    segments.forEach((segment, index) => {
      acc += `/${segment}`;
      // Preserve a trailing slash on the leaf when the original path had one.
      const isLeaf = index === segments.length - 1;
      const key = segment;
      let child = node.children.get(key);
      if (!child) {
        child = newNode(segment, acc);
        node.children.set(key, child);
      }
      if (isLeaf) {
        child.isPage = true;
        child.meta = entry;
        child.fullPath = entry.path;
      }
      node = child;
    });
  }
  return root;
}

/** Every discovered page path at or below this node. */
function pagePaths(node: TreeNode): string[] {
  const out: string[] = [];
  if (node.isPage) out.push(node.fullPath);
  for (const child of node.children.values()) out.push(...pagePaths(child));
  return out;
}

type Tri = "checked" | "unchecked" | "partial";

function triState(node: TreeNode, selected: Set<string>): Tri {
  const paths = pagePaths(node);
  if (paths.length === 0) return "unchecked";
  const inCount = paths.filter((p) => selected.has(p)).length;
  if (inCount === 0) return "unchecked";
  if (inCount === paths.length) return "checked";
  return "partial";
}

function NodeRow({
  node,
  depth,
  selected,
  onToggle,
}: {
  node: TreeNode;
  depth: number;
  selected: Set<string>;
  onToggle: (paths: string[], nextChecked: boolean) => void;
}) {
  const [open, setOpen] = useState(depth < 2);
  const children = [...node.children.values()].sort((a, b) => a.name.localeCompare(b.name));
  const hasChildren = children.length > 0;
  const state = triState(node, selected);

  return (
    <div>
      <div
        className="flex items-center gap-2 py-1 font-mono text-[11px]"
        style={{ paddingLeft: `${depth * 16}px` }}
      >
        {hasChildren ? (
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-label={open ? "Collapse" : "Expand"}
            className="h-4 w-4 shrink-0 border border-[#aaa6a1] bg-[#efedea] text-[9px] font-black leading-none text-[#454341]"
          >
            {open ? "−" : "+"}
          </button>
        ) : (
          <span className="h-4 w-4 shrink-0" />
        )}
        <input
          type="checkbox"
          checked={state === "checked"}
          ref={(el) => {
            if (el) el.indeterminate = state === "partial";
          }}
          onChange={(event) => onToggle(pagePaths(node), event.target.checked)}
          className="h-3.5 w-3.5 shrink-0 accent-[#f0321d]"
        />
        <span className={node.isPage ? "text-[#201f1e]" : "text-[#676360]"}>
          {node.name}
          {hasChildren ? "/" : ""}
        </span>
        {node.meta?.has_form && (
          <span className="bg-[#171616] px-1 py-0.5 text-[8px] font-bold uppercase text-white">
            form
          </span>
        )}
        {node.meta && node.meta.params.length > 0 && (
          <span className="text-[9px] text-[#8a5508]" title={node.meta.params.join(", ")}>
            {node.meta.params.length} param{node.meta.params.length === 1 ? "" : "s"}
          </span>
        )}
      </div>
      {open &&
        children.map((child) => (
          <NodeRow
            key={child.fullPath}
            node={child}
            depth={depth + 1}
            selected={selected}
            onToggle={onToggle}
          />
        ))}
    </div>
  );
}

export default function ScopeTree({
  paths,
  selected,
  onChange,
}: {
  paths: DiscoveredPath[];
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
}) {
  const root = buildTree(paths);
  const allPaths = pagePaths(root);

  function toggle(targetPaths: string[], nextChecked: boolean) {
    const next = new Set(selected);
    for (const p of targetPaths) {
      if (nextChecked) next.add(p);
      else next.delete(p);
    }
    onChange(next);
  }

  return (
    <div className="border border-[#aaa6a1] bg-[#f7f6f4]">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#aaa6a1] bg-[#efedea] px-3 py-2">
        <p className="vv-label">
          Scope · {selected.size}/{allPaths.length} paths in scope
        </p>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => onChange(new Set(allPaths))}
            className="border border-[#aaa6a1] bg-[#f7f6f4] px-2 py-1 text-[9px] font-black uppercase tracking-wide text-[#454341]"
          >
            Select all
          </button>
          <button
            type="button"
            onClick={() => onChange(new Set())}
            className="border border-[#aaa6a1] bg-[#f7f6f4] px-2 py-1 text-[9px] font-black uppercase tracking-wide text-[#454341]"
          >
            Clear
          </button>
        </div>
      </div>
      <div className="vv-scrollbar max-h-[360px] overflow-y-auto p-2">
        <NodeRow node={root} depth={0} selected={selected} onToggle={toggle} />
      </div>
    </div>
  );
}
