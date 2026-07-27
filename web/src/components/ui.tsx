/**
 * Shared presentational primitives.
 *
 * Every V2 screen shows the same kinds of thing — long hex values that must be
 * copyable, claims that are either locally verified or merely asserted by the
 * agent, and terminal commands to hand to `zkpof-client` — so those get one
 * implementation each rather than being re-styled per page.
 */

import { useState, type ReactNode } from "react";

// ── Layout ──────────────────────────────────────────────────────────────────

export function Card({
  title,
  subtitle,
  actions,
  children,
  className = "",
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`bg-white rounded-xl border border-gray-200 p-6 shadow-sm ${className}`}
    >
      {(title || actions) && (
        <header className="flex items-start justify-between gap-4 mb-4">
          <div>
            {title && <h2 className="text-lg font-semibold text-gray-900">{title}</h2>}
            {subtitle && <p className="text-sm text-gray-500 mt-0.5">{subtitle}</p>}
          </div>
          {actions && <div className="shrink-0 flex items-center gap-2">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function PageHeader({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <header className="mb-6">
      <h1 className="text-2xl font-bold text-gray-900">{title}</h1>
      {children && <p className="text-gray-500 mt-1 max-w-3xl">{children}</p>}
    </header>
  );
}

// ── Feedback ────────────────────────────────────────────────────────────────

type Tone = "neutral" | "good" | "bad" | "warn" | "info";

const TONE_CLASSES: Record<Tone, string> = {
  neutral: "bg-gray-50 border-gray-200 text-gray-700",
  good: "bg-green-50 border-green-200 text-green-800",
  bad: "bg-red-50 border-red-200 text-red-800",
  warn: "bg-amber-50 border-amber-200 text-amber-900",
  info: "bg-primary-50 border-primary-100 text-primary-900",
};

export function Callout({
  tone = "neutral",
  title,
  children,
}: {
  tone?: Tone;
  title?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className={`rounded-lg border px-4 py-3 text-sm ${TONE_CLASSES[tone]}`}>
      {title && <p className="font-semibold mb-1">{title}</p>}
      {children}
    </div>
  );
}

const PILL_CLASSES: Record<Tone, string> = {
  neutral: "bg-gray-100 text-gray-700 border-gray-200",
  good: "bg-green-50 text-green-700 border-green-200",
  bad: "bg-red-50 text-red-700 border-red-200",
  warn: "bg-amber-50 text-amber-800 border-amber-200",
  info: "bg-primary-50 text-primary-700 border-primary-100",
};

export function StatusPill({
  tone = "neutral",
  children,
}: {
  tone?: Tone;
  children: ReactNode;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border whitespace-nowrap ${PILL_CLASSES[tone]}`}
    >
      {children}
    </span>
  );
}

/**
 * A claim the UI either verified itself or is repeating on trust. The
 * distinction matters everywhere in this app, so it gets its own component.
 */
export function VerifiedPill({
  state,
  verifiedLabel = "verified locally",
  failedLabel = "MISMATCH",
  pendingLabel = "not checked",
}: {
  state: boolean | null;
  verifiedLabel?: string;
  failedLabel?: string;
  pendingLabel?: string;
}) {
  if (state === null) return <StatusPill>{pendingLabel}</StatusPill>;
  return state ? (
    <StatusPill tone="good">✓ {verifiedLabel}</StatusPill>
  ) : (
    <StatusPill tone="bad">✗ {failedLabel}</StatusPill>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm text-gray-500">
      <span className="w-3.5 h-3.5 rounded-full border-2 border-gray-300 border-t-primary-600 animate-spin" />
      {label}
    </span>
  );
}

// ── Data display ────────────────────────────────────────────────────────────

export function DefinitionList({ children }: { children: ReactNode }) {
  return <dl className="grid grid-cols-[minmax(0,10rem)_1fr] gap-x-4 gap-y-2.5 text-sm">{children}</dl>;
}

export function Row({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <>
      <dt className="text-gray-500">{label}</dt>
      <dd className="min-w-0 text-gray-900">{children}</dd>
    </>
  );
}

/** A long hex value: monospace, wrapping, with a copy affordance. */
export function Hex({
  value,
  truncate = false,
  copyable = true,
}: {
  value: string;
  truncate?: boolean;
  copyable?: boolean;
}) {
  const display =
    truncate && value.length > 22 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
  return (
    <span className="inline-flex items-baseline gap-1.5 min-w-0 max-w-full">
      <code className="font-mono text-xs break-all text-gray-800" title={value}>
        {display}
      </code>
      {copyable && <CopyButton value={value} compact />}
    </span>
  );
}

export function CopyButton({
  value,
  label = "Copy",
  compact = false,
}: {
  value: string;
  label?: string;
  compact?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard is unavailable (insecure origin / denied permission) — the
      // value is on screen and selectable, so this is not worth an error state.
    }
  }

  if (compact) {
    return (
      <button
        onClick={copy}
        title={`Copy ${label.toLowerCase()}`}
        className="shrink-0 text-[10px] uppercase tracking-wide text-gray-400 hover:text-primary-600 transition-colors"
      >
        {copied ? "copied" : "copy"}
      </button>
    );
  }
  return (
    <button
      onClick={copy}
      className="px-3 py-1.5 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors text-sm font-medium"
    >
      {copied ? "Copied ✓" : label}
    </button>
  );
}

/** A terminal command or JSON blob, with a one-click copy. */
export function CodeBlock({
  code,
  language,
  copyable = true,
}: {
  code: string;
  language?: string;
  copyable?: boolean;
}) {
  return (
    <div className="relative group">
      <pre className="bg-gray-900 text-gray-100 p-4 pr-20 rounded-lg text-xs overflow-x-auto leading-relaxed">
        <code>{code}</code>
      </pre>
      {language && (
        <span className="absolute top-2 left-4 text-[10px] uppercase tracking-wider text-gray-500">
          {language}
        </span>
      )}
      {copyable && (
        <div className="absolute top-2 right-2">
          <CopyButton value={code} />
        </div>
      )}
    </div>
  );
}

// ── Form controls ───────────────────────────────────────────────────────────

const INPUT_CLASSES =
  "w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent text-sm disabled:bg-gray-50 disabled:text-gray-400";

export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-1">{label}</label>
      {children}
      {error ? (
        <p className="text-xs text-red-600 mt-1">{error}</p>
      ) : (
        hint && <p className="text-xs text-gray-500 mt-1">{hint}</p>
      )}
    </div>
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  mono = false,
  type = "text",
  disabled = false,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  mono?: boolean;
  type?: string;
  disabled?: boolean;
}) {
  return (
    <input
      type={type}
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className={`${INPUT_CLASSES} ${mono ? "font-mono" : ""}`}
    />
  );
}

export function TextArea({
  value,
  onChange,
  placeholder,
  rows = 6,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  rows?: number;
}) {
  return (
    <textarea
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      rows={rows}
      className={`${INPUT_CLASSES} font-mono`}
    />
  );
}

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";

const BUTTON_CLASSES: Record<ButtonVariant, string> = {
  primary: "bg-primary-600 text-white hover:bg-primary-700",
  secondary: "bg-gray-700 text-white hover:bg-gray-800",
  ghost: "bg-gray-100 text-gray-700 hover:bg-gray-200",
  danger: "bg-red-600 text-white hover:bg-red-700",
};

export function Button({
  onClick,
  children,
  variant = "primary",
  disabled = false,
  full = false,
  size = "md",
}: {
  onClick?: () => void;
  children: ReactNode;
  variant?: ButtonVariant;
  disabled?: boolean;
  full?: boolean;
  size?: "sm" | "md";
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`${BUTTON_CLASSES[variant]} ${
        size === "sm" ? "px-3 py-1.5 text-sm" : "px-4 py-2.5"
      } rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
        full ? "w-full" : ""
      }`}
    >
      {children}
    </button>
  );
}

// ── Stepper ─────────────────────────────────────────────────────────────────

export interface Step {
  id: string;
  label: string;
}

/**
 * Progress through a multi-step flow. Completed steps are clickable so the
 * user can go back and change an earlier answer without restarting.
 */
export function Stepper({
  steps,
  current,
  furthest,
  onSelect,
}: {
  steps: Step[];
  current: number;
  furthest: number;
  onSelect: (index: number) => void;
}) {
  return (
    <ol className="flex items-center gap-1 mb-8 overflow-x-auto pb-1">
      {steps.map((step, i) => {
        const done = i < furthest;
        const active = i === current;
        const reachable = i <= furthest;
        return (
          <li key={step.id} className="flex items-center gap-1 shrink-0">
            <button
              disabled={!reachable}
              onClick={() => onSelect(i)}
              className={`flex items-center gap-2 pl-1.5 pr-3 py-1.5 rounded-full transition-colors ${
                active
                  ? "bg-primary-50 text-primary-800"
                  : reachable
                  ? "text-gray-600 hover:bg-gray-100"
                  : "text-gray-400 cursor-not-allowed"
              }`}
            >
              <span
                className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-semibold ${
                  active
                    ? "bg-primary-600 text-white"
                    : done
                    ? "bg-green-500 text-white"
                    : "bg-gray-200 text-gray-500"
                }`}
              >
                {done ? "✓" : i + 1}
              </span>
              <span className="text-sm font-medium whitespace-nowrap">{step.label}</span>
            </button>
            {i < steps.length - 1 && <span className="w-4 h-px bg-gray-300" />}
          </li>
        );
      })}
    </ol>
  );
}
