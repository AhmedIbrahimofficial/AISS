/**
 * AISS Setup Wizard — Popup Dialog System
 * Auto-shows on first connect when the backend sends {event: "wizard_start"}
 * via WebSocket. Also mountable manually via the Settings page.
 *
 * Question types: text | password | select | toggle | url | number
 */
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { X, ChevronRight, ChevronLeft, Check, ExternalLink, Eye, EyeOff } from "lucide-react";
import { applyWizardAnswers, getWizardQuestions, submitPopupAnswer, type WizardQuestion, type WizardData } from "@/lib/api";

// ── Single question field ─────────────────────────────────────────────

function QuestionField({
  q,
  value,
  onChange,
}: {
  q: WizardQuestion;
  value: string;
  onChange: (v: string) => void;
}) {
  const [show, setShow] = useState(false);

  const base =
    "w-full rounded-md border border-[var(--hairline)] bg-white/5 px-3 py-2 text-sm text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/60 focus:ring-1 focus:ring-primary/30";

  if (q.type === "select" && q.options?.length) {
    return (
      <select
        className={base + " cursor-pointer"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{ background: "#0f1a16" }}
      >
        <option value="">— choose —</option>
        {q.options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    );
  }

  if (q.type === "toggle") {
    const on = value === "true" || value === "1";
    return (
      <button
        type="button"
        onClick={() => onChange(on ? "false" : "true")}
        className={`relative inline-flex h-7 w-12 items-center rounded-full border transition-colors ${on ? "border-primary/60 bg-primary/20" : "border-[var(--hairline)] bg-white/5"}`}
      >
        <span className={`absolute size-5 rounded-full transition-transform ${on ? "translate-x-6 bg-primary" : "translate-x-1 bg-muted-foreground"}`} />
      </button>
    );
  }

  if (q.type === "password") {
    return (
      <div className="relative">
        <input
          type={show ? "text" : "password"}
          className={base + " pr-9"}
          placeholder={q.placeholder ?? "Enter value…"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete="off"
        />
        <button
          type="button"
          onClick={() => setShow(!show)}
          className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
        >
          {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
        </button>
      </div>
    );
  }

  return (
    <input
      type={q.type === "number" ? "number" : "text"}
      className={base}
      placeholder={q.placeholder ?? "Enter value…"}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

// ── Main wizard dialog ────────────────────────────────────────────────

export function SetupWizard({
  onClose,
  initialStep = 0,
}: {
  onClose: () => void;
  initialStep?: number;
}) {
  const [data, setData]       = useState<WizardData | null>(null);
  const [stepIdx, setStepIdx] = useState(initialStep);
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [saving, setSaving]   = useState(false);

  useEffect(() => {
    getWizardQuestions()
      .then((d) => {
        setData(d);
        // Pre-fill with current values
        const pre: Record<string, string> = {};
        Object.values(d.questions_by_step).flat().forEach((q) => {
          if (q.current_value) pre[q.id] = q.current_value;
        });
        setAnswers(pre);
      })
      .catch(() => { /* backend not reachable — fail silently */ });
  }, []);

  if (!data) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
        <div className="panel p-8 text-center">
          <div className="mx-auto size-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          <p className="mt-4 text-sm text-muted-foreground">Loading configuration wizard…</p>
        </div>
      </div>
    );
  }

  const steps        = data.steps;
  const currentStep  = steps[stepIdx];
  if (!currentStep) return null;
  const questions    = data.questions_by_step[currentStep.id] ?? [];
  const isLast       = stepIdx === steps.length - 1;
  const isFirst      = stepIdx === 0;

  const handleSave = async () => {
    setSaving(true);
    try {
      const result = await applyWizardAnswers(answers);
      toast.success(`${result.applied} setting(s) saved`, {
        description: result.message,
      });
      if (isLast) {
        onClose();
      } else {
        setStepIdx((i) => i + 1);
      }
    } catch (e) {
      toast.error("Failed to save settings", { description: String(e) });
    } finally {
      setSaving(false);
    }
  };

  const progress = Math.round(((stepIdx + 1) / steps.length) * 100);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
      <div className="panel flex w-full max-w-2xl flex-col gap-0 overflow-hidden p-0" style={{ maxHeight: "90vh" }}>
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[var(--hairline)] px-6 py-4">
          <div>
            <h2 className="font-serif text-lg font-bold">AISS Configuration Wizard</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Step {stepIdx + 1} of {steps.length} — {currentStep.title}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="grid size-8 place-items-center rounded-md border border-[var(--hairline)] text-muted-foreground hover:border-primary/40 hover:text-foreground"
          >
            <X className="size-4" />
          </button>
        </div>

        {/* Progress bar */}
        <div className="h-0.5 w-full bg-white/8">
          <div className="h-full bg-primary transition-all duration-500" style={{ width: `${progress}%` }} />
        </div>

        {/* Step tabs */}
        <div className="flex overflow-x-auto border-b border-[var(--hairline)] px-4 py-2 gap-1">
          {steps.map((s, i) => (
            <button
              key={s.id}
              type="button"
              onClick={() => setStepIdx(i)}
              className={`shrink-0 rounded px-2.5 py-1 font-mono text-[0.6rem] tracking-wider uppercase transition-colors ${
                i === stepIdx
                  ? "bg-primary/15 text-primary border border-primary/30"
                  : i < stepIdx
                  ? "text-muted-foreground border border-transparent"
                  : "text-muted-foreground/50 border border-transparent"
              }`}
            >
              {i < stepIdx ? <Check className="inline size-3 mr-1" /> : null}
              {s.icon} {s.title}
            </button>
          ))}
        </div>

        {/* Questions */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
          {questions.length === 0 ? (
            <p className="text-sm text-muted-foreground">No settings for this step.</p>
          ) : (
            questions.map((q) => (
              <div key={q.id} className="space-y-1.5">
                <label className="flex items-center gap-2 text-sm font-medium">
                  {q.icon && <span>{q.icon}</span>}
                  {q.title}
                  {q.required && <span className="text-[var(--critical)]">*</span>}
                </label>
                <p className="text-xs text-muted-foreground">{q.label}</p>
                <QuestionField
                  q={q}
                  value={answers[q.id] ?? ""}
                  onChange={(v) => setAnswers((a) => ({ ...a, [q.id]: v }))}
                />
                {q.help_text && (
                  <p className="text-[0.68rem] text-muted-foreground leading-relaxed whitespace-pre-line">
                    {q.help_text}
                    {q.help_url && (
                      <a
                        href={q.help_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="ml-1.5 inline-flex items-center gap-0.5 text-primary hover:underline"
                      >
                        Learn more <ExternalLink className="size-3" />
                      </a>
                    )}
                  </p>
                )}
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-[var(--hairline)] px-6 py-4">
          <button
            type="button"
            onClick={() => setStepIdx((i) => Math.max(0, i - 1))}
            disabled={isFirst}
            className="inline-flex items-center gap-1.5 rounded-md border border-[var(--hairline)] px-3 py-1.5 text-xs text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground disabled:opacity-30"
          >
            <ChevronLeft className="size-3.5" /> Previous
          </button>

          <p className="font-mono text-[0.65rem] text-muted-foreground">
            {data.completed}/{data.total_questions} configured
          </p>

          <button
            type="button"
            onClick={handleSave}
            disabled={saving}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary/20 border border-primary/40 px-4 py-1.5 text-xs text-primary transition-colors hover:bg-primary/30 disabled:opacity-50"
          >
            {saving ? (
              <span className="size-3.5 animate-spin rounded-full border border-primary border-t-transparent" />
            ) : (
              <>
                {isLast ? <Check className="size-3.5" /> : <ChevronRight className="size-3.5" />}
              </>
            )}
            {isLast ? "Finish" : "Save & Continue"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Single popup question (for inline wizard_start events) ────────────

export function PopupQuestion({
  question,
  onAnswer,
  onDismiss,
}: {
  question: WizardQuestion;
  onAnswer: (value: string) => void;
  onDismiss: () => void;
}) {
  const [value, setValue] = useState(question.current_value ?? question.default ?? "");

  const handleSubmit = async () => {
    try {
      await submitPopupAnswer(question.id, value);
      onAnswer(value);
      toast.success(`${question.title} saved`);
    } catch {
      toast.error("Failed to save — check backend connection");
    }
  };

  return (
    <div className="fixed bottom-6 right-6 z-50 w-96 panel p-5 shadow-2xl">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="flex items-center gap-1.5 text-sm font-semibold">
            {question.icon && <span>{question.icon}</span>}
            {question.title}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">{question.label}</p>
        </div>
        <button type="button" onClick={onDismiss} className="shrink-0 text-muted-foreground hover:text-foreground">
          <X className="size-4" />
        </button>
      </div>

      <div className="mt-3">
        <QuestionField q={question} value={value} onChange={setValue} />
      </div>

      {question.help_text && (
        <p className="mt-2 text-[0.65rem] text-muted-foreground">{question.help_text}</p>
      )}

      <div className="mt-4 flex items-center gap-2">
        <button
          type="button"
          onClick={handleSubmit}
          className="flex-1 rounded-md bg-primary/20 border border-primary/40 py-1.5 text-xs text-primary hover:bg-primary/30"
        >
          Save
        </button>
        <button
          type="button"
          onClick={onDismiss}
          className="rounded-md border border-[var(--hairline)] px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground"
        >
          Later
        </button>
      </div>
    </div>
  );
}
