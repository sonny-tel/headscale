export function UnsavedFooter({
  visible,
  message,
  onDiscard,
  onSave,
  saving,
  saveLabel = "Save changes",
  discardLabel = "Discard",
}: {
  visible: boolean;
  message?: string;
  onDiscard: () => void;
  onSave: () => void;
  saving?: boolean;
  saveLabel?: string;
  discardLabel?: string;
}) {
  if (!visible) return null;
  return (
    <>
      {/* Spacer so page content isn't hidden behind the fixed footer */}
      <div style={{ height: "3.5rem" }} />
      <div
        style={{
          position: "fixed",
          bottom: 0,
          left: 0,
          right: 0,
          padding: "0.75rem 1.5rem",
          background: "var(--color-surface)",
          borderTop: "1px solid var(--color-border)",
          display: "flex",
          alignItems: "center",
          justifyContent: "flex-end",
          gap: "0.5rem",
          zIndex: 100,
          boxShadow: "0 -2px 12px rgba(0,0,0,0.3)",
        }}
      >
        <span
          className="text-sm text-secondary"
          style={{ marginRight: "auto" }}
        >
          {message || "You have unsaved changes"}
        </span>
        <button
          className="btn outline sm"
          onClick={onDiscard}
          disabled={saving}
        >
          {discardLabel}
        </button>
        <button
          className="btn primary sm"
          onClick={onSave}
          disabled={saving}
        >
          {saving ? "Saving\u2026" : saveLabel}
        </button>
      </div>
    </>
  );
}
