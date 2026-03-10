interface ConfirmModalProps {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function ConfirmModal({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  destructive = false,
  onConfirm,
  onCancel,
}: ConfirmModalProps) {
  if (!open) return null;
  return (
    <div className="overlay" onClick={onCancel}>
      <div className="dialog" onClick={(e) => e.stopPropagation()} style={{ minWidth: 380, maxWidth: 440 }}>
        <h3 style={{ fontWeight: 600, fontSize: "0.9375rem", marginBottom: "0.75rem" }}>{title}</h3>
        <p style={{ color: "var(--color-text-secondary)", fontSize: "0.85rem", lineHeight: 1.5, marginBottom: "1.25rem" }}>
          {message}
        </p>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem" }}>
          <button className="outline sm" onClick={onCancel}>{cancelLabel}</button>
          <button className={`${destructive ? "danger" : "primary"} sm`} onClick={onConfirm}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}
