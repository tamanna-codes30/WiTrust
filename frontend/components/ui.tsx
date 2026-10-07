import type { ComponentProps, ReactNode } from "react";
import type { RiskLevel } from "@/lib/types";
import { Icon } from "@/components/icons";

export function Panel({ children, className = "", title, icon, action }: {
  children: ReactNode;
  className?: string;
  title?: string;
  icon?: ComponentProps<typeof Icon>["name"];
  action?: ReactNode;
}) {
  return (
    <section className={`panel ${className}`}>
      {title && <div className="panel-heading">
        <div className="panel-title">{icon && <Icon name={icon} />}<h2>{title}</h2></div>
        {action}
      </div>}
      {children}
    </section>
  );
}

export function RiskBadge({ level, score }: { level: RiskLevel; score?: number }) {
  return <span className={`risk-badge risk-${level.toLowerCase()}`}><i />{score === undefined ? level : `${score}/100 · ${level}`}</span>;
}

export function EmptyState({ title, detail, action }: { title: string; detail: string; action?: ReactNode }) {
  return <div className="empty-state"><span className="empty-icon"><Icon name="scan" /></span><strong>{title}</strong><p>{detail}</p>{action}</div>;
}

export function Button({ children, onClick, icon, variant = "secondary", disabled, type = "button", className = "" }: {
  children: ReactNode;
  onClick?: () => void;
  icon?: ComponentProps<typeof Icon>["name"];
  variant?: "primary" | "secondary" | "quiet" | "danger";
  disabled?: boolean;
  type?: "button" | "submit";
  className?: string;
}) {
  return <button type={type} onClick={onClick} disabled={disabled} className={`button button-${variant} ${className}`}>{icon && <Icon name={icon} />}{children}</button>;
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return <span className="spinner-wrap" role="status"><i className="spinner" /><span>{label}</span></span>;
}
