import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { CheckCircle, XCircle, AlertTriangle, Shield } from "lucide-react";

interface DriftBadgeProps {
  severity: 0 | 1 | 2 | 3;
  className?: string;
}

const severityConfig = {
  0: { label: "LOW", className: "bg-severity-low text-white", icon: CheckCircle },
  1: { label: "MED", className: "bg-severity-medium text-white", icon: AlertTriangle },
  2: { label: "HIGH", className: "bg-severity-high text-white", icon: XCircle },
  3: { label: "BLOCKED", className: "bg-severity-blocked text-white", icon: Shield },
};

export const DriftBadge = ({ severity, className }: DriftBadgeProps) => {
  const config = severityConfig[severity];
  const Icon = config.icon;

  return (
    <Badge className={cn(
      config.className, 
      "gap-1 transition-all duration-300 hover:scale-105",
      className
    )}>
      <Icon className="h-3 w-3" />
      {config.label}
    </Badge>
  );
};

interface SignerBadgeProps {
  signerOk: boolean;
  className?: string;
}

export const SignerBadge = ({ signerOk, className }: SignerBadgeProps) => {
  return (
    <Badge 
      className={cn(
        signerOk 
          ? "bg-status-success text-white hover:glow-success" 
          : "bg-status-error text-white hover:glow-danger",
        "gap-1 transition-all duration-300 hover:scale-105",
        className
      )}
    >
      {signerOk ? (
        <>
          <CheckCircle className="h-3 w-3" />
          SIGNED
        </>
      ) : (
        <>
          <XCircle className="h-3 w-3" />
          UNSIGNED
        </>
      )}
    </Badge>
  );
};