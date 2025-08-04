import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { 
  ShieldAlert, 
  ShieldOff, 
  ShieldCheck,
  ArrowRight,
  AlertTriangle,
  Lock,
  Unlock
} from "lucide-react";
import { PermissionChange } from "@/types/drift";

interface SecurityAnalysisPanelProps {
  permissionChanges: PermissionChange[];
}

const severityColors = {
  low: "bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-500/20",
  medium: "bg-orange-500/10 text-orange-700 dark:text-orange-400 border-orange-500/20",
  high: "bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/20",
  critical: "bg-red-700/10 text-red-900 dark:text-red-300 border-red-700/20"
};

const severityIcons = {
  low: ShieldCheck,
  medium: ShieldAlert,
  high: ShieldOff,
  critical: ShieldOff
};

export const SecurityAnalysisPanel = ({ permissionChanges }: SecurityAnalysisPanelProps) => {
  if (permissionChanges.length === 0) {
    return (
      <Card className="glass-card hover-lift">
        <CardHeader>
          <CardTitle className="text-xl font-bold flex items-center gap-2">
            <Lock className="h-5 w-5 text-primary" />
            Permission Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Alert className="border-green-500/20 bg-green-500/10">
            <ShieldCheck className="h-4 w-4 text-green-600" />
            <AlertDescription className="text-green-700 dark:text-green-400">
              No permission changes detected. Tool permissions remain unchanged.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    );
  }

  const criticalChanges = permissionChanges.filter(c => c.severity === 'critical');
  const highChanges = permissionChanges.filter(c => c.severity === 'high');

  return (
    <Card className="glass-card hover-lift">
      <CardHeader>
        <CardTitle className="text-xl font-bold flex items-center gap-2">
          <Lock className="h-5 w-5 text-primary" />
          Permission Analysis
        </CardTitle>
        <p className="text-sm text-muted-foreground mt-1">
          Detected {permissionChanges.length} permission change{permissionChanges.length !== 1 ? 's' : ''}
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Critical Alert */}
        {criticalChanges.length > 0 && (
          <Alert className="border-red-500/20 bg-red-500/10">
            <AlertTriangle className="h-4 w-4 text-red-600" />
            <AlertDescription className="text-red-700 dark:text-red-400">
              <strong>Critical:</strong> {criticalChanges.length} dangerous permission escalation{criticalChanges.length !== 1 ? 's' : ''} detected!
            </AlertDescription>
          </Alert>
        )}

        {/* Permission Changes List */}
        <div className="space-y-3">
          {permissionChanges.map((change, idx) => {
            const Icon = severityIcons[change.severity];
            
            return (
              <div
                key={idx}
                className={`p-4 rounded-lg border ${severityColors[change.severity]} transition-all duration-300 hover:scale-[1.02]`}
              >
                <div className="flex items-start gap-3">
                  <Icon className="h-5 w-5 mt-0.5 flex-shrink-0" />
                  <div className="flex-1 space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold">{change.tool}</span>
                      <Badge variant="outline" className="text-xs">
                        {change.type}
                      </Badge>
                      <Badge 
                        variant={change.severity === 'critical' ? 'destructive' : 'secondary'}
                        className="text-xs"
                      >
                        {change.severity.toUpperCase()}
                      </Badge>
                    </div>
                    
                    <p className="text-sm">{change.description}</p>
                    
                    {change.type === 'escalated' && change.from && change.to && (
                      <div className="flex items-center gap-2 text-sm mt-2">
                        <div className="flex items-center gap-1">
                          <Lock className="h-3 w-3" />
                          <code className="bg-muted px-2 py-0.5 rounded text-xs">
                            {change.from.join(', ')}
                          </code>
                        </div>
                        <ArrowRight className="h-4 w-4 text-muted-foreground" />
                        <div className="flex items-center gap-1">
                          <Unlock className="h-3 w-3" />
                          <code className="bg-muted px-2 py-0.5 rounded text-xs">
                            {change.to.join(', ')}
                          </code>
                        </div>
                      </div>
                    )}
                    
                    {change.type === 'added' && change.to && (
                      <div className="flex items-center gap-2 text-sm mt-2">
                        <span className="text-muted-foreground">New permissions:</span>
                        <code className="bg-muted px-2 py-0.5 rounded text-xs">
                          {change.to.join(', ')}
                        </code>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Summary */}
        {(criticalChanges.length > 0 || highChanges.length > 0) && (
          <Alert variant="destructive" className="mt-4">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              This drift contains {criticalChanges.length + highChanges.length} high-risk permission change{(criticalChanges.length + highChanges.length) !== 1 ? 's' : ''} that require careful review before approval.
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
};