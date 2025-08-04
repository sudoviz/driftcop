import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { DriftBadge, SignerBadge } from "./DriftBadge";
import { SecurityAnalysisPanel } from "./SecurityAnalysisPanel";
import { SemanticAnalysisPanel } from "./SemanticAnalysisPanel";
import { 
  ArrowLeft, 
  CheckCircle, 
  XCircle, 
  RefreshCw, 
  ExternalLink,
  Shield,
  Clock,
  AlertTriangle
} from "lucide-react";
import { Drift, DriftDiff } from "@/types/drift";
import { formatDistanceToNow } from "date-fns";
import { DiffEditor } from "@monaco-editor/react";

interface DriftWorkbenchProps {
  drift: Drift;
  driftDiff: DriftDiff;
  onBack: () => void;
  onApprove: (comment: string) => void;
  onBlock: (comment: string) => void;
  onRequestChanges: (comment: string) => void;
}

export const DriftWorkbench = ({ 
  drift, 
  driftDiff, 
  onBack, 
  onApprove, 
  onBlock, 
  onRequestChanges 
}: DriftWorkbenchProps) => {
  const [comment, setComment] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleAction = async (action: 'approve' | 'block' | 'changes') => {
    setIsSubmitting(true);
    try {
      switch (action) {
        case 'approve':
          await onApprove(comment);
          break;
        case 'block':
          await onBlock(comment);
          break;
        case 'changes':
          await onRequestChanges(comment);
          break;
      }
      setComment("");
    } finally {
      setIsSubmitting(false);
    }
  };

  const formatAge = (createdAt: string) => {
    return formatDistanceToNow(new Date(createdAt), { addSuffix: true });
  };

  const renderMonacoDiff = () => {
    return (
      <div className="h-[500px] rounded-lg overflow-hidden border border-primary/20">
        <DiffEditor
          height="500px"
          language="yaml"
          original={driftDiff.prevContent}
          modified={driftDiff.newContent}
          theme="vs-dark"
          options={{
            renderSideBySide: true,
            readOnly: true,
            fontSize: 13,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            wordWrap: "on",
            diffWordWrap: "on"
          }}
        />
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-background p-6 animate-fade-in-up">
      {/* Header */}
      <div className="mb-6 glass-card p-6 hover-lift">
        <div className="flex items-center gap-4 mb-4">
          <Button variant="outline" onClick={onBack} className="glass-card hover:glow-primary transition-all duration-300">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Dashboard
          </Button>
          <Separator orientation="vertical" className="h-6" />
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold bg-gradient-primary bg-clip-text text-transparent">
              {drift.repo?.name}
            </h1>
            <Badge variant="outline" className="glass-card">
              {drift.server?.env}
            </Badge>
            <span className="text-muted-foreground">•</span>
            <span className="text-xl font-semibold">{drift.toolName}</span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <DriftBadge severity={drift.severity} />
          <SignerBadge signerOk={drift.signerOk} />
          <div className="flex items-center gap-1 text-sm text-muted-foreground">
            <Clock className="h-3 w-3" />
            {formatAge(drift.createdAt)}
          </div>
          <Button variant="outline" size="sm">
            <ExternalLink className="h-4 w-4 mr-2" />
            View in GitHub
          </Button>
        </div>
      </div>

      {/* Main Content - Monaco Diff Editor */}
      <Card className="mb-6 glass-card hover-lift">
        <CardHeader>
          <CardTitle className="text-xl font-bold">Configuration Diff</CardTitle>
          <p className="text-sm text-muted-foreground">
            Side-by-side comparison of previous and new configurations
          </p>
        </CardHeader>
        <CardContent>
          {renderMonacoDiff()}
        </CardContent>
      </Card>

      {/* Security Summary Alert */}
      {driftDiff.securitySummary && (driftDiff.securitySummary.criticalFindings > 0 || driftDiff.securitySummary.highFindings > 0) && (
        <Alert className="mb-6 border-red-500/20 bg-red-500/10">
          <AlertTriangle className="h-5 w-5 text-red-600" />
          <AlertDescription className="text-red-700 dark:text-red-400">
            <strong>Security Alert:</strong> This drift contains {driftDiff.securitySummary.criticalFindings} critical and {driftDiff.securitySummary.highFindings} high severity findings that require immediate attention.
          </AlertDescription>
        </Alert>
      )}


      {/* Permission Changes Analysis */}
      {driftDiff.permissionChanges && driftDiff.permissionChanges.length > 0 && (
        <div className="mb-6">
          <SecurityAnalysisPanel permissionChanges={driftDiff.permissionChanges} />
        </div>
      )}

      {/* Semantic Analysis */}
      {driftDiff.semanticAnalysis && driftDiff.semanticAnalysis.length > 0 && (
        <div className="mb-6">
          <SemanticAnalysisPanel semanticAnalysis={driftDiff.semanticAnalysis} />
        </div>
      )}

      {/* Security Findings */}
      {driftDiff.securityFindings && driftDiff.securityFindings.length > 0 && (
        <Card className="mb-6 glass-card hover-lift">
          <CardHeader>
            <CardTitle className="text-xl font-bold flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary" />
              Security Findings
            </CardTitle>
            <p className="text-sm text-muted-foreground mt-1">
              Vulnerabilities and security issues detected in this drift
            </p>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {driftDiff.securityFindings.map((finding, idx) => (
                <div
                  key={idx}
                  className={`p-4 rounded-lg border transition-all duration-300 hover:scale-[1.02] ${
                    finding.severity === 'critical' ? 'border-red-500/20 bg-red-500/5' :
                    finding.severity === 'high' ? 'border-orange-500/20 bg-orange-500/5' :
                    finding.severity === 'medium' ? 'border-yellow-500/20 bg-yellow-500/5' :
                    'border-blue-500/20 bg-blue-500/5'
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge 
                          variant={finding.severity === 'critical' || finding.severity === 'high' ? 'destructive' : 'secondary'}
                          className="text-xs"
                        >
                          {finding.severity.toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          {finding.type.replace(/_/g, ' ')}
                        </Badge>
                        {finding.tool && (
                          <span className="text-sm font-medium">{finding.tool}</span>
                        )}
                      </div>
                      <p className="text-sm mb-2">{finding.description}</p>
                      {finding.location && (
                        <p className="text-xs text-muted-foreground mb-1">
                          Location: <code className="bg-muted px-1 py-0.5 rounded">{finding.location}</code>
                        </p>
                      )}
                      {finding.remediation && (
                        <p className="text-xs text-muted-foreground">
                          <strong>Remediation:</strong> {finding.remediation}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Comment & Actions */}
      <Card className="glass-card hover-lift">
        <CardHeader>
          <CardTitle className="text-xl font-bold">Review & Approval</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <div>
            <label className="text-sm font-semibold mb-3 block">
              Comment (Markdown supported)
            </label>
            <Textarea
              placeholder="Add your review comments here..."
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              rows={4}
              className="resize-none glass border-primary/30 focus:glow-primary transition-all duration-300"
            />
          </div>

          <div className="flex flex-wrap gap-4">
            <Button 
              onClick={() => handleAction('approve')}
              disabled={isSubmitting}
              className="flex-1 sm:flex-none bg-gradient-success hover:glow-success transition-all duration-300 font-semibold"
            >
              {isSubmitting ? (
                <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <CheckCircle className="h-4 w-4 mr-2" />
              )}
              Approve & Re-sign
            </Button>

            <Button 
              variant="destructive"
              onClick={() => handleAction('block')}
              disabled={isSubmitting}
              className="flex-1 sm:flex-none bg-gradient-danger hover:glow-danger transition-all duration-300 font-semibold"
            >
              <XCircle className="h-4 w-4 mr-2" />
              Block
            </Button>

            <Button 
              variant="outline"
              onClick={() => handleAction('changes')}
              disabled={isSubmitting}
              className="flex-1 sm:flex-none glass-card hover:glow-warning transition-all duration-300 font-semibold"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Request Changes
            </Button>
          </div>

          <div className="text-xs text-muted-foreground pt-2">
            <strong>Approve & Re-sign:</strong> Re-computes digest, signs DSSE with your key, updates lock file, creates GitHub commit, uploads to Rekor.
            <br />
            <strong>Block:</strong> Marks drift as blocked (severity 3), prevents deployment.
            <br />
            <strong>Request Changes:</strong> Notifies development team for manual review.
          </div>
        </CardContent>
      </Card>
    </div>
  );
};