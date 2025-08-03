import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { DriftBadge, SignerBadge } from "./DriftBadge";
import { 
  ArrowLeft, 
  CheckCircle, 
  XCircle, 
  RefreshCw, 
  ExternalLink,
  GitCommit,
  Shield,
  Clock,
  Percent
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

      {/* Analysis Section */}
      <Card className="mb-6 glass-card hover-lift">
        <CardHeader>
          <CardTitle className="text-xl font-bold">Analysis & Verification</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Similarity */}
            <div className="space-y-3 p-4 glass-card hover-lift">
              <div className="flex items-center gap-2">
                <Percent className="h-5 w-5 text-primary" />
                <span className="font-semibold">Similarity</span>
              </div>
              <div className="text-3xl font-mono bg-gradient-primary bg-clip-text text-transparent">
                {(drift.similarity * 100).toFixed(1)}%
              </div>
              <div className="text-sm text-muted-foreground">
                Content similarity score
              </div>
            </div>

            {/* Added Verbs */}
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <GitCommit className="h-4 w-4 text-muted-foreground" />
                <span className="font-medium">Added Verbs</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {driftDiff.addedVerbs.map((verb, idx) => (
                  <Badge key={idx} variant="outline" className="text-xs">
                    {verb}
                  </Badge>
                ))}
              </div>
              <div className="text-sm text-muted-foreground">
                New API operations detected
              </div>
            </div>

            {/* Verification Status */}
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-muted-foreground" />
                <span className="font-medium">Verification</span>
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  {drift.signerOk ? (
                    <CheckCircle className="h-4 w-4 text-status-success" />
                  ) : (
                    <XCircle className="h-4 w-4 text-status-error" />
                  )}
                  <span className="text-sm">
                    Signer check: {drift.signerOk ? 'verified' : 'unknown'}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {driftDiff.rekorProof ? (
                    <CheckCircle className="h-4 w-4 text-status-success" />
                  ) : (
                    <XCircle className="h-4 w-4 text-status-error" />
                  )}
                  <span className="text-sm">
                    Rekor proof: {driftDiff.rekorProof ? 'verified' : 'missing'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

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