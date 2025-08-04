import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { 
  Brain, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle,
  FileText,
  Zap
} from "lucide-react";
import { SemanticAnalysis } from "@/types/drift";

interface SemanticAnalysisPanelProps {
  semanticAnalysis: SemanticAnalysis[];
}

export const SemanticAnalysisPanel = ({ semanticAnalysis }: SemanticAnalysisPanelProps) => {
  if (semanticAnalysis.length === 0) {
    return (
      <Card className="glass-card hover-lift">
        <CardHeader>
          <CardTitle className="text-xl font-bold flex items-center gap-2">
            <Brain className="h-5 w-5 text-primary" />
            Semantic Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Alert className="border-blue-500/20 bg-blue-500/10">
            <Brain className="h-4 w-4 text-blue-600" />
            <AlertDescription className="text-blue-700 dark:text-blue-400">
              No semantic analysis performed. Enable LLM analysis for description matching.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    );
  }

  const mismatches = semanticAnalysis.filter(a => !a.descriptionMatch);
  const avgRiskScore = semanticAnalysis.reduce((sum, a) => sum + a.riskScore, 0) / semanticAnalysis.length;

  return (
    <Card className="glass-card hover-lift">
      <CardHeader>
        <CardTitle className="text-xl font-bold flex items-center gap-2">
          <Brain className="h-5 w-5 text-primary" />
          Semantic Analysis
        </CardTitle>
        <p className="text-sm text-muted-foreground mt-1">
          AI-powered analysis of tool descriptions vs actual capabilities
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Overall Risk Score */}
        <div className="p-4 rounded-lg bg-muted/50 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">Overall Semantic Risk</span>
            <span className="text-2xl font-bold bg-gradient-primary bg-clip-text text-transparent">
              {avgRiskScore.toFixed(1)}/10
            </span>
          </div>
          <Progress value={avgRiskScore * 10} className="h-2" />
          <p className="text-xs text-muted-foreground">
            Based on LLM analysis of {semanticAnalysis.length} tool{semanticAnalysis.length !== 1 ? 's' : ''}
          </p>
        </div>

        {/* Mismatch Alert */}
        {mismatches.length > 0 && (
          <Alert className="border-orange-500/20 bg-orange-500/10">
            <AlertTriangle className="h-4 w-4 text-orange-600" />
            <AlertDescription className="text-orange-700 dark:text-orange-400">
              <strong>Warning:</strong> {mismatches.length} tool{mismatches.length !== 1 ? 's' : ''} have descriptions that don't match their actual capabilities.
            </AlertDescription>
          </Alert>
        )}

        {/* Tool Analysis List */}
        <div className="space-y-3">
          {semanticAnalysis.map((analysis, idx) => (
            <div
              key={idx}
              className={`p-4 rounded-lg border transition-all duration-300 hover:scale-[1.02] ${
                analysis.descriptionMatch
                  ? 'border-green-500/20 bg-green-500/5'
                  : 'border-red-500/20 bg-red-500/5'
              }`}
            >
              <div className="space-y-3">
                {/* Header */}
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold">{analysis.tool}</span>
                    {analysis.descriptionMatch ? (
                      <CheckCircle2 className="h-4 w-4 text-green-600" />
                    ) : (
                      <XCircle className="h-4 w-4 text-red-600" />
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">
                      Risk: {analysis.riskScore}/10
                    </Badge>
                  </div>
                </div>

                {/* Claimed vs Actual */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                  <div className="space-y-1">
                    <div className="flex items-center gap-1 text-muted-foreground">
                      <FileText className="h-3 w-3" />
                      <span className="text-xs font-medium">Claimed</span>
                    </div>
                    <p className="text-sm italic">{analysis.claimedCapabilities}</p>
                  </div>
                  <div className="space-y-1">
                    <div className="flex items-center gap-1 text-muted-foreground">
                      <Zap className="h-3 w-3" />
                      <span className="text-xs font-medium">Actual</span>
                    </div>
                    <p className="text-sm font-mono">{analysis.actualCapabilities}</p>
                  </div>
                </div>

                {/* Mismatch Details */}
                {analysis.mismatchDetails && analysis.mismatchDetails.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-primary/10">
                    <p className="text-xs font-medium text-muted-foreground mb-1">Detected Issues:</p>
                    <ul className="space-y-1">
                      {analysis.mismatchDetails.map((detail, detailIdx) => (
                        <li key={detailIdx} className="text-xs flex items-start gap-1">
                          <span className="text-red-600 mt-0.5">•</span>
                          <span>{detail}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* LLM Note */}
        <div className="mt-4 p-3 rounded-lg bg-muted/30 text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <Brain className="h-3 w-3" />
            <span>Analysis powered by OpenAI GPT-4. Results may require human verification.</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};