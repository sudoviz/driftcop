import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { DriftBadge, SignerBadge } from "./DriftBadge";
import { ExternalLink, Eye, FileText, Clock, GitBranch } from "lucide-react";
import { Drift } from "@/types/drift";
import { formatDistanceToNow } from "date-fns";
import { apiClient } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { useState } from "react";

interface DriftDrawerProps {
  drift: Drift | null;
  open: boolean;
  onClose: () => void;
  onOpenWorkbench?: (driftId: string) => void;
  onDriftUpdated?: () => void;
}

export const DriftDrawer = ({ drift, open, onClose, onOpenWorkbench, onDriftUpdated }: DriftDrawerProps) => {
  const { toast } = useToast();
  const [isApproving, setIsApproving] = useState(false);
  
  if (!drift) return null;

  const formatAge = (createdAt: string) => {
    return formatDistanceToNow(new Date(createdAt), { addSuffix: true });
  };

  const handleApprove = async () => {
    try {
      setIsApproving(true);
      await apiClient.approveDrift(drift.id, 'web-user');
      
      toast({
        title: "Drift approved",
        description: `Successfully approved drift for ${drift.toolName}`,
      });
      
      onDriftUpdated?.();
      onClose();
    } catch (error) {
      toast({
        title: "Approval failed",
        description: error instanceof Error ? error.message : "Failed to approve drift",
        variant: "destructive",
      });
    } finally {
      setIsApproving(false);
    }
  };

  const handleBlock = () => {
    // For now, just show a toast - blocking functionality would need to be implemented
    toast({
      title: "Block functionality",
      description: "Block functionality would be implemented here",
      variant: "destructive",
    });
  };

  return (
    <Sheet open={open} onOpenChange={onClose}>
      <SheetContent className="w-full sm:max-w-md overflow-y-auto">
        <SheetHeader>
          <SheetTitle className="text-left">Drift Details</SheetTitle>
        </SheetHeader>
        
        <div className="space-y-6 mt-6">
          {/* Header Info */}
          <div className="space-y-4">
            <div>
              <h3 className="font-semibold text-lg">{drift.repo?.name}</h3>
              <div className="flex items-center gap-2 mt-1">
                <Badge variant="outline">{drift.server?.env}</Badge>
                <span className="text-sm text-muted-foreground">
                  {drift.server?.endpoint}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <DriftBadge severity={drift.severity} />
              <SignerBadge signerOk={drift.signerOk} />
            </div>
          </div>

          <Separator />

          {/* Tool & Timing Info */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Tool:</span>
              <code className="text-sm bg-muted px-2 py-1 rounded">
                {drift.toolName}
              </code>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Detected:</span>
              <div className="flex items-center gap-1 text-sm">
                <Clock className="h-3 w-3" />
                {formatAge(drift.createdAt)}
              </div>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Similarity:</span>
              <span className="text-sm font-mono">
                {(drift.similarity * 100).toFixed(1)}%
              </span>
            </div>
          </div>

          <Separator />

          {/* Diff Preview */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <FileText className="h-4 w-4" />
              <span className="font-medium">Change Preview</span>
            </div>
            
            <div className="bg-muted/50 rounded-lg p-4 space-y-2">
              <div className="text-xs text-muted-foreground uppercase tracking-wide">
                First 5 changed lines
              </div>
              <div className="font-mono text-sm space-y-1">
                <div className="text-red-600 dark:text-red-400">
                  - Previous configuration line 1
                </div>
                <div className="text-green-600 dark:text-green-400">
                  + New configuration line 1
                </div>
                <div className="text-red-600 dark:text-red-400">
                  - endpoint: https://old-api.example.com
                </div>
                <div className="text-green-600 dark:text-green-400">
                  + endpoint: https://new-api.example.com
                </div>
                <div className="text-muted-foreground">
                  ... and {Math.floor(Math.random() * 10) + 3} more changes
                </div>
              </div>
            </div>
          </div>

          <Separator />

          {/* Digest Info */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <GitBranch className="h-4 w-4" />
              <span className="font-medium">Digest Information</span>
            </div>
            
            <div className="space-y-2 text-sm">
              <div>
                <span className="text-muted-foreground">Previous:</span>
                <code className="ml-2 text-xs bg-muted px-2 py-1 rounded">
                  {drift.prevDigest.substring(0, 16)}...
                </code>
              </div>
              <div>
                <span className="text-muted-foreground">Current:</span>
                <code className="ml-2 text-xs bg-muted px-2 py-1 rounded">
                  {drift.newDigest.substring(0, 16)}...
                </code>
              </div>
            </div>
          </div>

          <Separator />

          {/* Actions */}
          <div className="space-y-3">
            <Button 
              className="w-full" 
              onClick={() => onOpenWorkbench?.(drift.id)}
            >
              <Eye className="h-4 w-4 mr-2" />
              Open in Workbench
            </Button>
            
            <div className="grid grid-cols-2 gap-2">
              <Button 
                variant="default"
                size="sm"
                onClick={handleApprove}
                disabled={isApproving}
                className="bg-green-600 hover:bg-green-700"
              >
                {isApproving ? "Approving..." : "Quick Approve"}
              </Button>
              <Button 
                variant="destructive" 
                size="sm"
                onClick={handleBlock}
              >
                Block
              </Button>
            </div>
            
            <Button variant="outline" className="w-full" size="sm">
              <ExternalLink className="h-4 w-4 mr-2" />
              View in GitHub
            </Button>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
};