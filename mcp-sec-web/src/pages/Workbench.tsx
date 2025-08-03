import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { DriftWorkbench } from "@/components/DriftWorkbench";
import { apiClient } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { Drift, DriftDiff } from "@/types/drift";

const Workbench = () => {
  const { driftId } = useParams<{ driftId: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [drift, setDrift] = useState<Drift | null>(null);
  const [driftDiff, setDriftDiff] = useState<DriftDiff | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!driftId) {
      setError("No drift ID provided");
      setLoading(false);
      return;
    }

    const fetchDriftData = async () => {
      try {
        setLoading(true);
        setError(null);
        
        // Fetch both drift details and diff in parallel
        const [driftData, diffData] = await Promise.all([
          apiClient.getDrift(driftId),
          apiClient.getDriftDiff(driftId)
        ]);
        
        setDrift(driftData);
        setDriftDiff(diffData);
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Failed to fetch drift data';
        setError(errorMessage);
        toast({
          title: "Error loading drift",
          description: errorMessage,
          variant: "destructive",
        });
      } finally {
        setLoading(false);
      }
    };

    fetchDriftData();
  }, [driftId, toast]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900 mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading drift analysis...</p>
        </div>
      </div>
    );
  }

  if (error || !drift || !driftDiff) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold mb-2">Drift Not Found</h2>
          <p className="text-muted-foreground mb-4">
            {error || "The requested drift could not be found."}
          </p>
          <button 
            onClick={() => navigate('/')}
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            Return to Dashboard
          </button>
        </div>
      </div>
    );
  }

  const handleBack = () => {
    navigate('/');
  };

  const handleApprove = async (comment: string) => {
    try {
      await apiClient.approveDrift(drift.id, 'web-user');
      
      toast({
        title: "Vulnerability Approved",
        description: "The security finding has been approved and acknowledged.",
      });
      
      // Navigate back after approval
      setTimeout(() => navigate('/'), 1000);
    } catch (error) {
      toast({
        title: "Approval failed",
        description: error instanceof Error ? error.message : "Failed to approve vulnerability",
        variant: "destructive",
      });
    }
  };

  const handleBlock = async (comment: string) => {
    try {
      // For blocking, we could create a rejection mechanism
      toast({
        title: "Vulnerability Blocked",
        description: "The security finding has been marked as critical and blocked.",
        variant: "destructive",
      });
      
      setTimeout(() => navigate('/'), 1000);
    } catch (error) {
      toast({
        title: "Block failed",
        description: "Failed to block vulnerability",
        variant: "destructive",
      });
    }
  };

  const handleRequestChanges = async (comment: string) => {
    toast({
      title: "Changes Requested", 
      description: "Development team has been notified to address the security vulnerability.",
    });
    
    setTimeout(() => navigate('/'), 1000);
  };

  return (
    <DriftWorkbench
      drift={drift}
      driftDiff={driftDiff}
      onBack={handleBack}
      onApprove={handleApprove}
      onBlock={handleBlock}
      onRequestChanges={handleRequestChanges}
    />
  );
};

export default Workbench;