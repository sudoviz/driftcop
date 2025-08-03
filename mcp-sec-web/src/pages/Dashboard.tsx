import { useState, useEffect } from "react";
import { DriftDashboard } from "@/components/DriftDashboard";
import { useNavigate } from "react-router-dom";
import { apiClient } from "@/lib/api";
import { Drift } from "@/types/drift";
import { useToast } from "@/hooks/use-toast";

const Dashboard = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [drifts, setDrifts] = useState<Drift[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDrifts = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await apiClient.getDrifts();
      setDrifts(data);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch drifts';
      setError(errorMessage);
      toast({
        title: "Error fetching drifts",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDrifts();
  }, []);

  const handleRefresh = () => {
    fetchDrifts();
    toast({
      title: "Refreshed",
      description: "Drift data has been refreshed",
    });
  };

  const handleExport = (format: 'csv' | 'json') => {
    try {
      const dataStr = format === 'json' 
        ? JSON.stringify(drifts, null, 2)
        : convertToCSV(drifts);
      
      const blob = new Blob([dataStr], { 
        type: format === 'json' ? 'application/json' : 'text/csv' 
      });
      
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `mcp-sec-drifts.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      
      toast({
        title: "Export successful",
        description: `Data exported as ${format.toUpperCase()}`,
      });
    } catch (err) {
      toast({
        title: "Export failed",
        description: "Failed to export data",
        variant: "destructive",
      });
    }
  };

  const convertToCSV = (data: Drift[]): string => {
    const headers = ['ID', 'Server', 'Tool', 'Severity', 'Similarity', 'Environment', 'Created At'];
    const rows = data.map(drift => [
      drift.id,
      drift.server?.endpoint || 'Unknown',
      drift.toolName,
      drift.severity,
      `${(drift.similarity * 100).toFixed(1)}%`,
      drift.server?.env || 'Unknown',
      drift.createdAt
    ]);
    
    return [headers, ...rows].map(row => row.join(',')).join('\n');
  };

  const handleOpenWorkbench = (driftId: string) => {
    navigate(`/workbench/${driftId}`);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900 mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading drift data...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <p className="text-red-600 mb-4">Error: {error}</p>
          <button 
            onClick={handleRefresh}
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <DriftDashboard
      drifts={drifts}
      onRefresh={handleRefresh}
      onExport={handleExport}
      onOpenWorkbench={handleOpenWorkbench}
      onDriftUpdated={fetchDrifts}
    />
  );
};

export default Dashboard;